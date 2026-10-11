//! Extracts `$keepass$` hashes from KeePass key databases.
//!
//! Two containers are handled:
//!
//! * KeePass 1.x (`$keepass$*1*...`) — fixed-layout header after the
//!   signature; the encrypted payload spans byte 124 to end of file.
//! * KDBX, KeePass 2.x versions 2–4.1 (`$keepass$*2*...` for KDBX3,
//!   `$keepass$*4*...` for KDBX4). KDBX4 takes its key-derivation
//!   parameters from the header's VariantDictionary (Argon2d, Argon2id or
//!   AES-KDF) and digests the raw header bytes with SHA-256 and HMAC; both
//!   digests are part of the hash line.
//!
//! Output labels follow the container convention: KDBX4 lines use the full
//! file name including its extension, earlier versions strip `.kdbx`.
//! A keyfile from `input.extra_files[0]` (CLI `-k`) is appended as a
//! keyfile section.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util::{self, basename};
use sha2::{Digest, Sha256};

pub struct Keepass;

const SIG1: u32 = 0x9AA2_D903;
const SIG2_OLD: u32 = 0xB54B_FB65; // KeePass 1.x
const SIG2: u32 = 0xB54B_FB67; // KeePass 2.x
const SIG2_PRERELEASE: u32 = 0xB54B_FB66;
const VERSION_CRITICAL_MASK: u32 = 0xFFFF_0000;
const FILE_VERSION_3_1: u32 = 0x0003_0001;
const FILE_VERSION_4: u32 = 0x0004_0000;
const FILE_VERSION_4_1: u32 = 0x0004_0001;

/// KDBX header field IDs (KeePass KDBX format).
const FIELD_END_OF_HEADER: u8 = 0;
const FIELD_CIPHER_ID: u8 = 2;
const FIELD_MASTER_SEED: u8 = 4;
const FIELD_TRANSFORM_SEED: u8 = 5;
const FIELD_TRANSFORM_ROUNDS: u8 = 6;
const FIELD_ENCRYPTION_IV: u8 = 7;
const FIELD_STREAM_START_BYTES: u8 = 9;
const FIELD_KDF_PARAMETERS: u8 = 11;

/// VariantDictionary value types used by the KDBX4 KDF parameters.
const VD_UINT32: u8 = 0x04;
const VD_UINT64: u8 = 0x05;
const VD_BYTE_ARRAY: u8 = 0x42;

/// Payload cipher UUIDs (first four bytes, as stored in the CipherID
/// header field).
const CIPHER_AES: [u8; 4] = [0x31, 0xC1, 0xF2, 0xE6];
const CIPHER_TWOFISH: [u8; 4] = [0xAD, 0x68, 0xF2, 0x9F];
const CIPHER_CHACHA20: [u8; 4] = [0xD6, 0x03, 0x8A, 0x2B];

/// Cipher codes carried by `$keepass$*1` and `$keepass$*2` lines.
const CIPHER_CODE_AES: u32 = 0;
const CIPHER_CODE_TWOFISH: u32 = 1;
const CIPHER_CODE_CHACHA20: u32 = 2;

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().expect("4 bytes"))
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes(b[..2].try_into().expect("2 bytes"))
}

/// Little-endian integer over up to 8 available bytes; short slices
/// contribute only the low-order bytes they have.
fn le_bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut value = 0u64;
    for (i, &b) in bytes.iter().take(8).enumerate() {
        value |= (b as u64) << (8 * i);
    }
    value
}

/// File name without the `.kdbx` extension — the label convention for
/// pre-KDBX4 output lines.
fn database_name(path: &str) -> String {
    let name = basename(path).to_string();
    match name.strip_suffix(".kdbx") {
        Some(stem) => stem.to_string(),
        None => name,
    }
}

/// Header and KDF parameters collected while walking a KDBX header.
#[derive(Default)]
struct KdbxParams<'a> {
    transform_rounds: u32,
    master_seed: Option<&'a [u8]>,
    transform_seed: Option<&'a [u8]>,
    encryption_iv: Option<&'a [u8]>,
    stream_start_bytes: Option<&'a [u8]>,
    cipher_code: u32, // defaults to AES
    kdf_uuid: u32,
    argon2_memory_kib: u64,
    argon2_version: u32,
    argon2_parallelism: u32,
}

impl Extractor for Keepass {
    fn name(&self) -> &'static str {
        "keepass"
    }

    fn description(&self) -> &'static str {
        "KeePass 1.x/2.x database files (.kdbx, optional keyfile)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.len() >= 12
            && le32(&input.data[0..4]) == SIG1
            && matches!(le32(&input.data[4..8]), SIG2_OLD | SIG2 | SIG2_PRERELEASE)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < 8 {
            return Err(Error::not_format("keepass", input.label()));
        }
        let (sig1, sig2) = (le32(&data[0..4]), le32(&data[4..8]));
        if sig1 == SIG1 && sig2 == SIG2_OLD {
            return extract_keepass1(input);
        }
        if sig1 != SIG1 || (sig2 != SIG2 && sig2 != SIG2_PRERELEASE) {
            return Err(Error::malformed(input.label(), "invalid KDBX signature"));
        }
        extract_kdbx(input)
    }
}

/// KeePass 1.x container: fixed-layout header, `$keepass$*1*` output.
fn extract_keepass1(input: &Input) -> Result<Vec<HashLine>> {
    let data = &input.data;
    let name = database_name(input.label());

    if data.len() < 124 {
        return Err(Error::malformed(
            input.label(),
            "truncated KeePass 1.x database",
        ));
    }
    let mut pos = 8;
    let cipher_flags = le32(&data[pos..]);
    pos += 4;
    let file_version = le32(&data[pos..]);
    pos += 4;
    let final_random_seed = &data[pos..pos + 16];
    pos += 16;
    let encryption_iv = &data[pos..pos + 16];
    pos += 16;
    let _group_count = le32(&data[pos..]);
    let _entry_count = le32(&data[pos + 4..]);
    pos += 8;
    let contents_hash = &data[pos..pos + 32];
    pos += 32;
    let master_seed = &data[pos..pos + 32];
    pos += 32;
    let transform_rounds = le32(&data[pos..]);

    if file_version & VERSION_CRITICAL_MASK != FILE_VERSION_3_1 & VERSION_CRITICAL_MASK {
        return Err(Error::malformed(
            input.label(),
            format!("unsupported KeePass 1.x file version {file_version}"),
        ));
    }
    let cipher_code = if cipher_flags & 2 != 0 {
        CIPHER_CODE_AES
    } else if cipher_flags & 8 != 0 {
        CIPHER_CODE_TWOFISH
    } else {
        return Err(Error::malformed(
            input.label(),
            format!("unsupported KeePass 1.x cipher flags 0x{cipher_flags:x}"),
        ));
    };

    let payload_len = data.len() - 124;
    let mut line = format!(
        "{}:$keepass$*1*{}*{}*{}*{}*{}*{}*1*{}*",
        name,
        transform_rounds,
        cipher_code,
        hex::encode(final_random_seed),
        hex::encode(master_seed),
        hex::encode(encryption_iv),
        hex::encode(contents_hash),
        payload_len,
    );
    line.push_str(&hex::encode(&data[124..124 + payload_len]));

    if let Some(kf) = input.extra_files.first() {
        line.push_str("*1*64*");
        line.push_str(&keyfile_hex_v1(kf.data.as_slice()));
    }
    Ok(vec![HashLine::new(name.clone(), line)])
}

/// KDBX container (KeePass 2.x): walk the header fields, then emit
/// `$keepass$*2*` (KDBX3) or `$keepass$*4*` (KDBX4).
fn extract_kdbx(input: &Input) -> Result<Vec<HashLine>> {
    let data = &input.data;
    let version_probe = if data.len() >= 12 {
        le32(&data[8..12])
    } else {
        0
    };
    // KDBX4+ lines keep the full file name (extension included); KDBX3 and
    // older strip the `.kdbx` suffix.
    let name = if version_probe & VERSION_CRITICAL_MASK >= FILE_VERSION_4 & VERSION_CRITICAL_MASK {
        basename(input.label()).to_string()
    } else {
        database_name(input.label())
    };
    let file_size = data.len() as u32;

    let file_version = le32(&data[8..12]);
    if file_version & VERSION_CRITICAL_MASK > FILE_VERSION_4_1 & VERSION_CRITICAL_MASK {
        return Err(Error::malformed(
            input.label(),
            format!("unsupported KDBX version 0x{file_version:x}"),
        ));
    }

    let mut params = KdbxParams::default();
    let mut pos = 12usize;
    loop {
        if pos >= data.len() {
            return Err(Error::malformed(
                input.label(),
                "truncated KDBX header (no end-of-header field)",
            ));
        }
        let field_id = data[pos];
        pos += 1;
        // KDBX3 header fields carry a 16-bit size, KDBX4 a 32-bit one.
        let field_size = if file_version < FILE_VERSION_4 {
            u32::from(le16(&data[pos..]))
        } else {
            le32(&data[pos..])
        } as usize;
        pos += if file_version < FILE_VERSION_4 { 2 } else { 4 };
        if field_size as u32 > file_size.saturating_sub(pos as u32) {
            return Err(Error::malformed(
                input.label(),
                "KDBX header field exceeds file size",
            ));
        }
        if field_size == 0 && field_id != FIELD_END_OF_HEADER {
            return Err(Error::malformed(
                input.label(),
                "truncated KDBX header (zero-length field)",
            ));
        }
        let field_data = &data[pos..pos + field_size];
        pos += field_size;

        match field_id {
            FIELD_END_OF_HEADER => break,
            FIELD_MASTER_SEED => params.master_seed = Some(field_data),
            FIELD_TRANSFORM_SEED => params.transform_seed = Some(field_data),
            FIELD_TRANSFORM_ROUNDS => {
                if field_size < 4 {
                    return Err(Error::malformed(
                        input.label(),
                        "KDBX TransformRounds field too short",
                    ));
                }
                params.transform_rounds = le_bytes_to_u64(field_data) as u32;
            }
            FIELD_ENCRYPTION_IV => params.encryption_iv = Some(field_data),
            FIELD_STREAM_START_BYTES => params.stream_start_bytes = Some(field_data),
            FIELD_CIPHER_ID => {
                if field_size < 4 {
                    return Err(Error::malformed(
                        input.label(),
                        format!("KDBX CipherID field too short ({field_size} bytes)"),
                    ));
                }
                params.cipher_code = if field_data.starts_with(&CIPHER_AES) {
                    CIPHER_CODE_AES
                } else if field_data.starts_with(&CIPHER_TWOFISH) {
                    CIPHER_CODE_TWOFISH
                } else if field_data.starts_with(&CIPHER_CHACHA20) {
                    CIPHER_CODE_CHACHA20
                } else {
                    return Err(Error::malformed(
                        input.label(),
                        "unsupported KDBX cipher UUID",
                    ));
                };
            }
            FIELD_KDF_PARAMETERS => parse_kdf_parameters(field_data, input.label(), &mut params)?,
            _ => {} // remaining header fields carry no hash parameters
        }
    }

    if params.transform_rounds == 0 {
        return Err(Error::malformed(input.label(), "KDF round count is zero"));
    }
    if file_version < FILE_VERSION_4
        && (params.master_seed.is_none()
            || params.transform_seed.is_none()
            || params.encryption_iv.is_none()
            || params.stream_start_bytes.is_none())
    {
        return Err(Error::malformed(
            input.label(),
            "KDBX3 header is missing required fields",
        ));
    }
    if file_version & VERSION_CRITICAL_MASK > FILE_VERSION_4 & VERSION_CRITICAL_MASK {
        return Err(Error::malformed(
            input.label(),
            format!("KDBX version 0x{file_version:x} is not supported"),
        ));
    }

    let kdbx_version = file_version >> 16;
    let mut line;
    if kdbx_version < 4 {
        if pos + 32 > data.len() {
            return Err(Error::malformed(
                input.label(),
                "truncated encrypted payload",
            ));
        }
        let first_encrypted_block = &data[pos..pos + 32];
        line = format!(
            "{}:$keepass$*2*{}*{}*{}*{}*{}*{}*{}",
            name,
            params.transform_rounds,
            params.cipher_code,
            hex::encode(params.master_seed.unwrap_or(&[])),
            hex::encode(params.transform_seed.unwrap_or(&[])),
            hex::encode(params.encryption_iv.unwrap_or(&[])),
            hex::encode(params.stream_start_bytes.unwrap_or(&[])),
            hex::encode(first_encrypted_block),
        );
    } else {
        // KDBX4: the raw header is digested with SHA-256 and HMAC; both
        // digests are part of the hash line.
        let header_len = pos;
        let header_sha256 = Sha256::digest(&data[..header_len]);
        if header_len + 32 > data.len() {
            return Err(Error::malformed(&name, "truncated KDBX4 header hash"));
        }
        let header_hash = &data[header_len..header_len + 32];
        if header_hash != header_sha256.as_slice() {
            eprintln!("{name}: KDBX4 header hash mismatch - database corrupt?");
        }
        let hmac_offset = header_len + 32;
        if hmac_offset + 32 > data.len() {
            return Err(Error::malformed(
                input.label(),
                "truncated KDBX4 header HMAC",
            ));
        }
        let header_hmac = &data[hmac_offset..hmac_offset + 32];

        line = format!(
            "{}:$keepass$*{}*{}*{:08x}*{}*{}*{}*{}*{}*{}*{}",
            name,
            kdbx_version,
            params.transform_rounds,
            params.kdf_uuid,
            params.argon2_memory_kib,
            params.argon2_version,
            params.argon2_parallelism,
            hex::encode(params.master_seed.unwrap_or(&[])),
            hex::encode(params.transform_seed.unwrap_or(&[])),
            hex::encode(&data[..header_len]),
            hex::encode(header_hmac),
        );
    }

    if let Some(kf) = input.extra_files.first() {
        line.push_str("*1*64*");
        line.push_str(&keyfile_hex_v2(kf.data.as_slice())?);
    }
    Ok(vec![HashLine::new(name.clone(), line)])
}

/// Parse the KDBX4 KDF-parameters VariantDictionary: a version word
/// followed by typed key/value entries. Recognized keys: `R`/`I` (rounds),
/// `M` (memory), `V` (Argon2 version), `P` (parallelism), `S` (KDF salt,
/// which supersedes the TransformSeed header field) and `$UUID` (KDF
/// identifier, stored little-endian and emitted big-endian).
fn parse_kdf_parameters<'a>(
    data: &'a [u8],
    label: &str,
    params: &mut KdbxParams<'a>,
) -> Result<()> {
    let dict_version = le_bytes_to_u64(data) as u16;
    if dict_version >> 8 != 1 {
        return Err(Error::malformed(
            label,
            format!("unsupported VariantDictionary version 0x{dict_version:04x}"),
        ));
    }
    let mut pos = 2usize;
    while pos < data.len() {
        let value_type = data[pos];
        pos += 1;
        if value_type == 0 {
            break; // end-of-dictionary marker
        }
        let key_len = le_bytes_to_u64(&data[pos..]) as u32 as usize;
        pos += 4;
        let key = &data[pos..pos + key_len];
        pos += key_len;
        let value_len = le_bytes_to_u64(&data[pos..]) as u32 as usize;
        pos += 4;
        let value = &data[pos..pos + value_len];
        pos += value_len;
        match value_type {
            VD_UINT32 => {
                let scalar = le_bytes_to_u64(value) as u32;
                match key {
                    b"P" => params.argon2_parallelism = scalar,
                    b"V" => params.argon2_version = scalar,
                    _ => {}
                }
            }
            VD_UINT64 => {
                let scalar = le_bytes_to_u64(value);
                match key {
                    b"R" | b"I" => params.transform_rounds = scalar as u32,
                    b"M" => params.argon2_memory_kib = scalar,
                    _ => {}
                }
            }
            VD_BYTE_ARRAY => {
                if key == b"S" {
                    params.transform_seed = Some(value);
                } else if key == b"$UUID" {
                    params.kdf_uuid = le32(value).swap_bytes();
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// KeePass 1.x keyfile section: 32 raw bytes hex-encoded, 64 hex chars
/// copied verbatim, anything else SHA-256-hashed and hex-encoded.
fn keyfile_hex_v1(content: &[u8]) -> String {
    match content.len() {
        32 => hex::encode(content),
        64 => String::from_utf8_lossy(content).into_owned(),
        _ => {
            let digest = Sha256::digest(content);
            hex::encode(digest)
        }
    }
}

/// KDBX keyfile section. XML keyfiles (`<?xml` opening tag, a `<Key>`
/// element followed by a `<Data>` element) are reduced to their base64
/// payload — whitespace is skipped, decoding stops at `=` padding or the
/// closing tag — and emitted as hex, at most 128 hex chars (the first 64
/// decoded bytes). Non-XML keyfiles follow [`keyfile_hex_v1`].
fn keyfile_hex_v2(content: &[u8]) -> Result<String> {
    let text = String::from_utf8_lossy(content);
    if text.starts_with("<?xml") {
        if let Some(start) =
            util::find(content, b"<Key>").and_then(|i| find_after(&text, i, "<Data>"))
        {
            let bytes = text.as_bytes();
            let mut payload = start + "<Data>".len();
            while payload < bytes.len() && matches!(bytes[payload], b' ' | b'\t' | b'\r' | b'\n') {
                payload += 1;
            }
            let end = text[payload..]
                .find("</Data>")
                .map(|e| payload + e)
                .unwrap_or(bytes.len());
            let mut hex_out = String::new();
            let mut sextets: Vec<i32> = Vec::new();
            for &c in &bytes[payload..end] {
                if c == b'=' || matches!(c, b' ' | b'\t' | b'\r' | b'\n') {
                    break;
                }
                match base64_sextet(c) {
                    Some(v) => sextets.push(v as i32),
                    None => break,
                }
                if sextets.len() == 4 {
                    emit_b64_quad(&mut sextets, &mut hex_out);
                }
            }
            if sextets.len() >= 2 {
                emit_b64_quad(&mut sextets, &mut hex_out);
            }
            hex_out.truncate(128);
            return Ok(hex_out);
        }
    }
    Ok(keyfile_hex_v1(content))
}

fn base64_sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode up to four base64 sextets into hex output; a truncated final
/// quad yields one or two bytes instead of three.
fn emit_b64_quad(sextets: &mut Vec<i32>, out: &mut String) {
    let sextet = |i: usize| {
        if i < sextets.len() {
            sextets[i] & 0x3F
        } else {
            0
        }
    };
    let word = ((sextet(0) << 18) | (sextet(1) << 12) | (sextet(2) << 6) | sextet(3)) as u32;
    out.push_str(&format!("{:02x}", (word >> 16) & 0xFF));
    if sextets.len() >= 2 {
        out.push_str(&format!("{:02x}", (word >> 8) & 0xFF));
    }
    if sextets.len() == 4 {
        out.push_str(&format!("{:02x}", word & 0xFF));
    }
    sextets.clear();
}

fn find_after(haystack: &str, from: usize, needle: &str) -> Option<usize> {
    haystack[from..].find(needle).map(|i| from + i)
}
