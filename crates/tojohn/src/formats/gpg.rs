//! Extracts `$gpg$` hashes from OpenPGP secret key files (binary or
//! ASCII-armored), supporting RSA (pub 1-3), ElGamal (16/20) and DSA (17)
//! secret key packets protected with the S2K usages 0/254/255 and the
//! symmetrically-encrypted (Tag 9/18) data path.
//!
//! Output label is the user ID text (up to `(` / `<`), or the file basename
//! without `.gpg`/`.pgp` suffix when no user ID packet precedes the key.

use base64::Engine;

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Gpg;

/// Every packet header byte has the high bit set.
const BINARY_TAG_FLAG: u8 = 0x80;
/// New-format header flag: the tag number sits in the low 6 bits.
const NEW_TAG_FLAG: u8 = 0x40;
/// Low 6 bits of the header byte.
const TAG_MASK: u8 = 0x3f;
/// Old-format tag numbers start at bit 2 of the header byte.
const OLD_TAG_SHIFT: u32 = 2;
/// Old-format 2-bit length type in the low header bits.
const OLD_LEN_MASK: u8 = 0x03;
/// Partial-length exponent carried in the low 5 length bits.
const PARTIAL_MASK: u32 = 0x1f;

const TAG_COMPRESSED: usize = 8;

/// S2K count decode bias (RFC 4880).
const EXPBIAS: u32 = 6;

/// IV lengths per symmetric algorithm (RFC 4880).
const IV_LEN: [usize; 14] = [0, 8, 8, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 16];

/// Parsed state shared across the packet walk.
#[derive(Default)]
struct State {
    gecos: String,
    login: String,
    last_hash: String,
    is_subkey: bool,
    dump_subkeys: bool,

    // fields carried into the emitted `$gpg$` line
    key_algorithm: usize,
    s2k_type: usize,
    s2k_usage: usize,
    hash_algorithm: usize,
    cipher_algorithm: usize,
    s2k_count: usize,
    salt: Vec<u8>,
    iv: Vec<u8>,
    iv_len: usize,
    n_bits: usize,
    p_bits: usize,
    q_bits: usize,
    g_bits: usize,
    y_bits: usize,
    key_bits: usize,
    public_algorithm: usize,
    version: usize,
    n: Vec<u8>,
    p: Vec<u8>,
    g: Vec<u8>,
    y: Vec<u8>,
}

impl Extractor for Gpg {
    fn name(&self) -> &'static str {
        "gpg"
    }

    fn description(&self) -> &'static str {
        "OpenPGP (GPG) secret key files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"\x8c")
            || input.data.starts_with(b"\x95")
            || crate::util::find(&input.data, b"---BEGIN").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut st = State {
            dump_subkeys: input.extra_args.iter().any(|a| a == "-S"),
            ..Default::default()
        };
        let raw = &input.data;
        // strip armor if present (the input is expected to hold a single key)
        let bytes = if raw.starts_with(b"-----BEGIN")
            || (!raw.is_empty() && raw[0] & BINARY_TAG_FLAG == 0)
        {
            match strip_armor(raw) {
                Some(bytes) => bytes,
                None => return Err(Error::malformed(input.label(), "can't find PGP armor.")),
            }
        } else {
            raw.clone()
        };

        let mut reader = Reader {
            data: &bytes,
            pos: 0,
        };
        let mut out = Vec::new();
        let filename = input.label();

        parse_packets(&mut reader, &mut st, &bytes, filename, &mut out);

        // emit a buffered `$gpg$` hash after the packet walk; the login is
        // computed at emit time from the user ID text accumulated over the
        // whole file
        if !st.last_hash.is_empty() {
            let login = if st.gecos.is_empty() {
                default_login(filename)
            } else {
                sanitize_login(&st.gecos)
            };
            out.push(HashLine::new(
                login.clone(),
                format!("{}:{}:::{}::{}", login, st.last_hash, st.gecos, filename),
            ));
            st.last_hash.clear();
        }

        if out.is_empty() {
            return Err(Error::malformed(
                input.label(),
                format!(
                    "no hash was generated for {filename}, ensure that the input file contains a single private key only."
                ),
            ));
        }
        Ok(out)
    }
}

fn default_login(filename: &str) -> String {
    let base = crate::util::basename(filename);
    let base = base.strip_suffix(".gpg").unwrap_or(base);
    let base = base.strip_suffix(".pgp").unwrap_or(base);
    base.to_string()
}

fn sanitize_login(login: &str) -> String {
    // cut at first '(' and last '<'
    let paren = login.find('(').unwrap_or(login.len());
    let angle = login.rfind('<').unwrap_or(login.len());
    let login = &login[..paren.min(angle)];
    // replace ':' with ' ' and trim trailing spaces
    let login = login.replace(':', " ");
    login.trim_end().to_string()
}

/// Strip ASCII armor: skip to the "-----BEGIN PGP" marker line (not the
/// SIGNED variant), skip the armor headers up to a blank line, then
/// base64-decode the body up to the checksum line.
fn strip_armor(raw: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(raw);
    let mut lines = text.lines();
    let is_begin_marker = |line: &str| {
        line.starts_with("-----BEGIN PGP") && !line.starts_with("-----BEGIN PGP SIGNED")
    };
    if !lines.by_ref().any(is_begin_marker) {
        return None;
    }
    // skip the armor headers up to the blank line
    for line in lines.by_ref() {
        if line.trim().is_empty() {
            break;
        }
    }
    // collect the base64 body up to a blank line or the '=' checksum line
    let mut base64_text = String::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !base64_text.is_empty() {
                break;
            }
            continue;
        }
        if trimmed.starts_with('=') || trimmed.starts_with("-----") {
            break;
        }
        base64_text.push_str(trimmed);
    }
    let engine = base64::engine::general_purpose::STANDARD;
    match engine.decode(base64_text.as_bytes()) {
        Ok(decoded) => Some(decoded),
        Err(_) => {
            // tolerate a missing pad
            let mut padded = base64_text.clone();
            while !padded.len().is_multiple_of(4) {
                padded.push('=');
            }
            engine.decode(padded.as_bytes()).ok()
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn read_byte(&mut self) -> Option<u8> {
        let byte = self.data.get(self.pos).copied();
        if byte.is_some() {
            self.pos += 1;
        }
        byte
    }

    /// Reads `count` bytes; stops (with `pos` at the failure point) at EOF.
    fn read_bytes(&mut self, count: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.read_byte()?);
        }
        Some(out)
    }
}

/// Parse packets from `reader`, including partial lengths for the tag-18/9
/// data packets.
fn parse_packets(
    reader: &mut Reader,
    st: &mut State,
    bytes: &[u8],
    filename: &str,
    out: &mut Vec<HashLine>,
) {
    let mut partial = false;
    let mut first_data = true;
    let mut hash_buf = String::new();
    let mut totlen: u64 = 0;

    while let Some(header_byte) = reader.read_byte() {
        // New-format headers carry the tag number in the low 6 bits;
        // old-format headers fold the 2-bit length type into those bits.
        let tag = (header_byte & TAG_MASK) as usize;
        let len: i64 = if header_byte & NEW_TAG_FLAG != 0 {
            let length_byte = reader.read_byte().unwrap_or(0);
            partial = is_partial(length_byte);
            read_new_length(length_byte, reader)
        } else {
            let length_type = header_byte & OLD_LEN_MASK;
            match length_type {
                0 => reader.read_byte().unwrap_or(0) as i64,
                1 => {
                    let hi = reader.read_byte().unwrap_or(0) as i64;
                    let lo = reader.read_byte().unwrap_or(0) as i64;
                    (hi << 8) + lo
                }
                2 => {
                    let b0 = (reader.read_byte().unwrap_or(0) as i64) << 24;
                    let b1 = (reader.read_byte().unwrap_or(0) as i64) << 16;
                    let b2 = (reader.read_byte().unwrap_or(0) as i64) << 8;
                    let b3 = reader.read_byte().unwrap_or(0) as i64;
                    b0 | b1 | b2 | b3
                }
                // indeterminate length: only compressed data has a size
                _ => {
                    let old_tag = ((header_byte & TAG_MASK) >> OLD_TAG_SHIFT) as usize;
                    if old_tag == TAG_COMPRESSED {
                        0
                    } else {
                        -1
                    }
                }
            }
        };

        if partial {
            // accumulate the data packet pieces; a tag-18 body is preceded
            // by one version byte
            if tag == 18 {
                let _ = reader.read_byte();
            }
            let body = &bytes[reader.pos..(reader.pos + len as usize).min(bytes.len())];
            totlen += body.len() as u64;
            hash_buf.push_str(&hex::encode(body));
            reader.pos = (reader.pos + len as usize).min(bytes.len());
            continue;
        }

        match tag {
            // Tag 5 / 7: secret key / subkey
            5 | 7 => {
                st.is_subkey = tag == 7;
                secret_key_packet(reader, st, len as usize, filename);
            }
            6 | 14 => public_key_packet(reader, st, len as usize),
            13 => {
                // User ID: fill gecos
                let uid_bytes = &bytes[reader.pos..(reader.pos + len as usize).min(bytes.len())];
                st.gecos = String::from_utf8_lossy(uid_bytes).into_owned();
                reader.pos += len as usize;
            }
            18 => {
                // Sym. Encrypted and Integrity Protected Data Packet —
                // final chunk (non-partial)
                let _ = reader.read_byte(); // version
                let body_len = (len - 1).max(0) as usize;
                let body = &bytes[reader.pos..(reader.pos + body_len).min(bytes.len())];
                if first_data {
                    hash_buf.clear();
                    totlen = 0;
                }
                totlen += body.len() as u64;
                hash_buf.push_str(&hex::encode(body));
                reader.pos += body_len;
                st.s2k_usage = 18;
                let full_hash = format!(
                    "$gpg$*{}*{}*{}*{}*{}*{}*{}*{}*{}{}",
                    st.key_algorithm,
                    totlen,
                    hash_buf,
                    st.s2k_type,
                    st.s2k_usage,
                    st.hash_algorithm,
                    st.cipher_algorithm,
                    st.s2k_count,
                    hex::encode(&st.salt),
                    "",
                );
                let mut login = st.login.clone();
                if login.is_empty() {
                    login = default_login(filename);
                }
                let login = sanitize_login(&login);
                out.push(HashLine::new(
                    login.clone(),
                    format!("{}:{}:::{}::{}", login, full_hash, st.gecos, filename),
                ));
                st.last_hash.clear();
                first_data = true;
            }
            9 => {
                // Symmetrically Encrypted Data Packet
                let body = &bytes[reader.pos..(reader.pos + len as usize).min(bytes.len())];
                totlen += body.len() as u64;
                hash_buf.push_str(&hex::encode(body));
                reader.pos += len as usize;
            }
            _ => {
                reader.pos = (reader.pos + len.max(0) as usize).min(bytes.len());
            }
        }
    }
}

/// New-format packet length: one-byte, two-byte (+192 offset), five-byte
/// (0xff prefix) or a partial length (power of two).
fn read_new_length(first: u8, reader: &mut Reader) -> i64 {
    let first = first as u32;
    if first < 192 {
        first as i64
    } else if first < 224 {
        (((first - 192) << 8) + reader.read_byte().unwrap_or(0) as u32 + 192) as i64
    } else if first == 255 {
        let b0 = (reader.read_byte().unwrap_or(0) as i64) << 24;
        let b1 = (reader.read_byte().unwrap_or(0) as i64) << 16;
        let b2 = (reader.read_byte().unwrap_or(0) as i64) << 8;
        let b3 = reader.read_byte().unwrap_or(0) as i64;
        b0 | b1 | b2 | b3
    } else {
        1i64 << (first & PARTIAL_MASK)
    }
}

fn is_partial(length_byte: u8) -> bool {
    let length_byte = length_byte as u32;
    !(length_byte < 224 || length_byte == 255)
}

fn public_key_packet(reader: &mut Reader, st: &mut State, len: usize) {
    st.version = reader.read_byte().unwrap_or(0) as usize;
    let _creation_time = reader.read_bytes(4);
    st.public_algorithm = reader.read_byte().unwrap_or(0) as usize;
    match st.public_algorithm {
        1..=3 => {
            st.n = read_mpi(reader, &mut st.n_bits);
            // the e MPI only advances the stream; its length is not recorded
            let mut e_bits = 0usize;
            let _ = read_mpi(reader, &mut e_bits);
        }
        16 | 20 => {
            st.p = read_mpi(reader, &mut st.p_bits);
            // the g MPI is read once transiently, then recorded
            let _ = read_mpi(reader, &mut st.g_bits);
            st.g = read_mpi(reader, &mut st.g_bits);
            st.y = read_mpi(reader, &mut st.y_bits);
        }
        17 => {
            st.p = read_mpi(reader, &mut st.key_bits);
            let _ = read_mpi(reader, &mut st.q_bits);
            st.g = read_mpi(reader, &mut st.g_bits);
            st.y = read_mpi(reader, &mut st.y_bits);
        }
        _ => {
            reader.pos += len.saturating_sub(5);
        }
    }
}

fn secret_key_packet(reader: &mut Reader, st: &mut State, len: usize, filename: &str) {
    let packet_start = reader.pos;
    public_key_packet(reader, st, len);
    let s2k_usage = reader.read_byte().unwrap_or(0) as usize;
    match s2k_usage {
        0 => {
            // plain (unencrypted) secret key: unsupported for hashing
            st.s2k_usage = s2k_usage;
        }
        254 => {
            let sym = reader.read_byte().unwrap_or(0) as usize;
            st.cipher_algorithm = sym;
            st.s2k_usage = s2k_usage;
            if read_s2k(reader, st) {
                st.iv_len = iv_len(st.cipher_algorithm);
                st.iv = reader.read_bytes(st.iv_len).unwrap_or_default();
            }
            encrypted_secret_key(reader, st, len, filename, packet_start);
        }
        255 => {
            let sym = reader.read_byte().unwrap_or(0) as usize;
            st.s2k_usage = s2k_usage;
            st.cipher_algorithm = sym;
            if read_s2k(reader, st) {
                st.iv_len = iv_len(st.cipher_algorithm);
                st.iv = reader.read_bytes(st.iv_len).unwrap_or_default();
            }
            encrypted_secret_key(reader, st, len, filename, packet_start);
        }
        sym => {
            // usage below 254: the value is itself the cipher algorithm
            st.s2k_usage = sym;
            st.cipher_algorithm = sym;
            st.iv_len = iv_len(st.cipher_algorithm);
            st.iv = reader.read_bytes(st.iv_len).unwrap_or_default();
            encrypted_secret_key(reader, st, len, filename, packet_start);
        }
    }
}

fn iv_len(cipher: usize) -> usize {
    if cipher < IV_LEN.len() {
        IV_LEN[cipher]
    } else {
        0
    }
}

/// Reads the S2K specifier fields (RFC 4880 section 3.7.1); returns whether
/// an IV follows the specifier.
fn read_s2k(reader: &mut Reader, st: &mut State) -> bool {
    let s2k_type = reader.read_byte().unwrap_or(0) as usize;
    match s2k_type {
        0 => {
            st.s2k_type = s2k_type;
            st.hash_algorithm = reader.read_byte().unwrap_or(0) as usize;
        }
        1 => {
            st.s2k_type = s2k_type;
            st.s2k_count = 0;
            st.hash_algorithm = reader.read_byte().unwrap_or(0) as usize;
            st.salt = reader.read_bytes(8).unwrap_or_default();
        }
        2 => {}
        3 => {
            st.s2k_type = s2k_type;
            st.hash_algorithm = reader.read_byte().unwrap_or(0) as usize;
            st.salt = reader.read_bytes(8).unwrap_or_default();
            let count_byte = reader.read_byte().unwrap_or(0) as u32;
            st.s2k_count = ((16 + (count_byte & 15)) << ((count_byte >> 4) + EXPBIAS)) as usize;
        }
        101 => {
            let _ = reader.read_bytes(5);
            return false; // no IV follows this specifier
        }
        _ => {}
    }
    true
}

/// Reads one MPI: a 16-bit bit count followed by `ceil(bits / 8)` bytes.
fn read_mpi(reader: &mut Reader, bits: &mut usize) -> Vec<u8> {
    let hi = reader.read_byte().unwrap_or(0) as usize;
    let lo = reader.read_byte().unwrap_or(0) as usize;
    let bit_count = hi * 256 + lo;
    *bits = bit_count;
    reader.read_bytes(bit_count.div_ceil(8)).unwrap_or_default()
}

fn encrypted_secret_key(
    reader: &mut Reader,
    st: &mut State,
    len: usize,
    filename: &str,
    packet_start: usize,
) {
    // remaining length inside the packet after the public key part and the
    // S2K fields
    let consumed = reader.pos - packet_start;
    let remaining = len as i64 - consumed as i64;
    if remaining < 0 {
        return;
    }
    let used_len = remaining as usize;
    let encrypted_data = reader.read_bytes(used_len).unwrap_or_default();
    st.key_algorithm = st.public_algorithm;

    if st.last_hash.is_empty() && st.gecos.is_empty() {
        st.gecos = default_login(filename);
    }
    let login = sanitize_login(&st.gecos);
    st.login = login;

    if st.dump_subkeys || !st.is_subkey {
        let mut line = format!("$gpg$*{}*{}*{}*", st.key_algorithm, used_len, st.n_bits);
        line.push_str(&hex::encode(&encrypted_data));
        line.push_str(&format!(
            "*{}*{}*{}*{}*{}*",
            st.s2k_type, st.s2k_usage, st.hash_algorithm, st.cipher_algorithm, st.iv_len
        ));
        line.push_str(&hex::encode(&st.iv));
        line.push_str(&format!("*{}*", st.s2k_count));
        line.push_str(&hex::encode(&st.salt));
        if st.s2k_usage == 255 {
            line.push_str(&format!("*{}*", st.n_bits.div_ceil(8)));
            line.push_str(&hex::encode(&st.n));
        }
        st.last_hash = line;
    }
}
