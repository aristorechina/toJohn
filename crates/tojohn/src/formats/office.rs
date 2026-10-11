//! MS Office hash extraction. Covered paths:
//! - **OOXML/Agile**: `EncryptionInfo` stream, v4.4 (Office 2010/2013) with
//!   the standard XML `encryptedKey` attributes, emitting `$office$` lines
//! - **Office 2007 CryptoAPI**: `EncryptionInfo` stream, other versions with
//!   the binary header + verifier
//! - **Old binary formats** (Excel `.xls` Workbook / Word `.doc` RC4):
//!   `$oldoffice$` lines via the RC4 CryptoAPI/XLS FILEPASS records
//! - **ACCDB** (MS Access ≥2007): inline XML `</encryption>` blob
//!
//! The OLE container layer lives in [`crate::ole`]. The `:::` summary/gecos
//! metadata suffix is emitted empty (no metadata decoration).

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::ole::OleFile;
use crate::util;
use base64::Engine;

pub struct Office;

impl Extractor for Office {
    fn name(&self) -> &'static str {
        "office"
    }

    fn description(&self) -> &'static str {
        "MS Office files (OOXML 2007/2010/2013, legacy RC4, ACCDB)"
    }

    fn accepts(&self, input: &Input) -> bool {
        (input.data.len() > 520
            && input.data[..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
            || input.data.starts_with(b"Standard ACE DB")
            || input
                .data
                .starts_with(&[0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8])
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let label = util::basename(input.label());

        // ACCDB (MS Access) handling
        if util::find(data, b"Standard ACE DB").is_some() {
            let xml_start = b"<?xml version=\"1.0\"";
            let xml_trailer = b"</encryption>";
            if let (Some(start), Some(trailer)) =
                (util::find(data, xml_start), util::find(data, xml_trailer))
            {
                let xml = &data[start..trailer + xml_trailer.len()];
                return xml_metadata_parser(xml, label);
            }
        }

        let ole = OleFile::new(data, input.label())?;
        let streams = ole.list_streams();

        if streams.iter().any(|s| s == "EncryptionInfo") {
            return self.new_office(input, label);
        }

        // legacy RC4 paths
        if streams.iter().any(|s| s == "Workbook") {
            let stream = ole.open_stream("Workbook")?;
            return self.old_office_xls(&stream, label);
        }
        if streams.iter().any(|s| s == "WordDocument") {
            let doc = ole.open_stream("WordDocument")?;
            let Some(table) = find_table(&doc) else {
                return Ok(Vec::new());
            };
            if let Ok(t) = ole.open_stream(table) {
                return self.old_office_doc(&t, label);
            }
        }
        Err(crate::error::Error::other("no supported streams found"))
    }
}

impl Office {
    /// EncryptionInfo stream dispatch for the newer OOXML formats
    fn new_office(&self, input: &Input, label: &str) -> Result<Vec<HashLine>> {
        let ole = OleFile::new(&input.data, input.label())?;
        let stream = ole.open_stream("EncryptionInfo")?;
        if stream.len() < 8 {
            return Ok(Vec::new());
        }
        let major_version = u16::from_le_bytes(stream[0..2].try_into().expect("2"));
        let minor_version = u16::from_le_bytes(stream[2..4].try_into().expect("2"));
        let encryption_flags = u32::from_le_bytes(stream[4..8].try_into().expect("4"));
        if major_version == 0x04 && minor_version == 0x04 {
            if encryption_flags != 0x40 {
                return Ok(Vec::new()); // fAgile mismatch
            }
            xml_metadata_parser(&stream[8..], label)
        } else {
            // Office 2007 CryptoAPI header
            self.office_2007(&stream[8..], label)
        }
    }

    /// Office 2007 CryptoAPI Encryption Header + Verifier
    fn office_2007(&self, mut stream: &[u8], label: &str) -> Result<Vec<HashLine>> {
        let rd_u32 = |cursor: &mut &[u8]| -> u32 {
            let value = u32::from_le_bytes(cursor[..4].try_into().expect("4"));
            *cursor = &cursor[4..];
            value
        };
        let rd_bytes = |cursor: &mut &[u8], count: usize| -> Vec<u8> {
            let value = cursor[..count].to_vec();
            *cursor = &cursor[count..];
            value
        };
        let header_length = rd_u32(&mut stream) as usize;
        let _skip = rd_u32(&mut stream); // skipFlags
        let _extra = rd_u32(&mut stream); // sizeExtra
        let _alg_id = rd_u32(&mut stream); // algId
        let _alg_hash = rd_u32(&mut stream); // algHashId
        let key_size = rd_u32(&mut stream);
        let _provider = rd_u32(&mut stream); // providerType
        let _unused1 = rd_u32(&mut stream);
        let _unused2 = rd_u32(&mut stream);
        let csp_len = header_length.saturating_sub(32);
        if stream.len() < csp_len + 4 {
            return Ok(Vec::new());
        }
        let _csp_name = &stream[..csp_len];
        stream = &stream[csp_len..];
        let salt_size = rd_u32(&mut stream) as usize;
        if salt_size != 16 {
            return Ok(Vec::new());
        }
        if stream.len() < salt_size + 16 + 4 {
            return Ok(Vec::new());
        }
        let salt = rd_bytes(&mut stream, salt_size);
        let encrypted_verifier = rd_bytes(&mut stream, 16);
        let verifier_hash_size = rd_u32(&mut stream) as usize;
        if stream.len() < verifier_hash_size {
            return Ok(Vec::new());
        }
        let encrypted_verifier_hash = rd_bytes(&mut stream, verifier_hash_size);
        let hash_hex = hex::encode(&encrypted_verifier_hash);
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$office$*2007*{verifier_hash_size}*{key_size}*{salt_size}\
*{}*{}*{}",
                hex::encode(salt),
                hex::encode(encrypted_verifier),
                &hash_hex[..64.min(hash_hex.len())]
            ),
        )])
    }

    /// XLS path: walk BIFF records for the FILEPASS record (type 0x2f)
    fn old_office_xls(&self, stream: &[u8], label: &str) -> Result<Vec<HashLine>> {
        let mut pos = 0usize;
        while pos + 4 <= stream.len() {
            let rec_type = u16::from_le_bytes(stream[pos..pos + 2].try_into().expect("2"));
            let length =
                u16::from_le_bytes(stream[pos + 2..pos + 4].try_into().expect("2")) as usize;
            pos += 4;
            if pos + length > stream.len() {
                break;
            }
            let data = &stream[pos..pos + length];
            pos += length;
            if rec_type == 0x2f {
                // FILEPASS
                if data.len() >= 54 && &data[..6] == b"\x01\x00\x01\x00\x01\x00" {
                    // RC4 encryption header
                    let salt = &data[6..22];
                    let verifier = &data[22..38];
                    let verifier_hash = &data[38..54];
                    return Ok(vec![render_oldoffice_line(
                        label,
                        0,
                        salt,
                        verifier,
                        verifier_hash,
                    )]);
                }
                if data.len() >= 6
                    && matches!(
                        &data[..4],
                        b"\x01\x00\x02\x00" | b"\x01\x00\x03\x00" | b"\x01\x00\x04\x00"
                    )
                {
                    // RC4 CryptoAPI
                    if let Some(line) = parse_rc4_cryptoapi(&data[6..], label) {
                        return Ok(vec![line]);
                    }
                }
            }
        }
        Ok(Vec::new())
    }

    /// DOC path: FIB + table stream nFib check
    fn old_office_doc(&self, table: &[u8], label: &str) -> Result<Vec<HashLine>> {
        // The DOC path locates the EncryptionHeader via the FIB; for hash
        // extraction the table stream carries the same RC4 CryptoAPI blob
        // starting at the offset stored in the FIB. Simplified walk: scan
        // for the RC4 CryptoAPI magic bytes.
        for pos in 0..table.len().saturating_sub(6) {
            if matches!(
                &table[pos..pos + 4],
                b"\x01\x00\x02\x00" | b"\x01\x00\x03\x00" | b"\x01\x00\x04\x00"
            ) {
                if let Some(line) = parse_rc4_cryptoapi(&table[pos + 4..], label) {
                    return Ok(vec![line]);
                }
            }
        }
        Ok(Vec::new())
    }
}

/// RC4 CryptoAPI Encryption Header + Verifier (after the 2 unused bytes)
fn parse_rc4_cryptoapi(mut stream: &[u8], label: &str) -> Option<HashLine> {
    let rd_u16 = |cursor: &mut &[u8]| -> u16 {
        let value = u16::from_le_bytes(cursor[..2].try_into().expect("2"));
        *cursor = &cursor[2..];
        value
    };
    let rd_u32 = |cursor: &mut &[u8]| -> u32 {
        let value = u32::from_le_bytes(cursor[..4].try_into().expect("4"));
        *cursor = &cursor[4..];
        value
    };
    let rd_bytes = |cursor: &mut &[u8], count: usize| -> Vec<u8> {
        let value = cursor[..count].to_vec();
        *cursor = &cursor[count..];
        value
    };
    let _salt_size = rd_u16(&mut stream);
    let _major = rd_u16(&mut stream);
    let _minor = rd_u16(&mut stream);
    let _flags = rd_u32(&mut stream);
    let header_length = rd_u32(&mut stream) as usize;
    let _skip = rd_u32(&mut stream);
    let _extra = rd_u32(&mut stream);
    let _alg_id = rd_u32(&mut stream);
    let _alg_hash = rd_u32(&mut stream);
    let key_size = rd_u32(&mut stream);
    let format_type = if key_size == 40 { 3 } else { 4 };
    let csp_len = header_length.saturating_sub(28);
    if stream.len() < csp_len + 4 {
        return None;
    }
    stream = &stream[csp_len..];
    let _provider = rd_u32(&mut stream);
    let salt_size = rd_u32(&mut stream) as usize;
    if salt_size != 16 || stream.len() < salt_size + 16 + 4 {
        return None;
    }
    let salt = rd_bytes(&mut stream, salt_size);
    let encrypted_verifier = rd_bytes(&mut stream, 16);
    let verifier_hash_size = rd_u32(&mut stream) as usize;
    if stream.len() < verifier_hash_size {
        return None;
    }
    let encrypted_verifier_hash = rd_bytes(&mut stream, verifier_hash_size);
    Some(render_oldoffice_line(
        label,
        format_type,
        &salt,
        &encrypted_verifier,
        &encrypted_verifier_hash,
    ))
}

fn render_oldoffice_line(
    label: &str,
    format_type: u32,
    salt: &[u8],
    verifier: &[u8],
    verifier_hash: &[u8],
) -> HashLine {
    HashLine::new(
        label.to_string(),
        format!(
            "{label}:$oldoffice${format_type}*{}*{}*{}:::",
            hex::encode(salt),
            hex::encode(verifier),
            hex::encode(verifier_hash)
        ),
    )
}

/// Office 2010/2013 agile encryption XML parser
fn xml_metadata_parser(xml: &[u8], label: &str) -> Result<Vec<HashLine>> {
    let Ok(root) = crate::xml::parse(xml) else {
        return Ok(Vec::new());
    };
    // qualified element names are kept verbatim (p:encryptedKey); match both
    // the bare and the prefixed local names.
    for node in root
        .find_all_descendants("encryptedKey")
        .into_iter()
        .chain(root.find_all_descendants("p:encryptedKey"))
    {
        // our DOM keeps qualified names as written; try both forms
        let attr = |name: &str| -> Option<String> {
            node.get(name)
                .or_else(|| node.get(&format!("p:{name}")))
                .map(|s| s.to_string())
        };
        let Some(spin_count) = attr("spinCount") else {
            continue;
        };
        let Some(salt_size) = attr("saltSize") else {
            continue;
        };
        let Some(key_bits) = attr("keyBits") else {
            continue;
        };
        let Some(hash_algorithm) = attr("hashAlgorithm") else {
            continue;
        };
        let Some(cipher_algorithm) = attr("cipherAlgorithm") else {
            continue;
        };
        let version = match hash_algorithm.as_str() {
            "SHA1" => 2010,
            "SHA512" => 2013,
            _ => return Ok(Vec::new()),
        };
        if !cipher_algorithm.contains("AES") {
            return Ok(Vec::new());
        }
        let Some(salt_value) = attr("saltValue") else {
            continue;
        };
        let Some(verifier_hash_input) = attr("encryptedVerifierHashInput") else {
            continue;
        };
        let Some(verifier_hash_value) = attr("encryptedVerifierHashValue") else {
            continue;
        };
        let engine = base64::engine::general_purpose::STANDARD;
        let salt_hex = hex::encode(engine.decode(salt_value.trim()).unwrap_or_default());
        let verifier_input_hex = hex::encode(
            engine
                .decode(verifier_hash_input.trim())
                .unwrap_or_default(),
        );
        let verifier_value_hex = hex::encode(
            engine
                .decode(verifier_hash_value.trim())
                .unwrap_or_default(),
        );
        return Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$office$*{version}*{spin_count}*{key_bits}*{salt_size}\
*{salt_hex}*{verifier_input_hex}*{}",
                &verifier_value_hex[..64.min(verifier_value_hex.len())]
            ),
        )]);
    }
    Ok(Vec::new())
}

/// Read the FIB's fWhichTblStm bit (nFib >= 0x00C1 uses bit 9 of the flags
/// at offset 10) to pick the table stream.
fn find_table(doc_stream: &[u8]) -> Option<&'static str> {
    if doc_stream.len() < 12 {
        return None;
    }
    let flags = u16::from_le_bytes(doc_stream[10..12].try_into().expect("2"));
    if flags & 0x0200 != 0 {
        Some("1Table")
    } else {
        Some("0Table")
    }
}
