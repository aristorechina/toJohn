//! PKCS#8 encrypted private key parser (EncryptedPrivateKeyInfo) using the
//! internal DER reader, emitting `$PEM$` lines.

use crate::asn1::{children, node_int, oid_to_string, oids, read_node};
use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;
use std::borrow::Cow;

pub struct Pem;

impl Extractor for Pem {
    fn name(&self) -> &'static str {
        "pem"
    }

    fn description(&self) -> &'static str {
        "PKCS#8 encrypted private key files (.pem)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"-----BEGIN ENCRYPTED PRIVATE KEY-----").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let armored = util::find(data, b"-----BEGIN ENCRYPTED PRIVATE KEY-----").is_some();
        let der: Cow<'_, [u8]> = if armored {
            // unarmor: concatenate base64 lines between BEGIN/END markers
            let text = String::from_utf8_lossy(data);
            let mut base64_text = String::new();
            let mut inside = false;
            for line in text.lines() {
                if line.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
                    inside = true;
                    continue;
                }
                if line.contains("-----END ENCRYPTED PRIVATE KEY-----") {
                    break;
                }
                if inside {
                    base64_text.push_str(line.trim());
                }
            }
            let engine = base64::engine::general_purpose::STANDARD;
            match engine.decode(base64_text.as_bytes()) {
                Ok(decoded) => Cow::Owned(decoded),
                Err(_) => return Ok(Vec::new()),
            }
        } else {
            Cow::Borrowed(data)
        };
        if let Some(line) = unwrap_pkcs8_data(&der)? {
            return Ok(vec![HashLine::new(String::new(), line)]);
        }
        Ok(Vec::new())
    }
}

/// unwrap_pkcs8_data: EncryptedPrivateKeyInfo ASN.1 walk.
///
/// ```text
/// SEQUENCE {
///   SEQUENCE {                       -- encryptionAlgorithm
///     OID PBES2
///     SEQUENCE {                     -- parameters
///       SEQUENCE { OID PBKDF2, SEQUENCE { salt, iterations } }
///       SEQUENCE { OID cipher, OCTET STRING iv }
///     }
///   }
///   OCTET STRING encryptedData
/// }
/// ```
pub fn unwrap_pkcs8_data(blob: &[u8]) -> Result<Option<String>> {
    let mut pos = 0;
    let Some((top, _)) = read_node(blob, &mut pos) else {
        return Ok(None);
    };
    let top_children = children(blob, top);
    if top_children.len() < 2 {
        return Ok(None);
    }
    let encryption_algorithm = top_children[0];
    let algorithm_children = children(blob, encryption_algorithm);
    if algorithm_children.len() < 2 {
        return Ok(None);
    }
    let algorithm_oid = oid_to_string(algorithm_children[0].content(blob));
    if algorithm_oid != oids::PBES2 {
        return Ok(None); // unsupported encryption algorithm
    }
    let encrypted_data = top_children[1].content(blob).to_vec();

    let params = children(blob, algorithm_children[1]);
    if params.len() < 2 {
        return Ok(None);
    }
    let kdf = children(blob, params[0]);
    if kdf.len() < 2 {
        return Ok(None);
    }
    let kdf_oid = oid_to_string(kdf[0].content(blob));
    if kdf_oid != oids::PBKDF2 {
        return Ok(None); // unsupported KDF algorithm
    }
    let mut salt: Option<Vec<u8>> = None;
    let mut iterations: Option<u32> = None;
    for tlv in children(blob, kdf[1]) {
        match tlv.tag {
            0x04 => salt = Some(tlv.content(blob).to_vec()),
            0x02 => iterations = Some(node_int(blob, tlv)),
            _ => {}
        }
    }
    let (Some(salt), Some(iterations)) = (salt, iterations) else {
        return Ok(None);
    };

    let scheme = children(blob, params[1]);
    if scheme.len() < 2 {
        return Ok(None);
    }
    let cipher_oid = oid_to_string(scheme[0].content(blob));
    let cipher_id: u32 = match cipher_oid.as_str() {
        oids::TRIPLEDES_3KEY => 1,
        oids::AES128_CBC => 2,
        oids::AES192_CBC => 3,
        oids::AES256_CBC => 4,
        _ => return Ok(None), // unsupported cipher
    };
    let iv = scheme[1].content(blob).to_vec();

    Ok(Some(format!(
        "$PEM$1${cipher_id}${}${}${}${}${}",
        hex::encode(salt),
        iterations,
        hex::encode(iv),
        encrypted_data.len(),
        hex::encode(encrypted_data)
    )))
}
