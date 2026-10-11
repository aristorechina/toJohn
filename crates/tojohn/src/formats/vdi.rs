//! Parses VirtualBox `.vbox` XML files for `CRYPT/KeyId` properties whose
//! value blob (base64, with `&#13;&#10;` sequences removed) starts with the
//! `SCNE` marker. Emits `$vdi$` lines for AES-XTS with PBKDF2-SHA256.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Vdi;

/// NUL-padded 32-byte cipher field selecting AES-XTS with 128-bit keys.
const CIPHER_AES_XTS128: [u8; 32] = *b"AES-XTS128-PLAIN64\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
/// NUL-padded 32-byte cipher field selecting AES-XTS with 256-bit keys.
const CIPHER_AES_XTS256: [u8; 32] = *b"AES-XTS256-PLAIN64\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
/// NUL-padded 32-byte KDF field selecting PBKDF2 with SHA-256.
const KDF_PBKDF2_SHA256: [u8; 32] = *b"PBKDF2-SHA256\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

impl Extractor for Vdi {
    fn name(&self) -> &'static str {
        "vdi"
    }

    fn description(&self) -> &'static str {
        "VirtualBox .vbox encryption property files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"CRYPT/KeyId").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Ok(root) = crate::xml::parse(&input.data) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();

        // A <Property name="CRYPT/KeyId..."> element's value attribute is the
        // label, and the NEXT property's value attribute is the base64 blob.
        for window in collect_properties(&root).windows(2) {
            let (prop_name, prop_value) = &window[0];
            if prop_name.starts_with("CRYPT/KeyId") {
                if let Some(line) = parse_blob(&window[1].1, prop_value) {
                    out.push(line);
                }
            }
        }
        Ok(out)
    }
}

/// Collect (name, value) of all Property elements in document order.
fn collect_properties(root: &crate::xml::Element) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for e in root.find_all_descendants("Property") {
        let name = e.get("name").unwrap_or_default().to_string();
        let value = e.get("value").unwrap_or_default().to_string();
        out.push((name, value));
    }
    out
}

/// Decode one CRYPT property blob and assemble the hash line.
fn parse_blob(blob_b64: &str, label: &str) -> Option<HashLine> {
    let engine = base64::engine::general_purpose::STANDARD;
    // strip the literal "&#13;&#10;" entity text from the value
    let cleaned = {
        let mut cleaned = blob_b64.to_string();
        for entity in ["&#13;&#10;", "&#13;", "&#10;", "\r\n", "\r", "\n"] {
            cleaned = cleaned.replace(entity, "");
        }
        cleaned
    };
    let decoded = engine.decode(cleaned.trim()).ok()?;

    // SCNE marker + version 0x0100 (little-endian u16)
    if decoded.len() < 6 || !decoded.starts_with(b"SCNE") {
        return None;
    }
    if read_le_u64(&decoded[4..6]) != 0x100 {
        return None;
    }
    let mut cursor = &decoded[6..];
    fn take<'b>(cursor: &mut &'b [u8], n: usize) -> &'b [u8] {
        let prefix = &cursor[..n.min(cursor.len())];
        *cursor = &cursor[n.min(cursor.len())..];
        prefix
    }
    let algo = take(&mut cursor, 32).to_vec();
    let kdf = take(&mut cursor, 32).to_vec();
    let generated_key_len = read_le_u64(take(&mut cursor, 4));
    let final_ = take(&mut cursor, 32).to_vec();
    let key_len = read_le_u64(take(&mut cursor, 4));
    let salt2 = take(&mut cursor, 32).to_vec();
    let salt2_iter = read_le_u64(take(&mut cursor, 4));
    let salt1 = take(&mut cursor, 32).to_vec();
    let salt1_iter = read_le_u64(take(&mut cursor, 4));
    let encrypted_password_len = read_le_u64(take(&mut cursor, 4)) as usize;
    let encrypted_password = take(&mut cursor, encrypted_password_len).to_vec();

    // only AES-XTS128/256-PLAIN64 + PBKDF2-SHA256 are accepted
    if (algo != CIPHER_AES_XTS128 && algo != CIPHER_AES_XTS256) || kdf != KDF_PBKDF2_SHA256 {
        return None;
    }

    // the line uses the first 10 chars of the lowercased cipher name
    // ("aes-xts128"/"aes-xts256") and chars 7..13 of the lowercased KDF
    // name ("sha256")
    let algo_str = String::from_utf8_lossy(&algo).to_lowercase();
    let kdf_str = String::from_utf8_lossy(&kdf).to_lowercase();
    let algo_label = &algo_str[..10.min(algo_str.len())];
    let kdf_label = &kdf_str[7.min(kdf_str.len())..(7 + 6).min(kdf_str.len())];

    Some(HashLine::new(
        label.to_string(),
        format!(
            "{label}:$vdi${algo_label}${kdf_label}${salt1_iter}${salt2_iter}${generated_key_len}${key_len}\
${}${}${}${}",
            hex::encode(salt1),
            hex::encode(salt2),
            hex::encode(encrypted_password),
            hex::encode(final_)
        ),
    ))
}

/// Interprets a byte slice as a little-endian unsigned integer, folding from
/// the most significant byte (short slices read as zero-extended values).
fn read_le_u64(bytes: &[u8]) -> u64 {
    let mut value: u64 = 0;
    for &byte in bytes.iter().rev() {
        value = value.wrapping_mul(256).wrapping_add(u64::from(byte));
    }
    value
}

#[cfg(test)]
mod tests {
    #[test]
    fn debug_props() {
        let data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/vdi/test.vbox"
        ))
        .unwrap();
        let root = crate::xml::parse(&data).unwrap();
        use super::collect_properties;
        let props = collect_properties(&root);
        println!("props: {}", props.len());
        for (n, v) in &props {
            println!("  {} = {} bytes", n, v.len());
        }
    }
}
