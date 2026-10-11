//! EncFS folder hash extractor, emitting `$encfs$` hash lines. Reads the
//! encryption parameters from the folder's `.encfs6.xml` (the folder path is
//! the label; the XML content is the primary input).

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use base64::Engine;

pub struct Encfs;

impl Extractor for Encfs {
    fn name(&self) -> &'static str {
        "encfs"
    }

    fn description(&self) -> &'static str {
        "EncFS folders (.encfs6.xml; input is the XML, label is the folder)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"<?xml")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Ok(root) = crate::xml::parse(&input.data) else {
            return Ok(Vec::new());
        };
        let mut cipher: Option<&str> = None;
        let mut key_size: Option<&str> = None;
        let mut iterations: Option<&str> = None;
        let mut salt: Option<&str> = None;
        let mut salt_len: Option<&str> = None;
        let mut data_len: Option<&str> = None;
        let mut data: Option<&str> = None;
        for element in root.iter_all() {
            match element.name.as_str() {
                "keySize" => key_size = Some(element.text.trim()),
                "kdfIterations" => iterations = Some(element.text.trim()),
                "name" if cipher.is_none() => cipher = Some(element.text.trim()),
                "saltData" => salt = Some(element.text.trim()),
                "saltLen" => salt_len = Some(element.text.trim()),
                "encodedKeySize" => data_len = Some(element.text.trim()),
                "encodedKeyData" => data = Some(element.text.trim()),
                _ => {}
            }
        }
        let (
            Some(cipher),
            Some(key_size),
            Some(iterations),
            Some(salt),
            Some(salt_len),
            Some(data_len),
            Some(data),
        ) = (cipher, key_size, iterations, salt, salt_len, data_len, data)
        else {
            return Ok(Vec::new()); // missing required XML fields: no output
        };
        let cipher_id: u32 = if cipher.to_uppercase().contains("AES") {
            0
        } else {
            return Ok(Vec::new()); // unsupported cipher: no output
        };
        let engine = base64::engine::general_purpose::STANDARD;
        let salt_hex = hex::encode(engine.decode(salt.trim()).unwrap_or_default());
        let data_hex = hex::encode(engine.decode(data.trim()).unwrap_or_default());
        let label = input.label();
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$encfs${key_size}*{iterations}*{cipher_id}*{salt_len}*{salt_hex}\
*{data_len}*{data_hex}",
            ),
        )])
    }
}
