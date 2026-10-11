//! Two paths: Telegram Desktop TDFS map files (primary input, taken
//! directly) and Android userconfing.xml files (fallback, tried when the
//! input is not a TDFS file). TDFS files emit `$telegram$1*...` lines;
//! userconfing.xml emits `$dynamic_1528$` lines.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;
use md5::{Digest, Md5};

pub struct Telegram;

/// Passcode KDF iteration count, fixed by the TDFS format.
const ITERATION_COUNT: u32 = 4000;
/// Salt length the TDFS payload requires for the passcode salt.
const SALT_SIZE: usize = 32;
/// Encrypted passcode key length the TDFS payload requires.
const ENCRYPTED_KEY_SIZE: usize = 288;

impl Extractor for Telegram {
    fn name(&self) -> &'static str {
        "telegram"
    }

    fn description(&self) -> &'static str {
        "Telegram Desktop TDFS map files / Android userconfing.xml"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"TDF$") || util::find(&input.data, b"passcodeHash1").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        if let Some(map) = self.tdfs(input)? {
            return Ok(vec![map]);
        }
        self.xml(input)
    }
}

impl Telegram {
    /// TDFS path: returns None when the input is not a valid TDFS file.
    fn tdfs(&self, input: &Input) -> Result<Option<HashLine>> {
        let data = &input.data;
        if data.len() < 8 || !data.starts_with(b"TDF$") {
            return Ok(None);
        }
        let version = &data[4..8];
        let body = &data[8..];
        if body.len() <= 16 {
            return Ok(None);
        }
        let (payload, checksum) = body.split_at(body.len() - 16);
        let mut hasher = Md5::new();
        hasher.update(payload);
        hasher.update((payload.len() as u32).to_le_bytes());
        hasher.update(version);
        hasher.update(b"TDF$");
        if hasher.finalize().as_slice() != checksum {
            return Ok(None);
        }

        // read salt
        let mut pos = 0usize;
        let read_len =
            |data: &[u8], at: usize| u32::from_be_bytes(data[at..at + 4].try_into().expect("4"));
        let salt_len = read_len(payload, pos) as usize;
        if salt_len != SALT_SIZE {
            return Ok(None);
        }
        pos += 4;
        let salt = &payload[pos..pos + salt_len];
        pos += salt_len;
        // read the encrypted key
        let key_len = read_len(payload, pos) as usize;
        if key_len != ENCRYPTED_KEY_SIZE {
            return Ok(None);
        }
        pos += 4;
        let encrypted_key = &payload[pos..pos + key_len];

        let label = input.label();
        Ok(Some(HashLine::new(
            label.to_string(),
            format!(
                "{label}:$telegram$1*{ITERATION_COUNT}*{}*{}",
                hex::encode(salt),
                hex::encode(encrypted_key)
            ),
        )))
    }

    /// Android userconfing.xml path.
    fn xml(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Ok(root) = crate::xml::parse(&input.data) else {
            return Ok(Vec::new());
        };
        let mut passcode_hash: Option<&str> = None;
        let mut salt: Option<&str> = None;
        for item in &root.children {
            if item.name != "string" {
                continue;
            }
            match item.get("name") {
                Some("passcodeHash1") => passcode_hash = Some(item.text.trim()),
                Some("passcodeSalt") => salt = Some(item.text.trim()),
                _ => {}
            }
        }
        let (Some(passcode_hash), Some(salt)) = (passcode_hash, salt) else {
            return Ok(Vec::new());
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        let salt_hex = hex::encode(b64.decode(salt.trim()).unwrap_or_default());
        Ok(vec![HashLine::new(
            String::new(),
            format!(
                "$dynamic_1528${}$HEX${salt_hex}",
                passcode_hash.to_lowercase()
            ),
        )])
    }
}
