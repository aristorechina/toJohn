//! Parses Padlock for Android database exports (JSON with base64 fields)
//! into `$padlock$` lines. Only ccm/AES/256 records are accepted.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Padlock;

impl Extractor for Padlock {
    fn name(&self) -> &'static str {
        "padlock"
    }

    fn description(&self) -> &'static str {
        "Padlock for Android database exports"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"{") && util::find(&input.data, b"\"cipher\"").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let json: serde_json::Value = match serde_json::from_slice(&input.data) {
            Ok(v) => v,
            Err(_) => return Ok(Vec::new()), // JSON parsing failed
        };
        let (
            Some(cipher),
            Some(tag_len),
            Some(iterations),
            Some(mode),
            Some(adata),
            Some(iv),
            Some(key_size),
            Some(salt),
            Some(ciphertext),
        ) = (
            json.get("cipher").and_then(|v| v.as_str()),
            json.get("ts").and_then(|v| v.as_i64()),
            json.get("iter").and_then(|v| v.as_i64()),
            json.get("mode").and_then(|v| v.as_str()),
            json.get("adata").and_then(|v| v.as_str()),
            json.get("iv").and_then(|v| v.as_str()),
            json.get("keySize").and_then(|v| v.as_i64()),
            json.get("salt").and_then(|v| v.as_str()),
            json.get("ct").and_then(|v| v.as_str()),
        )
        else {
            return Ok(Vec::new());
        };
        if mode != "ccm" || cipher != "AES" || key_size.to_string() != "256" {
            // unexpected mode/cipher/key size: no hash line
            return Ok(Vec::new());
        }
        let engine = base64::engine::general_purpose::STANDARD;
        let ciphertext_bytes = engine.decode(ciphertext).unwrap_or_default();
        let adata_bytes = engine.decode(adata).unwrap_or_default();
        let salt_bytes = engine.decode(salt).unwrap_or_default();
        let iv_bytes = engine.decode(iv).unwrap_or_default();

        let ciphertext_hex = hex::encode(&ciphertext_bytes);
        let adata_hex = hex::encode(&adata_bytes);
        let salt_hex = hex::encode(&salt_bytes);
        let iv_hex = hex::encode(&iv_bytes);
        let ciphertext_len = ciphertext_hex.len() / 2;
        let adata_len = adata_hex.len() / 2;
        let salt_len = salt_hex.len() / 2;
        let version = 1;

        let tag_len_bytes = tag_len / 8;
        let _ = ciphertext_len.checked_sub(tag_len_bytes.max(0) as usize); // empty database: no separate diagnostic

        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$padlock${version}${iterations}${tag_len}${salt_len}${salt_hex}\
${iv_hex}${adata_len}${adata_hex}${ciphertext_len}${ciphertext_hex}"
            ),
        )])
    }
}
