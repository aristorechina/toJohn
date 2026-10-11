//! Bitwarden parser for JSON `storage.js` files and Android/Firefox XML
//! preference files, emitting `$bitwarden$` lines. The LevelDB path is not
//! supported.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Bitwarden;

impl Extractor for Bitwarden {
    fn name(&self) -> &'static str {
        "bitwarden"
    }

    fn description(&self) -> &'static str {
        "Bitwarden storage.js / preferences.xml files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"encKey").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let (email, enc_key): (String, String) =
            if input.label().ends_with(".xml") || input.data.starts_with(b"<?xml") {
                let Ok(root) = crate::xml::parse(&input.data) else {
                    return Ok(Vec::new());
                };
                let mut email: Option<String> = None;
                let mut enc_key: Option<String> = None;
                for item in &root.children {
                    if item.name != "string" {
                        continue;
                    }
                    match item.get("name") {
                        Some("encKey") => enc_key = Some(item.text.clone()),
                        Some("email") => email = Some(item.text.clone()),
                        _ => {}
                    }
                }
                match (email, enc_key) {
                    (Some(email), Some(enc_key)) => (email, enc_key),
                    _ => return Ok(Vec::new()), // XML preferences missing email or encKey
                }
            } else {
                let Ok(json) = serde_json::from_slice::<serde_json::Value>(&input.data) else {
                    return Ok(Vec::new());
                };
                let Some(email) = json.get("userEmail").and_then(|v| v.as_str()) else {
                    return Ok(Vec::new());
                };
                let Some(enc_key) = json.get("encKey").and_then(|v| v.as_str()) else {
                    return Ok(Vec::new());
                };
                (email.to_string(), enc_key.to_string())
            };

        let iterations: u32 = 5000;
        let email = email.to_lowercase();
        let Some((iv_field, blob)) = enc_key.split_once('|') else {
            return Err(Error::malformed(
                input.label(),
                "encKey does not split into 2 '|'-fields",
            ));
        };
        let iv = &iv_field[2.min(iv_field.len())..]; // skip the leading "0."
        let b64 = base64::engine::general_purpose::STANDARD;
        let iv_hex = hex::encode(b64.decode(iv.trim()).unwrap_or_default());
        let blob_hex = hex::encode(b64.decode(blob.trim()).unwrap_or_default());
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:$bitwarden$0*{iterations}*{email}*{iv_hex}*{blob_hex}"),
        )])
    }
}
