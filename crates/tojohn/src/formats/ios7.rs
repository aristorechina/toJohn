//! iOS 7 restrictions-passcode hash extractor: parses the XML of a
//! `com.apple.restrictionspassword.plist` — a `<key>` ending in `Key`
//! followed by two `<data>` blobs (key then salt) — and emits
//! `$pbkdf2-hmac-sha1$1000.<salt>.<key>` lines. Handles both single-line
//! and multi-line `<data>` elements (the multi-line form reads the base64
//! from the next line).

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Ios7;

impl Extractor for Ios7 {
    fn name(&self) -> &'static str {
        "ios7"
    }

    fn description(&self) -> &'static str {
        "iOS 7 restrictionspassword plists"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"RestrictionsPassword").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        // strip \r (CR) characters
        let text = String::from_utf8_lossy(data).replace('\r', "");
        let mut lines = text.split('\n').peekable();

        let mut type_name: Option<String> = None;
        let mut key: Option<String> = None;
        let mut salt: Option<String> = None;
        let mut out = Vec::new();

        while let Some(line) = lines.next() {
            let trimmed = line.trim();
            // <key>NAMEKey</key> — a non-empty NAME marks the value type
            if let Some(name) = trimmed
                .strip_prefix("<key>")
                .and_then(|s| s.strip_suffix("Key</key>"))
                .filter(|name| !name.is_empty())
            {
                type_name = Some(name.to_string());
                continue;
            }
            // single-line <data>...</data>
            if type_name.is_some() && trimmed.starts_with("<data>") && trimmed.ends_with("</data>")
            {
                let encoded = trimmed
                    .strip_prefix("<data>")
                    .and_then(|s| s.strip_suffix("</data>"))
                    .unwrap_or("");
                assign_data(
                    &mut type_name,
                    &mut key,
                    &mut salt,
                    &mut out,
                    encoded,
                    input.label(),
                );
                continue;
            }
            // multi-line: <data> alone, base64 on the next line
            if type_name.is_some() && trimmed == "<data>" {
                if let Some(next_line) = lines.next() {
                    let encoded = next_line.trim();
                    assign_data(
                        &mut type_name,
                        &mut key,
                        &mut salt,
                        &mut out,
                        encoded,
                        input.label(),
                    );
                }
                continue;
            }
        }
        Ok(out)
    }
}

/// State machine: the first blob is the key, the second the salt; emit and
/// reset when both are present.
fn assign_data(
    type_name: &mut Option<String>,
    key: &mut Option<String>,
    salt: &mut Option<String>,
    out: &mut Vec<HashLine>,
    encoded: &str,
    label: &str,
) {
    let engine = base64::engine::general_purpose::STANDARD;
    let decoded = hex::encode(engine.decode(encoded.trim()).unwrap_or_default());
    if key.is_none() {
        *key = Some(decoded);
    } else if salt.is_none() {
        *salt = Some(decoded);
        let name = type_name.take().unwrap_or_default();
        let key_hex = key.take().unwrap_or_default();
        let salt_hex = salt.take().unwrap_or_default();
        let user = util::basename(label).trim_end_matches(".plist").to_string();
        let line = format!("{name}:$pbkdf2-hmac-sha1$1000.{salt_hex}.{key_hex}:::{user}::{label}");
        out.push(HashLine::new(name, line));
    }
}
