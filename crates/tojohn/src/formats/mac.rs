//! macOS user .plist parser, tolerant of both layouts: an outer plist with
//! a `ShadowHashData` entry (a binary plist wrapping the inner one), and
//! "preprocessed" plists with `SALTED-SHA512-PBKDF2` at the top level.
//! Emits `$pbkdf2-hmac-sha512$` crackable hash lines.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use plist::Value;

pub struct Mac;

impl Extractor for Mac {
    fn name(&self) -> &'static str {
        "mac"
    }

    fn description(&self) -> &'static str {
        "OS X / macOS .plist user files (ShadowHashData or preprocessed)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"bplist") || input.data.starts_with(b"<?xml")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Ok(outer) = Value::from_reader(std::io::Cursor::new(&input.data)) else {
            return Ok(Vec::new()); // not a plist file
        };
        let outer_dict = outer.as_dictionary().cloned().unwrap_or_default();

        // first element of the ShadowHashData array holds the inner plist
        let shadow = outer_dict
            .get("ShadowHashData")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first());
        let inner_dict = match shadow {
            None => outer_dict.clone(), // preprocessed output
            Some(entry) => {
                let shadow_bytes = entry.as_data().unwrap_or_default();
                match Value::from_reader(std::io::Cursor::new(shadow_bytes)) {
                    Ok(inner) => inner.as_dictionary().cloned().unwrap_or_default(),
                    Err(_) => return Ok(Vec::new()), // unreadable inner ShadowHashData plist
                }
            }
        };
        let Some(pb) = inner_dict
            .get("SALTED-SHA512-PBKDF2")
            .and_then(|v| v.as_dictionary())
        else {
            return Ok(Vec::new()); // no SALTED-SHA512-PBKDF2 entry
        };
        let salt = pb.get("salt").and_then(|v| v.as_data()).unwrap_or_default();
        let entropy = pb
            .get("entropy")
            .and_then(|v| v.as_data())
            .unwrap_or_default();
        let iterations = pb
            .get("iterations")
            .and_then(|v| v.as_unsigned_integer())
            .unwrap_or(0);

        let string_list = |key: &str| -> Vec<String> {
            outer_dict
                .get(key)
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(|v| v.as_string().map(|s| s.to_string()))
                .collect()
        };
        let mut hints: Vec<String> = string_list("realname");
        hints.extend(string_list("hint"));
        let hints = hints.join(",");
        let first_of = |key: &str, default: &str| -> String {
            outer_dict
                .get(key)
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_string())
                .unwrap_or(default)
                .to_string()
        };
        let uid = first_of("uid", "500");
        let gid = first_of("gid", "500");
        let shell = first_of("shell", "bash");
        let name = first_of("name", "user");

        let entropy_hex = hex::encode(entropy);
        Ok(vec![HashLine::new(
            name.clone(),
            format!(
                "{name}:$pbkdf2-hmac-sha512${iterations}.{}.{}:{uid}:{gid}:{hints}:{shell}:{}",
                hex::encode(salt),
                &entropy_hex[..128.min(entropy_hex.len())],
                input.label()
            ),
        )])
    }
}
