//! macOS user .plist parser for the SALTED-SHA512-PBKDF2 shadow hash:
//! reads the `ShadowHashData` entry, parses the embedded inner plist and
//! emits a `$pbkdf2-hmac-sha512$` crackable hash line.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct MacAlt;

impl Extractor for MacAlt {
    fn name(&self) -> &'static str {
        "mac_alt"
    }

    fn description(&self) -> &'static str {
        "macOS .plist user files (SALTED-SHA512-PBKDF2)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"bplist") || input.data.starts_with(b"<?xml")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Ok(document) = plist::Value::from_reader(std::io::Cursor::new(&input.data)) else {
            return Ok(Vec::new()); // not parseable as a plist file
        };
        let dict = document.as_dictionary().cloned().unwrap_or_default();

        let string_list = |key: &str| -> Vec<String> {
            dict.get(key)
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
            dict.get(key)
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

        let Some(shadow) = dict
            .get("ShadowHashData")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
        else {
            return Ok(Vec::new()); // no ShadowHashData entry
        };
        let Ok(inner) =
            plist::Value::from_reader(std::io::Cursor::new(shadow.as_data().unwrap_or_default()))
        else {
            return Ok(Vec::new());
        };
        let inner = inner.as_dictionary().cloned().unwrap_or_default();
        let Some(pb) = inner
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
