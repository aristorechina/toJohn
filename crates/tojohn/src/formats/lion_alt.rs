//! Mac OS X 10.7 Lion salted SHA-512 hash extractor using a structural
//! binary-plist parse, emitting `$pbkdf2-hmac-sha512$` hash lines:
//!
//! ```text
//! name[0] : $pbkdf2-hmac-sha512$<hex of SALTED-SHA512 payload>
//! ```
//!
//! The plist is walked with the `plist` crate; the SALTED-SHA512 value is a
//! data blob of `<8-byte salt><128-byte sha512>` (136 bytes).

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use plist::Value;

pub struct LionAlt;

impl Extractor for LionAlt {
    fn name(&self) -> &'static str {
        "lion_alt"
    }

    fn description(&self) -> &'static str {
        "Mac OS X 10.7 Lion plists, structural parser (SALTED-SHA512)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"bplist00")
            && crate::util::find(&input.data, b"SALTED-SHA512").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Ok(plist) = Value::from_reader(std::io::Cursor::new(&input.data)) else {
            return Ok(Vec::new());
        };
        let empty = plist::Dictionary::new();
        let dict = plist.as_dictionary().cloned().unwrap_or(empty);

        // user = the first entry of the name array
        let user = dict
            .get("name")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_string())
            .unwrap_or("UNKNOWN_USERNAME")
            .to_string();

        // hash = the SALTED-SHA512 blob inside the first ShadowHashData entry
        let Some(shadow) = dict
            .get("ShadowHashData")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
        else {
            return Ok(Vec::new());
        };
        let bytes = shadow.as_data().unwrap_or_default();
        let Ok(inner) = Value::from_reader(std::io::Cursor::new(bytes)) else {
            return Ok(Vec::new());
        };
        let empty = plist::Dictionary::new();
        let inner = inner.as_dictionary().cloned().unwrap_or(empty);
        let Some(salted) = inner.get("SALTED-SHA512").and_then(|v| v.as_data()) else {
            return Ok(Vec::new());
        };

        Ok(vec![HashLine::new(
            user.clone(),
            format!("{user}:$pbkdf2-hmac-sha512${}", hex::encode(salted)),
        )])
    }
}
