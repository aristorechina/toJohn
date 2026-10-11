//! Extracts XMPP SCRAM hashes from Prosody IM `.dat` account files, emitting
//! `$xmpp-scram$` lines. Lines that do not split into exactly 2 `=`-fields
//! are skipped; output requires iteration_count, stored_key and salt to all
//! be present.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Prosody;

impl Extractor for Prosody {
    fn name(&self) -> &'static str {
        "prosody"
    }

    fn description(&self) -> &'static str {
        "Prosody IM .dat account files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"stored_key").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut iterations: Option<String> = None;
        let mut stored_key: Option<String> = None;
        let mut salt: Option<String> = None;
        for raw in util::lines(&input.data) {
            let text = match std::str::from_utf8(raw) {
                Ok(t) => t,
                Err(_) => continue, // invalid UTF-8 lines are skipped
            };
            let fields: Vec<&str> = text.split('=').collect();
            let [_, value] = fields.as_slice() else {
                continue;
            };
            let value = cleanup(value);
            if util::find(raw, b"iteration_count").is_some() {
                iterations = Some(value.clone());
            }
            if util::find(raw, b"stored_key").is_some() {
                stored_key = Some(value.clone());
            }
            if util::find(raw, b"salt").is_some() {
                salt = Some(hex::encode(value.as_bytes()));
            }
        }
        let (Some(iterations), Some(stored_key), Some(salt)) = (iterations, stored_key, salt)
        else {
            return Ok(Vec::new());
        };
        let name = util::basename(input.label());
        let salt_len = salt.len() / 2;
        Ok(vec![HashLine::new(
            name.to_string(),
            format!("{name}:$xmpp-scram$0${iterations}${salt_len}${salt}${stored_key}"),
        )])
    }
}

/// Trims whitespace, strips a trailing ';' and removes double quotes.
fn cleanup(value: &str) -> String {
    value.trim().trim_end_matches(';').replace('"', "")
}
