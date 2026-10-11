//! Extracts the global salt and password-check verifier from Mozilla
//! key3.db files and emits `$mozilla$` crackable hash lines.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Mozilla;

impl Extractor for Mozilla {
    fn name(&self) -> &'static str {
        "mozilla"
    }

    fn description(&self) -> &'static str {
        "Mozilla key3.db files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"global-salt").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let Some(salt_tag_pos) = util::find(data, b"global-salt") else {
            return Ok(Vec::new()); // global-salt magic not found
        };
        if salt_tag_pos < 20 {
            return Ok(Vec::new());
        }
        let global_salt = &data[salt_tag_pos - 20..salt_tag_pos];

        let Some(check_tag_pos) = util::find(data, b"password-check") else {
            return Ok(Vec::new());
        };
        if check_tag_pos < 52 {
            return Ok(Vec::new());
        }
        let password_check = &data[check_tag_pos - 52..check_tag_pos];
        let entry_salt = &password_check[3..23];
        let verifier = &password_check[36..52];

        // fixed header fields: format version 3, a 1-byte nickname length and
        // an all-zero OID of length 11
        const OID_LEN: usize = 11;
        let oid = [0u8; OID_LEN];
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$mozilla$*3*{}*1*{}*{OID_LEN}*{}*16*{}*20*{}",
                entry_salt.len(),
                hex::encode(entry_salt),
                hex::encode(oid),
                hex::encode(verifier),
                hex::encode(global_salt),
            ),
        )])
    }
}
