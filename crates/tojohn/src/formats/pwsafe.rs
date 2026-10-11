//! Password Safe V3 header parser: magic `PWS3`, 32-byte salt, big-endian
//! iteration count and 32-byte hash, emitted as a `$pwsafe$` line.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Pwsafe;

impl Extractor for Pwsafe {
    fn name(&self) -> &'static str {
        "pwsafe"
    }

    fn description(&self) -> &'static str {
        "Password Safe .psafe3 files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"PWS3")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < 4 || &data[..4] != b"PWS3" {
            return Ok(Vec::new()); // PWS3 magic missing
        }
        let salt = data.get(4..36).unwrap_or(&[]);
        if salt.len() != 32 {
            return Ok(Vec::new()); // salt read failed
        }
        let iterations = u32::from_be_bytes(data[36..40].try_into().expect("4 bytes"));
        let hash = data.get(40..72).unwrap_or(&[]);
        if hash.len() != 32 {
            return Ok(Vec::new()); // hash read failed
        }
        // character-set trim: strips any of the '.', 'p', 's', 'a', 'f', 'e',
        // '3' characters from the end of the basename (not the suffix as a
        // whole).
        let label =
            util::basename(input.label()).trim_end_matches(['.', 'p', 's', 'a', 'f', 'e', '3']);
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$pwsafe$*3*{}*{iterations}*{}",
                hex::encode(salt),
                hex::encode(hash)
            ),
        )])
    }
}
