//! Lotus Notes ID file parser: extracts the user id cipher blob at fixed
//! offset 0xD8 (size taken from the preceding 2-byte field, bounded to
//! 0x10..=0x64) and emits it hex-encoded as the hash. Malformed files are
//! rejected with [`Error::Malformed`].

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Lotus;

impl Extractor for Lotus {
    fn name(&self) -> &'static str {
        "lotus"
    }

    fn description(&self) -> &'static str {
        "Lotus Notes ID files"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < 0xD8 {
            return Err(Error::malformed(input.label(), "file too small"));
        }
        let user_blob_size = u16::from_le_bytes(data[0xD6..0xD8].try_into().expect("2 bytes"));
        if !(0x10..=0x64).contains(&user_blob_size) {
            return Err(Error::malformed(input.label(), "blob size out of range"));
        }
        if user_blob_size as usize + 0xD8 > data.len() {
            return Err(Error::malformed(input.label(), "blob extends past EOF"));
        }
        let blob = &data[0xD8..0xD8 + user_blob_size as usize];
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:{}", hex::encode(blob).to_uppercase()),
        )])
    }
}
