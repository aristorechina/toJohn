//! andOTP backup file parser: splits the `IV || ciphertext || TAG` backup
//! blob into hex fields of an `$andotp$` line. Files shorter than
//! IV + minimum data + TAG produce no output.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Andotp;

impl Extractor for Andotp {
    fn name(&self) -> &'static str {
        "andotp"
    }

    fn description(&self) -> &'static str {
        "andOTP backup .json.aes files"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        // weak sanity check: IV + minimum-data-size + TAG
        if data.len() < 12 + 2 + 16 {
            return Ok(Vec::new());
        }
        let iv = hex::encode(&data[0..12]);
        let tag = hex::encode(&data[data.len() - 16..]);
        let ciphertext = hex::encode(&data[12..data.len() - 16]);
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:$andotp$0*{iv}*{ciphertext}*{tag}"),
        )])
    }
}
