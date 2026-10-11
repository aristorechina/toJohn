//! Enpass Password Manager hash extractor: hex-encodes the first 1024 bytes
//! of a `.walltex` file into an `$enpass$0$24000$...` hash line. The label
//! is the file's basename.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Enpass;

impl Extractor for Enpass {
    fn name(&self) -> &'static str {
        "enpass"
    }

    fn description(&self) -> &'static str {
        "Enpass Password Manager .walltex files"
    }

    fn accepts(&self, _input: &Input) -> bool {
        // No reliable content marker; detection is by file extension in the CLI.
        false
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data[..1024.min(input.data.len())];
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:$enpass$0$24000${}", hex::encode(data)),
        )])
    }
}
