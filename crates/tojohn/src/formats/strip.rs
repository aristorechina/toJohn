//! STRIP password database parser: reads the first 1024 bytes of the file
//! into a `$strip$` line.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Strip;

impl Extractor for Strip {
    fn name(&self) -> &'static str {
        "strip"
    }

    fn description(&self) -> &'static str {
        "STRIP password database files"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data[..input.data.len().min(1024)];
        let label = input.label();
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:$strip$*{}", hex::encode(data)),
        )])
    }
}
