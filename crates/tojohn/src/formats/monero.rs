//! Hex-encodes a Monero `.keys` wallet file into a
//! `name:$monero$0*<hex-of-file>` line keyed on the file label.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Monero;

impl Extractor for Monero {
    fn name(&self) -> &'static str {
        "monero"
    }

    fn description(&self) -> &'static str {
        "Monero .keys wallet files"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false // detection is by .keys extension in the CLI
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let name = util::basename(input.label());
        Ok(vec![HashLine::new(
            name.to_string(),
            format!("{name}:$monero$0*{}", hex::encode(&input.data)),
        )])
    }
}
