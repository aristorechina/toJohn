//! CRACF.TXT parser (RACF password listings). Each line is whitespace-split
//! and emitted as a `$racf$` line; lines with fewer than 2 fields are
//! rejected as [`Error::Malformed`].

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Cracf;

impl Extractor for Cracf {
    fn name(&self) -> &'static str {
        "cracf"
    }

    fn description(&self) -> &'static str {
        "CRACF.TXT files (RACF)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::lines(&input.data)
            .map(util::rstrip)
            .find(|l| !l.is_empty())
            .is_some_and(|l| String::from_utf8_lossy(l).split_whitespace().count() >= 3)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        for raw in util::lines(&input.data) {
            let line = String::from_utf8_lossy(raw);
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 2 {
                return Err(Error::malformed(
                    input.label(),
                    "line has fewer than 2 fields",
                ));
            }
            let user = fields[0];
            let last = fields[fields.len() - 1];
            let second_last = fields[fields.len() - 2];
            out.push(HashLine::new(
                user,
                format!("{user}:$racf$*{user}*{last}*{second_last}"),
            ));
        }
        Ok(out)
    }
}
