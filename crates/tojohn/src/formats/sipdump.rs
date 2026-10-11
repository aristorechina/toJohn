//! sipdump dump file parser: emits `$sip$` lines for SIP digest
//! authentication challenges. Quotes and colons on each input line are
//! replaced with `*`; a line with fewer than 2 `*`-separated fields is
//! rejected as malformed.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Sipdump;

impl Extractor for Sipdump {
    fn name(&self) -> &'static str {
        "sipdump"
    }

    fn description(&self) -> &'static str {
        "sipdump dump files (SIP digest authentication)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::lines(&input.data)
            .map(util::rstrip)
            .find(|l| !l.is_empty())
            .is_some_and(|l| l.split(|&b| b == b':').count() >= 13)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        for raw in util::lines(&input.data) {
            let line = String::from_utf8_lossy(util::rstrip(raw)).replace(['"', ':'], "*");
            let mut fields: Vec<&str> = line.split('*').collect();
            if fields.len() < 2 {
                return Err(Error::malformed(
                    input.label(),
                    "line has fewer than 2 fields",
                ));
            }
            // when the port number is not explicit in the URI field, an
            // empty field is inserted at its position
            if fields.len() == 13 {
                fields.insert(7, "");
            }
            let label = format!("{}-{}", fields[0], fields[1]);
            let body = fields.join("*");
            let line = format!("{label}:$sip$*{body}");
            out.push(HashLine::new(label, line));
        }
        Ok(out)
    }
}
