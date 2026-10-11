//! Oracle APEX password hash parser: `username,apexhash,sgid` per line,
//! emitted as `$dynamic_1$` lines. Lines that do not split into exactly 3
//! comma-separated fields are skipped.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Apex;

impl Extractor for Apex {
    fn name(&self) -> &'static str {
        "apex"
    }

    fn description(&self) -> &'static str {
        "Oracle APEX hash files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::lines(&input.data)
            .map(util::rstrip)
            .find(|l| !l.is_empty())
            .is_some_and(|l| l.split(|&b| b == b',').count() == 3)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        for raw in util::lines(&input.data) {
            let fields: Vec<&[u8]> = raw.split(|&b| b == b',').collect();
            // line must split into exactly 3 comma-separated fields
            let [username, apex_hash, sgid] = fields.as_slice() else {
                continue;
            };
            let username = String::from_utf8_lossy(util::strip(username));
            let apex_hash = String::from_utf8_lossy(util::strip(apex_hash));
            let sgid = String::from_utf8_lossy(util::strip(sgid));
            out.push(HashLine::new(
                String::new(),
                format!("$dynamic_1${apex_hash}${sgid}{username}"),
            ));
        }
        Ok(out)
    }
}
