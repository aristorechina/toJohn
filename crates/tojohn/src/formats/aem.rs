//! Adobe AEM (Adobe Experience Manager) native hash converter: reads
//! `{SHA-256}salt-iterations-hash` / `{SHA-512}...` lines and emits `$sspr$`
//! lines. Lines without a known tag, and lines whose body does not split
//! into exactly 3 `-` fields, are skipped.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Aem;

/// Length of both supported tags, `{SHA-256}` and `{SHA-512}`.
const TAG_LEN: usize = 9;

impl Extractor for Aem {
    fn name(&self) -> &'static str {
        "aem"
    }

    fn description(&self) -> &'static str {
        "Adobe AEM (Adobe Experience Manager) hashes"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::lines(&input.data)
            .map(util::rstrip)
            .find(|l| !l.is_empty())
            .is_some_and(|l| l.starts_with(b"{SHA-256}") || l.starts_with(b"{SHA-512}"))
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        for raw in util::lines(&input.data) {
            let line = util::rstrip(raw);
            let algo: u32 = if util::find(line, b"{SHA-256}").is_some() {
                3 // SHA-256
            } else if util::find(line, b"{SHA-512}").is_some() {
                4 // SHA-512
            } else {
                // unknown hash format: skip the line
                continue;
            };
            let body = &line[TAG_LEN.min(line.len())..];
            let fields: Vec<&[u8]> = body.split(|&b| b == b'-').collect();
            // body must split into exactly 3 `-` fields, otherwise skip
            let [salt, iterations, digest] = fields.as_slice() else {
                continue;
            };
            let salt = String::from_utf8_lossy(salt);
            let iterations = String::from_utf8_lossy(iterations);
            let digest = String::from_utf8_lossy(digest);
            out.push(HashLine::new(
                String::new(),
                format!("$sspr${algo}${iterations}${salt}${digest}"),
            ));
        }
        Ok(out)
    }
}
