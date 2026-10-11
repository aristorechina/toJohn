//! ibmiscanner hash extractor: converts `userid:hash` lines to
//! `$as400ssha1$` hash lines. Lines that do not split into at least 2
//! `:`-fields are skipped.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Ibmiscanner;

impl Extractor for Ibmiscanner {
    fn name(&self) -> &'static str {
        "ibmiscanner"
    }

    fn description(&self) -> &'static str {
        "ibmiscanner userid:hash files (AS/400 SHA)"
    }

    fn accepts(&self, input: &Input) -> bool {
        // userid:hash — the hash side is a fixed-length hex/SHA blob, so
        // require a plausibly long second field; this keeps the loose
        // "exactly one colon" shape from swallowing unrelated colon files
        // (PuTTY PPK headers, passwd lines, ...) during auto-detection.
        util::splitlines(&input.data)
            .find(|l| !l.is_empty())
            .is_some_and(|l| {
                let mut it = l.splitn(2, |&b| b == b':');
                let user = it.next().unwrap_or(&[]);
                let hash = it.next().unwrap_or(&[]);
                !user.is_empty() && hash.len() >= 16 && !hash.contains(&b':')
            })
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        for line in util::splitlines(&input.data) {
            let fields: Vec<&[u8]> = line.split(|&b| b == b':').collect();
            if fields.len() < 2 {
                // unparseable line: skipping
                continue;
            }
            let user = String::from_utf8_lossy(fields[0]);
            let hash = String::from_utf8_lossy(fields[1]);
            out.push(HashLine::new(
                user.to_string(),
                format!("{user}:$as400ssha1${hash}${user}"),
            ));
        }
        Ok(out)
    }
}
