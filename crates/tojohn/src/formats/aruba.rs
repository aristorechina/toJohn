//! ArubaOS password hash parser: `username:<50 hex chars>` per line
//! (first 10 hex chars are the salt, the remaining 40 the SHA-1 digest),
//! emitted as `$dynamic_25$` lines. Lines whose hash part is not exactly
//! 50 characters are skipped.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Aruba;

impl Extractor for Aruba {
    fn name(&self) -> &'static str {
        "aruba"
    }

    fn description(&self) -> &'static str {
        "ArubaOS password hashes"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::lines(&input.data).any(|line| {
            let hash = hash_part(util::rstrip(line));
            hash.len() == 50 && hash.iter().all(u8::is_ascii_hexdigit)
        })
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        for raw in util::lines(&input.data) {
            let fields: Vec<&[u8]> = util::rstrip(raw).split(|&b| b == b':').collect();
            // when a colon exists, only the second field is the hash part;
            // later fields are ignored
            let (username, hash) = match fields.split_first() {
                Some((first, tail)) if !tail.is_empty() => (Some(*first), tail[0]),
                Some((first, _)) => (None, *first),
                None => continue,
            };
            if hash.len() != 50 {
                // unsupported hash length: skip the line
                continue;
            }
            let salt = String::from_utf8_lossy(&hash[..10]);
            let digest = String::from_utf8_lossy(&hash[10..]);
            let output = format!("$dynamic_25${digest}$HEX${salt}");
            if let Some(name) = username.filter(|name| !name.is_empty()) {
                let name = String::from_utf8_lossy(name);
                out.push(HashLine::new(name.to_string(), format!("{name}:{output}")));
                continue;
            }
            out.push(HashLine::new(String::new(), output));
        }
        Ok(out)
    }
}

/// The hash part of a line: the second `:`-separated field when one exists,
/// the whole line otherwise.
fn hash_part(line: &[u8]) -> &[u8] {
    let mut fields = line.split(|&b| b == b':');
    let first = fields.next().unwrap_or(&[]);
    fields.next().unwrap_or(first)
}
