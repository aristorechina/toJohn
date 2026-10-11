//! Apache htdigest hash extractor: reads `user:realm:md5hash` lines and
//! emits `$dynamic_4$` hash lines. Malformed lines are skipped silently.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Htdigest;

impl Extractor for Htdigest {
    fn name(&self) -> &'static str {
        "htdigest"
    }

    fn description(&self) -> &'static str {
        "Apache htdigest files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::lines(&input.data)
            .map(util::rstrip)
            .find(|l| !l.is_empty())
            .is_some_and(looks_like)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        for raw in util::lines(&input.data) {
            let line = util::rstrip(raw);
            // a line must split into exactly 3 `:`-fields; anything else is
            // skipped
            let fields: Vec<&[u8]> = line.split(|&b| b == b':').collect();
            if fields.len() != 3 {
                continue;
            }
            let username = String::from_utf8_lossy(fields[0]);
            let realm = String::from_utf8_lossy(fields[1]);
            let hash = String::from_utf8_lossy(fields[2]);
            let prefix = format!("{username}:{realm}:");
            out.push(HashLine::new(
                username.to_string(),
                format!(
                    "{username}:$dynamic_4${hash}$HEX${}",
                    hex::encode(prefix.as_bytes())
                ),
            ));
        }
        Ok(out)
    }
}

/// First non-empty line must be `user:realm:<32 hex chars>`.
fn looks_like(line: &[u8]) -> bool {
    let fields: Vec<&[u8]> = line.split(|&b| b == b':').collect();
    fields.len() == 3 && fields[2].len() == 32 && fields[2].iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_malformed_lines() {
        let input = Input::from_bytes(
            "x",
            b"admin:realm:0123456789abcdef0123456789abcdef\nbad-line\nonly:two\n".to_vec(),
        );
        let out = Htdigest.extract(&input).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].line,
            "admin:$dynamic_4$0123456789abcdef0123456789abcdef$HEX$61646d696e3a7265616c6d3a"
        );
    }
}
