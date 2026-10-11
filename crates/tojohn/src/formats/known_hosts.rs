//! OpenSSH `known_hosts` hash extractor for entries with hashed hostnames
//! (`|1|...`), emitting `$known_hosts$` hash lines.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct KnownHosts;

impl Extractor for KnownHosts {
    fn name(&self) -> &'static str {
        "known_hosts"
    }

    fn description(&self) -> &'static str {
        "OpenSSH known_hosts files with hashed hostnames"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::lines(&input.data)
            .find(|l| !util::strip(l).is_empty())
            .is_some_and(|l| l.starts_with(b"|1|"))
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        for raw in util::lines(&input.data) {
            // The `|1|` prefix is checked on the raw line, before stripping.
            if !raw.starts_with(b"|1|") {
                continue;
            }
            let line = util::strip(raw);
            // split on "= "; the head part gets "=" appended
            let head = match util::find(line, b"= ") {
                Some(pos) => &line[..pos],
                None => line,
            };
            let mut field = head.to_vec();
            field.push(b'=');
            // index after the last "|", or 0 when there is none
            let start = field.iter().rposition(|&b| b == b'|').map_or(0, |i| i + 1);
            let label = String::from_utf8_lossy(&field[start..]);
            let field_text = String::from_utf8_lossy(&field);
            out.push(HashLine::new(
                label.to_string(),
                format!("{label}:$known_hosts${field_text}"),
            ));
        }
        Ok(out)
    }
}
