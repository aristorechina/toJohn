//! ike-scan PSK hash extractor, emitting `$ike$` hash lines. An optional
//! norteluser is taken from `input.extra_args[0]`.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Ikescan;

impl Extractor for Ikescan {
    fn name(&self) -> &'static str {
        "ikescan"
    }

    fn description(&self) -> &'static str {
        "ike-scan PSK output files (optional: norteluser as extra arg)"
    }

    fn accepts(&self, input: &Input) -> bool {
        // ike-scan PSK output is "keyid:hexhash" — exactly 2 fields and a
        // hex second field (htdigest's 3-field user:realm:hash is excluded).
        util::lines(&input.data)
            .map(util::rstrip)
            .find(|l| !l.is_empty())
            .is_some_and(|l| {
                let fields: Vec<&[u8]> = l.split(|&b| b == b':').collect();
                fields.len() == 2
                    && !fields[1].is_empty()
                    && fields[1].iter().all(u8::is_ascii_hexdigit)
            })
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let nortel_user = input.extra_args.first().map(String::as_str);
        let mut out = Vec::new();
        for raw in util::lines(&input.data) {
            let line = String::from_utf8_lossy(util::rstrip(raw)).replace(':', "*");
            let line = match nortel_user {
                None => format!("$ike$*0*{line}"),
                Some(name) => format!("$ike$*1*{name}*{line}"),
            };
            out.push(HashLine::new(String::new(), line));
        }
        Ok(out)
    }
}
