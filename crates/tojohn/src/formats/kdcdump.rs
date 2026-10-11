//! kdcdump output hash extractor: translates kdcdump output lines into
//! `$NT$` (krb5-23) and `$krb18$` (krb5-18) hash lines.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Kdcdump;

impl Extractor for Kdcdump {
    fn name(&self) -> &'static str {
        "kdcdump"
    }

    fn description(&self) -> &'static str {
        "kdcdump output files (krb5-23 / krb5-18 hashes)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::lines(&input.data).any(|l| {
            let head = l.split(|&b| b == b',').next().unwrap_or(l);
            head == b"23".as_slice() || head == b"18".as_slice()
        })
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        let mut name = String::from("unknown");
        for raw in util::lines(&input.data) {
            let fields: Vec<&[u8]> = raw.split(|&b| b == b',').collect();
            if fields.len() == 1 {
                let stripped = util::strip(raw);
                if !stripped.is_empty() {
                    name = String::from_utf8_lossy(stripped).to_string();
                }
            }
            if fields[0] == b"23".as_slice() {
                let hash = stripped_field(&fields, 1)?;
                out.push(HashLine::new(name.clone(), format!("{name}:$NT${hash}")));
            } else if fields[0] == b"18".as_slice() {
                let hash = stripped_field(&fields, 1)?;
                // salt = the realm (part after '@') followed by the principal
                // (part before '@') with '/' removed
                let realm = name
                    .split('@')
                    .nth(1)
                    .ok_or_else(|| {
                        Error::malformed(input.label(), format!("principal {name:?} has no '@'"))
                    })?
                    .to_string();
                let principal = name.split('@').next().unwrap_or("").replace('/', "");
                let salt = format!("{realm}{principal}");
                out.push(HashLine::new(
                    name.clone(),
                    format!("{name}:$krb18${salt}${hash}"),
                ));
            }
        }
        Ok(out)
    }
}

fn stripped_field(fields: &[&[u8]], idx: usize) -> Result<String> {
    let field = fields
        .get(idx)
        .ok_or_else(|| Error::malformed("<kdcdump>", "hash line is missing the hash field"))?;
    Ok(String::from_utf8_lossy(util::strip(field)).to_string())
}
