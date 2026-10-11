//! AIX `/etc/security/passwd` parser: stanza headers (`user:`) followed by
//! indented `password = ...` lines (smd5 / ssha / DES forms), emitted as
//! `user:hash` lines.
//!
//! The optional standard-hash mode (for files created with
//! `lpa_options = std_hash=true`) re-emits smd5 entries as `$1$` lines; it is
//! enabled by passing `-s` / `--standard` / `s` in `input.extra_args`.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Aix;

impl Extractor for Aix {
    fn name(&self) -> &'static str {
        "aix"
    }

    fn description(&self) -> &'static str {
        "AIX /etc/security/passwd files (optional: -s in extra args for standard hashes)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::lines(&input.data).any(|l| util::find(l, b"password = ").is_some())
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let standard = input
            .extra_args
            .iter()
            .any(|a| a == "-s" || a == "--standard" || a == "s");
        let mut out = Vec::new();
        let mut username = "?".to_string();
        for raw in util::lines(&input.data) {
            if is_username_header(raw) {
                username =
                    String::from_utf8_lossy(raw.split(|&b| b == b':').next().unwrap_or(b"?"))
                        .to_string();
            }
            if util::find(raw, b"password = ").is_none() {
                continue;
            }
            if util::find(raw, b"smd5").is_some() {
                let eq_part = after_first_eq(raw);
                let value = util::strip(&eq_part);
                if value.len() != 37 {
                    continue;
                }
                if standard {
                    let tail = String::from_utf8_lossy(&value[6..]);
                    out.push(HashLine::new(
                        username.clone(),
                        format!("{username}:$1${tail}"),
                    ));
                } else {
                    let hash = String::from_utf8_lossy(value);
                    out.push(HashLine::new(
                        username.clone(),
                        format!("{username}:{hash}"),
                    ));
                }
            } else if util::find(raw, b"ssha").is_some() {
                let eq_part = after_first_eq(raw);
                let value = util::strip(&eq_part);
                let fields: Vec<&[u8]> = value.split(|&b| b == b'$').collect();
                let [scheme, salt, hash] = fields.as_slice() else {
                    // malformed ssha value: not exactly 3 '$'-separated fields
                    return Err(Error::malformed(
                        input.label(),
                        "ssha hash does not split into exactly 3 '$'-separated fields",
                    ));
                };
                let scheme = String::from_utf8_lossy(scheme);
                let salt = String::from_utf8_lossy(salt);
                let hash = String::from_utf8_lossy(hash);
                out.push(HashLine::new(
                    username.clone(),
                    format!("{username}:{scheme}${salt}${hash}"),
                ));
            } else {
                let eq_part = after_first_eq(raw);
                let value = util::strip(&eq_part);
                if value != b"*" {
                    let hash = String::from_utf8_lossy(value);
                    out.push(HashLine::new(
                        username.clone(),
                        format!("{username}:{hash}"),
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// Matches `^\s*\S+\s*:\s*$` (ASCII whitespace only).
fn is_username_header(line: &[u8]) -> bool {
    let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let Some(body_end) = line.iter().rposition(|&b| !is_ws(b)) else {
        return false; // whitespace-only line
    };
    let body = &line[..body_end + 1];
    if body.last() != Some(&b':') {
        return false;
    }
    let mid = util::rstrip(&body[..body.len() - 1]);
    let Some(start) = mid.iter().position(|&b| !is_ws(b)) else {
        return false; // no \S+ before the colon
    };
    mid[start..].iter().all(|&b| !is_ws(b))
}

/// The part of the line between the first and second `=`.
fn after_first_eq(line: &[u8]) -> Vec<u8> {
    let Some(eq) = line.iter().position(|&b| b == b'=') else {
        return Vec::new();
    };
    line[eq + 1..]
        .split(|&b| b == b'=')
        .next()
        .unwrap_or(&[])
        .to_vec()
}
