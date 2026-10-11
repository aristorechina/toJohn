//! AIX `/etc/security/passwd` plaintext-password variant parser: stanza
//! headers (`user:`) followed by `password = <value>` lines (skipping the
//! `*` placeholder), emitting `user:value` lines. This complements the
//! `aix` module, which handles the hashed forms.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct AixPlaintext;

impl Extractor for AixPlaintext {
    fn name(&self) -> &'static str {
        "aix_plaintext"
    }

    fn description(&self) -> &'static str {
        "AIX /etc/security/passwd files with clear-text passwords"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"password = ").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        let mut current_user = String::new();
        for raw in util::lines(&input.data) {
            let line = String::from_utf8_lossy(util::rstrip(raw)).to_string();
            // ^\s*([^:]+):\s*$
            if let Some(user) = parse_stanza_header(&line) {
                current_user = user;
                continue;
            }
            // ^\s*password\s+=\s*(\S+)\s*$ and value != "*"
            if let Some(password) = parse_password_line(&line) {
                if password != "*" {
                    out.push(HashLine::new(
                        current_user.clone(),
                        format!("{current_user}:{password}"),
                    ));
                    current_user.clear();
                }
            }
        }
        Ok(out)
    }
}

/// Matches `^\s*([^:]+):\s*$` and returns the captured user.
fn parse_stanza_header(line: &str) -> Option<String> {
    let after_ws = line.trim_start();
    if !after_ws.ends_with(':') || !line.trim_end().ends_with(':') {
        return None;
    }
    let user = after_ws.strip_suffix(':')?.trim_end();
    if user.is_empty() || user.contains(':') {
        return None;
    }
    Some(user.to_string())
}

/// Matches `^\s*password\s+=\s*(\S+)\s*$` and returns the value.
fn parse_password_line(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("password")?;
    let rest = rest.trim_start().strip_prefix('=')?.trim();
    if rest.is_empty() || rest.contains(char::is_whitespace) {
        return None;
    }
    Some(rest.to_string())
}
