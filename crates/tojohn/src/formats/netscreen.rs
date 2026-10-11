//! Generates NetScreen-formatted password hashes (`user:user$ciphertext`)
//! built from an MD5 of the `user:Administration Tools:password` string.
//! Two modes:
//!
//! - **single mode**: username + plaintext password in `input.extra_args`
//! - **file mode**: lines of `user,pass` or `user:pass` in the primary input

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use md5::{Digest, Md5};

pub struct Netscreen;

/// The 64-character base64 alphabet used by the NetScreen encoding.
const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

impl Extractor for Netscreen {
    fn name(&self) -> &'static str {
        "netscreen"
    }

    fn description(&self) -> &'static str {
        "NetScreen password hashes (user,pass pairs or user+pass extra args)"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        if input.extra_args.len() >= 2 {
            let user = &input.extra_args[0];
            let password = &input.extra_args[1];
            let ciphertext = render_ciphertext(user, password);
            return Ok(vec![HashLine::new(
                user.clone(),
                format!("{user}:{user}${ciphertext}"),
            )]);
        }
        let mut out = Vec::new();
        for raw in crate::util::lines(&input.data) {
            // tolerate CRLF input: strip a trailing \r before splitting.
            let line = strip_trailing_cr(raw);
            let Some((username_raw, password_raw)) = split_once_any(line, b',', b':') else {
                // stop processing at the first line without a separator
                break;
            };
            let username = String::from_utf8_lossy(username_raw).to_string();
            let password = String::from_utf8_lossy(password_raw).to_string();
            let ciphertext = render_ciphertext(&username, &password);
            out.push(HashLine::new(
                username.clone(),
                format!("{username}:{username}${ciphertext}"),
            ));
        }
        Ok(out)
    }
}

fn strip_trailing_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn split_once_any(line: &[u8], first: u8, second: u8) -> Option<(&[u8], &[u8])> {
    let separator = if line.contains(&first) {
        first
    } else if line.contains(&second) {
        second
    } else {
        return None;
    };
    let position = line.iter().position(|&b| b == separator)?;
    Some((&line[..position], &line[position + 1..]))
}

/// Renders the NetScreen ciphertext: an MD5 over
/// `user:Administration Tools:password`, encoded with the custom alphabet and
/// interleaved with fixed characters.
fn render_ciphertext(user: &str, password: &str) -> String {
    let source = format!("{user}:Administration Tools:{password}");
    // the NetScreen algorithm hashes the latin-1 encoding of source; identical
    // bytes for ASCII input.
    let digest = Md5::digest(source.as_bytes());
    let mut ciphertext = String::new();
    for pair in digest.chunks_exact(2) {
        // two hash bytes form a 16-bit value split into three 6-bit indices
        let packed = ((u16::from(pair[0]) << 8) & 0xff00) | (u16::from(pair[1]) & 0xff);
        let high = ((packed >> 12) & 0xf) as usize;
        let mid = ((packed >> 6) & 0x3f) as usize;
        let low = (packed & 0x3f) as usize;
        ciphertext.push(B64[high] as char);
        ciphertext.push(B64[mid] as char);
        ciphertext.push(B64[low] as char);
    }
    // six fixed characters are interleaved at fixed positions
    for (character, position) in std::iter::zip("nrcstn".chars(), [0usize, 6, 12, 17, 23, 29]) {
        ciphertext.insert(position, character);
    }
    ciphertext
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Documented example pair (admin / netscreen) with its ciphertext.
    #[test]
    fn documented_example() {
        assert_eq!(
            render_ciphertext("admin", "netscreen"),
            "nKv3LvrdAVtOcE5EcsGIpYBtniNbUn"
        );
    }
}
