//! Extracts hashes from VMware `.vmx` files with `encryption.keySafe`/
//! `displayName` lines, emitting `$vmx$` lines for PBKDF2-HMAC-SHA-1 /
//! AES-256 key safes.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Vmx;

/// Shape of the `encryption.keySafe` line: id, key derivation, cipher,
/// rounds, salt, HMAC name and cipher data fields.
const KS_RE: &str =
    r"^.+phrase/(.*?)/pass2key=(.*?):cipher=(.*?):rounds=(.*?):salt=(.*?),(.*?),(.*?)\)";

impl Extractor for Vmx {
    fn name(&self) -> &'static str {
        "vmx"
    }

    fn description(&self) -> &'static str {
        "VMware .vmx files with encrypted disks"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"encryption.keySafe").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut display_name = String::from("Unknown");
        let mut keysafe: Option<&[u8]> = None;
        for raw in util::lines(&input.data) {
            if util::find(raw, b"encryption.keySafe").is_some() {
                keysafe = Some(raw);
            }
            if util::find(raw, b"displayName").is_some() {
                // value = text after " = ", quote-trimmed
                let separator = util::find(raw, b" = ").ok_or_else(|| {
                    Error::malformed(input.label(), "displayName line has no ' = ' separator")
                })?;
                let value = &raw[separator + 3..];
                display_name = String::from_utf8_lossy(util::strip(value))
                    .trim_matches('"')
                    .to_string();
            }
        }
        let Some(keysafe) = keysafe else {
            // a missing keysafe line is an error, not an empty result
            return Err(Error::malformed(
                input.label(),
                "no encryption.keySafe line found",
            ));
        };
        // percent-decode the keysafe line, UTF-8 with replacement.
        let keysafe = String::from_utf8_lossy(&util::percent_decode(keysafe)).to_string();
        let re = regex::Regex::new(KS_RE).expect("valid regex");
        let Some(caps) = re.captures(&keysafe) else {
            // keysafe in an unsupported format: return without output
            return Ok(Vec::new());
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        // the id is decoded to validate it but never included in the output
        b64.decode(caps[1].trim()).map_err(|e| {
            Error::malformed(input.label(), format!("keySafe id is not base64: {e}"))
        })?;
        if &caps[2] != "PBKDF2-HMAC-SHA-1" {
            return Ok(Vec::new()); // unsupported pass2key algorithm
        }
        if &caps[3] != "AES-256" {
            return Ok(Vec::new());
        }
        let iterations: i64 = caps[4]
            .parse()
            .map_err(|e| Error::malformed(input.label(), format!("bad rounds: {e}")))?;
        let salt =
            hex::encode(b64.decode(caps[5].trim()).map_err(|e| {
                Error::malformed(input.label(), format!("salt is not base64: {e}"))
            })?);
        if &caps[6] != "HMAC-SHA-1" {
            return Ok(Vec::new());
        }
        let cipherdata = hex::encode(b64.decode(caps[7].trim()).map_err(|e| {
            Error::malformed(input.label(), format!("cipherdata is not base64: {e}"))
        })?);
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            format!("{label}-{display_name}"),
            format!("{label}-{display_name}:$vmx$1$0$0${iterations}${salt}${cipherdata}"),
        )])
    }
}
