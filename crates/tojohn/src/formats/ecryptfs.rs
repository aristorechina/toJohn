//! eCryptfs wrapped-passphrase hash extractor.
//!
//! Parses eCryptfs wrapped-passphrase files (version 1 and 2) with an
//! optional `.ecryptfsrc` passed as a secondary file (`input.extra_files[0]`)
//! providing a variable salt; emits `$ecryptfs$0$` hash lines.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Ecryptfs;

impl Extractor for Ecryptfs {
    fn name(&self) -> &'static str {
        "ecryptfs"
    }

    fn description(&self) -> &'static str {
        "eCryptfs wrapped-passphrase files (optional: .ecryptfsrc as extra file)"
    }

    fn accepts(&self, input: &Input) -> bool {
        // Only the version-2 marker is distinctive; bare v1 files must be
        // selected with -f explicitly.
        input.data.starts_with(b":\x02")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut salt: Option<String> = None;
        if let Some(src) = input.extra_files.first() {
            for raw in util::lines(&src.data) {
                // The salt= prefix is checked on the raw line, before stripping.
                if !raw.starts_with(b"salt=") {
                    continue;
                }
                let line = util::strip(raw);
                let fields: Vec<&[u8]> = line.split(|&b| b == b'=').collect();
                if fields.len() != 2 {
                    return Err(Error::malformed(
                        &src.label,
                        "salt= line does not split into exactly 2 fields",
                    ));
                }
                let value = util::strip(fields[1]);
                // Byte semantics: cut to the first 16 bytes.
                let cut = 16.min(value.len());
                salt = Some(String::from_utf8_lossy(&value[..cut]).to_string());
            }
        }

        let data = &input.data;
        let (salt, hash): (Option<String>, String) = if data.len() >= 2 && data[..2] == *b":\x02" {
            // Version 2: an 8-byte salt follows the version marker.
            if data.len() < 10 {
                return Ok(Vec::new());
            }
            let salt = hex::encode(&data[2..10]);
            let hash = decode_ascii(&data[10..], input.label())?;
            (Some(salt), hash)
        } else {
            // Version 1: the hash is the first 16 bytes (version included).
            if data.is_empty() {
                return Ok(Vec::new());
            }
            let end = 16.min(data.len());
            let hash = decode_ascii(&data[..end], input.label())?;
            (salt, hash)
        };

        if hash.len() != 16 {
            return Ok(Vec::new());
        }

        let line = match salt {
            None => format!("{}:$ecryptfs$0${hash}", input.label()),
            Some(salt) => format!("{}:$ecryptfs$0$1${salt}${hash}", input.label()),
        };
        Ok(vec![HashLine::new(input.label().to_string(), line)])
    }
}

/// Decodes the hash bytes as UTF-8/ASCII; non-ASCII input is rejected as
/// malformed.
fn decode_ascii(bytes: &[u8], file: &str) -> Result<String> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(Error::malformed(file, "hash bytes are not ASCII")),
    }
}
