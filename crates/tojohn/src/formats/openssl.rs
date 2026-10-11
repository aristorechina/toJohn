//! Processes files encrypted with `openssl enc` into `$openssl$` lines.
//! Options `-c` (cipher), `-m` (md), `-p` (plaintext), `-a` (minascii) are
//! taken from `input.extra_args` as `["-c", "1", ...]`-style pairs.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use base64::Engine;
use std::borrow::Cow;

pub struct Openssl;

impl Extractor for Openssl {
    fn name(&self) -> &'static str {
        "openssl"
    }

    fn description(&self) -> &'static str {
        "'openssl enc' encrypted files (options: -c -m -p -a)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"Salted__")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut cipher = String::from("0");
        let mut md = String::from("0");
        let mut plaintext: Option<String> = None;
        let mut minascii: Option<String> = None;
        let mut args = input.extra_args.iter();
        while let Some(flag) = args.next() {
            let value = args.next();
            match flag.as_str() {
                "-c" => {
                    if let Some(arg) = value {
                        cipher = arg.clone();
                    }
                }
                "-m" => {
                    if let Some(arg) = value {
                        md = arg.clone();
                    }
                }
                "-p" => {
                    if let Some(arg) = value {
                        plaintext = Some(arg.clone());
                    }
                }
                "-a" => {
                    if let Some(arg) = value {
                        minascii = Some(arg.clone());
                    }
                }
                _ => {}
            }
        }

        let data = if input.data.starts_with(b"Salted__") {
            Cow::Borrowed(&input.data[..])
        } else {
            // fall back to base64-decoded input
            let engine = base64::engine::general_purpose::STANDARD;
            match engine.decode(std::str::from_utf8(&input.data).unwrap_or("").trim()) {
                Ok(decoded) => Cow::Owned(decoded),
                Err(_) => {
                    // data is neither raw nor base64-encoded openssl output
                    return Ok(Vec::new());
                }
            }
        };
        if !data.starts_with(b"Salted__") {
            return Ok(Vec::new());
        }
        if data.len() < 32 {
            return Ok(Vec::new());
        }

        let payload_len = data.len() - 16;
        let salt = hex::encode(&data[8..16]);
        let mode = match (&plaintext, &minascii) {
            (Some(p), _) => format!("1${p}"),
            (None, Some(a)) => format!("2${a}"),
            (None, None) => String::from("0"),
        };
        let label = input.label();
        if payload_len <= 16 {
            let last_chunk = hex::encode(&data[data.len() - 16..]);
            Ok(vec![HashLine::new(
                label.to_string(),
                format!("{label}:$openssl${cipher}${md}$8${salt}${last_chunk}$1${mode}"),
            )])
        } else {
            let last_chunk = hex::encode(&data[data.len() - 32..]);
            // at most 256 bytes of ciphertext are carried in the line
            let ciphertext_prefix = hex::encode(&data[16..272.min(data.len())]);
            Ok(vec![HashLine::new(
                label.to_string(),
                format!(
                    "{label}:$openssl${cipher}${md}$8${salt}${last_chunk}$0${}${ciphertext_prefix}${mode}",
                    ciphertext_prefix.len() / 2
                ),
            )])
        }
    }
}
