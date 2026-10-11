//! Dashlane .aes / .dash profile parser: raw 256-byte header or "Data
//! BEGIN" secure archives, emitted as `$dashlane$` lines. The output label
//! is the file path exactly as given.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Dashlane;

/// Bytes of the raw header embedded in the hash line.
const HEADER_LEN: usize = 256;

impl Extractor for Dashlane {
    fn name(&self) -> &'static str {
        "dashlane"
    }

    fn description(&self) -> &'static str {
        "Dashlane .aes / .dash files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"Data BEGIN").is_some()
            || util::find(&input.data, b"KWC3").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let raw = &input.data;
        let data: Vec<u8> = if util::find(raw, b"Data BEGIN").is_some() {
            // secure archive: the base64 payload is the line after the last
            // "Data BEGIN" marker
            let mut capture_next = false;
            let mut payload_line: Option<&[u8]> = None;
            for line in util::lines(raw) {
                if util::find(line, b"Data BEGIN").is_some() {
                    capture_next = true;
                    continue;
                }
                if capture_next {
                    payload_line = Some(util::strip(line));
                    capture_next = false;
                }
            }
            match payload_line {
                Some(line) => {
                    let b64 = base64::engine::general_purpose::STANDARD;
                    let decoded = b64
                        .decode(std::str::from_utf8(line).unwrap_or("").trim())
                        .unwrap_or_default();
                    decoded[..HEADER_LEN.min(decoded.len())].to_vec()
                }
                None => Vec::new(),
            }
        } else {
            raw[..HEADER_LEN.min(raw.len())].to_vec()
        };

        if data.len() < 32 {
            return Ok(Vec::new()); // too short to be a valid database
        }
        let salt = hex::encode(&data[0..32]);
        let (version, aes_data): (u32, &[u8]) = if data[32..].starts_with(b"KWC3") {
            (1, &data[36..])
        } else {
            (0, &data[32..])
        };
        let aes_hex = hex::encode(aes_data);
        let label = input.label();
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$dashlane${version}*{salt}*{}*{aes_hex}",
                aes_hex.len() / 2
            ),
        )])
    }
}
