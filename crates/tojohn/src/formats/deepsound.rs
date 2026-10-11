//! DeepSound 2.0 steganographic WAV file parser: scans for the `DSCF`
//! magic and emits `$dynamic_1529$` lines with the embedded SHA-1.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Deepsound;

/// Size of the packed DeepSound header window.
const HEADER_SIZE: usize = 104;

impl Extractor for Deepsound {
    fn name(&self) -> &'static str {
        "deepsound"
    }

    fn description(&self) -> &'static str {
        "DeepSound 2.0 steganographic WAV files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.len() >= 12 && is_wave(&input.data)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < 12 || !is_wave(data) {
            // not a WAV file: produce no output
            return Ok(Vec::new());
        }
        let Some(header) = data
            .windows(HEADER_SIZE)
            .find(|window| is_magic(window))
            .map(decode_packed_header)
        else {
            return Ok(Vec::new()); // no DSCF magic found: not a DeepSound file
        };
        let mode = header[4];
        let encrypted = header[5];
        if mode != 2 && mode != 4 && mode != 8 {
            return Ok(Vec::new()); // unexpected data encoding mode
        }
        if encrypted == 0 {
            return Ok(Vec::new()); // file is not encrypted
        } else if encrypted != 1 {
            return Ok(Vec::new()); // unexpected encryption flag
        }
        let sha1 = &header[6..6 + 20];
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:$dynamic_1529${}", hex::encode(sha1)),
        )])
    }
}

fn is_wave(buf: &[u8]) -> bool {
    buf.len() >= 12 && &buf[0..4] == b"RIFF" && &buf[8..12] == b"WAVE"
}

fn is_magic(window: &[u8]) -> bool {
    // The `DSCF` magic is nibble-packed: byte 4*i holds the high nibble of
    // magic[i] and byte 4*i+2 the low nibble, so the window never holds the
    // magic as plain bytes.
    b"DSCF".iter().enumerate().all(|(i, &byte)| {
        (window[i * 4] & 15) == (byte >> 4) && (window[i * 4 + 2] & 15) == (byte & 15)
    })
}

/// Decode the nibble-packed header: one output byte per 4-byte group, from
/// the high nibble of the first and the low nibble of the third byte.
fn decode_packed_header(window: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + 3 < window.len() {
        out.push((window[offset] & 15) << 4 | (window[offset + 2] & 15));
        offset += 4;
    }
    out
}
