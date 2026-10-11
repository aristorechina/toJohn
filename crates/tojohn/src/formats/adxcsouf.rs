//! Extracts password hashes from IBM/Toshiba 4690 POS data files:
//! ADXCRYPT hashes (username + 8-digit hash pairs) from ADXCSOUF.DAT files
//! and SHA-1 hashes from ADXEPW0F.DAT files, emitted as `$adxcrypt$` /
//! `{SHA}` lines. A simple byte-count heuristic picks the parser.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Adxcsouf;

impl Extractor for Adxcsouf {
    fn name(&self) -> &'static str {
        "adxcsouf"
    }

    fn description(&self) -> &'static str {
        "IBM/Toshiba 4690 ADXCSOUF.DAT / ADXEPW0F.DAT files"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false // the DAT formats have no distinctive magic
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        // Heuristic split between the two DAT layouts: the password file is
        // mostly space/NUL padding within the first 2 KiB.
        let length = 2048.min(data.len());
        let count = data[..length]
            .iter()
            .filter(|&&b| b == 0x20 || b == 0x00)
            .count();
        if count > 128 {
            return parse_epw_file(input);
        }
        Ok(parse_dat_file(data))
    }
}

/// Parser for ADXCSOUF.DAT files: `(username hash)` pairs where the hash is
/// 8 digits.
fn parse_dat_file(data: &[u8]) -> Vec<HashLine> {
    let re = regex::bytes::Regex::new(r"([a-zA-Z0-9_-]{3,9})\ (\d{8})").expect("valid regex");
    let mut out = Vec::new();
    for caps in re.captures_iter(data) {
        let username = String::from_utf8_lossy(&caps[1]).to_string();
        let hash = String::from_utf8_lossy(&caps[2]).to_string();
        out.push(HashLine::new(
            username.clone(),
            format!("{username}:$adxcrypt${hash}"),
        ));
    }
    out
}

/// Parser for ADXEPW0F.DAT files (layout inferred by heuristics):
/// 16-byte aligned "lines" of 7 spaces + username; the following 20 bytes are
/// a SHA-1 hash if their entropy is high enough.
fn parse_epw_file(input: &Input) -> Result<Vec<HashLine>> {
    let data = &input.data;
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + 16).min(data.len());
        let line = &data[offset..end];
        if line.starts_with(b"\x20\x20\x20\x20\x20\x20\x20")
            && !line.is_empty()
            && line[line.len() - 1] != 0x20
            && line[line.len() - 1] != 0x00
        {
            let username = &line[line.iter().rposition(|&b| b == 0x20).map_or(0, |i| i + 1)..];
            let hash = data.get(offset + 16..offset + 16 + 20).unwrap_or(&[]);
            if entropy(hash) < 2.5 {
                offset += 16;
                continue;
            }
            let username = String::from_utf8_lossy(username).to_string();
            out.push(HashLine::new(
                username.clone(),
                format!("{username}:{{SHA}}{}", hex::encode(hash)),
            ));
        }
        offset += 16;
    }
    Ok(out)
}

/// Shannon entropy of a byte string (bits per byte).
fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_basics() {
        assert_eq!(entropy(b""), 0.0);
        assert_eq!(entropy(b"aaaa"), 0.0);
        // 16 distinct bytes -> 4 bits each
        let distinct: Vec<u8> = (0u8..16).collect();
        assert!((entropy(&distinct) - 4.0).abs() < 1e-9);
    }
}
