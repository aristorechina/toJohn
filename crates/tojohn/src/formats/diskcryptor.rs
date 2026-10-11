//! DiskCryptor volume header parser: hex-encodes the 2 KiB volume header
//! into a `$diskcryptor$` line. Non-encrypted headers (BOOTMGR/NTFS
//! markers, low entropy) produce no output.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Diskcryptor;

impl Extractor for Diskcryptor {
    fn name(&self) -> &'static str {
        "diskcryptor"
    }

    fn description(&self) -> &'static str {
        "DiskCryptor encrypted volume headers"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false // no pre-entropy cheap check
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let header = &input.data[..2048.min(input.data.len())];
        if util::find(header, b"BOOTMGR").is_some()
            || util::find(header, b"NTFS").is_some()
            || util::find(header, b"disk read").is_some()
        {
            return Ok(Vec::new());
        }
        if entropy(header) < 6.0 {
            // low-entropy header: treated as not encrypted
            return Ok(Vec::new());
        }
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:$diskcryptor$0*{}", hex::encode(header)),
        )])
    }
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
