//! Parses OpenBSD softraid crypto metadata (magic `marcCRAM`): validates
//! the RAID type, optional header and encryption type, then emits an
//! `$openbsd-softraid$` line from the KDF parameters and masked keys.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct OpenbsdSoftraid;

impl Extractor for OpenbsdSoftraid {
    fn name(&self) -> &'static str {
        "openbsd_softraid"
    }

    fn description(&self) -> &'static str {
        "OpenBSD softraid crypto volumes"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"marcCRAM").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        // scan a bounded window covering the metadata area
        let mut headers = &input.data[..(0xaa0 + 81920).min(input.data.len())];
        if let Some(start) = util::find(headers, b"marcCRAM") {
            headers = &headers[start..];
        }
        if headers.len() < 2696 {
            return Ok(Vec::new());
        }
        if &headers[0..8] != b"marcCRAM" {
            return Ok(Vec::new()); // wrong magic
        }
        if &headers[72..81] != b"SR CRYPTO" {
            return Ok(Vec::new()); // wrong RAID type
        }
        if headers[260] != 0x01 {
            return Ok(Vec::new()); // wrong optional header type
        }
        if headers[284] != 0x02 {
            return Ok(Vec::new()); // wrong encryption type
        }
        let kdf_type = u32::from_le_bytes(headers[2416..2420].try_into().expect("4 bytes"));
        if kdf_type != 1 && kdf_type != 3 {
            return Ok(Vec::new()); // unsupported kdf type
        }
        let num_iterations = u32::from_le_bytes(headers[2420..2424].try_into().expect("4 bytes"));
        // KDF salt, masked keys area and trailing HMAC
        let salt = hex::encode(&headers[2424..2552]);
        let masked_keys = hex::encode(&headers[364..2412]);
        let hmac = hex::encode(&headers[2676..2696]);
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$openbsd-softraid${num_iterations}${salt}${masked_keys}${hmac}${kdf_type}"
            ),
        )])
    }
}
