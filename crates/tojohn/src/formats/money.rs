//! MS Money 2002-2007 / Money Plus file parser: XORs the fixed header mask
//! into the first 4 KiB, then extracts the salt and check bytes into a
//! `$money$` line.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Money;

/// Offset of the 8-byte salt within the decrypted header.
const SALT_OFFSET: usize = 0x72;
/// Start of the check-value area, shifted by the byte stored at SALT_OFFSET.
const CRYPT_CHECK_START: usize = 0x2e9;
/// Offset of the encryption-flags byte in the decrypted header.
const ENCRYPTION_FLAGS_OFFSET: usize = 0x298;
/// Flags bit selecting SHA-1 based check values.
const USE_SHA1: u8 = 0x20;
/// Flags bit marking the newer encryption scheme.
const NEW_ENCRYPTION: u8 = 0x06;
/// Number of header bytes preceding the masked region.
const OFFSET_MASKED_HEADER: usize = 24;

/// Fixed mask XORed into the header bytes (hex-encoded).
const HEADER_MASK: &str = "b56f03626108c255eba96772433f009c7a9f90ff809a31c579baed30bcdfcc9d63d9e4c37b42fb8abc4e86fbec375d449cfac65e28e613b68a6054947b36f572dfb177f41343cfafb1333461795b92b57c2a05f17c99011b98fd124f4a946c3e60265f95f8d089248567c61f2744d2eecf65edff07c746a178160cede92d62d4";

impl Extractor for Money {
    fn name(&self) -> &'static str {
        "money"
    }

    fn description(&self) -> &'static str {
        "MS Money 2002-2007 / Money Plus files"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data[..4096.min(input.data.len())];
        let mut buf = data.to_vec();
        // XOR the fixed header mask into the bytes starting at offset 24
        let mask = hex::decode(HEADER_MASK).unwrap_or_default();
        if buf.len() > OFFSET_MASKED_HEADER {
            for (masked, &mask_byte) in buf[OFFSET_MASKED_HEADER..].iter_mut().zip(&mask) {
                *masked ^= mask_byte;
            }
        }
        if buf.len() <= ENCRYPTION_FLAGS_OFFSET {
            return Ok(Vec::new());
        }
        if buf[ENCRYPTION_FLAGS_OFFSET] & NEW_ENCRYPTION == 0 {
            return Ok(Vec::new());
        }
        let salt = hex::encode(&buf[SALT_OFFSET..SALT_OFFSET + 8]);
        let crypt_check_offset = buf[SALT_OFFSET] as usize;
        let start = CRYPT_CHECK_START + crypt_check_offset;
        if start + 4 > buf.len() {
            return Ok(Vec::new());
        }
        let check = hex::encode(&buf[start..start + 4]);
        let format_type = if buf[ENCRYPTION_FLAGS_OFFSET] & USE_SHA1 != 0 {
            1
        } else {
            0
        };
        let name = util::basename(input.label());
        // format type 0 denotes the old money file format; the hash line is
        // emitted either way.
        Ok(vec![HashLine::new(
            name.to_string(),
            format!("{name}:$money${format_type}*{salt}*{check}"),
        )])
    }
}
