//! Mac OS X keychain hash extractor: scans the file backwards for the
//! DbBlob magic (`FA DE 07 11`) and emits `$keychain$` hash lines with
//! salt, IV and ciphertext.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Keychain;

/// DbBlob magic `FA DE 07 11`.
const MAGIC: &[u8] = &[0xfa, 0xde, 0x07, 0x11];
/// DbBlob salt length (bytes).
const SALT_LEN: usize = 20;
/// DbBlob IV length (bytes).
const IV_LEN: usize = 8;
/// DbBlob ciphertext length (bytes).
const CT_LEN: usize = 48;

impl Extractor for Keychain {
    fn name(&self) -> &'static str {
        "keychain"
    }

    fn description(&self) -> &'static str {
        "Mac OS X keychain files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, MAGIC).is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < 4 {
            return Ok(Vec::new());
        }
        // Backwards scan from near EOF, sliding 4 bytes per step.
        let mut found: Option<usize> = None;
        let mut pos = data.len().checked_sub(12);
        while let Some(offset) = pos {
            if offset + 4 > data.len() {
                break;
            }
            if &data[offset..offset + 4] == MAGIC {
                found = Some(offset);
                break;
            }
            if offset < 4 {
                break;
            }
            pos = Some(offset - 4);
        }
        let Some(pos) = found else {
            return Err(Error::other("keychain db key not found"));
        };

        let read_u32 = |o: usize| u32::from_be_bytes(data[o..o + 4].try_into().expect("4 bytes"));
        let ciphertext_offset = read_u32(pos + 8) as usize;
        let salt = data.get(pos + 44..pos + 44 + SALT_LEN).unwrap_or(&[]);
        let iv = data.get(pos + 64..pos + 64 + IV_LEN).unwrap_or(&[]);
        let ciphertext = data
            .get(pos + ciphertext_offset..pos + ciphertext_offset + CT_LEN)
            .unwrap_or(&[]);
        if salt.len() != SALT_LEN || iv.len() != IV_LEN || ciphertext.len() != CT_LEN {
            return Err(Error::malformed(
                input.label(),
                "blob fields could not be read",
            ));
        }

        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$keychain$*{}*{}*{}",
                hex::encode(salt),
                hex::encode(iv),
                hex::encode(ciphertext)
            ),
        )])
    }
}
