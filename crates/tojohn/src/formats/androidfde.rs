//! Android FDE (full-disk encryption) parser: emits `$fde$` lines from the
//! footer partition's `crypt_mnt_ftr` structure (magic scan, key, salt).
//! Two inputs are required: the data partition (primary input, its path
//! becomes the label) and the footer partition (`input.extra_files[0]`).

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct AndroidFde;

/// `crypt_mnt_ftr` magic, 0xD0B5B1C4 stored little-endian.
const CRYPT_MNT_MAGIC_LE: &[u8] = b"\xC4\xB1\xB5\xD0";
/// Size of the fixed `crypt_mnt_ftr` prefix up to the key material.
const STRUCT_SIZE: usize = 4 + 2 + 2 + 4 + 4 + 4 + 4 + 8 + 4 + 64;
/// KDF salt length stored after the key material.
const SALT_LEN: usize = 16;
/// Padding bytes between the key material and the KDF salt.
const KEY_TO_SALT_PADDING: usize = 32;

impl Extractor for AndroidFde {
    fn name(&self) -> &'static str {
        "androidfde"
    }

    fn description(&self) -> &'static str {
        "Android FDE images (data partition + footer partition as extra file)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.len() >= STRUCT_SIZE && input.data[..4] == *CRYPT_MNT_MAGIC_LE
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Some(footer_file) = input.extra_files.first() else {
            return Err(Error::other(
                "androidfde: footer partition required as extra file",
            ));
        };
        // only the first 3 sectors of the data partition are embedded
        let data = &input.data[..(512 * 3).min(input.data.len())];
        let footer_data = &footer_file.data;

        // Scan for the magic; the footer must hold at least a full header.
        let Some(footer_offset) = footer_data
            .windows(STRUCT_SIZE)
            .position(|window| window[..4] == *CRYPT_MNT_MAGIC_LE)
        else {
            // footer magic not found: produce no output
            return Ok(Vec::new());
        };
        let footer = &footer_data[footer_offset..];
        let ftr_size = u32::from_le_bytes(footer[8..12].try_into().expect("4 bytes")) as usize;
        let keysize = u32::from_le_bytes(footer[16..20].try_into().expect("4 bytes")) as usize;
        // The remaining fixed header fields (versions, flags, fs_size, ...)
        // are covered by STRUCT_SIZE.

        let mut offset = footer_offset + STRUCT_SIZE;
        if ftr_size > STRUCT_SIZE {
            offset += ftr_size - STRUCT_SIZE;
        }
        let key = footer_data
            .get(offset..(offset + keysize).min(footer_data.len()))
            .unwrap_or(&[]);
        let offset = offset + key.len() + KEY_TO_SALT_PADDING;
        let salt = footer_data
            .get(offset..(offset + SALT_LEN).min(footer_data.len()))
            .unwrap_or(&[]);

        let label = input.label();
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$fde${}${}${}${}${}",
                salt.len(),
                hex::encode(salt),
                keysize,
                hex::encode(key),
                hex::encode(data)
            ),
        )])
    }
}
