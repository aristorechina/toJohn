//! Gnome Keyring hash extractor: reads the header fields (salt, iterations,
//! crypto size, hash value) and emits `$keyring$` hash lines.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Keyring;

/// File magic `GnomeKeyring\n\r\0\n`.
const HEADER: &[u8] = b"GnomeKeyring\n\r\0\n";

impl Extractor for Keyring {
    fn name(&self) -> &'static str {
        "keyring"
    }

    fn description(&self) -> &'static str {
        "Gnome Keyring files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(HEADER)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if !data.starts_with(HEADER) {
            return Err(Error::not_format("GNOME Keyring", input.label()));
        }
        let mut pos = HEADER.len(); // 16
        let read =
            |offset: usize, len: usize| -> &[u8] { &data[offset..(offset + len).min(data.len())] };
        // version 2, crypto 1, hash_t 1
        pos += 4;
        let name_length = be_u32(read(pos, 4)) as usize;
        pos += 4;
        pos += name_length; // name
        pos += 8 + 8; // ctime, mtime
        pos += 4; // flags
        pos += 4; // lock_timeout
        let iterations = be_u32(read(pos, 4));
        pos += 4;
        let salt = hex::encode(read(pos, 8));
        pos += 8;
        pos += 16; // reserved
        let _num_items = be_u32(read(pos, 4)); // 8-byte field, low 4 used
        pos += 8;
        let hash_value = hex::encode(read(pos, 16));
        let crypto_size = hash_value.len() / 2;

        Ok(vec![HashLine::new(
            input.label().to_string(),
            format!(
                "{}:$keyring${}*{}*{}*0*{}",
                input.label(),
                salt,
                iterations,
                crypto_size,
                hash_value
            ),
        )])
    }
}

fn be_u32(bytes: &[u8]) -> u32 {
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    u32::from_be_bytes(out)
}
