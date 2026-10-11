//! KDE KWallet hash extractor, emitting `$kwallet$` hash lines. Old-format
//! wallets (minor version 0) are handled from the primary input; new-format
//! wallets (minor version 1, PBKDF2-HMAC-SHA512) additionally need the
//! sibling `.salt` file as `input.extra_files[0]`.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Kwallet;

/// Wallet file magic `KWALLET\n\r\0\r\n`.
const KWMAGIC: &[u8] = b"KWALLET\n\r\0\r\n";
/// Length of the wallet file magic.
const KWMAGIC_LEN: usize = 12;

impl Extractor for Kwallet {
    fn name(&self) -> &'static str {
        "kwallet"
    }

    fn description(&self) -> &'static str {
        "KDE KWallet files (new format needs .salt as extra file)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(KWMAGIC)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let label = util::basename(input.label());
        if data.len() < KWMAGIC_LEN + 4 || &data[..KWMAGIC_LEN] != KWMAGIC {
            return Ok(Vec::new()); // bad magic: no output
        }
        let mut pos = KWMAGIC_LEN;
        let major = data[pos];
        let minor = data[pos + 1];
        let cipher = data[pos + 2];
        let hash = data[pos + 3];
        pos += 4;
        if major != 0 {
            return Ok(Vec::new()); // unknown major version: no output
        }
        let is_new_format = minor != 0;
        let minor_version = if is_new_format { minor as i64 } else { -1 };
        if !matches!(cipher, 0 | 3) {
            return Ok(Vec::new()); // unsupported cipher: no output
        }
        if !matches!(hash, 0 | 2) {
            return Ok(Vec::new()); // unsupported hash: no output
        }

        // Read in the hashes
        let read_u32 = |pos: usize| -> u32 {
            u32::from_be_bytes(data[pos..pos + 4].try_into().expect("4 bytes"))
        };
        let entry_count = read_u32(pos);
        if entry_count > 0xffff {
            return Err(Error::other("hash count sanity check failed"));
        }
        pos += 4;
        for _ in 0..entry_count {
            pos += 16;
            let entry_size = read_u32(pos);
            pos += 4;
            pos += entry_size as usize * 16;
        }

        let encrypted = &data[pos..];
        let encrypted_size = encrypted.len();
        if !encrypted_size.is_multiple_of(8) {
            return Err(Error::other("encrypted block size is not a multiple of 8"));
        }

        if is_new_format {
            let salt = input
                .extra_files
                .first()
                .ok_or_else(|| Error::other("kwallet: .salt file required"))?;
            let salt_len = salt.data.len();
            // the new format uses 50000 PBKDF2 iterations
            let iterations: i64 = 50000;
            Ok(vec![HashLine::new(
                label.to_string(),
                format!(
                    "{label}:$kwallet${encrypted_size}${}${minor_version}${salt_len}\
${}${iterations}:::::{label}",
                    hex::encode(encrypted),
                    hex::encode(&salt.data),
                ),
            )])
        } else {
            Ok(vec![HashLine::new(
                label.to_string(),
                format!(
                    "{label}:$kwallet${encrypted_size}${}:::::{label}",
                    hex::encode(encrypted)
                ),
            )])
        }
    }
}
