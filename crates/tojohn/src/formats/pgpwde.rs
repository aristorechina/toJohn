//! PGP Whole Disk Encryption user record scanner (magic 0x57446900):
//! sliding-window scan for supported user records (kind 0x08), emitting
//! `$pgpwde$` lines with the symmetric algorithm, S2K type, iterations,
//! salt and encrypted secret key.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Pgpwde;

/// Size of a user-record scan window.
const FMT_SIZE: usize = 330;

impl Extractor for Pgpwde {
    fn name(&self) -> &'static str {
        "pgpwde"
    }

    fn description(&self) -> &'static str {
        "PGP WDE / Symantec Encryption Desktop whole disk images"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.len() >= FMT_SIZE && input.data[4..8] == [0x00, 0x69, 0x44, 0x57]
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data[..(1 << 20).min(input.data.len())];
        if data.len() < FMT_SIZE {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for offset in 0..=(data.len() - FMT_SIZE) {
            let window = &data[offset..offset + FMT_SIZE];
            let size = u16::from_le_bytes(window[0..2].try_into().expect("2 bytes"));
            let version = window[2];
            let kind = window[3];
            let magic = u32::from_le_bytes(window[4..8].try_into().expect("4 bytes"));
            let current_record = window[9];
            if size != 512 || version != 0 || magic != 0x57446900 || current_record != 0 {
                continue;
            }
            if kind != 0x08 {
                // skip unsupported user record types
                continue;
            }
            let symmetric_algorithm = window[28];
            let user_name = String::from_utf8_lossy(&window[34..162])
                .trim_matches('\0')
                .to_string();
            let s2k_type = window[162];
            let hash_iterations = u32::from_le_bytes(window[163..167].try_into().expect("4 bytes"));
            let salt = &window[170..186];
            let encrypted_secret_key = &window[186..330];
            let secret_key_hex = hex::encode(encrypted_secret_key);
            let secret_key_hex = &secret_key_hex[..256.min(secret_key_hex.len())];
            out.push(HashLine::new(
                user_name.clone(),
                format!(
                    "{user_name}:$pgpwde$0*{symmetric_algorithm}*{s2k_type}*{hash_iterations}*{}*{secret_key_hex}",
                    hex::encode(salt)
                ),
            ));
        }
        Ok(out)
    }
}
