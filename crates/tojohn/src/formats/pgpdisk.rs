//! PGP Virtual Disk (.pgd) parser: locates the `PGPd`/`MAIN` header (magic,
//! algorithm, salt), then follows `nextHeaderOffset` to the `USER`/`SYMM`
//! record for the user name, check bytes and iteration count, emitting
//! `$pgpdisk$` lines.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Pgpdisk;

/// Size of a MAIN header record.
const MAIN_SIZE: usize = 356;
/// Size of a USER/SYMM record.
const USER_SIZE: usize = 312;

impl Extractor for Pgpdisk {
    fn name(&self) -> &'static str {
        "pgpdisk"
    }

    fn description(&self) -> &'static str {
        "PGP Virtual Disk (.pgd) files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"PGPd")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        // the MAIN header is located within the first 4 KiB of the volume
        let data = &input.data[..4096.min(input.data.len())];
        let mut algorithm: u32 = 0;
        let mut salt = String::new();
        let mut next_header_offset: u64 = 0;
        let mut found = false;
        if data.len() >= MAIN_SIZE {
            for offset in 0..=(data.len() - MAIN_SIZE) {
                let window = &data[offset..offset + MAIN_SIZE];
                if &window[0..4] != b"PGPd" || &window[4..8] != b"MAIN" {
                    continue;
                }
                algorithm = u32::from_le_bytes(window[60..64].try_into().expect("4 bytes"));
                if !matches!(algorithm, 3..=7) {
                    // unsupported algorithm: no output
                    return Ok(Vec::new());
                }
                let major_version = window[32];
                if major_version != 7 && major_version != 6 {
                    return Ok(Vec::new()); // untested major version
                }
                salt = hex::encode(&window[64..80]);
                next_header_offset =
                    u64::from_le_bytes(window[16..24].try_into().expect("8 bytes"));
                found = true;
                break;
            }
        }
        if !found {
            return Ok(Vec::new());
        }

        // the USER/SYMM record is searched from nextHeaderOffset, which can
        // point near the end of the volume
        let data = &input.data;
        let start = (next_header_offset as usize).min(data.len());
        // scan at most 1 MiB after the header
        let region = &data[start..(start + (1 << 20)).min(data.len())];
        if region.len() < USER_SIZE {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for offset in 0..=(region.len() - USER_SIZE) {
            let window = &region[offset..offset + USER_SIZE];
            if &window[0..4] != b"USER" || &window[4..8] != b"SYMM" {
                continue;
            }
            let user_name = String::from_utf8_lossy(&window[32..160])
                .trim_end_matches('\0')
                .to_string();
            if algorithm == 3 && window[296..304] != [0u8; 8] {
                // CAST5 requires zero check bytes here; reject the record
                return Err(Error::malformed(
                    input.label(),
                    "cast5 check bytes are not zero",
                ));
            }
            let check_bytes = &window[288..304];
            let iterations = u16::from_le_bytes(window[304..306].try_into().expect("2 bytes"));
            out.push(HashLine::new(
                user_name.clone(),
                format!(
                    "{user_name}:$pgpdisk$0*{algorithm}*{iterations}*{salt}*{}",
                    hex::encode(check_bytes)
                ),
            ));
        }
        Ok(out)
    }
}
