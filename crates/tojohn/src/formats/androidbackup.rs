//! Android Backup `.ab` file parser: reads the header (magic, version,
//! compression flag, algorithm, salts, rounds, IV, master-key blob) and
//! emits `$ab$` lines.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct AndroidBackup;

// The magic line is compared without its trailing newline; util::lines()
// already strips the newline.
const MAGIC: &[u8] = b"ANDROID BACKUP";
const ENCRYPTION_ALGORITHM: &[u8] = b"AES-256";

impl Extractor for AndroidBackup {
    fn name(&self) -> &'static str {
        "androidbackup"
    }

    fn description(&self) -> &'static str {
        "Android Backup .ab files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(MAGIC)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let all: Vec<&[u8]> = util::lines(&input.data).collect();
        let mut index = 0;

        // Skip lines until the magic; a blank line or EOF first produces no
        // output.
        let mut magic_found = false;
        while index < all.len() {
            let line = all[index];
            index += 1;
            if line == MAGIC {
                magic_found = true;
                break;
            }
            if line.is_empty() {
                break;
            }
        }
        if !magic_found {
            // magic line missing: produce no output
            return Ok(Vec::new());
        }

        let Some(version) = parse_int_line(take(&all, &mut index)) else {
            return Ok(Vec::new());
        };
        if !(1..=5).contains(&version) {
            return Ok(Vec::new());
        }
        let Some(_is_compressed) = parse_int_line(take(&all, &mut index)) else {
            return Ok(Vec::new());
        };
        let algorithm = util::strip(take(&all, &mut index));
        if algorithm != ENCRYPTION_ALGORITHM {
            return Ok(Vec::new());
        }
        let user_salt = util::strip(take(&all, &mut index)).to_ascii_lowercase();
        let user_salt = String::from_utf8_lossy(&user_salt);
        let checksum_salt = util::strip(take(&all, &mut index)).to_ascii_lowercase();
        let checksum_salt = String::from_utf8_lossy(&checksum_salt);
        let Some(rounds) = parse_int_line(take(&all, &mut index)) else {
            return Ok(Vec::new());
        };
        let user_iv = util::strip(take(&all, &mut index)).to_ascii_lowercase();
        let user_iv = String::from_utf8_lossy(&user_iv);
        let master_key_blob = util::strip(take(&all, &mut index)).to_ascii_lowercase();
        let master_key_blob = String::from_utf8_lossy(&master_key_blob);

        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$ab${version}*0*{rounds}*{user_salt}*{checksum_salt}*{user_iv}*{master_key_blob}"
            ),
        )])
    }
}

fn take<'a>(all: &'a [&'a [u8]], index: &mut usize) -> &'a [u8] {
    let line = all.get(*index).copied().unwrap_or(&[]);
    *index += 1;
    line
}

/// Integer parse of a header line; surrounding whitespace is allowed.
fn parse_int_line(line: &[u8]) -> Option<i64> {
    std::str::from_utf8(util::strip(line))
        .ok()?
        .parse::<i64>()
        .ok()
}
