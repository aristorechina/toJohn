//! Sliding-window scan for PGP SDA headers (`PGPSDA`) at the end of
//! self-decrypting archives. An informational note line about the archive
//! parameters (compressed length, file count, iterations) is emitted before
//! each `$pgpsda$` hash line.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Pgpsda;

/// Fixed size of one PGPSDA header record: 6-byte magic, u32 archive offset,
/// two u64 length fields, 8-byte salt, u16 iteration count, 8 check bytes.
const FMT_SIZE: usize = 44;

impl Extractor for Pgpsda {
    fn name(&self) -> &'static str {
        "pgpsda"
    }

    fn description(&self) -> &'static str {
        "PGP Self-Decrypting Archive (SDA) files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"PGPSDA").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < FMT_SIZE {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for offset in 0..=(data.len() - FMT_SIZE) {
            let window = &data[offset..offset + FMT_SIZE];
            if &window[0..6] != b"PGPSDA" {
                continue;
            }
            let archive_offset = u32::from_le_bytes(window[6..10].try_into().expect("4 bytes"));
            if archive_offset as usize >= data.len() {
                continue;
            }
            let file_count = u64::from_le_bytes(window[18..26].try_into().expect("8 bytes"));
            let compressed_length = u64::from_le_bytes(window[10..18].try_into().expect("8 bytes"));
            let salt = &window[26..34];
            let iterations = u16::from_le_bytes(window[34..36].try_into().expect("2 bytes"));
            let check_bytes = &window[36..44];
            let label = util::basename(input.label());
            out.push(HashLine::new(
                label.to_string(),
                format!(
                    "The following hash is for an SDA archive with compressed length = \
{compressed_length}, number of files = {file_count}, iterations = {iterations}. \
Make sure that these values sound correct!\n"
                ),
            ));
            // the note above is emitted as its own output line
            out.push(HashLine::new(
                label.to_string(),
                format!(
                    "{label}:$pgpsda$0*{iterations}*{}*{}",
                    hex::encode(salt),
                    hex::encode(check_bytes)
                ),
            ));
        }
        Ok(out)
    }
}
