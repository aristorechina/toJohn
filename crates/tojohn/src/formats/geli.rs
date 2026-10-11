//! FreeBSD geli hash extractor: parses g_eli metadata (the last 1 KiB of a
//! disk image, magic `GEOM::ELI`) into `$geli$` hash lines. Supports
//! metadata v0..v7; the v0 layout lacks the `md_aalgo` field, so the value
//! read at the v1..v7 offset is kept.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Geli;

/// Metadata magic `GEOM::ELI`, located in the last 1 KiB of the image.
const G_ELI_MAGIC: &[u8] = b"GEOM::ELI";

/// Total metadata size for version 0 (no `md_aalgo` field).
const V0_SIZE: usize = 495;

impl Extractor for Geli {
    fn name(&self) -> &'static str {
        "geli"
    }

    fn description(&self) -> &'static str {
        "FreeBSD GELI encrypted disk images"
    }

    fn accepts(&self, input: &Input) -> bool {
        let tail_start = input.data.len().saturating_sub(1024);
        util::find(&input.data[tail_start..], G_ELI_MAGIC).is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < 1024 {
            // file too short: no output
            return Ok(Vec::new());
        }
        let tail = &data[data.len() - 1024..];
        let Some(start) = util::find(tail, G_ELI_MAGIC) else {
            return Ok(Vec::new()); // magic not found: no output
        };
        let metadata = &tail[start..];

        // GELI v1..v7 layout
        let read_u16 =
            |o: usize| u16::from_le_bytes(metadata[o..o + 2].try_into().expect("2 bytes"));
        let md_version = u32::from_le_bytes(metadata[16..20].try_into().expect("4 bytes"));
        let md_ealgo = read_u16(24);
        let mut md_keylen = read_u16(26);
        let md_aalgo = read_u16(28);
        let mut md_keys = metadata[42];
        let mut md_iterations = i32::from_le_bytes(metadata[43..47].try_into().expect("4 bytes"));
        let mut salt = &metadata[47..47 + 64];
        let mut mkeys = &metadata[111..111 + 384];

        if md_version == 0 {
            // GELI v0 layout (no md_aalgo field; md_aalgo keeps the value
            // read at the v1..v7 offset)
            if metadata.len() < V0_SIZE {
                return Ok(Vec::new());
            }
            md_keylen = read_u16(26);
            md_keys = metadata[40];
            md_iterations = i32::from_le_bytes(metadata[41..45].try_into().expect("4 bytes"));
            salt = &metadata[45..45 + 64];
            mkeys = &metadata[109..109 + 384];
        }

        if md_version > 7 {
            return Ok(Vec::new()); // unsupported metadata version: no output
        }
        // md_ealgo is an opencrypto cipher id; only AES (11) and Camellia
        // (22) are accepted.
        if md_ealgo != 22 && md_ealgo != 11 {
            return Ok(Vec::new()); // unsupported cipher algorithm: no output
        }
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$geli$0${md_version}${md_ealgo}${md_keylen}${md_aalgo}\
${md_keys}${md_iterations}${}${}",
                hex::encode(salt),
                hex::encode(mkeys)
            ),
        )])
    }
}
