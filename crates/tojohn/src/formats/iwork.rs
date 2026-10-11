//! Apple iWork hash extractor, emitting `$iwork$` hash lines: 2013+ files
//! (.iwph hint + .iwpv2 verifier in a zip) and iWork '09 files (verifier
//! after the central directory).

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Iwork;

/// Verifier blob size: u16 version + u16 format + u32 iterations + 16-byte
/// salt + 16-byte IV + 64-byte data blob.
const VERIFIER_SIZE: usize = 104;

impl Extractor for Iwork {
    fn name(&self) -> &'static str {
        "iwork"
    }

    fn description(&self) -> &'static str {
        "Apple iWork files (.key)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"PK\x03\x04")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let label = util::basename(input.label());
        let Ok(zf) = crate::zip::ZipArchive::new(data, input.label()) else {
            return Err(Error::not_format("zip", input.label()));
        };
        let mut password_hint: Option<String> = None;
        let mut verifier_data: Option<Vec<u8>> = None;
        let names: Vec<String> = zf.entries().map(|e| e.to_string()).collect();
        for name in &names {
            if name.ends_with(".iwph") {
                let hint_bytes = zf.open(name).unwrap_or_default();
                password_hint = Some(String::from_utf8_lossy(&hint_bytes).to_string());
            }
            if name.ends_with(".iwpv2") {
                verifier_data = zf.open(name);
            }
        }

        let Some(verifier_data) = verifier_data else {
            return self.extract_legacy(input);
        };
        if verifier_data.len() != VERIFIER_SIZE {
            return Err(Error::malformed(
                input.label(),
                "password verifier size mismatch",
            ));
        }
        let version = u16::from_le_bytes(verifier_data[0..2].try_into().expect("2"));
        let format = u16::from_le_bytes(verifier_data[2..4].try_into().expect("2"));
        let iterations = u32::from_le_bytes(verifier_data[4..8].try_into().expect("4"));
        let salt = &verifier_data[8..24];
        let iv = &verifier_data[24..40];
        let datablob = &verifier_data[40..104];
        if version != 2 || format != 1 {
            return Ok(Vec::new()); // unsupported version or format: no output
        }
        let hint = password_hint.unwrap_or_default();
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$iwork$1${version}${format}${iterations}${}${}${}::::{hint} {label}",
                hex::encode(salt),
                hex::encode(iv),
                hex::encode(datablob)
            ),
        )])
    }
}

impl Iwork {
    /// Parser for Apple iWork '09 files.
    fn extract_legacy(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < 0x40 || !data.starts_with(b"PK\x03\x04") {
            return Err(Error::malformed(input.label(), "not a zip"));
        }
        // find end of central directory
        let Some(eocd_pos) = data.windows(4).rposition(|w| w == b"PK\x05\x06") else {
            return Err(Error::malformed(input.label(), "no EOCD"));
        };
        let central_dir_pos =
            u32::from_le_bytes(data[eocd_pos + 16..eocd_pos + 20].try_into().expect("4")) as usize;
        if central_dir_pos + 4 > data.len()
            || &data[central_dir_pos..central_dir_pos + 4] != b"\x50\x4B\x01\x02"
        {
            return Err(Error::malformed(
                input.label(),
                "central directory not found",
            ));
        }
        let entry_size = u32::from_le_bytes(
            data[central_dir_pos + 30..central_dir_pos + 34]
                .try_into()
                .expect("4"),
        );
        if entry_size < 108 {
            return Err(Error::malformed(input.label(), "entry size < 108"));
        }
        let cd_count =
            u16::from_le_bytes(data[eocd_pos + 10..eocd_pos + 12].try_into().expect("2")) as usize;
        let data_offset = central_dir_pos + cd_count * entry_size as usize;
        let s1 = data.get(data_offset + 54..data_offset + 58).unwrap_or(&[]);
        if s1 != b"\x01\x00\x01\x00" {
            return Err(Error::malformed(
                input.label(),
                "unexpected version/format bytes",
            ));
        }
        let version = 1u32;
        let format = 1u32;
        let iterations = u32::from_le_bytes(
            data[data_offset + 58..data_offset + 62]
                .try_into()
                .expect("4"),
        );
        let salt: &[u8] = b"someSalt"; // hardcoded placeholder salt
        let end = (data_offset + 62 + 80).min(data.len());
        let verifier = &data[data_offset + 62..end];
        let iv = &verifier[..16.min(verifier.len())];
        let datablob = &verifier[16.min(verifier.len())..];
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$iwork$2${version}${format}${iterations}${}${}${}::::{label}",
                hex::encode(salt),
                hex::encode(iv),
                hex::encode(datablob)
            ),
        )])
    }
}
