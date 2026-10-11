//! iOS iTunes backup `Manifest.plist` hash extractor, emitting
//! `$itunes_backup$` hash lines. The binary plist is pattern-scanned for the
//! key markers `SALT`, `ITER`, `WPKY` (and optionally `DPIC`, `DPSL` for iOS
//! 10.2+), where each marker is followed by a 4-byte big-endian length and
//! the value. Order is assumed salt → iter → wpky, all within a 256-byte
//! distance.
//!
//! Output:
//! - `$itunes_backup$*9*<wpky hex>*<iter>*<salt hex>**` (iOS < 10.2)
//! - `$itunes_backup$*10*<wpky>*<iter>*<salt>*<dpic>*<dpsl>` (iOS 10.2+)

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct ItunesBackup;

const MAX_PLIST_SEARCH_DISTANCE: usize = 256;

impl Extractor for ItunesBackup {
    fn name(&self) -> &'static str {
        "itunes_backup"
    }

    fn description(&self) -> &'static str {
        "iTunes backup Manifest.plist files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"bplist00")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < 24 {
            return Ok(Vec::new());
        }

        // scan salt → iter → wpky (assumed order)
        let mut wpky: Option<Vec<u8>> = None;
        let mut salt: Option<Vec<u8>> = None;
        let mut iterations: Option<u32> = None;

        let mut start = 0usize;
        while let Some(idx_salt) = find_from(data, b"SALT", start) {
            let Some(idx_iter) = find_from(data, b"ITER", idx_salt + 1) else {
                break;
            };
            let Some(idx_wpky) = find_from(data, b"WPKY", idx_iter + 1) else {
                break;
            };
            if data.len() - idx_wpky < 8 {
                break; // too close to EOF
            }
            if idx_wpky - idx_salt < MAX_PLIST_SEARCH_DISTANCE {
                salt = Some(read_typed_value(data, idx_salt));
                iterations = Some(u32::from_be_bytes(
                    read_typed_value(data, idx_iter)
                        .as_slice()
                        .try_into()
                        .unwrap_or([0; 4]),
                ));
                wpky = Some(read_typed_value(data, idx_wpky));
                break;
            }
            start = idx_wpky + 1;
        }

        // optional DPIC / DPSL (iOS 10.2+): DPIC is located first, and the
        // DPSL value must follow it
        let mut dpic: Option<u32> = None;
        let mut dpsl: Option<Vec<u8>> = None;
        let mut start = 0usize;
        while let Some(idx_dpic) = find_from(data, b"DPIC", start) {
            let Some(idx_dpsl) = find_from(data, b"DPSL", idx_dpic + 1) else {
                break;
            };
            if idx_dpsl - idx_dpic < MAX_PLIST_SEARCH_DISTANCE {
                dpic = Some(u32::from_be_bytes(
                    read_typed_value(data, idx_dpic)
                        .as_slice()
                        .try_into()
                        .unwrap_or([0; 4]),
                ));
                dpsl = Some(read_typed_value(data, idx_dpsl));
                break;
            }
            start = idx_dpsl + 1;
        }

        let (Some(wpky), Some(salt), Some(iterations)) = (wpky, salt, iterations) else {
            // required markers not found: no output
            return Ok(Vec::new());
        };
        if wpky.len() != 40 {
            return Ok(Vec::new()); // WPKY must be exactly 40 bytes
        }
        if salt.len() != 20 {
            return Ok(Vec::new()); // SALT must be exactly 20 bytes
        }

        let line = if let Some(dpsl) = dpsl {
            let dpic = dpic.unwrap_or(0);
            if dpic == 0 {
                return Ok(Vec::new()); // invalid DPIC
            }
            if dpsl.len() != 20 {
                return Ok(Vec::new()); // DPSL must be exactly 20 bytes
            }
            format!(
                "$itunes_backup$*10*{}*{iterations}*{}*{dpic}*{}",
                hex::encode(wpky),
                hex::encode(salt),
                hex::encode(dpsl)
            )
        } else {
            format!(
                "$itunes_backup$*9*{}*{iterations}*{}**",
                hex::encode(wpky),
                hex::encode(salt)
            )
        };
        Ok(vec![HashLine::new(String::new(), line)])
    }
}

/// First occurrence of `marker` at or after `from`.
fn find_from(data: &[u8], marker: &[u8], from: usize) -> Option<usize> {
    if from > data.len() {
        return None;
    }
    crate::util::find(&data[from..], marker).map(|p| p + from)
}

/// A typed plist field: 4-byte BE length after the 4-byte marker, then the
/// value bytes.
fn read_typed_value(data: &[u8], marker_idx: usize) -> Vec<u8> {
    let len_pos = marker_idx + 4;
    if len_pos + 4 > data.len() {
        return Vec::new();
    }
    let len = u32::from_be_bytes(data[len_pos..len_pos + 4].try_into().expect("4")) as usize;
    let start = marker_idx + 8;
    data.get(start..(start + len).min(data.len()))
        .unwrap_or(&[])
        .to_vec()
}
