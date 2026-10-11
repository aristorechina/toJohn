//! Extracts `$racf$` hashes from IBM RACF databases (z/OS user-profile
//! records, EBCDIC-encoded).
//!
//! The database is scanned for base user-profile signatures (`BASE    ` in
//! EBCDIC). Each matching record's profile segment is searched for the
//! password verifier fields: the legacy DES field (8 bytes) or the KDFAES
//! extended field (40 bytes, emitted together with the DES verifier that
//! follows it). Usernames are rendered through the EBCDIC→ASCII byte
//! mapping that the `$racf$` hash convention is built on — note that this
//! mapping renders `TESTUSR` as `MELMNLK`, and hash hex is uppercase.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Racf;

/// EBCDIC-to-ASCII byte mapping used by the `$racf$` username convention.
#[rustfmt::skip]
const EBCDIC_TO_ASCII: [u8; 256] = [
    0,  1,  2,  3,156,  9,134,127,151,141,142, 11, 12, 13, 14, 15,
    16, 17, 18, 19,157,133,  8,135, 24, 25,146,143, 28, 29, 30, 31,
    128,129,130,131,132, 10, 23, 27,136,137,138,139,140,  5,  6,  7,
    144,145, 22,147,148,149,150,  4,152,153,154,155, 20, 21,158, 26,
    32,160,161,162,163,164,165,166,167,168, 91, 46, 60, 40, 43, 33,
    38,169,170,171,172,173,174,175,176,177, 93, 36, 42, 41, 59, 94,
    45, 47,178,179,180,181,182,183,184,185,124, 44, 37, 95, 62, 63,
    186,187,188,189,190,191,192,193,194, 96, 58, 35, 64, 39, 61, 34,
    195, 97, 98, 99,100,101,102,103,104,105,196,197,198,199,200,201,
    202,106,107,108,109,110,111,112,113,114,203,204,205,206,207,208,
    209,126,115,116,117,118,119,120,121,122,210,211,212,213,214,215,
    216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,
    123, 65, 66, 67, 68, 69, 70, 71, 72, 73,232,233,234,235,236,237,
    125, 74, 75, 76, 77, 78, 79, 80, 81, 82,238,239,240,241,242,243,
    92,159, 83, 84, 85, 86, 87, 88, 89, 90,244,245,246,247,248,249,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57,250,251,252,253,254,255,
];

/// `BASE    ` in EBCDIC — the signature that introduces a base user
/// profile.
const BASE_PROFILE_SIGNATURE: [u8; 8] = [0xC2, 0xC1, 0xE2, 0xC5, 0x40, 0x40, 0x40, 0x40];

/// Segment-data marker identifying a user profile record.
const USER_SEGMENT_DATA_TYPE: u8 = 0x02;

/// Password verifier field IDs within a user profile segment.
const DES_PASSWORD_FIELD: u8 = 12;
const KDFAES_PASSWORD_FIELD: u8 = 100;

/// Layout of a base user profile relative to the signature: the record
/// header starts this many bytes before the signature's first byte.
const RECORD_HEADER_BEFORE_SIGNATURE: usize = 9;
/// The profile name follows the signature plus this many layout bytes.
const PROFILE_NAME_AFTER_SIGNATURE: usize = 11;

impl Extractor for Racf {
    fn name(&self) -> &'static str {
        "racf"
    }

    fn description(&self) -> &'static str {
        "IBM RACF binary database files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.len() > 16 && input.data.windows(4).any(|w| w == [0xC2, 0xC1, 0xE2, 0xC5])
        // "BASE"
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let buffer = &input.data;
        let mut hashes = Vec::new();

        let mut scan_from = 0usize;
        while let Some(offset) = find_signature(buffer, scan_from) {
            scan_from = offset + 1;
            // tail[0..3] = three layout bytes after the signature: a zero,
            // the profile-name length (< 9), another zero.
            let Some(tail) = buffer.get(offset + 8..) else {
                continue;
            };
            if tail.len() < 3 || tail[0] != 0 || tail[2] != 0 || tail[1] > 8 {
                continue;
            }
            if offset < RECORD_HEADER_BEFORE_SIGNATURE {
                continue;
            }
            // Record length sits in the two bytes before the signature.
            let record_len = u16::from_be_bytes([buffer[offset - 2], buffer[offset - 1]]) as usize;
            let name_len = tail[1] as usize;
            let profile_name = &tail[3..3 + name_len];
            // Profile segment = record header + fixed layout + name.
            let profile_offset = name_len + 20;
            if record_len < profile_offset {
                continue;
            }
            let profile_len = record_len - profile_offset;
            let Some(profile) = buffer.get(offset + PROFILE_NAME_AFTER_SIGNATURE + name_len..)
            else {
                continue;
            };
            if profile.first() == Some(&USER_SEGMENT_DATA_TYPE) {
                extract_password_verifier(profile, profile_len, profile_name, &mut hashes);
            }
        }
        Ok(hashes)
    }
}

fn find_signature(buffer: &[u8], from: usize) -> Option<usize> {
    if from >= buffer.len() {
        return None;
    }
    buffer[from..]
        .windows(BASE_PROFILE_SIGNATURE.len())
        .position(|w| w == BASE_PROFILE_SIGNATURE)
        .map(|i| from + i)
}

/// Locate the DES (8-byte) and KDFAES (40-byte) password verifier fields
/// in a user profile segment and emit at most one `$racf$` line.
///
/// Field entries are `id` byte + length; a repeating entry marks its
/// length byte with the high bit and carries a 32-bit length instead.
fn extract_password_verifier(
    profile: &[u8],
    profile_len: usize,
    name: &[u8],
    out: &mut Vec<HashLine>,
) {
    let mut des_hash: Option<&[u8]> = None;
    let mut kdfaes_hash: Option<&[u8]> = None;

    let mut pos = 0usize;
    let mut repeating = false;
    while pos < profile_len && pos + 1 < profile.len() {
        let field_id = profile[pos];
        let mut field_len = profile[pos + 1] as u16;

        if field_len >> 7 == 1 {
            if pos + 5 >= profile.len() {
                break;
            }
            // 32-bit repeating-entry length; the format only honors the
            // low 16 bits of it.
            field_len = u16::from_be_bytes([profile[pos + 3], profile[pos + 4]]);
            repeating = true;
        }

        if !repeating && field_id == DES_PASSWORD_FIELD {
            if field_len == 8 {
                if let Some(hash) = profile.get(pos + 2..pos + 2 + 8) {
                    des_hash = Some(hash);
                }
            }
        } else if !repeating && field_id == KDFAES_PASSWORD_FIELD && field_len == 40 {
            if let Some(hash) = profile.get(pos + 2..pos + 2 + 40) {
                kdfaes_hash = Some(hash);
            }
        }

        if repeating {
            pos += field_len as usize + 5;
            repeating = false;
        } else {
            pos += field_len as usize + 2;
        }
    }

    let username: String = name
        .iter()
        .take_while(|&&b| b != 0x02)
        .map(|&b| EBCDIC_TO_ASCII[b as usize] as char)
        .collect();
    if let Some(kdfaes) = kdfaes_hash {
        let mut line = format!("{username}:$racf$*{username}*");
        line.push_str(&hex_upper(kdfaes));
        line.push_str(&hex_upper(des_hash.unwrap_or(&[])));
        out.push(HashLine::new(username.clone(), line));
    } else if let Some(des) = des_hash {
        let line = format!("{username}:$racf$*{username}*{}", hex_upper(des));
        out.push(HashLine::new(username.clone(), line));
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}
