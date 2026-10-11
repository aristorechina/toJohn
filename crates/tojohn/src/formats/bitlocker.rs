//! Extracts `$bitlocker$` hashes from BitLocker-encrypted disk images.
//!
//! The image is scanned for the `-FVE-FS-` full-volume-encryption
//! signature and for VMK (Volume Master Key) entries; the salt, nonce,
//! MAC and encrypted VMK material is captured for the two protector types
//! that map to a passphrase: User Password (`$bitlocker$0/1$`) and
//! Recovery Password (`$bitlocker$2/3$`).
//!
//! Progress lines (`Salt:`, `UP Nonce:`, `RP VMK:`, ...) are interleaved
//! with the hash lines — they are part of this extractor's stdout
//! contract.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Bitlocker;

const SALT_SIZE: usize = 16;
const MAC_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const VMK_SIZE: usize = 44;

/// Full-volume-encryption signature.
const FVE_SIGNATURE: &[u8; 8] = b"-FVE-FS-";
/// VMK entry marker: version 2, entry type 0x0008.
const VMK_ENTRY_MARKER: [u8; 4] = [0x02, 0x00, 0x08, 0x00];
/// AES-CCM value-type marker that guards the encrypted VMK material.
const AES_CCM_VALUE_TYPE: [u8; 2] = [0x00, 0x05];
/// Key-protection types carried by a VMK entry.
const PROTECTION_RECOVERY_PASSWORD: [u8; 2] = [0x00, 0x08];
const PROTECTION_USER_PASSWORD: [u8; 2] = [0x00, 0x20];
/// Bytes to search past a signature for its VMK entry.
const PROTECTION_SEARCH_WINDOW: i64 = 0x400;
/// Recovery-protector salt candidate offsets, tried in order.
const SALT_CANDIDATE_OFFSETS: [usize; 2] = [12, 32];
/// Offset of the AES-CCM marker past the end of each salt candidate.
const AES_CCM_MARKER_OFFSET: usize = 147;

/// Salt/nonce/MAC/encrypted-VMK material captured for one protector.
struct ProtectorMaterial {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    mac: Vec<u8>,
    vmk: Vec<u8>,
}

impl ProtectorMaterial {
    fn zeroed() -> Self {
        Self {
            salt: vec![0; SALT_SIZE],
            nonce: vec![0; NONCE_SIZE],
            mac: vec![0; MAC_SIZE],
            vmk: vec![0; VMK_SIZE],
        }
    }
}

/// Per-image extraction state.
struct State {
    user: ProtectorMaterial,
    recovery: ProtectorMaterial,
    user_found: bool,
    recovery_found: bool,
}

impl State {
    fn new() -> Self {
        Self {
            user: ProtectorMaterial::zeroed(),
            recovery: ProtectorMaterial::zeroed(),
            user_found: false,
            recovery_found: false,
        }
    }
}

/// Read one byte; past EOF this yields 0xff, matching the
/// unsigned-char-EOF semantics the `$bitlocker$` scanner relies on.
fn read_byte(data: &[u8], pos: &mut usize) -> u8 {
    let byte = data.get(*pos).copied().unwrap_or(0xff);
    *pos += 1;
    byte
}

/// Fill `buf` with consecutive bytes; reads past EOF yield 0xff.
fn read_into(data: &[u8], pos: &mut usize, buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = read_byte(data, pos);
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Extractor for Bitlocker {
    fn name(&self) -> &'static str {
        "bitlocker"
    }

    fn description(&self) -> &'static str {
        "BitLocker encrypted disk images"
    }

    fn accepts(&self, input: &Input) -> bool {
        crate::util::find(&input.data, FVE_SIGNATURE).is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let mut st = State::new();
        let mut lines: Vec<String> = Vec::new();

        let file_len = data.len();
        lines.push(format!(
            "Encrypted device {} opened, size {}MB",
            input.label(),
            (file_len / 1024) / 1024
        ));

        let mut pos = 0usize;
        let mut match_left: i64 = 0;
        // Carries the last signature byte into the VMK-entry check: the
        // entry marker starts inside the signature scan.
        let mut last_byte: u8 = 0;

        for _ in 0..file_len {
            let mut matched = 0usize;
            while matched < FVE_SIGNATURE.len() {
                last_byte = read_byte(data, &mut pos);
                if last_byte != FVE_SIGNATURE[matched] {
                    break;
                }
                matched += 1;
            }
            if matched == FVE_SIGNATURE.len() {
                match_left = PROTECTION_SEARCH_WINDOW;
                pos += 2;
                let version = read_byte(data, &mut pos);
                if version != 1 && version != 2 {
                    // invalid version: reset and keep scanning
                    match_left = 0;
                }
                continue;
            }
            if match_left <= 0 {
                continue;
            }
            match_left -= matched as i64 + 1;

            // VMK-entry check: the first marker byte is `last_byte` from
            // the signature scan above.
            let mut is_entry = true;
            for (k, &expected) in VMK_ENTRY_MARKER.iter().enumerate() {
                if k > 0 {
                    last_byte = read_byte(data, &mut pos);
                    match_left -= 1;
                }
                if last_byte != expected {
                    is_entry = false;
                    break;
                }
            }
            if !is_entry {
                continue;
            }

            // VMK entry: skip 28 bytes, then read the 2-byte protection type
            pos += 28;
            let protection_type = [read_byte(data, &mut pos), read_byte(data, &mut pos)];

            if protection_type == PROTECTION_RECOVERY_PASSWORD && !st.recovery_found {
                if search_recovery_material(data, &mut pos, &mut st, &mut lines) {
                    read_into(data, &mut pos, &mut st.recovery.nonce);
                    lines.push(format!("RP Nonce: {}", hex_lower(&st.recovery.nonce)));
                    read_into(data, &mut pos, &mut st.recovery.mac);
                    lines.push(format!("RP MAC: {}", hex_lower(&st.recovery.mac)));
                    read_into(data, &mut pos, &mut st.recovery.vmk);
                    lines.push(format!("RP VMK: {}", hex_lower(&st.recovery.vmk)));
                    lines.push(String::new());
                    st.recovery_found = true;
                    if st.user_found {
                        break;
                    }
                }
            } else if protection_type == PROTECTION_USER_PASSWORD && !st.user_found {
                pos += 12;
                read_into(data, &mut pos, &mut st.user.salt);
                pos += 83;
                // The two marker bytes are consumed with short-circuit
                // semantics: the second is only read when the first matches.
                let first = read_byte(data, &mut pos);
                let marker_ok = first == AES_CCM_VALUE_TYPE[0]
                    && read_byte(data, &mut pos) == AES_CCM_VALUE_TYPE[1];
                if !marker_ok {
                    continue;
                }
                pos += 3;
                read_into(data, &mut pos, &mut st.user.nonce);
                lines.push(format!("UP Nonce: {}", hex_lower(&st.user.nonce)));
                read_into(data, &mut pos, &mut st.user.mac);
                lines.push(format!("UP MAC: {}", hex_lower(&st.user.mac)));
                read_into(data, &mut pos, &mut st.user.vmk);
                lines.push(format!("UP VMK: {}", hex_lower(&st.user.vmk)));
                lines.push(String::new());
                st.user_found = true;
                if st.recovery_found {
                    break;
                }
            }
        }

        if !st.user_found && !st.recovery_found {
            return Err(Error::malformed(
                input.label(),
                "no VMK entries with a password protector were found",
            ));
        }

        let mut out: Vec<HashLine> = Vec::new();
        if st.user_found {
            lines.push(String::new());
            lines.push("User Password hash:".to_string());
            for ty in [0, 1] {
                lines.push(format!(
                    "$bitlocker${ty}$16${}$1048576$12${}$60${}{}",
                    hex_lower(&st.user.salt),
                    hex_lower(&st.user.nonce),
                    hex_lower(&st.user.mac),
                    hex_lower(&st.user.vmk)
                ));
                if ty == 0 {
                    lines.push(
                        "Hash type: User Password with MAC verification (slower solution, no false positives)"
                            .to_string(),
                    );
                }
            }
        }
        if st.recovery_found {
            lines.push("Hash type: Recovery Password fast attack".to_string());
            for ty in [2, 3] {
                lines.push(format!(
                    "$bitlocker${ty}$16${}$1048576$12${}$60${}{}",
                    hex_lower(&st.recovery.salt),
                    hex_lower(&st.recovery.nonce),
                    hex_lower(&st.recovery.mac),
                    hex_lower(&st.recovery.vmk)
                ));
                if ty == 2 {
                    lines.push(
                        "Hash type: Recovery Password with MAC verification (slower solution, no false positives)"
                            .to_string(),
                    );
                }
            }
        }
        for line in lines {
            out.push(HashLine::new(String::new(), line));
        }
        Ok(out)
    }
}

/// Locate the recovery-protector material: try the salt candidates in
/// order, and for each candidate check for the AES-CCM marker 147 bytes
/// past the salt. The `Salt:` progress line is emitted for every attempt.
/// Returns true when a marker was found, with `pos` left just past it.
fn search_recovery_material(
    data: &[u8],
    pos: &mut usize,
    st: &mut State,
    lines: &mut Vec<String>,
) -> bool {
    let base_pos = *pos;
    for (attempt, &salt_offset) in SALT_CANDIDATE_OFFSETS.iter().enumerate() {
        *pos = base_pos + salt_offset;
        read_into(data, pos, &mut st.recovery.salt);
        lines.push(format!("Salt: {}", hex_lower(&st.recovery.salt)));

        *pos += AES_CCM_MARKER_OFFSET;
        let first = read_byte(data, pos);
        let second = read_byte(data, pos);
        if first == AES_CCM_VALUE_TYPE[0] && second == AES_CCM_VALUE_TYPE[1] {
            *pos += 3;
            return true;
        } else if attempt == 0 {
            // rewind so the second candidate is relative to the same spot
            *pos = base_pos;
        }
    }
    false
}
