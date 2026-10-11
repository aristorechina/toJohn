//! Converts hashcat hccap (392 bytes) and hccapx (393 bytes) handshake
//! records into `$WPAPSK$` lines: crypt-base64 over the hccap record tail
//! (from offset 36), lowercase hex MACs, and the source file name as the
//! final field. Unlike the `hccapx` module there is no nonce-correction
//! expansion here.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Hccap;

const HCCAP_LEN: usize = 392;
const HCCAPX_LEN: usize = 393;
/// crypt(3)/crypt-base64 alphabet used by `$WPAPSK$` lines.
const CRYPT_ALPHABET: &[u8; 64] =
    b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// hccap record layout (hashcat hccap format), 392 bytes total.
struct HccapRecord {
    essid: [u8; 36],
    mac_ap: [u8; 6],
    mac_sta: [u8; 6],
    nonce_sta: [u8; 32],
    nonce_ap: [u8; 32],
    eapol: [u8; 256],
    eapol_size: u32,
    keyver: u32,
    keymic: [u8; 16],
}

impl HccapRecord {
    fn parse_hccap(rec: &[u8]) -> Self {
        Self {
            essid: rec[0..36].try_into().expect("36 bytes"),
            mac_ap: rec[36..42].try_into().expect("6 bytes"),
            mac_sta: rec[42..48].try_into().expect("6 bytes"),
            nonce_sta: rec[48..80].try_into().expect("32 bytes"),
            nonce_ap: rec[80..112].try_into().expect("32 bytes"),
            eapol: rec[112..368].try_into().expect("256 bytes"),
            eapol_size: u32::from_le_bytes(rec[368..372].try_into().expect("4 bytes")),
            keyver: u32::from_le_bytes(rec[372..376].try_into().expect("4 bytes")),
            keymic: rec[376..392].try_into().expect("16 bytes"),
        }
    }

    /// Map an hccapx record (393 bytes, little-endian fields) onto the
    /// hccap layout the output is rendered from: the ESSID is
    /// length-prefixed, the nonce order is swapped, and EAPOL is clamped
    /// to 256 bytes.
    fn parse_hccapx(rec: &[u8]) -> Self {
        let essid_len = (rec[9] as usize).min(32);
        let eapol_len =
            (u16::from_le_bytes(rec[135..137].try_into().expect("2 bytes")) as usize).min(256);
        let mut record = Self {
            essid: [0; 36],
            mac_ap: rec[59..65].try_into().expect("6 bytes"),
            mac_sta: rec[97..103].try_into().expect("6 bytes"),
            nonce_sta: rec[103..135].try_into().expect("32 bytes"),
            nonce_ap: rec[65..97].try_into().expect("32 bytes"),
            eapol: [0; 256],
            eapol_size: eapol_len as u32,
            keyver: rec[42] as u32,
            keymic: rec[43..59].try_into().expect("16 bytes"),
        };
        record.essid[..essid_len].copy_from_slice(&rec[10..10 + essid_len]);
        record.eapol[..eapol_len].copy_from_slice(&rec[137..137 + eapol_len]);
        record
    }
}

impl Extractor for Hccap {
    fn name(&self) -> &'static str {
        "hccap"
    }

    fn description(&self) -> &'static str {
        "hashcat hccap / hccapx handshake captures"
    }

    fn accepts(&self, input: &Input) -> bool {
        if input.data.starts_with(b"HCPX") {
            return input.data.len().is_multiple_of(HCCAPX_LEN);
        }
        !input.data.is_empty() && input.data.len().is_multiple_of(HCCAP_LEN)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let is_x = data.starts_with(b"HCPX");
        let file = file_label(input.label());

        let record_len = if is_x && data.len().is_multiple_of(HCCAPX_LEN) {
            HCCAPX_LEN
        } else if data.len().is_multiple_of(HCCAP_LEN) {
            HCCAP_LEN
        } else {
            return Err(Error::malformed(
                input.label(),
                if is_x {
                    "hccapx magic found but file size is not a multiple of the hccapx record size"
                } else {
                    "file size is not a multiple of the hccap record size"
                },
            ));
        };

        let mut out = Vec::new();
        for rec in data.chunks(record_len) {
            let record = if record_len == HCCAPX_LEN {
                HccapRecord::parse_hccapx(rec)
            } else {
                HccapRecord::parse_hccap(rec)
            };
            out.push(HashLine::new(String::new(), render(&record, file)));
        }
        Ok(out)
    }
}

/// The `$WPAPSK$` line's final field is the file name after the last
/// forward slash (backslashes are not treated as separators).
fn file_label(path: &str) -> &str {
    match path.rfind('/') {
        Some(p) => &path[p + 1..],
        None => path,
    }
}

/// Render one record: crypt-base64 over the record tail (MACs, nonces,
/// EAPOL, then the trailing size/version/MIC fields), followed by the
/// MAC fields, WPA version suffix and file name.
fn render(r: &HccapRecord, file: &str) -> String {
    let essid = trim_essid(&r.essid);
    let mac_ap = hex::encode(r.mac_ap);
    let mac_sta = hex::encode(r.mac_sta);

    let mut tail = Vec::with_capacity(HCCAP_LEN - 36);
    tail.extend_from_slice(&r.mac_ap);
    tail.extend_from_slice(&r.mac_sta);
    tail.extend_from_slice(&r.nonce_sta);
    tail.extend_from_slice(&r.nonce_ap);
    tail.extend_from_slice(&r.eapol);
    tail.extend_from_slice(&r.eapol_size.to_le_bytes());
    tail.extend_from_slice(&r.keyver.to_le_bytes());
    tail.extend_from_slice(&r.keymic);

    let mut b64 = String::new();
    let mut blocks = tail.chunks_exact(3);
    for block in &mut blocks {
        push_crypt_block(block, true, &mut b64);
    }
    push_crypt_block(blocks.remainder(), false, &mut b64);

    let mut line = format!("{essid}:$WPAPSK${essid}#{b64}:{mac_sta}:{mac_ap}:{mac_ap}::WPA");
    if r.keyver > 1 {
        line.push_str(&r.keyver.to_string());
    }
    line.push(':');
    line.push_str(file);
    line
}

fn trim_essid(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Encode 3 bytes into 4 crypt-alphabet characters; the final partial
/// block encodes its first 2 bytes into 3 characters.
fn push_crypt_block(input: &[u8], full: bool, out: &mut String) {
    let (b0, b1) = (input[0], input[1]);
    out.push(CRYPT_ALPHABET[(b0 >> 2) as usize] as char);
    out.push(CRYPT_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
    if full {
        let b2 = input[2];
        out.push(CRYPT_ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        out.push(CRYPT_ALPHABET[(b2 & 0x3f) as usize] as char);
    } else {
        out.push(CRYPT_ALPHABET[((b1 & 0x0f) << 2) as usize] as char);
    }
}
