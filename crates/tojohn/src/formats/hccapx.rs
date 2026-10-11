//! hashcat hccapx (v4) handshake converter: turns 393-byte handshake records
//! into `$WPAPSK$` lines in the john hash-line format, including the AP
//! nonce-correction expansion. Options `-nc <N>` (default 8) and `--no-mp`
//! are taken from `input.extra_args`.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use base64::Engine;

pub struct Hccapx;

const HCCAPX_LEN: usize = 393;
const HCCAP_LEN: usize = 392;
const BCRYPT_ALPHABET: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

impl Extractor for Hccapx {
    fn name(&self) -> &'static str {
        "hccapx"
    }

    fn description(&self) -> &'static str {
        "hashcat hccapx files (options: -nc N, --no-mp)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"HCPX")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut nc: i32 = 8;
        let mut mp = true;
        let mut args = input.extra_args.iter();
        while let Some(a) = args.next() {
            match a.as_str() {
                "-nc" => {
                    if let Some(v) = args.next() {
                        nc = v.parse().unwrap_or(8);
                    }
                }
                "--no-mp" | "-mp" => mp = false,
                _ => {}
            }
        }
        let file_label = input.label();

        let mut out: Vec<HashLine> = Vec::new();
        for chunk in input.data.chunks(HCCAPX_LEN) {
            if chunk.len() != HCCAPX_LEN {
                break;
            }
            if let Some(blob) = render_hccapx_record(chunk, nc, mp, file_label) {
                for line in blob.lines() {
                    out.push(HashLine::new(String::new(), line.to_string()));
                }
            }
        }
        Ok(out)
    }
}

fn render_hccapx_record(
    hccapx: &[u8],
    ncorr: i32,
    message_pair_flag: bool,
    file: &str,
) -> Option<String> {
    if !hccapx.starts_with(b"HCPX") || hccapx.len() != HCCAPX_LEN {
        return None;
    }
    let (hccap, mut message_pair) = hccapx2hccap(hccapx);

    if !message_pair_flag {
        message_pair &= 0x8F;
    }

    // exact handshake
    let mut hccaps = pack_jtr(&hccap, message_pair, file, 0);
    if message_pair & 0x10 != 0 {
        return Some(hccaps);
    }

    // detect if we have endianness info
    let mut flip = false;
    if message_pair & 0x60 == 0 {
        flip = true;
        message_pair |= 0x20;
    }

    let mut i = 1;
    while i <= ncorr {
        if flip {
            hccaps += &pack_jtr(&hccap, message_pair, file, i);
            hccaps += &pack_jtr(&hccap, message_pair, file, -i);
            message_pair ^= 0x60;
        }
        hccaps += &pack_jtr(&hccap, message_pair, file, i);
        hccaps += &pack_jtr(&hccap, message_pair, file, -i);
        i += 1;
    }
    Some(hccaps)
}

/// hccapx (393 bytes) -> hccap (392 bytes) + message_pair.
fn hccapx2hccap(h: &[u8]) -> ([u8; HCCAP_LEN], u8) {
    let message_pair = h[8];
    let essid = &h[10..42];
    let keyver = h[42];
    let keymic = &h[43..59];
    let mac_ap = &h[59..65];
    let nonce_ap = &h[65..97];
    let mac_sta = &h[97..103];
    let nonce_sta = &h[103..135];
    let eapol_len = u16::from_le_bytes(h[135..137].try_into().expect("2 bytes"));
    let eapol = &h[137..137 + 256];

    let mut hccap = [0u8; HCCAP_LEN];
    hccap[0..32].copy_from_slice(essid); // 36-byte field, zero padded
    hccap[36..42].copy_from_slice(mac_ap);
    hccap[42..48].copy_from_slice(mac_sta);
    hccap[48..80].copy_from_slice(nonce_sta);
    hccap[80..112].copy_from_slice(nonce_ap);
    hccap[112..368].copy_from_slice(eapol);
    hccap[368..372].copy_from_slice(&u32::from(eapol_len).to_le_bytes());
    hccap[372..373].copy_from_slice(&[keyver]);
    hccap[376..392].copy_from_slice(keymic);
    (hccap, message_pair)
}

fn pack_jtr(hccap: &[u8], message_pair: u8, file: &str, ncorr: i32) -> String {
    let essid_raw = &hccap[0..36];
    let mac_ap = &hccap[36..42];
    let mac_sta = &hccap[42..48];
    let corr = &hccap[108..112];
    let keyver = u32::from_le_bytes(hccap[372..376].try_into().expect("4 bytes"));

    let mut ver: String = if message_pair & 0x80 != 0 {
        "verified".to_string()
    } else {
        "not verified".to_string()
    };

    let mut corr_bytes = corr.to_vec();
    if ncorr != 0 {
        if message_pair & 0x40 != 0 {
            ver += &format!(", fuzz {ncorr} BE");
            let dcorr = u32::from_be_bytes(corr_bytes[..4].try_into().expect("4 bytes"));
            corr_bytes[..4].copy_from_slice(&dcorr.wrapping_add(ncorr as u32).to_be_bytes());
        }
        if message_pair & 0x20 != 0 {
            ver += &format!(", fuzz {ncorr} LE");
            let dcorr = u32::from_le_bytes(corr_bytes[..4].try_into().expect("4 bytes"));
            corr_bytes[..4].copy_from_slice(&dcorr.wrapping_add(ncorr as u32).to_le_bytes());
        }
    }

    // cut essid part and stuff correction
    let mut newhccap: Vec<u8> = hccap[36..108].to_vec();
    newhccap.extend_from_slice(&corr_bytes);
    newhccap.extend_from_slice(&hccap[112..]);

    let essid: String = String::from_utf8_lossy(essid_raw)
        .trim_end_matches('\0')
        .to_string();
    let mac_sta_hex = hex::encode(mac_sta);
    let mac_ap_hex = hex::encode(mac_ap);
    let keyver_str = match keyver {
        1 => "WPA".to_string(),
        2 => "WPA2".to_string(),
        k if k >= 3 => "WPA CMAC".to_string(),
        k => k.to_string(),
    };

    let b64 = base64::engine::general_purpose::STANDARD.encode(&newhccap);
    // translate to the crypt(3) base64 alphabet, strip trailing '=\n'
    let b64_crypt: String = b64
        .trim_end_matches('=')
        .chars()
        .map(|c| {
            let idx = match c {
                'A'..='Z' => c as usize - 'A' as usize,
                'a'..='z' => 26 + c as usize - 'a' as usize,
                '0'..='9' => 52 + c as usize - '0' as usize,
                '+' => 62,
                '/' => 63,
                _ => c as usize, // '=' never reaches here after trim
            };
            BCRYPT_ALPHABET[idx] as char
        })
        .collect();

    format!(
        "{essid}:$WPAPSK${essid}#{b64_crypt}:{mac_sta_hex}:{mac_ap_hex}:{mac_ap_hex}::\
{keyver_str}:{ver}:{file}\n"
    )
}
