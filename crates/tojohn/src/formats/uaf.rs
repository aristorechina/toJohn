//! Extracts OpenVMS SYSUAF password hashes from raw SYSUAF records (the
//! fixed 1412-byte records produced by the VMS `convert` utility) and
//! renders them as passwd-style lines.
//!
//! Each record's 64-bit password hash, 8-bit algorithm, 16-bit salt,
//! RAD-50-encoded username and the password-mix flag are packed into the
//! `$V$` string via a 6-bit alphabet. Each line follows the passwd layout:
//! username, encoded hash, UIC member/group, owner, home directory and
//! default CLI.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Uaf;

const UAF_RAW_REC_MIN_LENGTH: usize = 644;
const UAF_RECTYPE_USER: u8 = 1;

const SIXBIT_ALPHABET: &[u8] = b"-ABCDEFGHIJKLMNOPQRTSUVWXYZ0123456789abcedfghijklmnopqrstuvwxyz+";
const RAD50_ALPHABET: &[u8] = b" ABCDEFGHIJKLMNOPQRSTUVWXYZ$._0123456789";

/// Bit offsets inside the SYSUAF flags bitfield.
const FLAG_DISACNT: u32 = 1 << 4;
const FLAG_PWDMIX: u32 = 1 << 25;

impl Extractor for Uaf {
    fn name(&self) -> &'static str {
        "uaf"
    }

    fn description(&self) -> &'static str {
        "OpenVMS SYSUAF raw record files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.len() >= 1412 && input.data[0] == UAF_RECTYPE_USER
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let rec_len = 1412usize;
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + rec_len <= data.len() {
            let rec = &data[off..off + rec_len];
            off += rec_len;
            if let Some(line) = record_line(rec) {
                out.push(HashLine::new(String::new(), line));
            }
        }
        if out.is_empty() {
            return Err(Error::malformed(input.label(), "no valid user records"));
        }
        Ok(out)
    }
}

fn record_line(rec: &[u8]) -> Option<String> {
    if rec.len() < UAF_RAW_REC_MIN_LENGTH || rec[0] != UAF_RECTYPE_USER {
        return None;
    }
    let rd_u16 = |o: usize| u16::from_le_bytes(rec[o..o + 2].try_into().expect("2 bytes"));
    let rd_u32 = |o: usize| u32::from_le_bytes(rec[o..o + 4].try_into().expect("4 bytes"));

    // username: blank-filled at offset 4, uppercased
    let mut username = String::new();
    for &c in &rec[4..4 + 32] {
        if c == b' ' {
            break;
        }
        username.push(c.to_ascii_uppercase() as char);
    }
    if username.len() > 12 {
        return None;
    }

    let uic_mem = rd_u16(36);
    let uic_grp = rd_u16(38);

    // owner: counted string at 84 (len byte + 31 chars)
    let owner_len = rec[84] as usize;
    let owner: Vec<u8> = rec[85..85 + owner_len.min(31)].to_vec();
    let defcli_len = rec[276] as usize;
    let defcli: Vec<u8> = rec[277..277 + defcli_len.min(31)].to_vec();

    // auth info: pwd(8) at 340, pwd2(8) at 348, salt(2) at 358, encrypt(1) at 360
    let pwd = &rec[340..348];
    let pwd2 = &rec[348..356];
    let salt = rd_u16(358);
    let alg = rec[360];
    let flags = rd_u32(468);
    let disacnt = flags & FLAG_DISACNT != 0;
    let pwdmix = flags & FLAG_PWDMIX != 0;
    let priv0 = rd_u32(412);
    let priv1 = rd_u32(416);

    // privilege summary categories; first matching category wins
    let priv_categories: [(&str, [u32; 2]); 7] = [
        ("All", [0x3440_40a7, 0x000b]),
        ("Objects", [0x0222_0040, 0x010]),
        ("System", [0xc005_3000, 0x060]),
        ("Devour", [0x0988_0e18, 0x000]),
        ("Group", [0x0000_0100, 0x004]),
        ("Normal", [0x0010_8000, 0]),
        ("None", [0, 0]),
    ];
    let mut priv_summary = "None";
    for (name, mask) in priv_categories.iter() {
        if (mask[0] & priv0 != 0) || (mask[1] & priv1 != 0) {
            priv_summary = name;
            break;
        }
        if *mask == [0, 0] {
            break;
        }
    }

    let acct_status = if disacnt { "/Disuser" } else { "" };

    let rad50 = encode_rad50_username(&username);
    let opt = if pwdmix { 1u8 } else { 0u8 };

    // primary password line; the `.1` suffix marks accounts that also
    // carry a secondary password hash
    let encoded = encode_hash(pwd, alg, salt, &rad50, opt);
    let suffix = if pwd2 != [0u8; 8] { ".1" } else { "" };

    // non-VMS accounts live under /USERS[|/Disuser]/<privilege summary>
    let home = format!("/USERS{acct_status}/{priv_summary}");

    let owner_s = sanitize_colons(&String::from_utf8_lossy(&owner));
    let shell_s = sanitize_colons(&String::from_utf8_lossy(&defcli));
    let username_out = sanitize_colons(&username);

    Some(format!(
        "{username_out}{suffix}:{encoded}:{uic_mem}:{uic_grp}:{owner_s}:{home}:{shell_s}"
    ))
}

/// Passwd lines forbid colons in these fields; replace them with '.'.
fn sanitize_colons(s: &str) -> String {
    s.replace(':', ".")
}

/// Encode the `$V$` string: hash (64 bits), algorithm (8), salt (16),
/// RAD-50 username (64) and flag bits (4) packed as a little-endian bit
/// stream over the 6-bit alphabet.
fn encode_hash(hash: &[u8], alg: u8, salt: u16, rad50: &[u8], opt: u8) -> String {
    let mut accum: u128 = 0;
    let mut bits: u32 = 0;
    let mut out = String::from("$V$");

    // hash bytes, little-endian order as in memory
    for &b in hash {
        accum |= (b as u128) << bits;
        bits += 8;
        flush6(&mut accum, &mut bits, &mut out);
    }
    // algorithm byte
    accum |= (alg as u128) << bits;
    bits += 8;
    flush6(&mut accum, &mut bits, &mut out);
    // salt word, little-endian
    for &b in &salt.to_le_bytes() {
        accum |= (b as u128) << bits;
        bits += 8;
        flush6(&mut accum, &mut bits, &mut out);
    }
    // RAD-50 packed username (8 bytes, LE order)
    for &b in rad50 {
        accum |= (b as u128) << bits;
        bits += 8;
        flush6(&mut accum, &mut bits, &mut out);
    }
    // flag bits
    accum |= (opt as u128) << bits;
    bits += 4;
    flush6(&mut accum, &mut bits, &mut out);
    // flush remaining partial bits
    while bits > 0 {
        out.push(SIXBIT_ALPHABET[(accum & 63) as usize] as char);
        accum >>= 6;
        bits = bits.saturating_sub(6);
    }
    out
}

fn flush6(accum: &mut u128, bits: &mut u32, out: &mut String) {
    while *bits >= 6 {
        out.push(SIXBIT_ALPHABET[(*accum & 63) as usize] as char);
        *accum >>= 6;
        *bits -= 6;
    }
}

/// Pack a username into 4 RAD-50 16-bit words (8 bytes, LE order): 3
/// chars per word, value = c2*1600 + c1*40 + c0.
fn encode_rad50_username(username: &str) -> Vec<u8> {
    let mut words = [0u16; 4];
    let mut chars = username.as_bytes().to_vec();
    chars.resize(12, b' ');
    for i in 0..4 {
        let mut ci = [0u16; 3];
        for (j, c) in chars[i * 3..i * 3 + 3].iter().enumerate() {
            ci[j] = rad50_index(*c);
        }
        words[i] = ci[2] * 1600 + ci[1] * 40 + ci[0];
    }
    let mut out = Vec::with_capacity(8);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

fn rad50_index(c: u8) -> u16 {
    RAD50_ALPHABET
        .iter()
        .position(|&r| r == c.to_ascii_uppercase())
        .map(|i| i as u16)
        .unwrap_or(3) // '.' fallback
}
