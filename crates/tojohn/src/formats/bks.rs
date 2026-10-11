//! BouncyCastle BKS (V1/V2) and Uber keystore parser, emitting `$bks$`
//! lines. The keystore type (`bks`/`uber`) is taken from
//! `input.extra_args[0]` and defaults to `bks`.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Bks;

impl Extractor for Bks {
    fn name(&self) -> &'static str {
        "bks"
    }

    fn description(&self) -> &'static str {
        "BouncyCastle BKS / Uber keystores (type via extra args: bks|uber)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.len() >= 20
            && matches!(
                u32::from_be_bytes(input.data[0..4].try_into().unwrap()),
                1 | 2
            )
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let keystore_type = input
            .extra_args
            .first()
            .map(String::as_str)
            .unwrap_or("bks");
        let label = util::basename(input.label());
        let mut pos = 0usize;
        if keystore_type == "uber" {
            return uber(data, &mut pos, label);
        }
        bks(data, &mut pos, label)
    }
}

fn be_u32(data: &[u8], pos: &mut usize) -> u32 {
    let v = u32::from_be_bytes(data[*pos..*pos + 4].try_into().expect("4 bytes"));
    *pos += 4;
    v
}

fn be_u16(data: &[u8], pos: &mut usize) -> u16 {
    let v = u16::from_be_bytes(data[*pos..*pos + 2].try_into().expect("2 bytes"));
    *pos += 2;
    v
}

fn read_utf<'a>(data: &'a [u8], pos: &mut usize) -> &'a [u8] {
    let size = be_u16(data, pos) as usize;
    let out = &data[*pos..(*pos + size).min(data.len())];
    *pos += size;
    out
}

fn read_data<'a>(data: &'a [u8], pos: &mut usize) -> &'a [u8] {
    let size = be_u32(data, pos) as usize;
    let out = &data[*pos..(*pos + size).min(data.len())];
    *pos += size;
    out
}

fn bks(data: &[u8], pos: &mut usize, label: &str) -> Result<Vec<HashLine>> {
    let version = be_u32(data, pos);
    if version != 1 && version != 2 {
        // unsupported BKS keystore version: produce no output
        return Ok(Vec::new());
    }
    let salt_size = be_u32(data, pos) as usize;
    let salt = &data[*pos..(*pos + salt_size).min(data.len())];
    *pos += salt_size;
    let iteration_count = be_u32(data, pos);

    let initial_pos = *pos;
    while *pos < data.len() {
        let entry_type = data[*pos];
        *pos += 1;
        if entry_type == 0 {
            break;
        }
        let _alias = read_utf(data, pos);
        *pos += 8; // timestamp
        let chain_length = be_u32(data, pos);
        for _ in 0..chain_length {
            let _cert_type = read_utf(data, pos);
            let _cert_data = read_data(data, pos);
        }
        match entry_type {
            1 => {
                let _cert_type = read_utf(data, pos);
                let _cert_data = read_data(data, pos);
            }
            2 => {
                *pos += 1; // key_type
                let _key_format = read_utf(data, pos);
                let _key_algorithm = read_utf(data, pos);
                let _key_enc = read_data(data, pos);
            }
            3 => {
                let _secret_data = read_data(data, pos);
            }
            4 => {
                let _sealed_data = read_data(data, pos);
            }
            _ => {} // unexpected keystore entry type: skipped
        }
    }
    let store_data = &data[initial_pos..*pos];
    let store_hmac = &data[*pos..(*pos + 20).min(data.len())];
    // 20 bytes * 8 bits, except for V1 keystores
    let hmac_key_size = if version != 1 { 160 } else { 20 };
    Ok(vec![HashLine::new(
        label.to_string(),
        format!(
            "{label}:$bks$0${version}${hmac_key_size}${iteration_count}${salt_size}${}${}${}:::::{label}",
            hex::encode(salt),
            hex::encode(store_data),
            hex::encode(store_hmac),
        ),
    )])
}

fn uber(data: &[u8], pos: &mut usize, label: &str) -> Result<Vec<HashLine>> {
    let version = be_u32(data, pos);
    let salt = read_data(data, pos);
    let salt_size = salt.len();
    let iteration_count = be_u32(data, pos);
    let encrypted_bks_store = &data[*pos..];
    let store_hmac = [0u8; 20]; // unused for UBER keystore
    Ok(vec![HashLine::new(
        label.to_string(),
        format!(
            "{label}:$bks$1${version}$20${iteration_count}${salt_size}${}${}${}:::::{label}",
            hex::encode(salt),
            hex::encode(encrypted_bks_store),
            hex::encode(store_hmac),
        ),
    )])
}
