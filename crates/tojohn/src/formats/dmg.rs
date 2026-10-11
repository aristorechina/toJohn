//! Encrypted Apple DMG parser: header version 1 (the `cdsaencr` footer
//! magic) and version 2 (the `encrcdsa` header magic), emitting `$dmg$`
//! lines with salt, wrapped AES/HMAC keys and chunk data.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Dmg;

/// Version-1 footer magic (`cdsaencr`).
const MAGIC_V1: &[u8] = b"cdsaencr";
/// Version-2 header magic (`encrcdsa`).
const MAGIC_V2: &[u8] = b"encrcdsa";
/// Size of the version-1 footer header.
const V1_HEADER_SIZE: usize = 1276;
/// Size of the version-2 header.
const V2_HEADER_SIZE: usize = 264;

impl Extractor for Dmg {
    fn name(&self) -> &'static str {
        "dmg"
    }

    fn description(&self) -> &'static str {
        "encrypted Apple DMG files (v1/v2)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(MAGIC_V2) || input.data.ends_with(MAGIC_V1)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.starts_with(MAGIC_V2) {
            return self.v2(input);
        }
        if data.ends_with(MAGIC_V1) {
            return self.v1(input);
        }
        // neither header magic: not an encrypted DMG
        Ok(Vec::new())
    }
}

impl Dmg {
    fn v1(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < V1_HEADER_SIZE {
            return Ok(Vec::new());
        }
        let header = &data[data.len() - V1_HEADER_SIZE..];
        // v1 footer layout: 48 pad bytes | iterations(u32 BE) | salt_len(u32)
        // | salt(48) | 32 pad bytes | wrapped AES key length(u32) at 136 |
        // wrapped AES key(296) at 140 | wrapped HMAC key length(u32) at 436 |
        // wrapped HMAC key(300) at 440
        let rd_u32 = |o: usize| u32::from_be_bytes(header[o..o + 4].try_into().expect("4 bytes"));
        let kdf_iteration_count = rd_u32(48);
        let kdf_salt_len = rd_u32(52) as usize;
        let kdf_salt = &header[56..104];
        let len_wrapped_aes_key = rd_u32(136);
        let wrapped_aes_key = &header[140..436];
        let len_hmac_sha1_key = rd_u32(436);
        let wrapped_hmac_sha1_key = &header[440..740];

        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$dmg$1*{kdf_salt_len}*{}*{len_wrapped_aes_key}*{}\
*{len_hmac_sha1_key}*{}*{kdf_iteration_count}::::{label}",
                hex_slice(kdf_salt, kdf_salt_len),
                hex_slice(wrapped_aes_key, len_wrapped_aes_key as usize),
                hex_slice(wrapped_hmac_sha1_key, len_hmac_sha1_key as usize),
            ),
        )])
    }

    fn v2(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < V2_HEADER_SIZE {
            return Ok(Vec::new());
        }
        let rd_u32 = |o: usize| u32::from_be_bytes(data[o..o + 4].try_into().expect("4 bytes"));
        let data_size = u64::from_be_bytes(data[56..64].try_into().expect("8 bytes"));
        let data_offset = u64::from_be_bytes(data[64..72].try_into().expect("8 bytes"));
        let kdf_iteration_count = rd_u32(104);
        let kdf_salt_len = rd_u32(108) as usize;
        let kdf_salt = &data[112..144];
        let blob_enc_iv = &data[148..180];
        let encrypted_keyblob_size = rd_u32(196) as usize;
        let encrypted_keyblob = &data[200..264];

        let chunk_no = data_size.div_ceil(4096) - 2;
        let chunk_size = data_size as i64 - (chunk_no * 4096) as i64;
        if chunk_size < 0 {
            return Ok(Vec::new()); // negative computed chunk size: not a valid DMG
        }
        if kdf_salt_len > 32 {
            return Ok(Vec::new()); // salt length exceeds the 32-byte field
        }
        let chunk_size = chunk_size as usize;
        // read starting chunk(s)
        let c1 = data_offset as usize + (chunk_no * 4096) as usize;
        let chunk1 = data
            .get(c1..(c1 + chunk_size).min(data.len()))
            .unwrap_or(&[]);
        if chunk1.len() != chunk_size {
            // chunk not fully available: return without output
            return Ok(Vec::new());
        }
        // read last chunk
        let chunk2 = data
            .get(data_offset as usize..data_offset as usize + 4096)
            .unwrap_or(&[]);
        if chunk2.len() != 4096 {
            // last chunk not fully available: return without output
            return Ok(Vec::new());
        }
        let keyblob_hex = format!(
            "{}{}",
            hex_slice(encrypted_keyblob, encrypted_keyblob_size),
            "0".repeat((encrypted_keyblob_size * 2).saturating_sub(encrypted_keyblob.len() * 2))
        );
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$dmg$2*{kdf_salt_len}*{}*32*{}*{encrypted_keyblob_size}*{keyblob_hex}\
*{chunk_no}*{chunk_size}*{}*1*{}*{kdf_iteration_count}::::{label}",
                hex_slice(kdf_salt, kdf_salt_len),
                hex_slice(blob_enc_iv, 32),
                hex::encode(chunk1),
                hex::encode(chunk2),
            ),
        )])
    }
}

/// Hex-encode at most `len` bytes of `bytes` (a field shorter than its
/// declared length is encoded only up to its actual size).
fn hex_slice(bytes: &[u8], len: usize) -> String {
    hex::encode(&bytes[..len.min(bytes.len())])
}
