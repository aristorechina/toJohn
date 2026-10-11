//! Extracts `$dmg$` hashes from encrypted Apple DMG images, with strict
//! validation and diagnostics. The [`super::dmg`] module is the lenient
//! variant of the same formats (silent skips instead of errors).
//!
//! Two container generations are handled: v1, whose filevault header sits
//! at the end of the file, and v2, whose chunk-table header carries a
//! key-pointer table. In v2 the password key header is the entry with key
//! type 1; its sizes use the 104-byte header stride and the key blob
//! follows at `header_offset + 104`.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util::basename;

pub struct DmgStrict;

const MAGIC_V1: &[u8] = b"cdsaencr";
const MAGIC_V2: &[u8] = b"encrcdsa";
const V1_HEADER_SIZE: usize = 1276;

fn be32(h: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(h[o..o + 4].try_into().expect("4 bytes"))
}

fn be64(h: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(h[o..o + 8].try_into().expect("8 bytes"))
}

impl Extractor for DmgStrict {
    fn name(&self) -> &'static str {
        "dmg_strict"
    }

    fn description(&self) -> &'static str {
        "encrypted Apple DMG files (v1/v2, strict validation)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(MAGIC_V2) || input.data.ends_with(MAGIC_V1)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let container_version = if data.starts_with(MAGIC_V2) {
            2
        } else if data.len() >= 8 && data.ends_with(MAGIC_V1) {
            1
        } else {
            0
        };
        match container_version {
            1 => self.extract_v1(input),
            2 => self.extract_v2(input),
            _ => Err(Error::malformed(
                input.label(),
                "not an encrypted DMG image",
            )),
        }
    }
}

impl DmgStrict {
    /// v1 container: filevault header at the end of the file.
    fn extract_v1(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < V1_HEADER_SIZE {
            return Err(Error::malformed(input.label(), "not a DMG image"));
        }
        let h = &data[data.len() - V1_HEADER_SIZE..];
        // filevault header layout: filler(48) iter(4) salt_len(4) salt(48)
        // unwrap_iv(32) len_aes(4) aes(296) len_hmac(4) hmac(300) ...
        let kdf_iteration_count = be32(h, 48);
        let kdf_salt_len = be32(h, 52) as usize;
        let kdf_salt = &h[56..104];
        let wrapped_aes_key_len = be32(h, 136) as usize;
        let wrapped_aes_key = &h[140..436];
        let wrapped_hmac_key_len = be32(h, 436) as usize;
        let wrapped_hmac_key = &h[440..740];

        if kdf_salt_len > 48 {
            return Err(Error::malformed(
                input.label(),
                "KDF salt length out of range",
            ));
        }
        if wrapped_aes_key_len > 296 {
            return Err(Error::malformed(
                input.label(),
                "wrapped AES key length out of range",
            ));
        }
        if wrapped_hmac_key_len > 300 {
            return Err(Error::malformed(
                input.label(),
                "wrapped HMAC key length out of range",
            ));
        }

        let label = output_label(input.label());
        Ok(vec![HashLine::new(
            label.clone(),
            format!(
                "{label}:$dmg$1*{kdf_salt_len}*{}*{wrapped_aes_key_len}*{}\
*{wrapped_hmac_key_len}*{}*{kdf_iteration_count}::::{label}",
                hex_prefix(kdf_salt, kdf_salt_len),
                hex_prefix(wrapped_aes_key, wrapped_aes_key_len),
                hex_prefix(wrapped_hmac_key, wrapped_hmac_key_len),
            ),
        )])
    }

    /// v2 container: chunk-table header with a key-pointer table.
    fn extract_v2(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let label = output_label(input.label());
        if data.len() < 76 {
            return Err(Error::malformed(input.label(), "not a DMG image"));
        }
        let h = data;
        let data_size = be64(h, 56);
        let data_offset = be64(h, 64);
        let key_count = be32(h, 72);

        let is_sparseimage = input.label().contains(".sparseimage");
        let (last_chunk_index, last_chunk_size) = if is_sparseimage {
            (1i64, 8192i64)
        } else {
            let index = data_size.div_ceil(4096) as i64 - 2;
            (index, data_size as i64 - index * 4096)
        };
        if last_chunk_size < 0 {
            return Err(Error::malformed(input.label(), "negative last-chunk size"));
        }

        // key header pointers (20 bytes each) start at offset 76; the
        // password key header is the entry with key type 1
        let mut password_key: Option<(usize, u32)> = None; // (header_offset, keyblob_size)
        for i in 0..key_count {
            let pointer_offset = 76 + 20 * i as usize;
            if pointer_offset + 20 > data.len() {
                return Err(Error::malformed(
                    input.label(),
                    "key header table extends past end of file",
                ));
            }
            let key_type = be32(h, pointer_offset);
            let header_offset = be32(h, pointer_offset + 8) as usize;
            if key_type != 1 {
                continue;
            }
            if header_offset + 104 > data.len() {
                return Err(Error::malformed(
                    input.label(),
                    "password key header extends past end of file",
                ));
            }
            // password key header: blob size sits at +100 on the 104-byte
            // header stride
            let keyblob_size = be32(h, header_offset + 100);
            if keyblob_size > 1024 {
                return Err(Error::malformed(
                    input.label(),
                    "unreasonable password key blob size",
                ));
            }
            password_key = Some((header_offset, keyblob_size));
            break;
        }
        let Some((header_offset, keyblob_size)) = password_key else {
            return Err(Error::malformed(
                input.label(),
                "password key header not found",
            ));
        };
        let salt_len = be32(h, header_offset + 12) as usize;
        if salt_len > 32 {
            return Err(Error::malformed(
                input.label(),
                "DMG salt length exceeds 32 bytes",
            ));
        }
        let iteration_count = be32(h, header_offset + 8);
        let salt = &h[header_offset + 16..header_offset + 48];
        let iv = &h[header_offset + 52..header_offset + 84];
        let blob_start = header_offset + 104;
        if blob_start + keyblob_size as usize > data.len() {
            return Err(Error::malformed(
                input.label(),
                "key blob extends past end of file",
            ));
        }
        let keyblob = &h[blob_start..blob_start + keyblob_size as usize];

        // last chunk (partial) and first chunk (full 4096 bytes)
        let last_chunk_start = data_offset as i64 + last_chunk_index * 4096;
        let last_chunk_start = last_chunk_start as usize;
        let last_chunk_end = last_chunk_start + last_chunk_size as usize;
        if last_chunk_end > data.len() {
            return Err(Error::malformed(
                input.label(),
                "chunk data extends past end of file",
            ));
        }
        let last_chunk = &data[last_chunk_start..last_chunk_end];
        let first_chunk_start = data_offset as usize;
        if first_chunk_start + 4096 > data.len() {
            return Err(Error::malformed(
                input.label(),
                "chunk data extends past end of file",
            ));
        }
        let first_chunk = &data[first_chunk_start..first_chunk_start + 4096];

        Ok(vec![HashLine::new(
            label.clone(),
            format!(
                "{label}:$dmg$2*{salt_len}*{}*32*{}*{keyblob_size}*{}*{last_chunk_index}*{last_chunk_size}\
*{}*1*{}*{iteration_count}::::{label}",
                hex_prefix(salt, salt_len),
                hex::encode(iv),
                hex::encode(keyblob),
                hex::encode(last_chunk),
                hex::encode(first_chunk),
            ),
        )])
    }
}

/// Label: the file name (':' replaced by ' '), taken after the last path
/// separator.
fn output_label(path: &str) -> String {
    let name = path.replace(':', " ");
    basename(&name).to_string()
}

/// Hex of the first `len` bytes (capped at the slice length).
fn hex_prefix(b: &[u8], len: usize) -> String {
    hex::encode(&b[..len.min(b.len())])
}
