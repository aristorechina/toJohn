//! Jetico BestCrypt V8 container parser (LOCOS94 keygen headers, keymap +
//! key slots), emitting `$BestCrypt$` lines. Only the CBC/XTS + RIJNDAEL
//! combinations with SHA-256/Whirlpool/SHA-512 header hashing are accepted;
//! anything else produces no output.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Bestcrypt;

/// "LOCOS94 " signature of a BestCrypt V8 database header.
const DB_HEADER_SIGNATURE: &[u8] = b"LOCOS94 ";
/// KeyGenID marker stored in the volume-label field.
const VOLUME_LABEL: &[u8] = b"BC_KeyGenID";
/// Size of the initial data block holding the unpacked header.
const DATA_BLOCK_64_SIZE: usize = 4096;
/// Size of one key slot.
const KEY_SLOT_SIZE: usize = 256;
/// Maximum number of key slots.
const KBCV8_MAX_KEYS: usize = 64;
/// Size of the packed header data block.
const DATA_BLOCK_SIZE: usize = 1536;
/// Size of the initial data block (holds the keymap).
const KBCV8_INITIAL_DATA_BLOCK_SIZE: usize = 4096;

/// KeyGenID field value of the legacy header layout (resolved version 3).
const KEY_GEN_ID: i32 = 4;
/// KeyGenID field value of the v5 header layout.
const KEY_GEN_ID_V5: i32 = 5;
/// Algorithm ID for RIJNDAEL (AES).
const ALGORITHM_RIJNDAEL: u32 = 240;
/// Encryption-mode ID: CBC.
const MODE_CBC: u32 = 0xBC00_0002;
/// Encryption-mode ID: XTS.
const MODE_XTS: u32 = 0xBC00_0004;
/// Hash-algorithm ID: SHA-512 (PGP numbering).
const HASH_ID_SHA512: u32 = 10;
/// Hash-algorithm ID: SHA-256.
const HASH_ID_SHA256: u32 = 0x80;
/// Hash-algorithm ID: Whirlpool-512.
const HASH_ID_WHIRLPOOL512: u32 = 0x81;
/// Keymap slot type: salt slot.
const KEY_TYPE_SALT: i16 = 5;

/// Offsets into the unpacked header layout (little-endian, packed).
mod off {
    pub const SIGNATURE: usize = 3;
    pub const VOLUME_LABEL: usize = 43;
    pub const KEY_GEN_ID: usize = 54;
    pub const VERSION: usize = 56;
    pub const ITERATIONS: usize = 58;
    pub const ALG_ID: usize = 128;
    pub const MODE_ID: usize = 132;
    pub const HASH_ID: usize = 136;
    pub const KEYMAP: usize = 140;
    pub const KEYS: usize = 4096 - 2560; // 1536
}

impl Extractor for Bestcrypt {
    fn name(&self) -> &'static str {
        "bestcrypt"
    }

    fn description(&self) -> &'static str {
        "Jetico BestCrypt V8 containers (.jbc)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.len() >= DATA_BLOCK_64_SIZE
            && &input.data[off::SIGNATURE..off::SIGNATURE + 8] == DB_HEADER_SIGNATURE
            && &input.data[off::VOLUME_LABEL..off::VOLUME_LABEL + 11] == b"BC_KeyGenID"
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < DATA_BLOCK_64_SIZE {
            // too small to hold a header: produce no output
            return Ok(Vec::new());
        }
        let le16 = |o: usize| u16::from_le_bytes(data[o..o + 2].try_into().expect("2 bytes"));
        let le32 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().expect("4 bytes"));

        let signature = &data[off::SIGNATURE..off::SIGNATURE + 8];
        let volume_label = &data[off::VOLUME_LABEL..off::VOLUME_LABEL + 11];
        if signature != DB_HEADER_SIGNATURE || volume_label != VOLUME_LABEL {
            // encrypted headers are not supported: produce no output
            return Ok(Vec::new());
        }
        let key_gen_id = le16(off::KEY_GEN_ID) as i32;
        let version = le16(off::VERSION);
        let iterations = le32(off::ITERATIONS);
        let alg_id = le32(off::ALG_ID);
        let mode_id = le32(off::MODE_ID);
        let hash_id = le32(off::HASH_ID);

        if key_gen_id != KEY_GEN_ID_V5 {
            let resolved_version = iterations; // union of iterations and version
            if resolved_version != 3 || key_gen_id != KEY_GEN_ID {
                // unsupported header version: produce no output
                return Ok(Vec::new());
            }
        }
        if alg_id != ALGORITHM_RIJNDAEL || (mode_id != MODE_CBC && mode_id != MODE_XTS) {
            return Ok(Vec::new());
        }
        if hash_id != HASH_ID_WHIRLPOOL512 && hash_id != HASH_ID_SHA256 && hash_id != HASH_ID_SHA512
        {
            return Ok(Vec::new());
        }
        let salt_size: usize = if hash_id == HASH_ID_WHIRLPOOL512 {
            64
        } else if hash_id == HASH_ID_SHA256 {
            32
        } else {
            64
        };
        let keys = &data[off::KEYS..off::KEYS + 2560];
        let salt = hex::encode(&keys[0..salt_size]);
        let keymap = &data[off::KEYMAP..off::KEYMAP + 512];
        // slot 0 must be a salt slot
        let first_slot_type = i16::from_le_bytes(keymap[2..4].try_into().expect("2 bytes"));
        if first_slot_type != KEY_TYPE_SALT {
            return Ok(Vec::new());
        }

        // capacity of the initial data block: 10 key slots
        let capacity =
            ((KBCV8_INITIAL_DATA_BLOCK_SIZE - DATA_BLOCK_SIZE) / KEY_SLOT_SIZE).min(KBCV8_MAX_KEYS);

        let mut out = Vec::new();
        for slot_index in 0..capacity {
            let slot = &keymap[slot_index * 8..(slot_index + 1) * 8];
            let slot_type = i16::from_le_bytes(slot[2..4].try_into().expect("2 bytes"));
            // key (-1) / salt (KEY_TYPE_SALT) / empty (0) slots are skipped
            if slot_type == -1 || slot_type == KEY_TYPE_SALT || slot_type == 0 {
                continue;
            }
            let active_key = &keys[slot_index * KEY_SLOT_SIZE..(slot_index + 1) * KEY_SLOT_SIZE];
            let label = util::basename(input.label());
            out.push(HashLine::new(
                label.to_string(),
                format!(
                    "{label}:$BestCrypt$1${key_gen_id}${version}${iterations}${alg_id}\
${mode_id}${hash_id}${salt_size}${salt}$1${}",
                    hex::encode(active_key)
                ),
            ));
        }
        Ok(out)
    }
}
