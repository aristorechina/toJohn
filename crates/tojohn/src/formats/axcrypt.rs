//! AxCrypt 1.x and 2.x encrypted file (.axx) parser. Walks the header chain
//! after the 16-byte GUID: v1 collects type-4 "StructKey" headers, v2 is
//! detected by a (252|253, 13) header. An optional key-file is
//! `input.extra_files[0]`. Emits `$axcrypt$` lines.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Axcrypt;

/// Header GUID starting every AxCrypt 1.x/2.x file.
const GUID: &[u8] = &[
    0xc0, 0xb9, 0x07, 0x2e, 0x4f, 0x93, 0xf1, 0x46, 0xa0, 0x15, 0x79, 0x2c, 0xa1, 0xd9, 0xe8, 0x21,
];
/// Offset of the header-type byte within each header block.
const OFFSET_TYPE: usize = 4;
/// Size of the StructKey key-data field.
const SIZE_KEYDATA: usize = 24;
/// Size of the StructKey salt field.
const SIZE_SALT: usize = 16;
/// Size of the iteration-count fields.
const SIZE_ITERATION: usize = 4;

struct StructKey {
    key_data: Vec<u8>,
    salt: Vec<u8>,
    iteration: u32,
}

impl Extractor for Axcrypt {
    fn name(&self) -> &'static str {
        "axcrypt"
    }

    fn description(&self) -> &'static str {
        "AxCrypt 1.x/2.x .axx files (optional key-file as extra file)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(GUID)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let mut offset = 16;
        let mut header_type: u8 = 0x02; // first type encountered
        let mut struct_keys: Vec<StructKey> = Vec::new();

        while header_type != 63 {
            if offset + OFFSET_TYPE + 1 > data.len() {
                // truncated header chain: return without output
                return Ok(Vec::new());
            }
            let header_len = data[offset] as usize;
            header_type = data[offset + OFFSET_TYPE];

            if (header_len == 252 || header_len == 253) && header_type == 13 {
                return self.extract_v2(input, data, offset);
            }

            // probably a StructKey
            if header_len == 49 && header_type == 4 {
                let key_data = offset + OFFSET_TYPE + 1;
                let salt = key_data + SIZE_KEYDATA;
                let iteration = salt + SIZE_SALT;
                if iteration + SIZE_ITERATION > data.len() {
                    return Err(Error::malformed(
                        input.label(),
                        "truncated StructKey header",
                    ));
                }
                struct_keys.push(StructKey {
                    key_data: data[key_data..salt].to_vec(),
                    salt: data[salt..iteration].to_vec(),
                    iteration: u32::from_le_bytes(
                        data[iteration..iteration + SIZE_ITERATION]
                            .try_into()
                            .expect("4 bytes"),
                    ),
                });
            }

            offset += header_len;
            if offset >= data.len() {
                return Ok(Vec::new());
            }
        }

        let Some(key) = struct_keys.first() else {
            // malformed file: the v1 header chain contains no StructKey header
            return Err(Error::malformed(input.label(), "no StructKey header found"));
        };
        let (label, keyfile_content) = label_and_keyfile(input);
        Ok(vec![HashLine::new(
            label.clone(),
            format!(
                "{label}:$axcrypt$*1*{}*{}*{}{}",
                key.iteration,
                hex::encode(&key.salt),
                hex::encode(&key.key_data),
                keyfile_content
            ),
        )])
    }
}

impl Axcrypt {
    fn extract_v2(&self, input: &Input, data: &[u8], offset: usize) -> Result<Vec<HashLine>> {
        /// Size of the v2 wrapped key-data field.
        const V2_KEY_DATA_LEN: usize = 144;
        /// Size of the key-wrap salt field.
        const WRAP_SALT_LEN: usize = 64;
        /// Size of the key-derivation salt field.
        const DERIV_SALT_LEN: usize = 32;
        let key_data = offset + OFFSET_TYPE + 1;
        let wrap_salt = key_data + V2_KEY_DATA_LEN;
        let wrap_iter = wrap_salt + WRAP_SALT_LEN;
        let deriv_salt = wrap_iter + SIZE_ITERATION;
        let deriv_iter = deriv_salt + DERIV_SALT_LEN;
        let required_len = deriv_iter + SIZE_ITERATION;
        if required_len > data.len() {
            return Err(Error::malformed(
                input.label(),
                "truncated AxCrypt 2.x header",
            ));
        }
        let wrapped_key = &data[key_data..wrap_salt];
        let wrap_salt_bytes = &data[wrap_salt..wrap_iter];
        let wrap_iterations =
            u32::from_le_bytes(data[wrap_iter..deriv_salt].try_into().expect("4 bytes"));
        let deriv_salt_bytes = &data[deriv_salt..deriv_iter];
        let deriv_iterations =
            u32::from_le_bytes(data[deriv_iter..required_len].try_into().expect("4 bytes"));
        let (label, keyfile_content) = label_and_keyfile(input);
        Ok(vec![HashLine::new(
            label.clone(),
            format!(
                "{label}:$axcrypt$*2*{wrap_iterations}*{}*{}*{deriv_iterations}*{}{}",
                hex::encode(wrap_salt_bytes),
                hex::encode(wrapped_key),
                hex::encode(deriv_salt_bytes),
                keyfile_content
            ),
        )])
    }
}

/// The hash-line label (basename, plus `*keyfile` when a key-file is given)
/// and the `*<hex>` key-file content suffix (empty when absent).
fn label_and_keyfile(input: &Input) -> (String, String) {
    match input.extra_files.first() {
        Some(keyfile) => {
            let keyfile_name = format!("*{}", basename_slash(&keyfile.label));
            (
                format!("{}{}", basename_slash(input.label()), keyfile_name),
                format!("*{}", hex::encode(&keyfile.data)),
            )
        }
        None => (basename_slash(input.label()).to_string(), String::new()),
    }
}

/// POSIX-style basename: split at the last `/` only (backslash is not a
/// separator).
fn basename_slash(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}
