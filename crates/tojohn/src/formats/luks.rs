//! LUKS header parser: emits `$luks$` lines with the hexed header, base64
//! cipher buffer and master-key digest. Only AES/cbc-essiv:sha256/sha1
//! combos are accepted; the best (lowest-iteration) active keyslot is used.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use base64::Engine;

pub struct Luks;

/// LUKS header magic `LUKS\xba\xbe`.
const LUKS_MAGIC: &[u8] = b"LUKS\xba\xbe";
/// LUKS header size in bytes.
const HEADER_SIZE: usize = 592;
/// Number of keyslots in the LUKS header.
const LUKS_NUMKEYS: usize = 8;
/// Size of one keyslot metadata block in the header (bytes).
const SLOT_SIZE: usize = 48;

impl Extractor for Luks {
    fn name(&self) -> &'static str {
        "luks"
    }

    fn description(&self) -> &'static str {
        "LUKS files / disk images"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(LUKS_MAGIC)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < HEADER_SIZE {
            return Ok(Vec::new()); // header too short: no output
        }
        let magic = &data[..LUKS_MAGIC.len()];
        if magic != LUKS_MAGIC {
            return Ok(Vec::new()); // magic mismatch: no output
        }
        let cipher_name = &data[8..40];
        let cipher_mode = &data[40..72];
        let hash_spec = &data[72..104];
        let key_bytes = u32::from_be_bytes(data[104..108].try_into().expect("4")) as usize;
        let mk_digest = &data[112..132];
        let _mk_digest_salt = &data[132..164];
        let _mk_digest_iterations = u32::from_be_bytes(data[164..168].try_into().expect("4"));
        if !cipher_name.starts_with(b"aes\x00") {
            return Ok(Vec::new());
        }
        if !cipher_mode.starts_with(b"cbc-essiv:sha256\x00") {
            return Ok(Vec::new());
        }
        if !hash_spec.starts_with(b"sha1\x00") {
            return Ok(Vec::new());
        }

        // find the best (lowest-iteration) active keyslot
        let mut best_iterations = u32::MAX;
        let mut best_key_material_offset: Option<u32> = None;
        // NOTE: the AF size is derived from the `stripes` value of the LAST
        // iterated slot (slot 7), not the best slot's — a quirk that is kept
        // for output compatibility.
        let mut last_stripes: u32 = 0;
        for slot in 0..LUKS_NUMKEYS {
            let offset = 208 + slot * SLOT_SIZE;
            if offset + SLOT_SIZE > data.len() {
                break;
            }
            let active = u32::from_be_bytes(data[offset..offset + 4].try_into().expect("4"));
            let password_iterations =
                u32::from_be_bytes(data[offset + 4..offset + 8].try_into().expect("4"));
            let key_material_offset =
                u32::from_be_bytes(data[offset + 40..offset + 44].try_into().expect("4"));
            let stripes = u32::from_be_bytes(data[offset + 44..offset + 48].try_into().expect("4"));
            last_stripes = stripes;
            if password_iterations < best_iterations
                && password_iterations > 1
                && active == 0x00ac_71f3
            {
                best_iterations = password_iterations;
                best_key_material_offset = Some(key_material_offset);
            }
        }
        let Some(key_material_offset) = best_key_material_offset else {
            return Ok(Vec::new()); // no usable slot
        };

        // af size = ceil(keyBytes * stripes / 512) * 512, with the
        // last-iterated stripes value (see NOTE above)
        let af_size = (key_bytes * last_stripes as usize).div_ceil(512) * 512;
        let start = key_material_offset as usize * 512;
        let cipher_buffer = data
            .get(start..(start + af_size).min(data.len()))
            .unwrap_or(&[]);

        let header_hex = hex::encode(&data[..HEADER_SIZE]);
        let cipherbuf_b64 = base64::engine::general_purpose::STANDARD.encode(cipher_buffer);
        let mk_digest_hex = hex::encode(mk_digest);
        Ok(vec![HashLine::new(
            String::new(),
            format!("$luks$1${HEADER_SIZE}${header_hex}${af_size}${cipherbuf_b64}${mk_digest_hex}"),
        )])
    }
}
