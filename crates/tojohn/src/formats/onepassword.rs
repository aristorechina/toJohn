//! 1Password parser with three paths:
//!
//! - **sqlite** (1Password 6 for macOS): `OnePassword.sqlite` with a
//!   `profiles` table (master_key_data, salt, iterations)
//! - **CloudKeychain/OPVault**: `<path>/default/profile.js` (JSON with a 12
//!   byte offset prefix and a trailing separator)
//! - **AgileKeychain**: `<path>/data/default/encryptionKeys.js`
//!
//! The composite inputs (folder / sqlite) are provided via `extra_files`:
//! - sqlite path: primary input is the .sqlite file content (label contains
//!   "sqlite")
//! - profile.js path: primary input is the profile.js content, label is the
//!   vault folder; the JS prefix/suffix is trimmed before parsing
//! - encryptionKeys.js: primary input, label is the keychain folder

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct OnePassword;

/// profile.js content starts after this many prefix bytes.
const INITIAL_KEY_OFFSET: usize = 12;
/// opdata1 trailer length: HMAC-SHA256 digest.
const HMAC_LENGTH: usize = 32;
/// Length of the `opdata01` magic.
const HEADER_LENGTH: usize = 8;
/// opdata1 header: magic, 8-byte plaintext length and 16-byte IV.
const TOTAL_HEADER_LENGTH: usize = 32;

impl Extractor for OnePassword {
    fn name(&self) -> &'static str {
        "1password"
    }

    fn description(&self) -> &'static str {
        "1Password Agile/Cloud Keychains and OnePassword.sqlite"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"SQLite format 3")
            || util::find(&input.data, b"opdata01").is_some()
            || util::find(&input.data, b"encryptionKeys").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        if input.label().contains("sqlite") || input.data.starts_with(b"SQLite format 3") {
            return self.sqlite(input);
        }
        // profile.js (CloudKeychain) or encryptionKeys.js (AgileKeychain)
        if util::find(&input.data, b"\"masterKey\"").is_some()
            && !util::find(&input.data, b"\"list\"").is_some()
        {
            return self.cloud_keychain(input);
        }
        self.agile_keychain(input)
    }
}

/// Unpacked opdata1 blob: (plaintext_length, iv, cryptext, expected_hmac,
/// hmac_d_data).
struct Opdata1 {
    plaintext_length: u64,
    iv: Vec<u8>,
    cryptext: Vec<u8>,
    expected_hmac: Vec<u8>,
    hmac_d_data: Vec<u8>,
}

fn opdata1_unpack(data: &[u8], label: &str) -> Result<Opdata1> {
    let owned;
    let data: &[u8] = if data.len() >= HEADER_LENGTH && &data[..HEADER_LENGTH] == b"opdata01" {
        data
    } else {
        let engine = base64::engine::general_purpose::STANDARD;
        owned = base64_decode(&engine, std::str::from_utf8(data).unwrap_or(""), label)?;
        &owned
    };
    if data.len() < TOTAL_HEADER_LENGTH || &data[..HEADER_LENGTH] != b"opdata01" {
        return Err(crate::error::Error::other(
            "expected opdata1 format message",
        ));
    }
    let plaintext_length = u64::from_le_bytes(
        data[HEADER_LENGTH..HEADER_LENGTH + 8]
            .try_into()
            .expect("8 bytes"),
    );
    let iv = data[HEADER_LENGTH + 8..TOTAL_HEADER_LENGTH].to_vec();
    if data.len() < TOTAL_HEADER_LENGTH + HMAC_LENGTH {
        return Err(crate::error::Error::malformed(
            label,
            "opdata1 payload too short",
        ));
    }
    let cryptext = data[TOTAL_HEADER_LENGTH..data.len() - HMAC_LENGTH].to_vec();
    let expected_hmac = data[data.len() - HMAC_LENGTH..].to_vec();
    let hmac_d_data = data[..data.len() - HMAC_LENGTH].to_vec();
    Ok(Opdata1 {
        plaintext_length,
        iv,
        cryptext,
        expected_hmac,
        hmac_d_data,
    })
}

fn base64_decode(
    engine: &base64::engine::GeneralPurpose,
    encoded: &str,
    label: &str,
) -> Result<Vec<u8>> {
    engine
        .decode(encoded.trim())
        .map_err(|e| crate::error::Error::malformed(label, format!("base64 decode failed: {e}")))
}

impl OnePassword {
    fn sqlite(&self, input: &Input) -> Result<Vec<HashLine>> {
        let tmp = super::applenotes::temp_write(&input.data)?;
        let db = rusqlite::Connection::open_with_flags(
            &tmp,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let mut stmt = db.prepare("SELECT master_key_data, salt, iterations FROM profiles")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let master_key: Vec<u8> = row.get(0)?;
            let salt: Vec<u8> = row.get(1)?;
            let iterations: i64 = row.get(2)?;
            let unpacked = opdata1_unpack(&master_key, input.label())?;
            out.push(HashLine::new(
                String::new(),
                format!(
                    "$cloudkeychain${}${}${}${}${}${}${}${}${}${}${}${}${}${}",
                    salt.len(),
                    hex::encode(salt),
                    iterations,
                    master_key.len(),
                    hex::encode(master_key),
                    unpacked.plaintext_length,
                    unpacked.iv.len(),
                    hex::encode(&unpacked.iv),
                    unpacked.cryptext.len(),
                    hex::encode(&unpacked.cryptext),
                    unpacked.expected_hmac.len(),
                    hex::encode(&unpacked.expected_hmac),
                    unpacked.hmac_d_data.len(),
                    hex::encode(&unpacked.hmac_d_data),
                ),
            ));
        }
        Ok(out)
    }

    fn cloud_keychain(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        // profile.js content is followed by one trailing separator byte
        let end = data.len().saturating_sub(1);
        let js = std::str::from_utf8(&data[INITIAL_KEY_OFFSET.min(end)..end])
            .map_err(|_| crate::error::Error::malformed(input.label(), "profile.js not UTF-8"))?;
        let parsed: serde_json::Value = serde_json::from_str(js.trim())
            .map_err(|e| crate::error::Error::malformed(input.label(), format!("{e}")))?;
        let engine = base64::engine::general_purpose::STANDARD;
        let salt = base64_decode(
            &engine,
            parsed["salt"].as_str().unwrap_or(""),
            input.label(),
        )?;
        let master_key_b64 = parsed["masterKey"].as_str().unwrap_or("");
        let master_key = base64_decode(&engine, master_key_b64, input.label())?;
        let iterations = parsed["iterations"].as_i64().unwrap_or(0);

        // note: the base64-DECODED masterKey is what gets unpacked here
        let unpacked = opdata1_unpack(&master_key, input.label())?;
        Ok(vec![HashLine::new(
            String::new(),
            format!(
                "$cloudkeychain${}${}${}${}${}${}${}${}${}${}${}${}${}${}",
                salt.len(),
                hex::encode(salt),
                iterations,
                master_key.len(),
                hex::encode(master_key),
                unpacked.plaintext_length,
                unpacked.iv.len(),
                hex::encode(&unpacked.iv),
                unpacked.cryptext.len(),
                hex::encode(&unpacked.cryptext),
                unpacked.expected_hmac.len(),
                hex::encode(&unpacked.expected_hmac),
                unpacked.hmac_d_data.len(),
                hex::encode(&unpacked.hmac_d_data),
            ),
        )])
    }

    fn agile_keychain(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let parsed: serde_json::Value = serde_json::from_slice(data)
            .map_err(|e| crate::error::Error::malformed(input.label(), format!("{e}")))?;
        let Some(list) = parsed.get("list").and_then(|v| v.as_array()) else {
            return Ok(Vec::new());
        };
        let engine = base64::engine::general_purpose::STANDARD;
        let mut line = format!("{}:$agilekeychain${}", input.label(), list.len());
        for key_entry in list {
            let data_field = key_entry.get("data").and_then(|v| v.as_str()).unwrap_or("");
            // fall back to stripping a trailing char before the base64
            // decode when the direct decode fails
            let trimmed = data_field.trim_end_matches(['\n', '\r']).as_bytes();
            let decoded = engine
                .decode(trimmed)
                .or_else(|_| {
                    engine.decode(
                        data_field
                            .get(..data_field.len().saturating_sub(1))
                            .unwrap_or(""),
                    )
                })
                .unwrap_or_default();
            let iterations = key_entry
                .get("iterations")
                .and_then(|v| v.as_i64())
                .unwrap_or(1000);
            // Salted__ prefix -> salt = data[8:16], key data = data[16:]
            let (salt, key_data) = if decoded.len() >= 16 && &decoded[..8] == b"Salted__" {
                (decoded[8..16].to_vec(), decoded[16..].to_vec())
            } else {
                (vec![0u8; 16], decoded)
            };
            line.push_str(&format!(
                "*{iterations}*{}*{}*{}*{}",
                salt.len(),
                hex::encode(salt),
                key_data.len(),
                hex::encode(key_data)
            ));
        }
        Ok(vec![HashLine::new(input.label().to_string(), line)])
    }
}
