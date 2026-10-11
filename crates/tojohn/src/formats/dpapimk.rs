//! DPAPI masterkey file parser: reads the MasterKey block header fields
//! (version, IV, rounds, algorithms, ciphertext, SID) and emits `$DPAPImk$`
//! lines; the full masterkey decryption machinery is out of scope for hash
//! extraction.
//!
//! Input: the raw masterkey file as primary input; SID and context are
//! `extra_args` (`["<SID>", "local|domain|domain1607+|domain1607-"]`).

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Dpapimk;

impl Extractor for Dpapimk {
    fn name(&self) -> &'static str {
        "dpapimk"
    }

    fn description(&self) -> &'static str {
        "DPAPI masterkey files (extra args: SID, context)"
    }

    fn accepts(&self, input: &Input) -> bool {
        // version field (LE 1) plus one of the expected algorithm IDs:
        // 0x800c = SHA-512, 0x6604 = 3DES-112
        input.data.len() >= 180
            && input.data[8..12] == [0x01, 0x00, 0x00, 0x00]
            && (input.data[28..32] == [0x0c, 0x80, 0x00, 0x00]
                || input.data[28..32] == [0x04, 0x66, 0x00, 0x00])
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let sid = input.extra_args.first().cloned().unwrap_or_default();
        let context_arg = input.extra_args.get(1).cloned().unwrap_or_default();
        let data = &input.data;

        // MasterKeyFile header: version(4) + guid(16) + policy(4) + ...
        // MasterKey block starts at offset 48:
        // version L, iv 16s, rounds L, hashAlgo L, cipherAlgo L, ciphertext
        if data.len() < 48 + 32 {
            return Ok(Vec::new());
        }
        let master_key = &data[48..];
        let iv = &master_key[4..20];
        let rounds = u32::from_le_bytes(master_key[20..24].try_into().expect("4"));
        let hash_algo = u32::from_le_bytes(master_key[24..28].try_into().expect("4"));
        let cipher_algo = u32::from_le_bytes(master_key[28..32].try_into().expect("4"));
        let ciphertext = &master_key[32..];

        // crypto algorithm name mapping
        let cipher_name = match cipher_algo {
            0x6603 => "des3",
            0x6610 => "aes-256",
            _ => {
                return Err(Error::other(format!(
                "unsupported cipher '{cipher_algo}' and hash algorithm '{hash_algo}' combination"
            )))
            }
        };
        let (version, cipher_algo_name, hmac_algo_name) = match cipher_name {
            "des3" if hash_algo == 0x8004 => (1, "des3", "sha1"),
            "aes-256" if hash_algo == 0x800c => (2, "aes256", "sha512"),
            _ => {
                return Err(Error::other(format!(
                "unsupported cipher '{cipher_name}' and hash algorithm '{hash_algo}' combination"
            )))
            }
        };

        let iv_hex = hex::encode(iv);
        let ciphertext_hex = hex::encode(ciphertext);
        let ciphertext_len = ciphertext_hex.len();

        let render_line = |context: u32| -> String {
            format!(
                "$DPAPImk${version}*{context}*{sid}*{cipher_algo_name}*{hmac_algo_name}\
*{rounds}*{iv_hex}*{ciphertext_len}*{ciphertext_hex}"
            )
        };

        let lines = match context_arg.as_str() {
            "domain" => vec![render_line(2), render_line(3)],
            "local" => vec![render_line(1)],
            "domain1607-" => vec![render_line(2)],
            "domain1607+" => vec![render_line(3)],
            _ => {
                return Err(Error::other(
                    "missing or unsupported context extra arg (expected local, domain, domain1607+ or domain1607-)",
                ))
            }
        };
        Ok(lines.into_iter().map(HashLine::from_line).collect())
    }
}
