//! SSH private key parser (PKCS#1 RSA/DSA, EC, and the OpenSSH new format).
//! Emits `$sshng$` lines. Supports the PEM ciphers DES-EDE3-CBC,
//! AES-128-CBC, AES-192-CBC and AES-256-CBC.

use base64::Engine;

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Ssh;

/// PEM DEK-Info cipher name to cipher key size.
fn cipher_key_size(name: &str) -> Option<usize> {
    match name {
        "AES-128-CBC" => Some(16),
        "DES-EDE3-CBC" => Some(24),
        "AES-256-CBC" => Some(32),
        "AES-192-CBC" => Some(24),
        _ => None,
    }
}

impl Extractor for Ssh {
    fn name(&self) -> &'static str {
        "ssh"
    }

    fn description(&self) -> &'static str {
        "SSH private key files (RSA/DSA/EC/OpenSSH)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"BEGIN ").is_some()
            && util::find(&input.data, b"PRIVATE KEY").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let text = String::from_utf8_lossy(&input.data);
        let lines: Vec<&str> = text.split('\n').collect();
        let all_lines: String = lines.concat();

        // key type detection (checked in this order)
        let (key_type, tag): (i32, &str) = if all_lines.contains("BEGIN RSA PRIVATE") {
            (0, "RSA")
        } else if all_lines.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
            (2, "OPENSSH")
        } else if all_lines.contains("-----BEGIN DSA PRIVATE KEY-----") {
            (1, "DSA")
        } else if all_lines.contains("-----BEGIN EC PRIVATE KEY-----") {
            (3, "EC")
        } else {
            return Ok(Vec::new()); // unrecognized key type
        };

        let strip = |s: &str| -> String {
            s.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'))
                .to_string()
        };
        let begin_marker = format!("-----BEGIN {tag} PRIVATE KEY-----");
        let openssh_marker = "-----BEGIN OPENSSH PRIVATE KEY-----";
        let end_marker = format!("-----END {tag} PRIVATE KEY-----");
        let mut start = 0usize;
        while start < lines.len()
            && strip(lines[start]) != begin_marker
            && strip(lines[start]) != openssh_marker
        {
            start += 1;
        }
        if start >= lines.len() {
            return Ok(Vec::new()); // BEGIN marker not found
        }

        // parse headers
        let mut headers: Vec<(String, String)> = Vec::new();
        start += 1;
        while start < lines.len() {
            let parts: Vec<&str> = lines[start].splitn(2, ": ").collect();
            if parts.len() == 1 {
                break;
            }
            headers.push((parts[0].to_lowercase(), strip(parts[1])));
            start += 1;
        }
        // find the END marker
        let mut end = start;
        loop {
            if end >= lines.len() {
                return Err(Error::malformed(input.label(), "no END marker"));
            }
            if strip(lines[end]) == end_marker {
                break;
            }
            end += 1;
        }

        let body: String = lines[start..end].concat();
        let b64 = base64::engine::general_purpose::STANDARD;
        let data = b64
            .decode(
                body.chars()
                    .filter(|c: &char| !c.is_ascii_whitespace())
                    .collect::<String>()
                    .as_str(),
            )
            .map_err(|e| Error::malformed(input.label(), format!("base64 decoding error: {e}")))?;

        let has_proc_type = headers.iter().any(|(key, _)| key == "proc-type");
        if !has_proc_type && key_type != 2 {
            return Ok(Vec::new()); // unencrypted key: no password to recover
        }

        let (encryption_type, salt_hex): (String, String) =
            match headers.iter().find(|(key, _)| key == "dek-info") {
                Some((_, value)) => {
                    let mut parts = value.splitn(2, ',');
                    let cipher = parts.next().unwrap_or("").to_string();
                    let salt = parts.next().unwrap_or("").to_string();
                    (cipher, salt)
                }
                None => {
                    if key_type != 2 {
                        return Err(Error::other("can't parse DEK-info in private key file"));
                    }
                    // OpenSSH keys carry the KDF parameters in the blob
                    ("AES-256-CBC".to_string(), "fefe".to_string())
                }
            };
        let Some(key_size) = cipher_key_size(&encryption_type) else {
            return Err(Error::other(format!(
                "unknown private key cipher \"{encryption_type}\""
            )));
        };

        // hex decode tolerating odd length and invalid digits (mapped to 0)
        let unhex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
                .collect()
        };
        let salt_bytes = unhex(&salt_hex);

        let data_hex = hex::encode(&data);
        let label = input.label();

        let mut openssh_salt_hex = String::new();
        let mut rounds: u32 = 0;
        let mut ciphertext_begin: usize = 0;
        if key_type == 2 {
            // OpenSSH key blob: magic, cipher name, KDF name, KDF options
            // (bcrypt_pbkdf salt and rounds), public key, encrypted section
            const AUTH_MAGIC: &[u8] = b"openssh-key-v1";
            const SALT_LENGTH: usize = 16;
            if !data.starts_with(AUTH_MAGIC) {
                return Err(Error::other("missing AUTH_MAGIC"));
            }
            let be32 = |offset: usize| -> u32 {
                u32::from_be_bytes(data[offset..offset + 4].try_into().expect("4 bytes"))
            };
            let mut offset = AUTH_MAGIC.len() + 1;
            let length = be32(offset) as usize; // ciphername length
            if length > 32 {
                return Err(Error::other("unknown ciphername"));
            }
            offset += 4 + length;
            let length = be32(offset) as usize; // kdfname length
            offset += 4 + length;
            let length = be32(offset) as usize; // kdf length
            let salt_offset = offset + 4 + 4;
            offset += 4 + length; // number of keys
            offset += 4; // pubkey blob
            let length = be32(offset) as usize; // pubkey length
            offset += 4 + length;
            offset += 4; // skip over length of "encrypted" blob
            if offset > data.len() {
                return Err(Error::other("computed offset beyond key data"));
            }
            ciphertext_begin = offset;
            openssh_salt_hex =
                hex::encode(&data[salt_offset..(salt_offset + SALT_LENGTH).min(data.len())]);
            let rounds_offset = salt_offset + SALT_LENGTH;
            rounds = be32(rounds_offset);
            if rounds == 0 {
                rounds = 16; // default when the round count field is zero
            }
        }

        let data_len = data.len();
        let hash_line = if key_size == 24
            && encryption_type == "AES-192-CBC"
            && (key_type == 0 || key_type == 1)
        {
            format!(
                "{label}:$sshng$4${}${}${data_len}${data_hex}",
                salt_hex.len() / 2,
                salt_hex
            )
        } else if key_size == 32
            && encryption_type == "AES-256-CBC"
            && (key_type == 0 || key_type == 1)
        {
            format!(
                "{label}:$sshng$5${}${}${data_len}${data_hex}",
                salt_hex.len() / 2,
                salt_hex
            )
        } else if key_size == 24 {
            format!(
                "{label}:$sshng$0${}${}${data_len}${data_hex}",
                salt_bytes.len(),
                salt_hex
            )
        } else if key_size == 16 && (key_type == 0 || key_type == 1) {
            format!(
                "{label}:$sshng$1${}${}${data_len}${data_hex}",
                salt_hex.len() / 2,
                salt_hex
            )
        } else if key_size == 16 && key_type == 3 {
            format!(
                "{label}:$sshng$3${}${}${data_len}${data_hex}",
                salt_hex.len() / 2,
                salt_hex
            )
        } else if key_size == 32 && key_type == 2 {
            format!(
                "{label}:$sshng$2${}${}${data_len}${data_hex}${rounds}${ciphertext_begin}",
                openssh_salt_hex.len() / 2,
                openssh_salt_hex
            )
        } else {
            return Ok(Vec::new()); // unsupported cipher/key-type combination
        };
        Ok(vec![HashLine::new(label.to_string(), hash_line)])
    }
}
