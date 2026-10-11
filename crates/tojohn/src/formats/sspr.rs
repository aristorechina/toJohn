//! NetIQ SSPR response-set parser: walks the `response` elements of the
//! `pwmResponseSet` XML blob (as stored in LDAP) and emits crackable hash
//! lines for the challenge/answer formats MD5, SHA1, SHA1_SALT, SHA256_SALT,
//! SHA512_SALT, PBKDF2, PBKDF2_SHA256, PBKDF2_SHA512, BCRYPT and SCRYPT.
//! The XML blob is the input; the LDAP transport itself is out of scope.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Sspr;

impl Extractor for Sspr {
    fn name(&self) -> &'static str {
        "sspr"
    }

    fn description(&self) -> &'static str {
        "NetIQ SSPR pwmResponseSet XML blobs (as stored in LDAP)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"ResponseSet").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let Some(xml_start) = util::find(data, b"<?xml version") else {
            return Ok(Vec::new());
        };
        let xml = &data[xml_start..];
        let Ok(root) = crate::xml::parse(xml) else {
            return Ok(Vec::new());
        };
        let user = input.label();
        let b64 = base64::engine::general_purpose::STANDARD;
        let mut out = Vec::new();

        let response_sets = root.find_all_descendants("ResponseSet");
        let responses: Vec<&crate::xml::Element> = response_sets
            .iter()
            .flat_map(|response_set| response_set.find_all_descendants("response"))
            .collect();
        for question in responses {
            let challenges = question.find_all_descendants("challenge");
            let challenge = challenges
                .first()
                .map(|entry| entry.text.trim().to_string())
                .unwrap_or_default();
            let answers = question.find_all_descendants("answer");
            let Some(answer) = answers.first() else {
                continue;
            };
            let format_name = answer.get("format").unwrap_or("").to_string();
            let hashcount = answer.get("hashcount").unwrap_or("0").to_string();
            let salt = answer.get("salt").unwrap_or("NONE").to_string();
            let text = answer.text.trim().to_string();

            let mut format_code: i64 = -1;
            match format_name.as_str() {
                "SHA1_SALT" => format_code = 2,
                "SHA1" => format_code = 1,
                "MD5" => format_code = 0,
                "SHA256_SALT" => format_code = 3,
                "SHA512_SALT" => format_code = 4,
                "PBKDF2" => {
                    let hash_hex = hex::encode(b64.decode(text.trim()).unwrap_or_default());
                    let hash_hex = &hash_hex[..40.min(hash_hex.len())];
                    let salt_hex = hex::encode(salt.as_bytes());
                    out.push(HashLine::new(
                        user.to_string(),
                        format!(
                            "{user}:$pbkdf2-hmac-sha1${hashcount}${salt_hex}${hash_hex}:::::{challenge}"
                        ),
                    ));
                }
                "PBKDF2_SHA256" => {
                    let raw = b64.decode(text.trim()).unwrap_or_default();
                    let adapted = |bytes: &[u8]| -> String {
                        base64::engine::general_purpose::STANDARD
                            .encode(bytes)
                            .trim_end_matches('=')
                            .replace('+', ".")
                    };
                    let hash_adapted = adapted(&raw[..32.min(raw.len())]);
                    let salt_adapted = adapted(salt.as_bytes());
                    out.push(HashLine::new(
                        user.to_string(),
                        format!(
                            "{user}:$pbkdf2-sha256${hashcount}${salt_adapted}${hash_adapted}:::::{challenge}"
                        ),
                    ));
                }
                "PBKDF2_SHA512" => {
                    let hash_hex = hex::encode(b64.decode(text.trim()).unwrap_or_default());
                    let hash_hex = &hash_hex[..128.min(hash_hex.len())];
                    let salt_hex = hex::encode(salt.as_bytes());
                    out.push(HashLine::new(
                        user.to_string(),
                        format!(
                            "{user}:$pbkdf2-hmac-sha512${hashcount}.{salt_hex}.{hash_hex}:::::{challenge}"
                        ),
                    ));
                }
                "BCRYPT" => {
                    out.push(HashLine::new(
                        user.to_string(),
                        format!("{user}:{text}:::::{challenge}"),
                    ));
                }
                "SCRYPT" => {
                    // $s0$e0801$salt$key
                    let parts: Vec<&str> = text.split('$').collect();
                    if parts.len() < 5 {
                        continue;
                    }
                    let Ok(packed) = i64::from_str_radix(parts[2], 16) else {
                        continue;
                    };
                    let parallelism = packed & 0xFF;
                    let block_size = (packed & 0xFF00) >> 8;
                    let cost = 1i64 << ((packed & 0xFF0000) >> 16);
                    out.push(HashLine::new(
                        user.to_string(),
                        format!(
                            "{user}:$ScryptKDF.pm${cost}*{block_size}*{parallelism}*{}*{}:::::{challenge}",
                            parts[3], parts[4]
                        ),
                    ));
                }
                _ => {}
            }

            if format_code != -1 {
                // skip over the "B:" prefix
                let body = if text.len() >= 2 { &text[2..] } else { "" };
                let hash_hex = hex::encode(b64.decode(body.trim()).unwrap_or_default());
                let salt_hex = hex::encode(salt.as_bytes());
                out.push(HashLine::new(
                    user.to_string(),
                    format!("{user}:$sspr${format_code}${hashcount}${salt_hex}${hash_hex}:::::{challenge}"),
                ));
            }
        }
        Ok(out)
    }
}
