//! Ansible Vault `.yml` parser: reads the `$ANSIBLE_VAULT` header and the
//! hex-decoded body, emitting `$ansible$` lines for AES256 vaults. Files not
//! starting with the header, and unsupported ciphers, produce no output.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Ansible;

const HEADER: &[u8] = b"$ANSIBLE_VAULT";

impl Extractor for Ansible {
    fn name(&self) -> &'static str {
        "ansible"
    }

    fn description(&self) -> &'static str {
        "Ansible Vault .yml files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(HEADER)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if !data.starts_with(HEADER) {
            return Ok(Vec::new());
        }
        let lines: Vec<&[u8]> = util::splitlines(data).collect();
        // header line is ';'-separated; the cipher name is the 3rd field
        let header = util::strip(lines[0]);
        let Some(cipher_field) = header.split(|&b| b == b';').nth(2) else {
            return Err(Error::malformed(
                input.label(),
                "vault header has fewer than 3 ';'-fields",
            ));
        };
        let cipher_name = util::strip(cipher_field);
        let hex_body: Vec<u8> = lines[1..].concat();
        let decoded = hex::decode(&hex_body)
            .map_err(|e| Error::malformed(input.label(), format!("body is not valid hex: {e}")))?;
        let parts: Vec<&[u8]> = decoded.split(|&b| b == b'\n').collect();
        // decoded body must contain exactly 3 newline-separated fields
        let [salt, checksum, ciphertext] = parts.as_slice() else {
            return Err(Error::malformed(
                input.label(),
                "decoded body does not contain exactly 3 newline-separated fields",
            ));
        };
        if cipher_name != b"AES256" {
            // unsupported cipher: produce no output
            return Ok(Vec::new());
        }
        let salt = String::from_utf8_lossy(salt);
        let checksum = String::from_utf8_lossy(checksum);
        let ciphertext = String::from_utf8_lossy(ciphertext);
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:$ansible$0*0*{salt}*{ciphertext}*{checksum}"),
        )])
    }
}
