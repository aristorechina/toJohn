//! LastPass hash extractor, emitting `$lp$` and `$lpcli$` hash lines. Two
//! modes:
//!
//! - **LastPass v3.x Firefox mode** (primary input = `*_lpall.slps` file,
//!   `input.extra_args[0]` = email, `input.extra_files[0]` = `*_key.itr`
//!   file): emits `$lp$` lines.
//! - **lastpass-cli mode** (a folder passed as primary input; the folder's
//!   `username`, `iterations` and `verify` files are provided as
//!   `input.extra_files` with those labels): emits `$lpcli$` lines.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Lastpass;

impl Extractor for Lastpass {
    fn name(&self) -> &'static str {
        "lastpass"
    }

    fn description(&self) -> &'static str {
        "LastPass v3.x slps+itr files or lastpass-cli folders"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false // no reliable single-file marker
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let find_extra = |label: &str| {
            input
                .extra_files
                .iter()
                .find(|f| f.label == label)
                .map(|f| f.data.clone())
        };
        if let (Some(username), Some(iterations), Some(verify)) = (
            find_extra("username"),
            find_extra("iterations"),
            find_extra("verify"),
        ) {
            return self.lastpass_cli(input, &username, &iterations, &verify);
        }
        self.lastpass_firefox(input)
    }
}

impl Lastpass {
    fn lastpass_cli(
        &self,
        input: &Input,
        username: &[u8],
        iterations: &[u8],
        verify: &[u8],
    ) -> Result<Vec<HashLine>> {
        let username = String::from_utf8_lossy(util::strip(username)).to_lowercase();
        let iterations = String::from_utf8_lossy(util::strip(iterations));
        // iv is bytes 32..48 of verify, ciphertext is bytes 48..64
        let iv = &verify[32.min(verify.len())..48.min(verify.len())];
        let ciphertext = &verify[48.min(verify.len())..64.min(verify.len())];
        let label = input.label();
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$lpcli$0${username}${iterations}${}${}",
                hex::encode(iv),
                hex::encode(ciphertext)
            ),
        )])
    }

    fn lastpass_firefox(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Some(email) = input.extra_args.first() else {
            return Err(Error::other("lastpass: email required in extra args"));
        };
        let Some(itr_file) = input.extra_files.first() else {
            return Err(Error::other(
                "lastpass: *_key.itr file required as extra file",
            ));
        };
        let lines: Vec<&[u8]> = util::lines(&input.data).collect();
        // the first line is ignored; the payload is the second line
        let data = lines.get(1).copied().unwrap_or(&[]);
        let iterations = String::from_utf8_lossy(util::strip(
            util::lines(&itr_file.data).next().unwrap_or(&[]),
        ));
        let engine = base64::engine::general_purpose::STANDARD;
        // trim before decoding (the decoder does not tolerate embedded
        // newlines)
        let decoded = engine
            .decode(std::str::from_utf8(data).unwrap_or("").trim())
            .map_err(|e| {
                Error::malformed(input.label(), format!("slps payload is not base64: {e}"))
            })?;
        let label = input.label();
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:$lp${email}${iterations}${}", hex::encode(decoded)),
        )])
    }
}
