//! Parses Oracle PS_TOKEN cookies (cookie value provided via
//! `input.extra_args[0]`) into `$dynamic_1600$` lines.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use base64::Engine;
use flate2::read::ZlibDecoder;
use sha1::{Digest, Sha1};
use std::io::Read;

pub struct PsToken;

impl Extractor for PsToken {
    fn name(&self) -> &'static str {
        "ps_token"
    }

    fn description(&self) -> &'static str {
        "Oracle PS_TOKEN cookies (cookie passed via extra args)"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Some(cookie) = input.extra_args.first() else {
            return Err(Error::other("ps_token: cookie required in extra args"));
        };
        let engine = base64::engine::general_purpose::STANDARD;
        let decoded_cookie = engine
            .decode(cookie.trim())
            .map_err(|e| Error::malformed(input.label(), format!("cookie is not base64: {e}")))?;
        if decoded_cookie.len() < 76 {
            return Err(Error::malformed(input.label(), "cookie too short"));
        }
        let sha_mac = hex::encode(&decoded_cookie[44..64]);
        let compressed_data = &decoded_cookie[76..];
        let mut decoder = ZlibDecoder::new(compressed_data);
        let mut data = Vec::new();
        decoder
            .read_to_end(&mut data)
            .map_err(|e| Error::malformed(input.label(), format!("zlib decompress failed: {e}")))?;

        let data_sha1 = hex::encode(Sha1::digest(&data));

        let user_length = *data
            .get(20)
            .ok_or_else(|| Error::malformed(input.label(), "compressed data too short"))?
            as usize;
        let end = 21 + user_length;
        if end > data.len() {
            return Err(Error::malformed(
                input.label(),
                "user field extends past compressed data",
            ));
        }
        let user: Vec<u8> = data[21..end].iter().copied().filter(|&b| b != 0).collect();
        let user = String::from_utf8_lossy(&user);

        if data_sha1 == sha_mac {
            Ok(vec![HashLine::new(
                user.to_string(),
                format!("{user}: there is no password for the attacking node!"),
            )])
        } else {
            Ok(vec![HashLine::new(
                user.to_string(),
                format!("{user}:$dynamic_1600${sha_mac}$HEX${}", hex::encode(&data)),
            )])
        }
    }
}
