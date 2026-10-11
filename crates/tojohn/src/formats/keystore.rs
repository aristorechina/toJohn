//! Sun/Java JKS keystore hash extractor, emitting
//! `$keystore$0$data_length$data$hash$nkeys$keylength$keydata...` hash
//! lines.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Keystore;

/// JKS magic `0xfeedfeed`.
const MAGIC: u32 = 0xfeed_feed;

impl Extractor for Keystore {
    fn name(&self) -> &'static str {
        "keystore"
    }

    fn description(&self) -> &'static str {
        "Java KeyStore (JKS) files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.len() >= 4 && u32::from_be_bytes(input.data[0..4].try_into().unwrap()) == MAGIC
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let read_u32 = |pos: &mut usize| -> Result<u32> {
            let bytes = data
                .get(*pos..*pos + 4)
                .ok_or_else(|| Error::malformed(input.label(), "truncated keystore"))?;
            *pos += 4;
            Ok(u32::from_be_bytes(bytes.try_into().expect("4 bytes")))
        };
        let mut pos = 0usize;
        let magic = read_u32(&mut pos)?;
        let version = read_u32(&mut pos)?;
        if magic != MAGIC || (version != 1 && version != 2) {
            return Ok(Vec::new()); // invalid magic or version: no output
        }
        let count = read_u32(&mut pos)?;
        let mut key_size: u32 = 0;
        let mut protected_priv_key: Vec<u8> = Vec::new();

        for _ in 0..count {
            let tag = read_u32(&mut pos)?;
            if tag == 1 {
                // alias: 1 unused byte + 1 length byte + data
                pos += 1;
                let length = *data
                    .get(pos)
                    .ok_or_else(|| Error::malformed(input.label(), "truncated alias"))?
                    as usize;
                pos += 1 + length;
                pos += 8; // timestamp
                key_size = read_u32(&mut pos)?;
                protected_priv_key = data
                    .get(pos..pos + key_size as usize)
                    .ok_or_else(|| Error::malformed(input.label(), "truncated key"))?
                    .to_vec();
                pos += key_size as usize;
                let cert_count = read_u32(&mut pos)?;
                for _ in 0..cert_count {
                    if version == 2 {
                        pos += 1; // cert type byte
                        let length = *data
                            .get(pos)
                            .ok_or_else(|| Error::malformed(input.label(), "truncated cert type"))?
                            as usize;
                        pos += 1 + length;
                    }
                    let cert_size = read_u32(&mut pos)?;
                    pos += cert_size as usize;
                }
            } else if tag == 2 {
                pos += 1; // 1-byte marker
                let length = *data
                    .get(pos)
                    .ok_or_else(|| Error::malformed(input.label(), "truncated alias"))?
                    as usize;
                pos += 1 + length;
                pos += 8; // timestamp
                if version == 2 {
                    pos += 1; // cert type byte
                    let length = *data
                        .get(pos)
                        .ok_or_else(|| Error::malformed(input.label(), "truncated cert type"))?
                        as usize;
                    pos += 1 + length;
                }
                let cert_size = read_u32(&mut pos)?;
                pos += cert_size as usize;
            } else {
                return Ok(Vec::new()); // unrecognized entry tag: no output
            }
        }

        let end = pos;
        let hash = data
            .get(pos..pos + 20)
            .ok_or_else(|| Error::malformed(input.label(), "missing keyed SHA1 hash"))?;

        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$keystore$0${end}${}${}${count}${key_size}${}:::::{label}",
                hex::encode(&data[..end]),
                hex::encode(hash),
                hex::encode(&protected_priv_key),
            ),
        )])
    }
}
