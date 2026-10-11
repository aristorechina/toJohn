//! MultiBit Classic (.key, v1), MultiBit HD (mbhd.wallet.aes, v2) and
//! protobuf `.wallet` (v3) parsers, emitting `$multibit$1/2/3` lines. The v3
//! path uses a minimal protobuf-wire walk of the Wallet message (field 5
//! encryption_type, field 6 scrypt params, field 3 keys → field 6 → field 2).

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Multibit;

impl Extractor for Multibit {
    fn name(&self) -> &'static str {
        "multibit"
    }

    fn description(&self) -> &'static str {
        "MultiBit Classic / HD wallet files (.key, mbhd.wallet.aes, .wallet)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.first() == Some(&0x0a)
            || input.data.starts_with(b"Salted__")
            || crate::util::find(&input.data, b"org.bitcoin.production").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let name = util::basename(input.label());

        // protobuf wallet path: if the wallet check does not match, fall
        // through to the v1/v2 detection below.
        let is_v3_candidate =
            name.contains("wallet") || crate::util::find(data, b"org.bitcoin.production").is_some();
        if is_v3_candidate {
            let hashes = self.extract_v3_wallet(input, name)?;
            if !hashes.is_empty() {
                return Ok(hashes);
            }
        }

        // MultiBit Classic (v1) / HD (v2)
        let stripped: Vec<u8> = data
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        if stripped.len() < 64 {
            return Ok(Vec::new()); // too short for a MultiBit wallet file
        }
        let engine = base64::engine::general_purpose::STANDARD;
        if let Ok(decoded) = engine.decode(&stripped[..64]) {
            if decoded.starts_with(b"Salted__") && decoded.len() >= 48 {
                let salt = hex::encode(&decoded[8..16]);
                let encrypted_data = hex::encode(&decoded[16..48]);
                return Ok(vec![HashLine::new(
                    name.to_string(),
                    format!("{name}:$multibit$1*{salt}*{encrypted_data}"),
                )]);
            }
        }
        // v2: three 16-byte blocks
        if data.len() < 32 {
            return Ok(Vec::new());
        }
        let iv = hex::encode(&data[..16]);
        let block_iv = hex::encode(&data[16..32]);
        let block_noiv = hex::encode(&data[..16]);
        Ok(vec![HashLine::new(
            name.to_string(),
            format!("{name}:$multibit$2*{iv}*{block_iv}*{block_noiv}"),
        )])
    }
}

impl Multibit {
    fn extract_v3_wallet(&self, input: &Input, name: &str) -> Result<Vec<HashLine>> {
        const VERSION: u32 = 3; // hash-line version for the protobuf wallet path
        let data = &input.data;
        // wallet sanity check: protobuf key byte, network-name length and the
        // field tag that follows
        if data.first() != Some(&0x0A) {
            return Ok(Vec::new());
        }
        let Some(&net_len_byte) = data.get(1) else {
            return Ok(Vec::new());
        };
        let net_len = usize::from(net_len_byte);
        if !(1..128).contains(&net_len) {
            return Ok(Vec::new());
        }
        if !matches!(data.get(2 + net_len), Some(0x12) | Some(0x1a)) {
            return Ok(Vec::new());
        }

        // minimal protobuf walk of the Wallet message
        let mut encryption_type: u64 = 1; // UNENCRYPTED
        let mut salt: Vec<u8> = Vec::new();
        let mut n: u64 = 16384;
        let mut r: u64 = 8;
        let mut p: u64 = 1;
        let mut part_encrypted_key: Option<Vec<u8>> = None;
        let mut fields = ProtoFields::new(data);
        // Walk top-level fields: 5 = encryption_type (varint), 6 =
        // encryption_parameters (message), 3 = key (message, repeated)
        while let Some((field_no, wire)) = fields.next() {
            match (field_no, wire) {
                (5, 0) => {
                    encryption_type = fields.varint()?.ok_or_else(truncated_varint)?;
                }
                (6, 2) => {
                    let msg = fields.bytes()?;
                    if salt.is_empty() {
                        let mut sub = ProtoFields::new(msg);
                        while let Some((sf, sw)) = sub.next() {
                            match (sf, sw) {
                                (1, 2) => salt = sub.bytes()?.to_vec(),
                                (2, 0) => n = sub.varint()?.ok_or_else(truncated_varint)?,
                                (3, 0) => r = sub.varint()?.ok_or_else(truncated_varint)?,
                                (4, 0) => p = sub.varint()?.ok_or_else(truncated_varint)?,
                                (_, 2) => {
                                    sub.bytes()?;
                                }
                                (_, 0) => {
                                    sub.varint()?.ok_or_else(truncated_varint)?;
                                }
                                _ => return Ok(Vec::new()),
                            }
                        }
                    } else {
                        fields.skip(wire)?;
                    }
                }
                (3, 2) => {
                    let msg = fields.bytes()?;
                    if part_encrypted_key.is_none() {
                        // key: 1 type (varint), 6 encrypted_data (message)
                        let mut sub = ProtoFields::new(msg);
                        let mut key_type: u64 = 0;
                        while let Some((kf, kw)) = sub.next() {
                            match (kf, kw) {
                                (1, 0) => key_type = sub.varint()?.ok_or_else(truncated_varint)?,
                                (6, 2) => {
                                    let encrypted_data = sub.bytes()?;
                                    if key_type == 2 || key_type == 4 {
                                        // EncryptedData { 1 iv, 2 encrypted_private_key }
                                        let mut encrypted = ProtoFields::new(encrypted_data);
                                        while let Some((ef, ew)) = encrypted.next() {
                                            match (ef, ew) {
                                                (1, 2) => {
                                                    encrypted.bytes()?;
                                                }
                                                (2, 2) => {
                                                    let encrypted_private_key =
                                                        encrypted.bytes()?.to_vec();
                                                    if encrypted_private_key.len() == 48 {
                                                        part_encrypted_key = Some(
                                                            encrypted_private_key[16..].to_vec(),
                                                        );
                                                    }
                                                }
                                                _ => return Ok(Vec::new()),
                                            }
                                        }
                                    }
                                }
                                (_, 2) => {
                                    sub.bytes()?;
                                }
                                (_, 0) => {
                                    sub.varint()?.ok_or_else(truncated_varint)?;
                                }
                                _ => return Ok(Vec::new()),
                            }
                        }
                    } else {
                        fields.skip(wire)?;
                    }
                }
                (_, 2) => {
                    fields.skip(wire)?;
                }
                (_, 0) => {
                    fields.varint()?.ok_or_else(truncated_varint)?;
                }
                _ => return Ok(Vec::new()),
            }
        }

        if encryption_type != 2 {
            // UNENCRYPTED or unsupported encryption type: no hash
            return Ok(Vec::new());
        }
        let Some(part) = part_encrypted_key else {
            return Ok(Vec::new());
        };
        Ok(vec![HashLine::new(
            name.to_string(),
            format!(
                "{name}:$multibit${VERSION}*{n}*{r}*{p}*{}*{}",
                hex::encode(salt),
                hex::encode(part)
            ),
        )])
    }
}

/// Error for a varint that runs past the end of its message.
fn truncated_varint() -> crate::error::Error {
    crate::error::Error::other("truncated varint")
}

/// Minimal protobuf wire-format walker.
struct ProtoFields<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ProtoFields<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn varint(&mut self) -> Result<Option<u64>> {
        let mut v: u64 = 0;
        let mut shift = 0;
        loop {
            let Some(&b) = self.data.get(self.pos) else {
                return Ok(None);
            };
            self.pos += 1;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(Some(v));
            }
            shift += 7;
            if shift > 63 {
                return Err(crate::error::Error::other("protobuf varint too long"));
            }
        }
    }

    /// Returns (field_number, wire_type) or None at end.
    fn next(&mut self) -> Option<(u64, u8)> {
        let key = self.varint().ok()??;
        Some((key >> 3, (key & 7) as u8))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let len = self
            .varint()?
            .ok_or_else(|| crate::error::Error::other("truncated"))? as usize;
        if self.pos + len > self.data.len() {
            return Err(crate::error::Error::other("truncated protobuf field"));
        }
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    fn skip(&mut self, wire: u8) -> Result<()> {
        match wire {
            0 => {
                self.varint()?;
            }
            2 => {
                self.bytes()?;
            }
            _ => return Err(crate::error::Error::other("unsupported wire type")),
        }
        Ok(())
    }
}
