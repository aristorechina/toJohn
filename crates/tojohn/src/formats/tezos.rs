//! Two modes: a Tezos faucet JSON file as primary input, or
//! `["mnemonic words...", "email", "tz1-address"]` in `input.extra_args`.
//! Emits `dummy:$tezos$1*2048*...` lines. Includes a minimal base58check
//! decoder.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use sha2::{Digest, Sha256};

pub struct Tezos;

/// The Base58 alphabet used by Tezos addresses.
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

impl Extractor for Tezos {
    fn name(&self) -> &'static str {
        "tezos"
    }

    fn description(&self) -> &'static str {
        "Tezos faucet JSON files or mnemonic+email+address extra args"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.trim_ascii_start().starts_with(b"{")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let (mnemonic, email, address) =
            if let [mnemonic, email, address, ..] = input.extra_args.as_slice() {
                (mnemonic.clone(), email.clone(), address.clone())
            } else {
                let json: serde_json::Value = serde_json::from_slice(&input.data).map_err(|e| {
                    Error::malformed(input.label(), format!("not a faucet JSON file: {e}"))
                })?;
                let mnemonic = json
                    .get("mnemonic")
                    .and_then(|v| v.as_array())
                    .map(|words| {
                        words
                            .iter()
                            .filter_map(|w| w.as_str())
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                let email = json
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let address = json
                    .get("pkh")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                (mnemonic, email, address)
            };

        let raw_address =
            hex::encode(decode_b58check(address.as_bytes()).map_err(|e| {
                Error::malformed(input.label(), format!("invalid tezos address: {e}"))
            })?);

        Ok(vec![HashLine::new(
            "dummy".to_string(),
            format!("dummy:$tezos$1*2048*{mnemonic}*{email}*{address}*{raw_address}"),
        )])
    }
}

/// SHA-256 applied twice.
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let inner: [u8; 32] = Sha256::digest(data).into();
    Sha256::digest(inner).into()
}

/// Base58check decode: returns the payload after the version byte with the
/// trailing 4-byte checksum stripped. Checksum mismatch maps to `Err`.
fn decode_b58check(input: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let leading_zeros = input.iter().take_while(|&&byte| byte == b'1').count();
    let value = decode_b58(input)?;
    let mut data = vec![0u8; leading_zeros];
    data.extend_from_slice(&value);
    if data.len() < 5 {
        return Err("data too short".to_string());
    }
    let (payload, checksum) = data.split_at(data.len() - 4);
    if double_sha256(payload)[..4] != *checksum {
        return Err("base58 checksum mismatch".to_string());
    }
    Ok(payload[1..].to_vec())
}

/// Base58 to raw bytes: big-endian minimal byte form.
fn decode_b58(input: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::new(); // little-endian accumulation
    for &byte in input {
        let value = BASE58_ALPHABET
            .iter()
            .position(|&a| a == byte)
            .ok_or_else(|| format!("invalid base58 character {:?}", byte as char))?
            as u32;
        let mut carry = value;
        for digit in out.iter_mut() {
            carry += (*digit as u32) * 58;
            *digit = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.push(carry as u8);
            carry >>= 8;
        }
    }
    // no leading zero bytes are emitted for the value; the leading '1's
    // were handled separately
    while out.last() == Some(&0) {
        out.pop();
    }
    out.reverse();
    Ok(out)
}
