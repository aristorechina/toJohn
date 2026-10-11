//! Electrum wallet hash extractor, emitting `$electrum$` hash lines: 2.8+
//! encrypted wallets (BIE1), v1 wallets (seed_version 4) and 2.x keystore
//! wallets (bip32 xprv, old seed, imported keypairs).
//! The `-t` truncate option is enabled via "truncate" in `input.extra_args`.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Electrum;

impl Extractor for Electrum {
    fn name(&self) -> &'static str {
        "electrum"
    }

    fn description(&self) -> &'static str {
        "Electrum wallet files (v1 / 2.x / 2.8+)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"BIE1")
            || (input.data.starts_with(b"{")
                && (util::find(&input.data, b"\"wallet_type\"").is_some()
                    || util::find(&input.data, b"\"seed_version\"").is_some()))
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let raw = &input.data;
        let label = util::basename(input.label());
        let truncate = input
            .extra_args
            .iter()
            .any(|a| a == "truncate" || a == "-t");
        let engine = base64::engine::general_purpose::STANDARD;

        // detect Electrum 2.7+ encrypted wallets (BIE1 magic after b64decode)
        if let Ok(decoded) = engine.decode(std::str::from_utf8(raw).unwrap_or("").trim()) {
            if decoded.starts_with(b"BIE1") {
                return extract_bie1(label, decoded, truncate);
            }
        }

        let text = match std::str::from_utf8(raw) {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()), // non-UTF-8 wallet: no output
        };
        let Ok(wallet) = serde_json::from_str::<serde_json::Value>(text) else {
            return Ok(Vec::new()); // unparseable wallet JSON: no output
        };

        if wallet.get("use_encryption") == Some(&serde_json::Value::Bool(false)) {
            return Ok(Vec::new()); // unencrypted wallet: no output
        }

        let mut version: u32 = 0;
        if wallet.get("wallet_type").and_then(|v| v.as_str()) == Some("old") {
            version = 1;
        }

        let iv: Vec<u8>;
        let encrypted: Vec<u8>;

        if version == 1 {
            let seed_version = wallet
                .get("seed_version")
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            let seed = wallet.get("seed").and_then(|v| v.as_str()).unwrap_or("");
            let seed_data = engine.decode(seed.trim()).unwrap_or_default();
            if seed_data.len() != 64 {
                return Ok(Vec::new()); // unexpected seed length: no output
            }
            if seed_version == 4 {
                iv = seed_data[..16].to_vec();
                encrypted = seed_data[16..32].to_vec();
                let iv_hex = hex::encode(&iv);
                let enc_hex = hex::encode(&encrypted);
                return Ok(vec![HashLine::new(
                    label.to_string(),
                    format!("{label}:$electrum$1*{iv_hex}*{enc_hex}"),
                )]);
            }
            return Ok(Vec::new()); // v1: unsupported seed_version: no output
        }

        // not version 1 wallet
        let wallet_type = wallet
            .get("wallet_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if wallet_type.is_empty() {
            return Ok(Vec::new()); // unrecognized wallet_type: no output
        }
        let seed_version = wallet
            .get("seed_version")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);
        if ![11i64, 12, 13].contains(&seed_version) && wallet_type != "imported" {
            return Ok(Vec::new()); // unsupported seed_version for this wallet_type: no output
        }

        let mut xprv: Option<String> = None;
        version = 2;

        if let Some(keystore) = wallet.get("keystore") {
            let keystore_type = keystore
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("(not found)");
            match keystore_type {
                "bip32" => {
                    xprv = keystore
                        .get("xprv")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
                "old" => {
                    if let Some(seed) = keystore.get("seed").and_then(|v| v.as_str()) {
                        let seed_data = engine.decode(seed.trim()).unwrap_or_default();
                        if seed_data.len() != 64 {
                            return Err(Error::other(
                                "electrum v1 encrypted seed plus iv is not 64 bytes long",
                            ));
                        }
                        let iv = seed_data[..16].to_vec();
                        let encrypted = seed_data[16..32].to_vec();
                        return finalize(label, 1, &iv, &encrypted);
                    }
                }
                "imported" => {
                    if let Some(keypairs) = keystore.get("keypairs").and_then(|v| v.as_object()) {
                        for privkey in keypairs.values() {
                            let Some(pk) = privkey.as_str() else { continue };
                            let pk_data = engine.decode(pk.trim()).unwrap_or_default();
                            if pk_data.len() != 80 {
                                return Err(Error::other(
                                    "electrum v2 private key plus iv is not 80 bytes long",
                                ));
                            }
                            let iv = pk_data[pk_data.len() - 32..pk_data.len() - 16].to_vec();
                            let encrypted = pk_data[pk_data.len() - 16..].to_vec();
                            return finalize(label, 3, &iv, &encrypted);
                        }
                    }
                }
                _ => {} // unsupported keystore type: ignored
            }
        }

        if xprv.is_none() {
            // Electrum 2.7+ multisig or 2fa wallets
            let mut index = 1;
            while xprv.is_none() {
                let Some(x) = wallet.get(format!("x{index}/")) else {
                    break;
                };
                let x_type = x
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(not found)");
                if x_type == "bip32" {
                    xprv = x.get("xprv").and_then(|v| v.as_str()).map(String::from);
                }
                index += 1;
            }
        }

        if xprv.is_none() {
            // Electrum 2.0-2.6.4 wallet with imported loose private keys
            if wallet_type == "imported" {
                if let Some(accounts) = wallet.get("accounts").and_then(|v| v.as_object()) {
                    if let Some(account) = accounts.get("/x") {
                        if let Some(imported) = account.get("imported").and_then(|v| v.as_object())
                        {
                            for entry in imported.values() {
                                let list = entry.as_array().cloned().unwrap_or_default();
                                let Some(pk) = list.get(1).and_then(|v| v.as_str()) else {
                                    continue;
                                };
                                let pk_data = engine.decode(pk.trim()).unwrap_or_default();
                                if pk_data.len() != 80 {
                                    return Err(Error::other(
                                        "electrum v2 private key plus iv is not 80 bytes long",
                                    ));
                                }
                                let iv = pk_data[pk_data.len() - 32..pk_data.len() - 16].to_vec();
                                let encrypted = pk_data[pk_data.len() - 16..].to_vec();
                                return finalize(label, 3, &iv, &encrypted);
                            }
                        }
                    }
                }
            } else if let Some(mpks) = wallet
                .get("master_private_keys")
                .and_then(|v| v.as_object())
            {
                if let Some((_, v)) = mpks.iter().next() {
                    xprv = v.as_str().map(|s| s.to_string());
                }
            }
        }

        let Some(xprv) = xprv else {
            return Err(Error::other(
                "no master private keys or seeds found in electrum v2 wallet",
            ));
        };

        let xprv_data = engine.decode(xprv.trim()).unwrap_or_default();
        if xprv_data.len() != 128 {
            return Err(Error::other(
                "unexpected electrum v2 encrypted master private key length",
            ));
        }
        let iv = xprv_data[..16].to_vec();
        let encrypted = xprv_data[16..32].to_vec();
        finalize(label, version, &iv, &encrypted)
    }
}

fn finalize(label: &str, version: u32, iv: &[u8], encrypted: &[u8]) -> Result<Vec<HashLine>> {
    Ok(vec![HashLine::new(
        label.to_string(),
        format!(
            "{label}:$electrum${version}*{}*{}",
            hex::encode(iv),
            hex::encode(encrypted)
        ),
    )])
}

fn extract_bie1(label: &str, data: Vec<u8>, truncate: bool) -> Result<Vec<HashLine>> {
    let mut version: u32 = 4;
    let min_len = 37 + 32 + 32;
    if (data.len() as f64) < min_len as f64 * 4.0 / 3.0 {
        return Ok(Vec::new()); // wallet too small to parse: no output
    }
    let ephemeral_pubkey = &data[4..37];
    let mac = &data[data.len() - 32..];
    let mut all_but_mac = &data[..data.len() - 32];
    if all_but_mac.len() > 16384 || truncate {
        all_but_mac = &data[37..(37 + 1024).min(data.len())];
        version = 5;
    }
    Ok(vec![HashLine::new(
        label.to_string(),
        format!(
            "{label}:$electrum${version}*{}*{}*{}",
            hex::encode(ephemeral_pubkey),
            hex::encode(all_but_mac),
            hex::encode(mac)
        ),
    )])
}
