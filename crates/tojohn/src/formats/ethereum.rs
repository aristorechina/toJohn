//! Ethereum keystore hash extractor, emitting `$ethereum$` hash lines:
//! Geth/Mist/MyEtherWallet keystores (scrypt and PBKDF2 variants) plus
//! presale wallets.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Ethereum;

impl Extractor for Ethereum {
    fn name(&self) -> &'static str {
        "ethereum"
    }

    fn description(&self) -> &'static str {
        "Ethereum wallet files (Geth/Mist/MyEtherWallet/presale)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"{")
            && (crate::util::find(&input.data, b"\"crypto\"").is_some()
                || crate::util::find(&input.data, b"\"Crypto\"").is_some()
                || crate::util::find(&input.data, b"bkp").is_some())
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let text = match std::str::from_utf8(&input.data) {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(text) else {
            return Ok(Vec::new()); // unparseable JSON: no output
        };
        let label = util::basename(input.label());

        let Some(crypto) = json.get("crypto").or_else(|| json.get("Crypto")) else {
            // presale wallet
            let Some(bkp) = json.get("bkp").and_then(|v| v.as_str()) else {
                return Ok(Vec::new()); // presale wallet without bkp: no hash
            };
            let Some(encseed) = json.get("encseed").and_then(|v| v.as_str()) else {
                return Ok(Vec::new());
            };
            let Some(ethaddr) = json.get("ethaddr").and_then(|v| v.as_str()) else {
                return Ok(Vec::new());
            };
            return Ok(vec![HashLine::new(
                label.to_string(),
                format!(
                    "{label}:$ethereum$w*{encseed}*{ethaddr}*{}",
                    &bkp[..32.min(bkp.len())]
                ),
            )]);
        };

        let Some(cipher) = crypto.get("cipher").and_then(|v| v.as_str()) else {
            return Ok(Vec::new());
        };
        if cipher != "aes-128-ctr" {
            return Ok(Vec::new()); // unsupported cipher: no output
        }
        let Some(kdf) = crypto.get("kdf").and_then(|v| v.as_str()) else {
            return Ok(Vec::new());
        };
        let Some(ciphertext) = crypto.get("ciphertext").and_then(|v| v.as_str()) else {
            return Ok(Vec::new());
        };
        let Some(mac) = crypto.get("mac").and_then(|v| v.as_str()) else {
            return Ok(Vec::new());
        };
        if kdf == "scrypt" {
            let params = &crypto["kdfparams"];
            let n = params.get("n").and_then(|v| v.as_i64()).unwrap_or(0);
            let r = params.get("r").and_then(|v| v.as_i64()).unwrap_or(0);
            let p = params.get("p").and_then(|v| v.as_i64()).unwrap_or(0);
            let salt = params.get("salt").and_then(|v| v.as_str()).unwrap_or("");
            Ok(vec![HashLine::new(
                label.to_string(),
                format!("{label}:$ethereum$s*{n}*{r}*{p}*{salt}*{ciphertext}*{mac}"),
            )])
        } else if kdf == "pbkdf2" {
            let params = &crypto["kdfparams"];
            let n = params.get("c").and_then(|v| v.as_i64()).unwrap_or(0);
            let prf = params.get("prf").and_then(|v| v.as_str()).unwrap_or("");
            if prf != "hmac-sha256" {
                return Ok(Vec::new()); // unsupported prf: no output
            }
            let salt = params.get("salt").and_then(|v| v.as_str()).unwrap_or("");
            Ok(vec![HashLine::new(
                label.to_string(),
                format!("{label}:$ethereum$p*{n}*{salt}*{ciphertext}*{mac}"),
            )])
        } else {
            Ok(Vec::new()) // unsupported kdf: no output
        }
    }
}
