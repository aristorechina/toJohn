//! Blockchain.info wallet parser: v1 (raw bytes), v2/v3 (`--json`:
//! pbkdf2_iterations + base64 payload) and base64-only (`--base64`)
//! variants, emitting `$blockchain$` lines. The `--json`/`--base64` flags
//! are taken from `input.extra_args`.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Blockchain;

impl Extractor for Blockchain {
    fn name(&self) -> &'static str {
        "blockchain"
    }

    fn description(&self) -> &'static str {
        "Blockchain.info wallet files (v1/v2/v3)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"guid").is_some()
            || util::find(&input.data, b"pbkdf2_iterations").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let json_mode = input
            .extra_args
            .iter()
            .any(|a| a == "--json" || a == "json");
        let base64_mode = input
            .extra_args
            .iter()
            .any(|a| a == "--base64" || a == "base64");
        let label = input.label();

        if util::find(data, b"guid").is_some() && json_mode {
            return Ok(Vec::new()); // v1 wallet data: --json is not applicable
        }
        if util::find(data, b"pbkdf2_iterations").is_some() && !json_mode {
            return Ok(Vec::new()); // v2/v3 wallet data: --json is required
        }

        let b64 = base64::engine::general_purpose::STANDARD;
        if json_mode {
            let Ok(decoded) = serde_json::from_slice::<serde_json::Value>(data) else {
                return Ok(Vec::new()); // invalid JSON: no output
            };
            let version = decoded
                .get("version")
                .map(|v| v.to_string())
                .unwrap_or_default();
            if version == "2" || version == "3" {
                let Some(payload_str) = decoded.get("payload").and_then(|v| v.as_str()) else {
                    return Ok(Vec::new());
                };
                let iterations = decoded
                    .get("pbkdf2_iterations")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let payload = b64.decode(payload_str.trim()).unwrap_or_default();
                return Ok(vec![HashLine::new(
                    label.to_string(),
                    format!(
                        "{label}:$blockchain$v2${iterations}${}${}",
                        payload.len(),
                        hex::encode(&payload)
                    ),
                )]);
            }
            return Ok(Vec::new());
        }

        if base64_mode {
            let decoded = b64
                .decode(std::str::from_utf8(data).unwrap_or("").trim())
                .unwrap_or_default();
            return Ok(vec![HashLine::new(
                label.to_string(),
                format!(
                    "{label}:$blockchain${}${}",
                    decoded.len(),
                    hex::encode(&decoded)
                ),
            )]);
        }

        // version 1 wallet format
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:$blockchain${}${}", data.len(), hex::encode(data)),
        )])
    }
}
