//! Converts CSV extracts of the McAfee ePO `dbo.OrionUsers` table
//! (`Name,AuthURI`) into `$dynamic_24$` lines. Rows whose AuthURI does not
//! start with `auth:pwd?pwd=` are skipped; the payload is percent-decoded,
//! then base64-decoded before splitting into digest and seed.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct McafeeEpo;

/// AuthURI query prefix carried in the CSV's second column.
const PREFIX: &[u8] = b"auth:pwd?pwd=";

impl Extractor for McafeeEpo {
    fn name(&self) -> &'static str {
        "mcafee_epo"
    }

    fn description(&self) -> &'static str {
        "McAfee ePO dbo.OrionUsers CSV extracts"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, PREFIX).is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let engine = base64::engine::general_purpose::STANDARD;
        let mut out = Vec::new();
        for raw in util::lines(&input.data) {
            let words: Vec<&[u8]> = util::strip(raw).split(|&b| b == b',').collect();
            let Some(second) = words.get(1) else {
                continue;
            };
            if !second.starts_with(PREFIX) {
                continue;
            }
            let payload = &second[PREFIX.len()..];
            let decoded = util::percent_decode(payload);
            let Ok(blob) = engine.decode(std::str::from_utf8(&decoded).unwrap_or("")) else {
                // malformed payload: report instead of emitting a partial hash
                return Err(crate::error::Error::malformed(
                    input.label(),
                    "AuthURI payload is not valid base64",
                ));
            };
            if blob.len() != 24 {
                // unexpected blob length: skip the row
                continue;
            }
            let seed = hex::encode(&blob[20..]);
            let digest = hex::encode(&blob[..20]);
            let user = String::from_utf8_lossy(words[0]);
            out.push(HashLine::new(
                user.to_string(),
                format!("{user}:$dynamic_24${digest}$HEX${seed}"),
            ));
        }
        Ok(out)
    }
}
