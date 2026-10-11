//! Signal Android SecureSMS-Preferences.xml parser: reads the first
//! boolean (password present), the first int (iteration count) and the
//! encryption_salt / mac_salt / master_secret strings, emitting
//! `$signal$1$<iterations>$<enc>$<mac>$<master>$<last-40-master-hex>` lines.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Signal;

impl Extractor for Signal {
    fn name(&self) -> &'static str {
        "signal"
    }

    fn description(&self) -> &'static str {
        "Signal Android SecureSMS-Preferences.xml files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"<?xml version").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Some(idx) = util::find(&input.data, b"<?xml version") else {
            return Ok(Vec::new());
        };
        let xml = &input.data[idx..];
        let Ok(root) = crate::xml::parse(xml) else {
            return Ok(Vec::new());
        };
        if root.name != "map" {
            return Ok(Vec::new());
        }
        // have_password = first boolean/@value
        let have_password = root
            .find_children("boolean")
            .first()
            .and_then(|b| b.get("value"))
            .map(|v| v == "true")
            .unwrap_or(false);
        if !have_password {
            return Ok(Vec::new());
        }
        let iterations = root
            .find_children("int")
            .first()
            .and_then(|i| i.get("value"))
            .unwrap_or_default()
            .to_string();
        let mut encryption_salt: Option<&str> = None;
        let mut mac_salt: Option<&str> = None;
        let mut master_secret: Option<&str> = None;
        for field in root.find_children("string") {
            match field.get("name") {
                Some("encryption_salt") => encryption_salt = Some(field.text.trim()),
                Some("mac_salt") => mac_salt = Some(field.text.trim()),
                Some("master_secret") => master_secret = Some(field.text.trim()),
                _ => {}
            }
        }
        let (Some(encryption_salt), Some(mac_salt), Some(master_secret)) =
            (encryption_salt, mac_salt, master_secret)
        else {
            return Ok(Vec::new());
        };
        let b64 = base64::engine::general_purpose::STANDARD;
        let enc_hex = hex::encode(b64.decode(encryption_salt).unwrap_or_default());
        let mac_hex = hex::encode(b64.decode(mac_salt).unwrap_or_default());
        let ms_hex = hex::encode(b64.decode(master_secret).unwrap_or_default());
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$signal$1${iterations}${enc_hex}${mac_hex}${ms_hex}${}",
                &ms_hex[ms_hex.len().saturating_sub(40)..]
            ),
        )])
    }
}
