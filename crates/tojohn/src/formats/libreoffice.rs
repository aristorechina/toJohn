//! OpenOffice/LibreOffice ODF hash extractor, emitting `$odf$` hash lines:
//! reads META-INF/manifest.xml from the zip for the encryption parameters,
//! plus optional meta.xml gecos data.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Libreoffice;

/// Namespace prefix kept verbatim on qualified attribute names by the
/// internal DOM.
const MANIFEST_PREFIX: &str = "manifest:";

impl Extractor for Libreoffice {
    fn name(&self) -> &'static str {
        "libreoffice"
    }

    fn description(&self) -> &'static str {
        "OpenOffice / LibreOffice files (ODF)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"PK\x03\x04")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let label = util::basename(input.label());
        let Ok(zf) = crate::zip::ZipArchive::new(&input.data, input.label()) else {
            return Ok(Vec::new()); // not a zip: no output
        };
        let Some(mf) = zf.open("META-INF/manifest.xml") else {
            return Ok(Vec::new()); // missing manifest: no output
        };
        let Ok(root) = crate::xml::parse(&mf) else {
            return Ok(Vec::new());
        };
        let elements = root.iter_all();

        let mut checksum: Option<String> = None;
        let mut checksum_type: Option<String> = None;
        let mut iv: Option<String> = None;
        let mut salt: Option<String> = None;
        let mut algorithm_name: Option<String> = None;
        let mut iteration_count: Option<String> = None;
        let mut key_size = String::from("16");
        let content_pos = elements.iter().position(|element| {
            element.get(&format!("{MANIFEST_PREFIX}full-path")) == Some("content.xml")
        });
        if let Some(content_pos) = content_pos {
            // the encryption parameters sit in the 3 elements after content.xml
            for element in elements.iter().skip(content_pos + 1).take(3) {
                if let Some(value) = element.get(&format!("{MANIFEST_PREFIX}checksum")) {
                    checksum = Some(value.to_string());
                }
                if let Some(value) = element.get(&format!("{MANIFEST_PREFIX}checksum-type")) {
                    checksum_type = Some(value.to_string());
                }
                if let Some(value) = element.get(&format!("{MANIFEST_PREFIX}initialisation-vector"))
                {
                    iv = Some(value.to_string());
                }
                if let Some(value) = element.get(&format!("{MANIFEST_PREFIX}salt")) {
                    salt = Some(value.to_string());
                }
                if let Some(value) = element.get(&format!("{MANIFEST_PREFIX}algorithm-name")) {
                    algorithm_name = Some(value.to_string());
                }
                if let Some(value) = element.get(&format!("{MANIFEST_PREFIX}iteration-count")) {
                    iteration_count = Some(value.to_string());
                }
                if let Some(value) = element.get(&format!("{MANIFEST_PREFIX}key-size")) {
                    key_size = value.to_string();
                }
            }
        }
        let (
            Some(checksum),
            Some(checksum_type),
            Some(iv),
            Some(salt),
            Some(algorithm_name),
            Some(iteration_count),
        ) = (
            checksum,
            checksum_type,
            iv,
            salt,
            algorithm_name,
            iteration_count,
        )
        else {
            return Ok(Vec::new()); // missing encryption parameters: no output
        };

        let content = zf.open("content.xml").unwrap_or_default();
        let content = &content[..1024.min(content.len())];

        let algorithm_type: u32 = if algorithm_name.contains("Blowfish CFB") {
            0
        } else if algorithm_name.contains("aes256-cbc") {
            1
        } else {
            return Ok(Vec::new()); // unsupported encryption algorithm: no output
        };
        let checksum_id: u32 = if checksum_type.to_uppercase().contains("SHA1") {
            0
        } else if checksum_type.to_uppercase().contains("SHA256") {
            1
        } else {
            return Ok(Vec::new()); // unsupported checksum algorithm: no output
        };

        // gecos from meta.xml (subject/keyword/title/description), best effort
        let mut gecos = String::new();
        let mut meta_available = false;
        if let Some(meta) = zf.open("meta.xml") {
            if let Ok(meta_root) = crate::xml::parse(&meta) {
                meta_available = true;
                let mut collect_gecos = |element: &crate::xml::Element| {
                    if element.name.contains("subject")
                        || element.name.contains("keyword")
                        || element.name.contains("title")
                        || element.name.contains("description")
                    {
                        gecos.push_str(element.text.trim());
                    }
                };
                for office_meta in &meta_root.children {
                    for child in &office_meta.children {
                        collect_gecos(child);
                    }
                    collect_gecos(office_meta);
                }
                gecos = gecos.replace(['\n', '\r', ':'], "");
            }
        }

        let engine = base64::engine::general_purpose::STANDARD;
        let checksum_hex = hex::encode(engine.decode(checksum.as_str().trim()).unwrap_or_default());
        let iv_hex = hex::encode(engine.decode(iv.as_str().trim()).unwrap_or_default());
        let salt_hex = hex::encode(engine.decode(salt.as_str().trim()).unwrap_or_default());

        Ok(vec![HashLine::new(
            label.to_string(),
            if meta_available {
                format!(
                    "{label}:$odf$*{algorithm_type}*{checksum_id}*{iteration_count}*{key_size}\
*{checksum_hex}*{}*{iv_hex}*{}*{salt_hex}*0*{}:::{gecos}::{label}",
                    iv_hex.len() / 2,
                    salt_hex.len() / 2,
                    hex::encode(content)
                )
            } else {
                format!(
                    "{label}:$odf$*{algorithm_type}*{checksum_id}*{iteration_count}*{key_size}\
*{checksum_hex}*{}*{iv_hex}*{}*{salt_hex}*0*{}:::::{label}",
                    iv_hex.len() / 2,
                    salt_hex.len() / 2,
                    hex::encode(content)
                )
            },
        )])
    }
}
