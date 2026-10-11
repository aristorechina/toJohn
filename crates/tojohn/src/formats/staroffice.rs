//! StarOffice (sxc/sdw/sxd/sxw/sxi) parser: reads the ODF-style manifest for
//! Blowfish CFB parameters and hex-encodes the first 1024 bytes of
//! content.xml (padded to an 8-byte boundary when short). Emits `$sxc$`
//! lines.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use base64::Engine;

pub struct Staroffice;

/// The XML front end keeps qualified attribute names verbatim.
const ATTR: &str = "manifest:";

impl Extractor for Staroffice {
    fn name(&self) -> &'static str {
        "staroffice"
    }

    fn description(&self) -> &'static str {
        "StarOffice files (.sxc .sdw .sxd .sxw .sxi)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"PK\x03\x04")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Ok(zf) = crate::zip::ZipArchive::new(&input.data, input.label()) else {
            return Ok(Vec::new()); // not a zip archive
        };
        let Some(manifest) = zf.open("META-INF/manifest.xml") else {
            return Ok(Vec::new());
        };
        let Ok(root) = crate::xml::parse(&manifest) else {
            return Ok(Vec::new());
        };
        let elements = root.iter_all();

        // The content.xml entry is followed (within three manifest entries)
        // by the entries carrying the encryption parameters.
        let Some(content_index) = elements
            .iter()
            .position(|element| element.get(&format!("{ATTR}full-path")) == Some("content.xml"))
        else {
            return Ok(Vec::new()); // no content.xml entry in the manifest
        };
        let mut checksum: Option<String> = None;
        let mut iv: Option<String> = None;
        let mut salt: Option<String> = None;
        let mut iteration_count: Option<String> = None;
        for element in elements.iter().skip(content_index + 1).take(3) {
            if let Some(value) = element.get(&format!("{ATTR}checksum")) {
                checksum = Some(value.to_string());
            }
            if let Some(value) = element.get(&format!("{ATTR}initialisation-vector")) {
                iv = Some(value.to_string());
            }
            if let Some(value) = element.get(&format!("{ATTR}salt")) {
                salt = Some(value.to_string());
            }
            if let Some(value) = element.get(&format!("{ATTR}iteration-count")) {
                iteration_count = Some(value.to_string());
            }
        }
        let (Some(checksum), Some(iv), Some(salt), Some(iteration_count)) =
            (checksum, iv, salt, iteration_count)
        else {
            return Ok(Vec::new()); // missing encryption parameters in the manifest
        };

        let content_xml = zf.open("content.xml").unwrap_or_default();
        let b64 = base64::engine::general_purpose::STANDARD;
        let checksum_hex = hex::encode(b64.decode(checksum.trim()).unwrap_or_default());
        let iv_hex = hex::encode(b64.decode(iv.trim()).unwrap_or_default());
        let salt_hex = hex::encode(b64.decode(salt.trim()).unwrap_or_default());

        // fixed fields of the $sxc$ line: Blowfish CFB with a 16-byte key
        let algorithm_type = 0u32;
        let checksum_type = 0u32;
        let key_size = 16usize;

        // the hash covers the first 1024 bytes of content.xml; shorter
        // content is padded to an 8-byte boundary with '0' bytes
        let original_length = content_xml.len().min(1024);
        let content: Vec<u8> = if content_xml.len() >= 1024 {
            content_xml[..1024].to_vec()
        } else {
            let mut padded = content_xml.clone();
            padded.extend_from_slice(&b"00000000"[..content_xml.len() % 8]);
            padded
        };
        let length = content.len();
        let content_hex = hex::encode(&content);

        Ok(vec![HashLine::new(
            input.label().to_string(),
            format!(
                "{}:$sxc$*{algorithm_type}*{checksum_type}*{iteration_count}*{key_size}\
*{checksum_hex}*{}*{iv_hex}*{}*{salt_hex}*{original_length}*{length}*{content_hex}",
                input.label(),
                iv_hex.len() / 2,
                salt_hex.len() / 2,
            ),
        )])
    }
}
