//! Password-protected PKCS#12 (PFX) parser using the internal DER reader,
//! emitting `$pfxng$` lines.
//!
//! ```text
//! SEQUENCE {                          -- Pfx
//!   INTEGER 3                         -- version
//!   [0] SEQUENCE { OID data, [0] OCTET STRING }   -- authSafe
//!   [1] SEQUENCE {                    -- macData
//!     SEQUENCE { SEQUENCE { OID }, OCTET STRING digest }
//!     OCTET STRING macSalt
//!     INTEGER iterations
//!   }
//! }
//! ```

use crate::asn1::{children, node_int, oid_to_string, oids, read_node};
use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Pfx;

impl Extractor for Pfx {
    fn name(&self) -> &'static str {
        "pfx"
    }

    fn description(&self) -> &'static str {
        "PKCS#12 / PFX files (.pfx .p12)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.len() > 40 && input.data.starts_with(&[0x30, 0x82])
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let mut pos = 0;
        let Some((pfx, _)) = read_node(data, &mut pos) else {
            return Ok(Vec::new());
        };
        let pfx_children = children(data, pfx);
        if pfx_children.len() < 2 {
            return Ok(Vec::new());
        }
        // authSafe: [0] EXPLICIT → SEQUENCE { OID, [0] EXPLICIT OCTET STRING }
        let auth_safe = pfx_children[1];
        let auth_safe_children = children(data, auth_safe);
        let Some(content_info) = auth_safe_children.first() else {
            return Ok(Vec::new());
        };
        let content_info_children = children(data, *content_info);
        if content_info_children.len() < 2 {
            return Ok(Vec::new());
        }
        let content_type = oid_to_string(content_info_children[0].content(data));
        if content_type != oids::DATA {
            // only password-protected PKCS12 is supported
            return Err(crate::error::Error::other(
                "only password-protected PKCS12 files are currently supported",
            ));
        }
        // [0] EXPLICIT → OCTET STRING: its content is the authSafe payload
        let mut payload: Vec<u8> = Vec::new();
        if let Some(explicit) = content_info_children.get(1) {
            if let Some(octet) = children(data, *explicit).first() {
                payload = octet.content(data).to_vec();
            }
        }

        // macData: [1] if present
        let Some(mac_data) = pfx_children.get(2) else {
            return Ok(Vec::new());
        };
        let mac_data_children = children(data, *mac_data);
        if mac_data_children.len() < 3 {
            return Ok(Vec::new());
        }
        // DigestInfo: SEQUENCE { SEQUENCE { OID }, OCTET STRING digest }
        let digest_info = children(data, mac_data_children[0]);
        if digest_info.len() < 2 {
            return Ok(Vec::new());
        }
        let algorithm_id = children(data, digest_info[0]);
        let Some(oid_node) = algorithm_id.first() else {
            return Ok(Vec::new());
        };
        let mac_algorithm = oid_to_string(oid_node.content(data));
        let key_length: u32 = match mac_algorithm.as_str() {
            oids::SHA1 => 20,
            oids::SHA224 => 28,
            oids::SHA256 => 32,
            oids::SHA384 => 48,
            oids::SHA512 => 64,
            oids::SHA512_224 => 28,
            oids::SHA512_256 => 32,
            _ => return Ok(Vec::new()), // unsupported MAC algorithm
        };
        let mac_algorithm_code: i64 = match mac_algorithm.as_str() {
            oids::SHA1 => 1,
            oids::SHA224 => 224,
            oids::SHA256 => 256,
            oids::SHA384 => 384,
            oids::SHA512 => 512,
            _ => -1,
        };
        let digest_children = children(data, digest_info[1]);
        let Some(stored_hmac) = digest_children.get(1) else {
            return Ok(Vec::new());
        };
        let salt = mac_data_children[1].content(data);
        let iterations = node_int(data, mac_data_children[2]);
        let salt_length = salt.len();

        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$pfxng${mac_algorithm_code}${key_length}${iterations}${salt_length}\
${}${}${}:::::{label}",
                hex::encode(salt),
                hex::encode(&payload),
                hex::encode(stored_hmac.content(data)),
            ),
        )])
    }
}
