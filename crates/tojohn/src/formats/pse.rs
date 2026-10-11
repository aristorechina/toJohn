//! SAP PSE file parser using the internal DER reader. SAPPSEFile layout:
//!
//! ```text
//! SEQUENCE {
//!   INTEGER version,
//!   [0] EXPLICIT SEQUENCE {            -- v2_ENC_CONT (tag 0xA0)
//!     OCTET STRING encrypted_pin,
//!     SEQUENCE {                       -- PKCS5 AlgorithmIdentifier
//!       OID pbe alg,
//!       SEQUENCE { salt OCTET STRING, iterations INTEGER }
//!     },
//!     OCTET STRING cipher_text
//!   }
//! }
//! ```
//!
//! Only `PKCS12_ALGORITHM_PBE1_SHA_3DES_CBC` (1.2.840.113549.1.12.1.3) is
//! supported, emitting `$pse$` lines.

use crate::asn1::{children, node_int, oid_to_string, read_node};
use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Pse;

/// PKCS#12 PBE algorithm OID: pbeWithSHAAnd3-KeyTripleDES-CBC.
const PKCS12_ALGORITHM_PBE1_SHA_3DES_CBC: &str = "1.2.840.113549.1.12.1.3";

impl Extractor for Pse {
    fn name(&self) -> &'static str {
        "pse"
    }

    fn description(&self) -> &'static str {
        "SAP PSE files (.pse)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.first() == Some(&0x30)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let mut pos = 0;
        let Some((top, _)) = read_node(data, &mut pos) else {
            return Ok(Vec::new());
        };
        let top_children = children(data, top);
        if top_children.len() < 2 {
            return Ok(Vec::new());
        }
        // enc_cont: [0] EXPLICIT -> SEQ { pin, alg_id, cipher_text }
        let Some(enc_cont_node) = top_children.iter().find(|n| n.tag == 0xA0) else {
            return Err(Error::other("unsupported encryption algorithm"));
        };
        // The 0xA0 node's content is already the v2_ENC_CONT body (a custom
        // context tag, not an extra EXPLICIT layer).
        let parts = children(data, *enc_cont_node);
        if parts.len() < 3 {
            return Err(Error::other("unsupported encryption algorithm"));
        }
        let encrypted_pin = parts[0].content(data).to_vec();
        // alg_id: SEQ { OID, params SEQ { salt OCTET, iterations INT } }
        let algorithm_children = children(data, parts[1]);
        if algorithm_children.len() < 2 {
            return Err(Error::other("unsupported encryption algorithm"));
        }
        let algorithm_oid = oid_to_string(algorithm_children[0].content(data));
        if algorithm_oid != PKCS12_ALGORITHM_PBE1_SHA_3DES_CBC {
            return Err(Error::other("unsupported encryption algorithm"));
        }
        let params = children(data, algorithm_children[1]);
        if params.len() < 2 {
            return Err(Error::other("unsupported encryption algorithm"));
        }
        let salt = params[0].content(data);
        let iterations = node_int(data, params[1]);

        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "{label}:$pse$1${iterations}${}${}$0$${}${}:::::",
                salt.len(),
                hex::encode(salt),
                encrypted_pin.len(),
                hex::encode(encrypted_pin)
            ),
        )])
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn debug_parse() {
        let data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/pse/user.pse"
        ))
        .unwrap();
        let mut pos = 0;
        let (top, _) = crate::asn1::read_node(&data, &mut pos).unwrap();
        let kids = crate::asn1::children(&data, top);
        println!("top kids: {}", kids.len());
        for k in &kids {
            println!("  tag={:#x} len={}", k.tag, k.end - k.start);
        }
        let cont_kids = crate::asn1::children(&data, kids[1]);
        let enc_cont = cont_kids.first().unwrap();
        println!("enc_cont tag={:#x}", enc_cont.tag);
        let parts = crate::asn1::children(&data, *enc_cont);
        for p in &parts {
            println!("  part tag={:#x} len={}", p.tag, p.end - p.start);
        }
        let alg_kids = crate::asn1::children(&data, parts[1]);
        for a in &alg_kids {
            println!("  alg kid tag={:#x} len={}", a.tag, a.end - a.start);
        }
        let oid = alg_kids[0].content(&data);
        println!("oid bytes: {}", hex::encode(oid));
        println!("oid str: {}", crate::asn1::oid_to_string(oid));
    }
}
