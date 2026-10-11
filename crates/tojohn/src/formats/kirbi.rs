//! Kerberos ticket hash extractor for exported KRBCRED (.kirbi) tickets,
//! emitting `$krb5tgs$` hash lines. The DER structure is parsed with the
//! internal DER reader:
//!
//! ```text
//! KRBCRED ::= SEQUENCE { [0] SEQUENCE {           -- array of tickets
//!     [0] SEQUENCE {                              -- KRB5Ticket
//!         [1] sname, [2] enc-part SEQUENCE {
//!             ... [0] etype INTEGER, [2] cipher OCTET STRING
//!         }
//!     }
//! }}
//! ```

use crate::asn1::{children, node_int, read_node};
use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Kirbi;

impl Extractor for Kirbi {
    fn name(&self) -> &'static str {
        "kirbi"
    }

    fn description(&self) -> &'static str {
        "exported kerberos tickets (.kirbi)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.first() == Some(&0x76)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.first() != Some(&0x76) {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut pos = 0usize;
        let Some((outer, _)) = read_node(data, &mut pos) else {
            return Ok(Vec::new());
        };
        for tlv in children(data, outer) {
            // ticket: [0] EXPLICIT -> SEQUENCE { [1] sname, [2] enc-part }
            let ticket_fields = children(data, tlv);
            let Some(enc_part) = ticket_fields.get(1) else {
                continue;
            };
            // enc_part: [2] EXPLICIT -> SEQUENCE
            let enc_part_fields = children(data, *enc_part);
            let Some(enc_seq) = enc_part_fields.first() else {
                continue;
            };
            let mut etype: Option<i64> = None;
            let mut cipher: Option<&[u8]> = None;
            for field in children(data, *enc_seq) {
                match field.tag {
                    0xA0 => {
                        // [0] EXPLICIT etype
                        if let Some(int_node) = children(data, field).first() {
                            etype = Some(node_int(data, *int_node) as i64);
                        }
                    }
                    0xA2 => {
                        // [2] EXPLICIT cipher
                        if let Some(octet) = children(data, field).first() {
                            cipher = Some(octet.content(data));
                        }
                    }
                    _ => {}
                }
            }
            let (Some(etype), Some(cipher)) = (etype, cipher) else {
                continue;
            };
            if etype != 23 {
                // only etype 23 is emitted
                continue;
            }
            // the first 16 cipher bytes are the checksum, the rest the
            // encrypted data
            let (checksum, rest) = cipher.split_at(16.min(cipher.len()));
            let line = format!(
                "$krb5tgs$unknown:$krb5tgs${etype}${}${}",
                hex::encode(checksum),
                hex::encode(rest)
            );
            out.push(HashLine::new(String::new(), line));
        }
        Ok(out)
    }
}
