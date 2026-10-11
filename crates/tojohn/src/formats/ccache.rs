//! krb5 credential cache (ccache) parser: file header + primary principal +
//! credentials; the embedded ticket's DER is walked with the internal ASN.1
//! reader to pull etype/cipher. Only etype-23 credentials produce output;
//! tickets with the TKT_FLG_INITIAL flag are skipped. Emits `$krb5tgs$`
//! lines.

use crate::asn1::{children, node_int, read_node};
use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Ccache;

const TKT_FLG_INITIAL: u32 = 0x0040_0000;

/// (name_type, components, realm) returned by [`Reader::principal`].
type PrincipalParts<'a> = (u32, Vec<&'a [u8]>, &'a [u8]);

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.data.len() {
            return None;
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(out)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u32_le(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn counted_octet(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn principal(&mut self) -> Option<PrincipalParts<'a>> {
        let _name_type = self.u32()?;
        let num_components = self.u32()? as usize;
        let realm = self.counted_octet()?;
        let mut components = Vec::with_capacity(num_components);
        for _ in 0..num_components {
            components.push(self.counted_octet()?);
        }
        Some((_name_type, components, realm))
    }
}

/// Extract (etype, cipher) from the ticket's DER:
/// SEQUENCE { ..., [3] EXPLICIT SEQUENCE { [0] etype, [2] cipher } } —
/// i.e. the context-tag-3 child of the top-level SEQUENCE, then context
/// children [0] and [2] of that.
fn ticket_etype_cipher(ticket: &[u8]) -> Option<(i64, &[u8])> {
    let mut pos = 0;
    let (top, _) = read_node(ticket, &mut pos)?;
    let enc_part = children(ticket, top).into_iter().find(|n| n.tag == 0xA3)?;
    let enc_kids = children(ticket, enc_part);
    let enc_seq = enc_kids.first()?;
    let mut etype: Option<i64> = None;
    let mut cipher: Option<&[u8]> = None;
    for field in children(ticket, *enc_seq) {
        match field.tag {
            0xA0 => {
                let a_kids = children(ticket, field);
                let inner = a_kids.first()?;
                etype = Some(node_int(ticket, *inner) as i64);
            }
            0xA2 => {
                let c_kids = children(ticket, field);
                let inner = c_kids.first()?;
                cipher = Some(inner.content(ticket));
            }
            _ => {}
        }
    }
    Some((etype?, cipher?))
}

impl Extractor for Ccache {
    fn name(&self) -> &'static str {
        "ccache"
    }

    fn description(&self) -> &'static str {
        "krb5 credential cache files (krb5cc_*)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"\x05\x04")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.first() != Some(&0x05) {
            return Ok(Vec::new()); // unknown file format
        }
        let mut r = Reader { data, pos: 0 };
        // CCacheHeader: version(2) + taglen(2) + tags
        let _version = r.u16().unwrap_or(0);
        let tag_length = r.u16().unwrap_or(0) as usize;
        if r.take(tag_length).is_none() {
            return Ok(Vec::new());
        }
        // the primary principal is parsed for its structure only
        if r.principal().is_none() {
            return Ok(Vec::new());
        }

        let mut out = Vec::new();
        // credentials until EOF
        while r.pos < data.len() {
            // parse one credential
            // client principal: parsed for its structure only
            if r.principal().is_none() {
                break;
            }
            let Some((_, server_components, _)) = r.principal() else {
                break;
            }; // server
            let _keytype = r.u16().unwrap_or(0);
            let _etype_kb = r.u16().unwrap_or(0);
            let keylen = r.u16().unwrap_or(0) as usize;
            if r.take(keylen).is_none() {
                break;
            }
            // times: authtime, starttime, endtime, renew_till (4x u32)
            if r.take(16).is_none() {
                break;
            }
            let _is_skey = r.u8().unwrap_or(0);
            let tkt_flags = r.u32_le().unwrap_or(0);
            let num_addresses = r.u32().unwrap_or(0) as usize;
            let addresses_ok =
                (0..num_addresses).all(|_| r.u16().is_some() && r.counted_octet().is_some());
            if !addresses_ok {
                break;
            }
            let num_authdata = r.u32().unwrap_or(0) as usize;
            let authdata_ok =
                (0..num_authdata).all(|_| r.u16().is_some() && r.counted_octet().is_some());
            if !authdata_ok {
                break;
            }
            let Some(ticket) = r.counted_octet() else {
                break;
            };
            if r.counted_octet().is_none() {
                break;
            }

            if tkt_flags & TKT_FLG_INITIAL != 0 {
                continue;
            }
            // etype/cipher from the ticket DER
            let Some((etype, cipher)) = ticket_etype_cipher(ticket) else {
                continue;
            };
            if etype != 23 {
                continue; // unsupported etype: skipped
            }
            // name = last 2 non-special server components joined by "-"
            let filtered: Vec<&[u8]> = server_components
                .iter()
                .copied()
                .filter(|c| !matches!(&c[..], b"krbtgt" | b"krb5_ccache_conf_data" | b"pa_type"))
                .collect();
            let name_parts: Vec<String> = filtered
                .iter()
                .rev()
                .take(2)
                .rev()
                .map(|c| String::from_utf8_lossy(c).to_string())
                .collect();
            let name = name_parts.join("-");
            let head = hex::encode(&cipher[..16.min(cipher.len())]);
            let tail = hex::encode(&cipher[16.min(cipher.len())..]);
            out.push(HashLine::new(
                name.clone(),
                format!("{name}:$krb5tgs${etype}${head}${tail}"),
            ));
        }
        Ok(out)
    }
}
