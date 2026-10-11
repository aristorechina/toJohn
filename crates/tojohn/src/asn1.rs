//! Minimal DER (ASN.1) reader used by the `pem` and `pfx` format modules.
//!
//! Nodes carry byte ranges relative to the ROOT blob, so nested content is
//! always addressable with the original slice.

/// A parsed DER TLV; byte ranges are relative to the root blob.
#[derive(Debug, Clone, Copy)]
pub struct Node {
    pub tag: u8,
    pub start: usize,
    pub end: usize,
}

impl Node {
    pub fn content<'a>(&self, root: &'a [u8]) -> &'a [u8] {
        &root[self.start..self.end]
    }
}

/// Read one TLV at `pos`; returns the Node and the position just after it.
pub fn read_node(data: &[u8], pos: &mut usize) -> Option<(Node, usize)> {
    if *pos >= data.len() {
        return None;
    }
    let tag = data[*pos];
    let mut p = *pos + 1;
    if p >= data.len() {
        return None;
    }
    let len_byte = data[p];
    p += 1;
    let content_len;
    if len_byte < 0x80 {
        content_len = len_byte as usize;
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || p + n > data.len() {
            return None;
        }
        let mut len = 0usize;
        for b in &data[p..p + n] {
            len = (len << 8) | *b as usize;
        }
        p += n;
        content_len = len;
    }
    let start = p;
    if start + content_len > data.len() {
        return None;
    }
    *pos = start + content_len;
    Some((
        Node {
            tag,
            start,
            end: start + content_len,
        },
        *pos,
    ))
}

/// Parse the contents of a constructed node as a sequence of TLVs.
pub fn children(data: &[u8], node: Node) -> Vec<Node> {
    let mut out = Vec::new();
    let mut pos = node.start;
    while pos < node.end {
        match read_node(data, &mut pos) {
            Some((tlv, next)) => {
                out.push(tlv);
                pos = next;
            }
            None => break,
        }
    }
    out
}

/// Decode an OID content into its dotted string form.
pub fn oid_to_string(content: &[u8]) -> String {
    if content.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    let first = content[0] as u32;
    parts.push((first / 40).to_string());
    parts.push((first % 40).to_string());
    let mut acc: u64 = 0;
    for &b in &content[1..] {
        acc = (acc << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            parts.push(acc.to_string());
            acc = 0;
        }
    }
    parts.join(".")
}

/// Read the positive big-endian integer content of an INTEGER node.
pub fn node_int(data: &[u8], node: Node) -> u32 {
    let mut v = 0u32;
    for &b in node.content(data) {
        v = (v << 8) | b as u32;
    }
    v
}

/// Well-known OIDs used by the pem/pfx modules.
pub mod oids {
    pub const PBES2: &str = "1.2.840.113549.1.5.13";
    pub const PBKDF2: &str = "1.2.840.113549.1.5.12";
    pub const DATA: &str = "1.2.840.113549.1.7.1";
    pub const TRIPLEDES_3KEY: &str = "1.2.840.113549.3.7";
    pub const AES128_CBC: &str = "2.16.840.1.101.3.4.1.2";
    pub const AES192_CBC: &str = "2.16.840.1.101.3.4.1.22";
    pub const AES256_CBC: &str = "2.16.840.1.101.3.4.1.42";
    pub const SHA1: &str = "1.3.14.3.2.26";
    pub const SHA224: &str = "2.16.840.1.101.3.4.2.4";
    pub const SHA256: &str = "2.16.840.1.101.3.4.2.1";
    pub const SHA384: &str = "2.16.840.1.101.3.4.2.2";
    pub const SHA512: &str = "2.16.840.1.101.3.4.2.3";
    pub const SHA512_224: &str = "2.16.840.1.101.3.4.2.5";
    pub const SHA512_256: &str = "2.16.840.1.101.3.4.2.6";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_and_long_tlv() {
        // SEQUENCE { INTEGER 2048-ish } with long-form length
        let der = [0x30, 0x81, 0x05, 0x02, 0x03, 0x08, 0x00, 0xFF];
        let mut pos = 0;
        let (seq, next) = read_node(&der, &mut pos).unwrap();
        assert_eq!(seq.tag, 0x30);
        assert_eq!(next, der.len());
        let kids = children(&der, seq);
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].tag, 0x02);
        assert_eq!(kids[0].content(&der), &[0x08, 0x00, 0xFF]);
    }

    #[test]
    fn decodes_oid() {
        // 1.2.840.113549.1.7.1 (PKCS#7 data)
        let oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
        assert_eq!(oid_to_string(&oid), oids::DATA);
    }
}
