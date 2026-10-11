//! Multi-protocol pcap dissector suite on top of the internal
//! [`crate::pcap`] reader:
//!
//! - **tacacs-plus** (TCP/49, $tacacs-plus$)
//! - **tgsrep** (UDP/TCP 88 Kerberos TGS-REP, $tgsrep$)
//! - **bfd** (UDP/3784 control, $netmd5$/$netsha1$)
//! - **htdigest** (HTTP Digest Authorization over TCP, $response$)
//! - **gadu-gadu** (TCP/8074 GG_LOGIN80/105, $dynamic_24$)
//!
//! Each dissector counts packets independently from 1. Dissectors not
//! listed above are not implemented; files they cannot handle are skipped
//! silently.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::pcap;
use crate::util;

pub struct Pcap;

impl Extractor for Pcap {
    fn name(&self) -> &'static str {
        "pcap"
    }

    fn description(&self) -> &'static str {
        "pcap files (tacacs-plus, tgsrep, bfd, htdigest, gadu-gadu)"
    }

    fn accepts(&self, input: &Input) -> bool {
        !pcap::packets(&input.data).is_empty()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        out.extend(self.tacacs_plus(&input.data));
        out.extend(self.tgsrep(&input.data));
        out.extend(self.bfd(&input.data));
        out.extend(self.gadu(&input.data));
        out.extend(self.htdigest(&input.data));
        Ok(out)
    }
}

impl Pcap {
    /// TACACS+ dissector (TCP/49)
    fn tacacs_plus(&self, data: &[u8]) -> Vec<HashLine> {
        /// TACACS+ TCP port.
        const TACACS_PORT: u16 = 49;
        /// TACACS+ authentication packet type.
        const TYPE_AUTHEN: u8 = 0x01;
        /// Flags bit marking a packet sent unencrypted.
        const FLAGS_UNENCRYPTED: u8 = 0x01;
        let mut out = Vec::new();
        for (index, packet) in pcap::packets(data).iter().enumerate() {
            let packet_no = index + 1;
            let Some(tcp) = packet.tcp() else { continue };
            if tcp.dst_port != TACACS_PORT && tcp.src_port != TACACS_PORT {
                continue;
            }
            let payload = tcp.payload;
            if payload.len() <= 12 {
                continue;
            }
            let server = tcp.src_port == TACACS_PORT;
            let version = payload[0];
            let kind = payload[1];
            let seq_no = payload[2];
            let flags = payload[3];
            let session_id = u32::from_be_bytes(payload[4..8].try_into().expect("4 bytes"));
            if flags & FLAGS_UNENCRYPTED != 0 {
                continue;
            }
            let version_minor = version & 0x0F;
            if !server || kind != TYPE_AUTHEN {
                continue;
            }
            let ciphertext = &payload[12..];
            let predata = session_id.to_be_bytes();
            // version byte encodes (VERSION_MAJOR << 4) + version_minor
            let postdata = [0xc0 + version_minor, seq_no];
            out.push(HashLine::new(
                String::new(),
                format!(
                    "{packet_no}:$tacacs-plus$0${}${}${}",
                    hex::encode(predata),
                    hex::encode(ciphertext),
                    hex::encode(postdata),
                ),
            ));
        }
        out
    }

    /// Kerberos TGS-REP dissector (UDP/TCP port 88)
    fn tgsrep(&self, data: &[u8]) -> Vec<HashLine> {
        /// Offset of the Kerberos message-type byte in a UDP TGS-REP.
        const MSG_TYPE_OFF_UDP: usize = 17;
        /// Message-type offset after the 4-byte TCP length prefix.
        const MSG_TYPE_OFF_TCP: usize = 21;
        /// Kerberos message type of a TGS-REP.
        const TGS_REP: u8 = 13;
        let mut out = Vec::new();
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        let mut unfinished: std::collections::HashMap<(String, String, u16), (Vec<u8>, usize)> =
            std::collections::HashMap::new();

        for packet in pcap::packets(data) {
            // UDP path
            if let Some(udp) = packet.udp() {
                if udp.src_port == 88
                    && udp.payload.len() > MSG_TYPE_OFF_UDP
                    && udp.payload[MSG_TYPE_OFF_UDP] == TGS_REP
                {
                    payloads.push(udp.payload.to_vec());
                }
                continue;
            }
            // TCP path
            if let Some(tcp) = packet.tcp() {
                // ACK-only data segment
                if tcp.src_port == 88 && tcp.flags & 23 == 16 {
                    let payload = tcp.payload;
                    if payload.len() > MSG_TYPE_OFF_TCP && payload[MSG_TYPE_OFF_TCP] == TGS_REP {
                        let size = u32::from_be_bytes(payload[..4].try_into().expect("4")) as usize;
                        if size + 4 == payload.len() {
                            payloads.push(payload[4..size + 4].to_vec());
                        } else {
                            let Some(ip_addrs) = packet.ip_addrs() else {
                                continue;
                            };
                            unfinished.insert(
                                (ip_addrs.0, ip_addrs.1, tcp.dst_port),
                                (payload[4..(size + 4).min(payload.len())].to_vec(), size),
                            );
                        }
                    } else {
                        let Some(ip_addrs) = packet.ip_addrs() else {
                            continue;
                        };
                        let key = (ip_addrs.0, ip_addrs.1, tcp.dst_port);
                        if let Some((mut ticket_data, size)) = unfinished.remove(&key) {
                            ticket_data.extend_from_slice(payload);
                            if ticket_data.len() == size {
                                payloads.push(ticket_data);
                            } else if ticket_data.len() < size {
                                unfinished.insert(key, (ticket_data, size));
                            }
                        }
                    }
                }
            }
        }
        for payload in payloads {
            out.push(HashLine::new(
                String::new(),
                format!(
                    "{}:$tgsrep${}",
                    pcap::packets(data).len(),
                    hex::encode(payload)
                ),
            ));
        }
        out
    }

    /// BFD control-packet dissector (UDP/3784)
    fn bfd(&self, data: &[u8]) -> Vec<HashLine> {
        let mut out = Vec::new();
        for packet in pcap::packets(data) {
            let Some(udp) = packet.udp() else { continue };
            if udp.dst_port != 3784 {
                continue;
            }
            let payload = udp.payload;
            if payload.len() < 25 {
                continue;
            }
            let message_flags = payload[1];
            if message_flags & 0x05 == 0 {
                continue; // no authentication present
            }
            let authentication_type = payload[24];
            let salt = hex::encode(&payload[..32.min(payload.len())]);
            if authentication_type == 2 || authentication_type == 3 {
                let digest = hex::encode(&payload[payload.len() - 16..]);
                out.push(HashLine::new(
                    String::new(),
                    format!("$netmd5${salt}${digest}"),
                ));
            } else if authentication_type == 4 || authentication_type == 5 {
                let digest = hex::encode(&payload[payload.len() - 20..]);
                out.push(HashLine::new(
                    String::new(),
                    format!("$netsha1${salt}${digest}"),
                ));
            }
        }
        out
    }

    /// Gadu-Gadu dissector (GG_LOGIN80 + GG_LOGIN105, TCP/8074)
    fn gadu(&self, data: &[u8]) -> Vec<HashLine> {
        let mut out = Vec::new();
        let mut nonce = String::new();
        for packet in pcap::packets(data) {
            let Some(tcp) = packet.tcp() else { continue };
            if tcp.dst_port != 8074 && tcp.src_port != 8074 {
                continue;
            }
            let payload = hex::encode(tcp.payload);
            if payload.starts_with("01000000") {
                // GG_WELCOME
                nonce = payload[16..].to_string();
            } else if payload.starts_with("31000000") {
                // GG_LOGIN80
                let hash_type = &payload[28..30];
                if hash_type == "02" {
                    let uid_hex = &payload[16..24];
                    let sha1 = &payload[30..70];
                    if let Some(h) = self.gadu_hash(uid_hex, &nonce, sha1) {
                        out.push(HashLine::new(String::new(), h));
                    }
                }
            } else if payload.starts_with("83000000") {
                // GG_LOGIN105
                if nonce.is_empty() {
                    continue;
                }
                let digits = usize::from_str_radix(&payload[30..32], 16).unwrap_or(0);
                let uid_hex = &payload[32..(32 + 2 * digits).min(payload.len())];
                let uid = match parse_hex(uid_hex) {
                    Some(bytes) => String::from_utf8_lossy(&bytes).to_string(),
                    None => continue,
                };
                let offset = 32 + 2 * digits + 4;
                let sha1 = &payload[offset..(offset + 40).min(payload.len())];
                out.push(HashLine::new(
                    String::new(),
                    format!("{uid}:$dynamic_24${sha1}$HEX${nonce}"),
                ));
            }
        }
        out
    }

    /// uid hex is little-endian-ish (reversed then byte-swapped)
    fn gadu_hash(&self, uid_hex: &str, nonce: &str, sha1: &str) -> Option<String> {
        if nonce.is_empty() {
            return None;
        }
        let reversed: String = uid_hex.chars().rev().collect();
        let swapped: String = reversed
            .as_bytes()
            .chunks(2)
            .map(|pair| {
                if pair.len() == 2 {
                    format!("{}{}", pair[1] as char, pair[0] as char)
                } else {
                    (pair[0] as char).to_string()
                }
            })
            .collect();
        let uid = u64::from_str_radix(&swapped, 16).ok()?;
        Some(format!("{uid}:$dynamic_24${sha1}$HEX${nonce}"))
    }

    /// HTTP Digest Authorization dissector over TCP
    fn htdigest(&self, data: &[u8]) -> Vec<HashLine> {
        let mut out = Vec::new();
        for packet in pcap::packets(data) {
            let Some(tcp) = packet.tcp() else { continue };
            let text = String::from_utf8_lossy(tcp.payload);
            // HTTP request parsing: method line + headers
            let mut lines = text.split("\r\n");
            let Some(request_line) = lines.next() else {
                continue;
            };
            let mut parts = request_line.split(' ');
            let Some(method) = parts.next() else { continue };
            let Some(uri) = parts.next() else { continue };
            let mut authorization: Option<&str> = None;
            for line in lines {
                if let Some((k, v)) = line.split_once(':') {
                    if k.eq_ignore_ascii_case("authorization") {
                        authorization = Some(v.trim());
                    }
                }
            }
            let Some(value) = authorization else { continue };
            if !value.contains("qop") || !value.contains("response") {
                continue;
            }
            let opts = parse_digest_header(value);
            let Some(user) = opts.get("Digest username") else {
                continue;
            };
            let Some(response) = opts.get("response") else {
                continue;
            };
            let Some(realm) = opts.get("realm") else {
                continue;
            };
            let Some(nonce) = opts.get("nonce") else {
                continue;
            };
            let Some(nc) = opts.get("nc") else { continue };
            let Some(cnonce) = opts.get("cnonce") else {
                continue;
            };
            let Some(qop) = opts.get("qop") else { continue };
            out.push(HashLine::new(
                user.clone(),
                format!(
                    "{user}:$response${response}${user}${realm}${method}${uri}${nonce}\
${nc}${cnonce}${qop}"
                ),
            ));
        }
        out
    }
}

/// Parses a Digest Authorization header into key/value pairs.
fn parse_digest_header(value: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut rest = value.trim();
    if let Some(idx) = rest.find(' ') {
        // scheme (e.g. "Digest") then k=v list
        map.insert("scheme".to_string(), rest[..idx].to_string());
        rest = &rest[idx + 1..];
    }
    for item in rest.split(',') {
        let item = item.trim();
        if let Some((k, v)) = item.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().trim_matches('"').to_string());
        }
    }
    map
}

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// silence unused helper warning when fixtures change
#[allow(unused)]
fn _unused(data: &[u8]) -> usize {
    util::find(data, b"").unwrap_or(0)
}
