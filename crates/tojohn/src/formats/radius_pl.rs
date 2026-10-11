//! RADIUS shared-secret attack extractor from pcap files, with two attack
//! modes:
//!
//! - **Attack 3.3** (User-Password based): Access-Requests (code 1) with a
//!   known login get their User-Password attribute XORed with the known
//!   PASSWORD (default `'1'`), emitting `$dynamic_1008$` lines.
//! - **Attack 3.1** (Response Authenticator based): Access-Accept/Challenge/
//!   Reject (code 2/3/11) responses are matched to requests by
//!   `<dest ip>-<identifier>`; the Response Authenticator is the hash and
//!   the salt is the response packet with the Response Authenticator
//!   replaced by the Request Authenticator, emitting `$dynamic_1009$` /
//!   `$dynamic_1017$` (when the salt exceeds 16 bytes).
//!
//! One (hash, salt) pair per client IP (deduplicated). Attack 3.3 takes
//! precedence. Link types: loopback (0), Ethernet (1), LINUX_SLL (113).
//!
//! Extra args: `input.extra_args[0]` overrides the known PASSWORD.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::pcap;
use std::collections::HashMap;

pub struct RadiusPl;

/// RADIUS authentication port.
const PORT_1812: u16 = 1812;

impl Extractor for RadiusPl {
    fn name(&self) -> &'static str {
        "radius_pl"
    }

    fn description(&self) -> &'static str {
        "RADIUS shared-secret attacks from pcap files (needs dictionary.rfc2865 semantics)"
    }

    fn accepts(&self, input: &Input) -> bool {
        let is_pcap = matches!(input.data.first(), Some(0xd4) | Some(0xa1) | Some(0x4d))
            && input.data.len() > 24;
        is_pcap
            && crate::pcap::packets(&input.data).iter().any(|p| {
                p.udp().is_some_and(|u| {
                    (u.src_port == PORT_1812 || u.dst_port == PORT_1812)
                        && u.payload.len() >= 20
                        && u.payload[0] == 1
                })
            })
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let password = input
            .extra_args
            .first()
            .cloned()
            .unwrap_or_else(|| "1".to_string());
        let mut out = Vec::new();

        // Attack 3.3
        let mut dumped_ips: HashMap<String, String> = HashMap::new();
        for packet in pcap::packets(&input.data) {
            let Some(udp) = packet.udp() else { continue };
            if udp.dst_port != PORT_1812 || udp.payload.len() < 20 {
                continue;
            }
            let payload = udp.payload;
            if payload[0] != 1 {
                continue;
            }
            let Some(src_ip) = packet.ip_addrs().map(|(src, _)| src) else {
                continue;
            };
            let request_authenticator = payload[4..20].to_vec();
            if let Some((login, user_password)) = radius_attributes(payload) {
                if login == "crack" || login == "toto" {
                    if dumped_ips.get(&src_ip).is_some_and(|s| s == "request") {
                        continue;
                    }
                    // xor the User-Password with the known PASSWORD
                    let xored: Vec<u8> = user_password
                        .iter()
                        .zip(password.as_bytes().iter().cycle())
                        .map(|(a, b)| a ^ b)
                        .collect();
                    out.push(HashLine::new(
                        String::new(),
                        format!(
                            "{src_ip}:$dynamic_1008${}$HEX${}",
                            hex::encode(xored),
                            hex::encode(request_authenticator)
                        ),
                    ));
                    dumped_ips.insert(src_ip.clone(), "request".to_string());
                }
            }
        }

        // Attack 3.1
        let mut requests: HashMap<String, Vec<u8>> = HashMap::new();
        let mut dumped: std::collections::HashSet<String> = std::collections::HashSet::new();
        for packet in pcap::packets(&input.data) {
            let Some(udp) = packet.udp() else { continue };
            let Some((src_ip, dst_ip)) = packet.ip_addrs() else {
                continue;
            };
            let payload = udp.payload;
            if payload.len() < 20 {
                continue;
            }
            let identifier = payload[1];
            match payload[0] {
                1 => {
                    requests.insert(format!("{src_ip}-{identifier}"), payload[4..20].to_vec());
                }
                2 | 3 | 11 => {
                    let key = format!("{dst_ip}-{identifier}");
                    let Some(req_auth) = requests.get(&key) else {
                        continue;
                    };
                    if dumped_ips.contains_key(&dst_ip) {
                        continue; // one hash per client IP
                    }
                    if dumped.contains(&dst_ip) {
                        continue;
                    }
                    let mut salt = payload.to_vec();
                    salt[4..20].copy_from_slice(req_auth);
                    let response_auth = &payload[4..20];
                    let hash_type = if salt.len() > 16 { 1017 } else { 1009 };
                    out.push(HashLine::new(
                        String::new(),
                        format!(
                            "{dst_ip}:$dynamic_{hash_type}${}$HEX${}",
                            hex::encode(response_auth),
                            hex::encode(salt)
                        ),
                    ));
                    dumped.insert(dst_ip.clone());
                    dumped_ips.insert(dst_ip, "reply".to_string());
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

/// Parse RADIUS attributes: returns (User-Name, User-Password) if present.
fn radius_attributes(payload: &[u8]) -> Option<(String, Vec<u8>)> {
    let len = u16::from_be_bytes(payload[2..4].try_into().expect("2")) as usize;
    let mut pos = 20;
    let mut user_name: Option<String> = None;
    let mut user_password: Option<Vec<u8>> = None;
    while pos + 2 <= payload.len().min(len) {
        let attr_type = payload[pos];
        let attr_len = payload[pos + 1] as usize;
        if attr_len < 2 || pos + attr_len > payload.len() {
            break;
        }
        let value = &payload[pos + 2..pos + attr_len];
        match attr_type {
            1 => user_name = Some(String::from_utf8_lossy(value).to_string()),
            2 => user_password = Some(value.to_vec()),
            _ => {}
        }
        pos += attr_len;
    }
    Some((user_name?, user_password?))
}
