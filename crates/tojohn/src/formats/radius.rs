//! RADIUS shared-secret extractor from pcap files using the internal pcap +
//! UDP parser. Tracks the first Accounting-Request (code 4)
//! per (src, dst) pair and the first Accounting-Response (code 5) per
//! (dst, src) pair, then emits one hash per matched response.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::pcap;
use std::collections::HashMap;

pub struct Radius;

/// (code, id, length, authenticator) RADIUS header tuple.
type RadiusHeader = (u8, u8, u16, Vec<u8>);
/// (source IP, destination IP) pair used as the correlation key.
type IpPair = (String, String);

impl Extractor for Radius {
    fn name(&self) -> &'static str {
        "radius"
    }

    fn description(&self) -> &'static str {
        "RADIUS shared secrets from pcap files"
    }

    fn accepts(&self, input: &Input) -> bool {
        // pcap magic AND at least one RADIUS (code 4/5) packet on a RADIUS port
        let is_pcap = input.data.starts_with(b"\xd4\xc3\xb2\xa1")
            || input.data.starts_with(b"\xa1\xb2\xc3\xd4")
            || input.data.starts_with(b"\x4d\x3c\xb2\xa1")
            || input.data.starts_with(b"\xa1\xb2\x3c\x4d");
        is_pcap
            && crate::pcap::packets(&input.data).iter().any(|p| {
                p.udp().is_some_and(|u| {
                    let radius_port = matches!(
                        (u.src_port, u.dst_port),
                        (1812, _)
                            | (_, 1812)
                            | (1813, _)
                            | (_, 1813)
                            | (1645, _)
                            | (_, 1645)
                            | (1646, _)
                            | (_, 1646)
                    );
                    radius_port && u.payload.len() >= 20 && matches!(u.payload[0], 4 | 5)
                })
            })
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        // (src, dst) -> (code, id, len, authenticator) of the first request
        let mut requests: HashMap<IpPair, RadiusHeader> = HashMap::new();
        // (dst, src) -> (code, id, len, authenticator) of the first response
        let mut responses: HashMap<IpPair, RadiusHeader> = HashMap::new();
        let mut response_order: Vec<IpPair> = Vec::new();

        for packet in pcap::packets(&input.data) {
            let Some(udp) = packet.udp() else { continue };
            let Some((src, dst)) = packet.ip_addrs() else {
                continue;
            };
            if udp.payload.len() < 20 {
                continue;
            }
            let code = udp.payload[0];
            let id = udp.payload[1];
            let len = u16::from_be_bytes(udp.payload[2..4].try_into().expect("2"));
            let authenticator = udp.payload[4..20].to_vec();
            if code == 4 {
                requests.entry((src.clone(), dst.clone())).or_insert((
                    code,
                    id,
                    len,
                    authenticator,
                ));
            } else if code == 5 {
                let key = (dst.clone(), src.clone());
                if !responses.contains_key(&key) {
                    responses.insert(key.clone(), (code, id, len, authenticator));
                    response_order.push(key);
                }
            }
        }

        let file_path = input.label();
        let mut out = Vec::new();
        for ip_pair in &response_order {
            let Some((code, id, length, response_auth)) = responses.get(ip_pair) else {
                continue;
            };
            let Some((.., request_auth)) = requests.get(ip_pair) else {
                continue;
            };
            let salt = format!(
                "{:02x}{:02x}{:04x}{}",
                code,
                id,
                length,
                hex::encode(request_auth)
            );
            let hash_type = if salt.len() <= 16 { 1009 } else { 1017 };
            out.push(HashLine::new(
                ip_pair.1.clone(),
                format!(
                    "{ip}({file_path}):$dynamic_{hash_type}${hash}$HEX${salt}",
                    ip = ip_pair.1,
                    hash = hex::encode(response_auth),
                ),
            ));
        }
        Ok(out)
    }
}
