//! Minimal pcap reader. Handles the classic pcap container format (both
//! endiannesses, microsecond and nanosecond variants), Ethernet, IPv4 and
//! UDP layers — as much as the format dissectors in this crate need.

/// One captured packet together with the link-layer type recorded for it.
pub struct Packet<'a> {
    pub data: &'a [u8],
    link_type: u16,
}

impl<'a> Packet<'a> {
    /// The network-layer payload: the Ethernet payload (or the raw bytes
    /// for DLT_RAW/NULL links).
    fn network_payload(&self) -> Option<&'a [u8]> {
        match self.link_type {
            1 => {
                // Ethernet; VLAN tags (0x8100, 0x88A8) are skipped
                if self.data.len() < 14 {
                    return None;
                }
                let mut ethertype = u16::from_be_bytes(self.data[12..14].try_into().ok()?);
                let mut offset = 14;
                while ethertype == 0x8100 || ethertype == 0x88A8 {
                    if offset + 4 > self.data.len() {
                        return None;
                    }
                    ethertype =
                        u16::from_be_bytes(self.data[offset + 2..offset + 4].try_into().ok()?);
                    offset += 4;
                }
                if ethertype != 0x0800 {
                    return None;
                }
                self.data.get(offset..)
            }
            101 | 228 => Some(self.data), // DLT_RAW (IPv4/IPv6)
            0 => {
                // DLT_NULL: 4-byte family header
                self.data.get(4..)
            }
            _ => None,
        }
    }

    /// IPv4 header + payload, if this is an IPv4 packet.
    pub fn ipv4(&self) -> Option<(&'a [u8], &'a [u8])> {
        let network = self.network_payload()?;
        if network.is_empty() || network[0] >> 4 != 4 {
            return None;
        }
        let ihl = (network[0] & 0x0f) as usize * 4;
        if network.len() < ihl || network.len() < 20 {
            return None;
        }
        let total_length = u16::from_be_bytes(network[2..4].try_into().ok()?) as usize;
        let end = if total_length >= ihl && total_length <= network.len() {
            total_length
        } else {
            network.len()
        };
        Some((&network[..ihl], &network[ihl..end]))
    }

    /// (src, dst) IPv4 addresses in dotted form.
    pub fn ip_addrs(&self) -> Option<(String, String)> {
        let (header, _) = self.ipv4()?;
        if header.len() < 12 {
            return None;
        }
        Some((
            format!(
                "{}.{}.{}.{}",
                header[12], header[13], header[14], header[15]
            ),
            format!(
                "{}.{}.{}.{}",
                header[16], header[17], header[18], header[19]
            ),
        ))
    }

    /// UDP header + payload, if this is a UDP packet.
    pub fn udp(&self) -> Option<Udp<'a>> {
        let (_, payload) = self.ipv4()?;
        if payload.is_empty() {
            return None;
        }
        let protocol = {
            let network = self.network_payload()?;
            network.get(9).copied()?
        };
        if protocol != 17 {
            return None;
        }
        if payload.len() < 8 {
            return None;
        }
        Some(Udp {
            src_port: u16::from_be_bytes(payload[0..2].try_into().ok()?),
            dst_port: u16::from_be_bytes(payload[2..4].try_into().ok()?),
            payload: &payload[8..],
        })
    }

    /// TCP header + payload, if this is a TCP packet.
    pub fn tcp(&self) -> Option<Tcp<'a>> {
        let (_, payload) = self.ipv4()?;
        if payload.is_empty() {
            return None;
        }
        let protocol = {
            let network = self.network_payload()?;
            network.get(9).copied()?
        };
        if protocol != 6 {
            return None;
        }
        if payload.len() < 20 {
            return None;
        }
        let data_offset = (payload[12] >> 4) as usize * 4;
        if data_offset < 20 || data_offset > payload.len() {
            return None;
        }
        Some(Tcp {
            src_port: u16::from_be_bytes(payload[0..2].try_into().ok()?),
            dst_port: u16::from_be_bytes(payload[2..4].try_into().ok()?),
            seq: u32::from_be_bytes(payload[4..8].try_into().ok()?),
            flags: payload[13],
            payload: &payload[data_offset..],
        })
    }
}

pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub struct Tcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

/// Iterate over all packets of a classic pcap file.
pub fn packets(data: &[u8]) -> Vec<Packet<'_>> {
    let mut out = Vec::new();
    if data.len() < 24 {
        return out;
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().expect("4"));
    // The magic is read as a little-endian u32. On-disk bytes a1 b2 c3 d4
    // (a big-endian producer) read as 0xd4c3b2a1 and are followed by
    // big-endian header fields; d4 c3 b2 a1 (a little-endian producer)
    // reads as 0xa1b2c3d4 and needs little-endian field reads. The
    // nanosecond variants only differ in timestamp resolution, which this
    // reader ignores.
    let (swap, _) = match magic {
        0xd4c3b2a1 => (false, false),
        0xa1b2c3d4 => (true, false),
        0x4d3cb2a1 => (false, true),
        0xa1b23c4d => (true, true),
        _ => return out,
    };
    let read_u32 = |bytes: &[u8]| -> u32 {
        if swap {
            u32::from_le_bytes(bytes.try_into().expect("4"))
        } else {
            u32::from_be_bytes(bytes.try_into().expect("4"))
        }
    };
    let link_type = u16::from_le_bytes(data[20..22].try_into().expect("2"));
    // packet records start after the 24-byte file header
    let mut pos = 24usize;
    while pos + 16 <= data.len() {
        let incl_len = read_u32(&data[pos + 8..pos + 12]) as usize;
        pos += 16;
        if incl_len > data.len() - pos {
            break;
        }
        out.push(Packet {
            data: &data[pos..pos + incl_len],
            link_type,
        });
        pos += incl_len;
    }
    out
}
