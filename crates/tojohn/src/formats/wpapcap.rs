//! pcap capture parser extracting WPA handshake material: supports classic
//! pcap files (big/little endian) with raw 802.11, radiotap, prism and PPI
//! link types, plus plain-Ethernet EAPOL frames via a synthetic 802.11
//! header. Walks the M1-M4 handshake state machine and emits `$WPAPSK$`
//! lines. pcapng and ivs2 inputs are not supported.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util::basename;

pub struct Wpapcap;

const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_PRISM_HEADER: u32 = 119;
const LINKTYPE_RADIOTAP_HDR: u32 = 127;
const LINKTYPE_PPI_HDR: u32 = 192;

/// crypt-style base64 alphabet used by the hash-line encoding.
const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// EAPOL-Key frame parsed from the packet body.
#[derive(Clone)]
struct Eapol {
    length: u16,
    key_info: u16,
    replay_count: u64,
    nonce: [u8; 32],
    key_mic: [u8; 16],
    key_data_len: u16,
}

impl Eapol {
    fn parse(data: &[u8]) -> Option<Eapol> {
        if data.len() < 99 {
            return None;
        }
        let key_info = u16::from_be_bytes([data[5], data[6]]);
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&data[17..49]);
        let mut key_mic = [0u8; 16];
        key_mic.copy_from_slice(&data[81..97]);
        Some(Eapol {
            length: u16::from_be_bytes([data[2], data[3]]),
            key_info,
            replay_count: u64::from_be_bytes(data[9..17].try_into().expect("8 bytes")),
            nonce,
            key_mic,
            key_data_len: u16::from_be_bytes([data[97], data[98]]),
        })
    }

    /// bit fields of key_info (little-endian word, bits from LSB).
    fn key_version(&self) -> u16 {
        self.key_info & 7
    }
    fn key_ack(&self) -> bool {
        self.key_info & (1 << 7) != 0
    }
    fn install(&self) -> bool {
        self.key_info & (1 << 6) != 0
    }
    fn secure(&self) -> bool {
        self.key_info & (1 << 9) != 0
    }
}

#[derive(Clone, Default)]
struct HandshakeMsg {
    eapol: Option<Eapol>,
    eapol_size: usize,
    raw_eapol: Vec<u8>,
}

#[derive(Clone, Default)]
struct ApSta {
    bssid: [u8; 6],
    staid: [u8; 6],
    replay_count: u64,
    handshake_done: bool,
    messages: [HandshakeMsg; 5],
}

#[derive(Clone, Default)]
struct EssidEntry {
    bssid: [u8; 6],
    essid: String,
    essid_len: usize,
    priority: i32,
}

struct WpaState {
    essids: Vec<EssidEntry>,
    apstas: Vec<ApSta>,
    lines: Vec<String>,
    filename: String,
}

impl WpaState {
    fn find_essid_index(&self, bssid: &[u8]) -> Option<usize> {
        (0..self.essids.len())
            .rev()
            .find(|&index| self.essids[index].bssid.as_slice() == bssid)
    }

    fn get_essid(&self, bssid: &[u8]) -> String {
        match self.find_essid_index(bssid) {
            Some(index) => {
                if self.essids[index].essid_len == 0 {
                    hex::encode_upper(self.essids[index].bssid)
                } else {
                    self.essids[index].essid.clone()
                }
            }
            None => "[NOTFOUND]".to_string(),
        }
    }

    fn learn_essid_from_beacon(&mut self, pkt: &[u8], subtype: usize, has_ht: bool, bssid: &[u8]) {
        // find the ESSID tag in management body
        let body_off = 24 + if has_ht { 4 } else { 0 };
        let (tag_off, priority) = match subtype {
            8 | 5 => (body_off + 12, 5), // beacon: 8 (ts) + 2 (interval) + 2 (cap)
            4 => (body_off, 4),          // probe request
            0 => (body_off + 4, 2),      // assoc request: cap(2) + interval(2)
            2 => (body_off + 10, 1),     // reassoc: cap(2)+interval(2)+current AP(6)
            _ => return,
        };
        if tag_off >= pkt.len() {
            return;
        }
        let mut pos = tag_off;
        let mut essid: Option<String> = None;
        while pos + 2 <= pkt.len() {
            let tag_type = pkt[pos];
            let tag_len = pkt[pos + 1] as usize;
            if pos + 2 + tag_len > pkt.len() {
                break;
            }
            if tag_type == 0 {
                if tag_len == 0 || tag_len > 32 {
                    return;
                }
                essid =
                    Some(String::from_utf8_lossy(&pkt[pos + 2..pos + 2 + tag_len]).into_owned());
                break;
            }
            pos += 2 + tag_len;
        }
        let Some(essid) = essid else { return };
        if essid.is_empty() {
            return;
        }
        // update db
        match self.find_essid_index(bssid) {
            Some(index) => {
                let better = self.essids[index].priority >= priority
                    || (self.essids[index].essid_len == 0
                        && priority <= self.essids[index].priority);
                if better {
                    self.essids[index].essid_len = essid.len();
                    self.essids[index].priority = priority;
                    self.essids[index].essid = essid;
                }
            }
            None => {
                let mut entry = EssidEntry::default();
                entry.bssid.copy_from_slice(bssid);
                entry.essid_len = essid.len();
                entry.priority = priority;
                entry.essid = essid;
                self.essids.push(entry);
            }
        }
    }

    fn handle4way(&mut self, auth: Eapol, bssid: &[u8], ta: &[u8], ra: &[u8], raw: Vec<u8>) {
        if auth.length == 0 {
            return;
        }
        let replay = auth.replay_count;

        let (message, staid): (usize, &[u8]) = if !auth.key_ack() {
            if auth.secure() || auth.key_data_len == 0 {
                (4, ta)
            } else {
                (2, ta)
            }
        } else if auth.install() {
            (3, ra)
        } else {
            (1, ra)
        };

        let apsta = self
            .apstas
            .iter()
            .rposition(|sta| {
                sta.bssid.as_slice() == bssid
                    && sta.staid.as_slice() == staid
                    && sta.replay_count.abs_diff(replay) <= 64
            })
            .unwrap_or_else(|| {
                let mut sta = ApSta::default();
                sta.bssid.copy_from_slice(bssid);
                sta.staid.copy_from_slice(staid);
                self.apstas.push(sta);
                self.apstas.len() - 1
            });
        self.apstas[apsta].replay_count = replay;

        if self.apstas[apsta].handshake_done {
            return;
        }
        // M2-like packets require non-trivial sizes
        let eapol_size = auth.length as usize + 4;
        if (message == 2 || message == 4) && !(91..=256).contains(&eapol_size) {
            return;
        }

        match message {
            1 => {
                if let Some(ref first) = self.apstas[apsta].messages[1].eapol {
                    if first.replay_count == auth.replay_count && first.nonce == auth.nonce {
                        return;
                    }
                }
                for message in 1..=4 {
                    self.remove_handshake(apsta, message);
                }
                self.apstas[apsta].bssid.copy_from_slice(ta);
                self.apstas[apsta].staid.copy_from_slice(ra);
                self.apstas[apsta].messages[1].eapol_size = eapol_size;
                self.apstas[apsta].messages[1].raw_eapol = raw.clone();
                self.apstas[apsta].messages[1].eapol = Some(auth.clone());
            }
            2 => {
                if self.apstas[apsta].handshake_done {
                    return;
                }
                self.remove_handshake(apsta, 2);
                self.remove_handshake(apsta, 3);
                self.remove_handshake(apsta, 4);
                self.apstas[apsta].staid.copy_from_slice(ta);
                self.apstas[apsta].bssid.copy_from_slice(ra);
                self.apstas[apsta].messages[2].eapol_size = eapol_size;
                self.apstas[apsta].messages[2].raw_eapol = raw.clone();
                self.apstas[apsta].messages[2].eapol = Some(auth.clone());
            }
            3 => {
                if self.apstas[apsta].handshake_done {
                    return;
                }
                self.remove_handshake(apsta, 3);
                self.remove_handshake(apsta, 4);
                self.apstas[apsta].bssid.copy_from_slice(ta);
                self.apstas[apsta].staid.copy_from_slice(ra);
                self.apstas[apsta].messages[3].eapol_size = eapol_size;
                self.apstas[apsta].messages[3].raw_eapol = raw.clone();
                self.apstas[apsta].messages[3].eapol = Some(auth.clone());
                if let Some(ref second) = self.apstas[apsta].messages[2].eapol {
                    if second.replay_count + 1 == auth.replay_count {
                        let m1_match = self.apstas[apsta].messages[1]
                            .eapol
                            .as_ref()
                            .is_none_or(|first| first.nonce == auth.nonce);
                        if m1_match {
                            self.dump_auth(apsta, 3, 2);
                        }
                    }
                }
            }
            4 => {
                if self.apstas[apsta].handshake_done {
                    return;
                }
                self.remove_handshake(apsta, 2);
                self.remove_handshake(apsta, 4);
                self.apstas[apsta].staid.copy_from_slice(ta);
                self.apstas[apsta].bssid.copy_from_slice(ra);
                self.apstas[apsta].messages[4].eapol_size = eapol_size;
                self.apstas[apsta].messages[4].raw_eapol = raw.clone();
                self.apstas[apsta].messages[4].eapol = Some(auth.clone());
                if let Some(ref third) = self.apstas[apsta].messages[3].eapol {
                    if third.replay_count == auth.replay_count {
                        self.dump_auth(apsta, 3, 4);
                        return;
                    }
                }
                if let Some(ref first) = self.apstas[apsta].messages[1].eapol {
                    if first.replay_count + 1 == auth.replay_count {
                        self.dump_auth(apsta, 1, 4);
                    }
                }
            }
            _ => {}
        }
    }

    fn remove_handshake(&mut self, apsta: usize, message: usize) {
        self.apstas[apsta].messages[message].eapol = None;
        self.apstas[apsta].messages[message].eapol_size = 0;
    }

    /// Emit the hash line for message pairs (1,2), (3,2), (3,4) and (1,4).
    fn dump_auth(&mut self, apsta: usize, ap_message: usize, sta_message: usize) {
        let Some(ref sta_auth) = self.apstas[apsta].messages[sta_message].eapol else {
            return;
        };
        let Some(ref ap_auth) = self.apstas[apsta].messages[ap_message].eapol else {
            return;
        };
        let Some(ess) = self.find_essid_index(&self.apstas[apsta].bssid) else {
            return;
        };
        if self.essids[ess].essid_len == 0 {
            if self.essids[ess].priority == 6 {
                self.essids[ess].priority = 10;
            }
            return;
        }

        // build the hccap equivalent (we only need the fields the output uses)
        let essid = self.get_essid(&self.apstas[apsta].bssid);
        let mac1 = self.apstas[apsta].bssid;
        let mac2 = self.apstas[apsta].staid;
        let nonce1 = sta_auth.nonce;
        let nonce2 = ap_auth.nonce;
        let keyver = sta_auth.key_version();
        let mic = sta_auth.key_mic;
        // the EAPOL body is the stored raw frame with the key MIC zeroed out
        // (offset 81..97)
        let mut eapol_data = self.apstas[apsta].messages[sta_message].raw_eapol.clone();
        if eapol_data.len() >= 97 {
            eapol_data[81..97].fill(0);
        }

        // pack: essid(36 zero padded) + mac1(6) mac2(6) nonce1(32) nonce2(32)
        // + eapol (padded to 256 at offset 112..). The hccap record layout is
        // rebuilt and base64-encoded from offset 36:
        let mut hccap = vec![0u8; 36 + 6 + 6 + 32 + 32 + 256 + 4 + 4 + 16];
        hccap[36..42].copy_from_slice(&mac1);
        hccap[42..48].copy_from_slice(&mac2);
        hccap[48..80].copy_from_slice(&nonce1);
        hccap[80..112].copy_from_slice(&nonce2);
        let copy_len = eapol_data.len().min(256);
        hccap[112..112 + copy_len].copy_from_slice(&eapol_data[..copy_len]);
        hccap[368..372].copy_from_slice(&(eapol_data.len() as u32).to_le_bytes());
        hccap[372..376].copy_from_slice(&(keyver as u32).to_le_bytes());
        hccap[376..392].copy_from_slice(&mic);

        let mut line = format!("{essid}:$WPAPSK${essid}#");
        let encoded = &hccap[36..];
        let mut offset = 0;
        while offset + 3 < encoded.len() {
            push_crypt_block(&encoded[offset..], true, &mut line);
            offset += 3;
        }
        push_crypt_block(&encoded[offset..], false, &mut line);
        line.push_str(&format!(
            ":{}:{}:{}::WPA",
            hex::encode(mac2),
            hex::encode(mac1),
            hex::encode(mac1)
        ));
        if keyver > 1 {
            line.push('2');
        }
        if keyver > 2 {
            line.push_str(" CMAC");
        }
        if keyver > 3 {
            line.push_str(&format!(", ver {keyver}"));
        }
        line.push_str(&format!(
            ", {}verified",
            if ap_message == 1 && sta_message == 2 {
                "not "
            } else {
                ""
            }
        ));
        line.push(':');
        line.push_str(&self.filename);
        self.lines.push(line);

        if ap_message.max(sta_message) > 2 {
            self.apstas[apsta].handshake_done = true;
            for message in 1..=4 {
                self.remove_handshake(apsta, message);
            }
        }
    }
}

fn push_crypt_block(input: &[u8], full: bool, out: &mut String) {
    let b0 = input[0];
    let b1 = input[1];
    out.push(ITOA64[(b0 >> 2) as usize] as char);
    out.push(ITOA64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
    if full {
        let b2 = input[2];
        out.push(ITOA64[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        out.push(ITOA64[(b2 & 0x3f) as usize] as char);
    } else {
        out.push(ITOA64[((b1 & 0x0f) << 2) as usize] as char);
    }
}

impl Extractor for Wpapcap {
    fn name(&self) -> &'static str {
        "wpapcap"
    }

    fn description(&self) -> &'static str {
        "pcap files with WPA handshakes (802.11/radiotap/prism/PPI)"
    }

    fn accepts(&self, input: &Input) -> bool {
        (input.data.len() >= 24 && &input.data[0..4] == b"\xd4\xc3\xb2\xa1")
            || (input.data.len() >= 24 && &input.data[0..4] == b"\xa1\xb2\xc3\xd4")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < 24 {
            return Err(Error::not_format("wpapcap", input.label()));
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().expect("4"));
        // classic pcap only; 0xd4c3b2a1 read LE means file is big-endian
        let (swap_needed, network) = if magic == 0xa1b2_c3d4 {
            (
                false,
                u32::from_le_bytes(data[20..24].try_into().expect("4")),
            )
        } else if magic == 0xd4c3_b2a1 {
            (
                true,
                u32::from_be_bytes(data[20..24].try_into().expect("4")),
            )
        } else {
            return Err(Error::not_format("wpapcap", input.label()));
        };

        let mut st = WpaState {
            essids: Vec::new(),
            apstas: Vec::new(),
            lines: Vec::new(),
            filename: basename(input.label()).to_string(),
        };

        let mut pos = 24usize;

        while pos + 16 <= data.len() {
            // per-packet header: timestamp seconds/usecs, captured length,
            // original length
            let _ts_sec = u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4"));
            let _ts_usec = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().expect("4"));
            let mut snap_len =
                u32::from_le_bytes(data[pos + 8..pos + 12].try_into().expect("4")) as usize;
            let _orig_len = u32::from_le_bytes(data[pos + 12..pos + 16].try_into().expect("4"));
            if swap_needed {
                snap_len = snap_len.swap_bytes();
            }
            pos += 16;
            if pos + snap_len > data.len() {
                break;
            }
            process_packet(&mut st, &data[pos..pos + snap_len], network);
            pos += snap_len;
        }

        if st.lines.is_empty() {
            return Err(Error::malformed(
                input.label(),
                "no handshakes found in capture",
            ));
        }
        Ok(st.lines.into_iter().map(HashLine::new_empty).collect())
    }
}

/// Process one packet after link-type dispatch (TZSP and pcapng handling
/// are not supported).
fn process_packet(st: &mut WpaState, packet_buf: &[u8], link_type: u32) {
    let mut packet: &[u8] = packet_buf;

    // Prism skip
    if link_type == LINKTYPE_PRISM_HEADER {
        if packet.len() < 8 {
            return;
        }
        let frame_skip = if packet[7] == 0x40 {
            64usize
        } else {
            u32::from_le_bytes(packet[4..8].try_into().expect("4")) as usize
        };
        if frame_skip < 8 || frame_skip >= packet.len() {
            return;
        }
        packet = &packet[frame_skip..];
    }
    // Radiotap skip
    if link_type == LINKTYPE_RADIOTAP_HDR {
        if packet.len() < 4 {
            return;
        }
        let frame_skip = u16::from_le_bytes([packet[2], packet[3]]) as usize;
        if frame_skip == 0 || frame_skip >= packet.len() {
            return;
        }
        packet = &packet[frame_skip..];
    }
    // PPI skip
    if link_type == LINKTYPE_PPI_HDR {
        if packet.len() < 4 {
            return;
        }
        let mut frame_skip = u16::from_le_bytes([packet[2], packet[3]]) as usize;
        if frame_skip == 24 && u16::from_le_bytes([packet[8], packet[9]]) == 2 {
            frame_skip = 32;
        }
        if frame_skip == 0 || frame_skip >= packet.len() {
            return;
        }
        packet = &packet[frame_skip..];
    }

    // Ethernet EAPOL: build a fake 802.11 frame
    if link_type == LINKTYPE_ETHERNET
        && packet.len() >= 14
        && packet[12] == 0x88
        && packet[13] == 0x8e
    {
        let mut fake = vec![0x88u8, 0x02, 0x3c, 0x00];
        fake.extend_from_slice(&packet[0..12]);
        fake.extend_from_slice(&[0u8; 12]);
        fake.extend_from_slice(&[0x06, 0x00, 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00]);
        fake.extend_from_slice(&packet[12..]);
        let eapol = Eapol::parse(&fake[30..]);
        let bssid: Vec<u8> = if let Some(ref parsed) = eapol {
            if parsed.key_ack() {
                packet[6..12].to_vec()
            } else {
                packet[0..6].to_vec()
            }
        } else {
            packet[6..12].to_vec()
        };
        if let Some(auth) = eapol {
            let ta = fake[10..16].to_vec();
            let ra = fake[4..10].to_vec();
            let eapol_size = auth.length as usize + 4;
            let raw = fake[30..(30 + eapol_size).min(fake.len())].to_vec();
            st.handle4way(auth, &bssid, &ta, &ra, raw);
        }
        return;
    }

    if packet.len() < 10 {
        return;
    }
    let frame_control = u16::from_le_bytes([packet[0], packet[1]]);
    let version = frame_control & 3;
    let ptype = (frame_control >> 2) & 3;
    let subtype = (frame_control >> 4) & 0xf;
    let to_ds = frame_control & (1 << 8) != 0;
    let from_ds = frame_control & (1 << 9) != 0;
    let order = frame_control & (1 << 15) != 0;
    if version != 0 {
        return;
    }
    let has_ht = order;

    if ptype == 0 {
        // management: bssid is addr3
        if packet.len() >= 24 {
            let bssid = &packet[16..22];
            st.learn_essid_from_beacon(packet, subtype as usize, has_ht, bssid);
        }
        return;
    }

    if ptype != 2 {
        return;
    }

    // data frame
    let has_qos = subtype & 8 != 0;
    let has_addr4 = to_ds && from_ds;
    if !has_addr4 && !(to_ds ^ from_ds) {
        return;
    }
    let hdr_len = 24 + if has_qos { 2 } else { 0 } + if has_ht { 4 } else { 0 };
    if hdr_len + 8 + 2 >= packet.len() {
        return;
    }
    let llc_off = hdr_len + if has_addr4 { 6 } else { 0 };
    if llc_off + 8 > packet.len() {
        return;
    }
    let ethertype = u16::from_be_bytes([packet[llc_off + 6], packet[llc_off + 7]]);
    if ethertype != 0x888e {
        return;
    }
    let eapol_off = llc_off + 8;
    let Some(eapol) = Eapol::parse(&packet[eapol_off..]) else {
        return;
    };
    // determine bssid from direction (toDS → RA=addr1, fromDS → TA=addr2)
    let bssid: Vec<u8> = if to_ds {
        packet[4..10].to_vec() // addr1 = RA = AP
    } else {
        packet[10..16].to_vec() // addr2 = TA = AP
    };
    let ta: Vec<u8> = packet[10..16].to_vec(); // addr2
    let ra: Vec<u8> = packet[4..10].to_vec(); // addr1
    let eapol_size = eapol.length as usize + 4;
    let raw = packet[eapol_off..(eapol_off + eapol_size).min(packet.len())].to_vec();
    st.handle4way(eapol, &bssid, &ta, &ra, raw);
}
