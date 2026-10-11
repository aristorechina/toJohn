//! Bitcoin Core wallet.dat (BerkeleyDB) parser. The BDB layer is read with
//! a minimal read-only btree/hash page walker (on-page items plus overflow
//! chains for the typical wallet layout); the `mkey` record and the first
//! `ckey` record feed a `$bitcoin$` line.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Bitcoin;

impl Extractor for Bitcoin {
    fn name(&self) -> &'static str {
        "bitcoin"
    }

    fn description(&self) -> &'static str {
        "Bitcoin Core wallet.dat files (BerkeleyDB)"
    }

    fn accepts(&self, input: &Input) -> bool {
        // BDB btree metadata magic 0x00053162 at offset 26 of page 0
        input.data.len() > 100 && input.data[26..30] == [0x00, 0x05, 0x31, 0x62]
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let records = bdb_records(data)
            .ok_or_else(|| Error::malformed(input.label(), "couldn't open wallet.dat/main"))?;

        // collect the mkey record and the first ckey record
        let mut mkey: Option<(Vec<u8>, Vec<u8>, u32)> = None; // (encrypted_key, salt, rounds)
        let mut ckey: Option<(Vec<u8>, Vec<u8>)> = None; // (pubkey, encrypted_privkey)

        for (key, value) in &records {
            let mut key_stream = RecordStream::new(key);
            let mut value_stream = RecordStream::new(value);
            let Ok(raw_type) = key_stream.read_string() else {
                continue;
            };
            // BDB stores the type string NUL-terminated
            let type_name = String::from_utf8_lossy(&raw_type).replace('\0', "");
            match type_name.as_str() {
                "mkey" => {
                    let _n_id = key_stream.read_uint32().unwrap_or(0);
                    let encrypted_key = value_stream.read_string().unwrap_or_default();
                    let salt = value_stream.read_string().unwrap_or_default();
                    // nDerivationMethod (4) then nDerivationIterations (4)
                    let _method = value_stream.read_uint32().unwrap_or(0);
                    let rounds = value_stream.read_uint32().unwrap_or(0);
                    mkey = Some((encrypted_key, salt, rounds));
                }
                "ckey" => {
                    let public_key_len = key_stream.read_compact_size().unwrap_or(0) as usize;
                    let public_key = key_stream.read_bytes(public_key_len).unwrap_or_default();
                    let private_key_len = value_stream.read_compact_size().unwrap_or(0) as usize;
                    let encrypted_private_key =
                        value_stream.read_bytes(private_key_len).unwrap_or_default();
                    if ckey.is_none() {
                        ckey = Some((public_key, encrypted_private_key));
                    }
                }
                _ => {}
            }
        }

        let Some((encrypted_key, salt, rounds)) = mkey else {
            // no mkey record: the wallet is not encrypted
            return Ok(Vec::new());
        };
        let Some((public_key, encrypted_privkey)) = ckey else {
            return Ok(Vec::new());
        };

        // last two aes blocks should be enough
        let encrypted_key_tail = if encrypted_key.len() > 64 {
            encrypted_key[encrypted_key.len() - 64..].to_vec()
        } else {
            encrypted_key
        };
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!(
                "$bitcoin${}${}${}${}${rounds}${}${}${}${}",
                encrypted_key_tail.len(),
                hex::encode(&encrypted_key_tail),
                salt.len(),
                hex::encode(salt),
                encrypted_privkey.len(),
                hex::encode(encrypted_privkey),
                public_key.len(),
                hex::encode(public_key),
            ),
        )])
    }
}

/// Read-only BerkeleyDB btree/hash page walker: returns the (key, value)
/// pairs of the "main" database. Handles the standard page layout with
/// on-page and overflow items.
fn bdb_records(data: &[u8]) -> Option<Vec<(Vec<u8>, Vec<u8>)>> {
    if data.len() < 40 {
        return None;
    }
    // metadata layout after type@25: magic(26..30), version(30..34),
    // pagesize(34..38), secsize...
    let page_size = u32::from_be_bytes(data[34..38].try_into().ok()?) as usize;
    if page_size == 0 || data.len() < page_size {
        return None;
    }
    let mut records = Vec::new();
    let num_pages = data.len() / page_size;
    // walk all pages; leaf pages (13 = btree leaf, 3 = hash leaf) hold items
    for page_no in 0..num_pages {
        let base = page_no * page_size;
        if base + 26 > data.len() {
            break;
        }
        let page_type = data[base + 25];
        if page_type != 13 && page_type != 3 {
            continue;
        }
        let num_entries = u16::from_be_bytes(data[base + 20..base + 22].try_into().ok()?) as usize;
        let entry_base = base + 26;
        for idx in 0..num_entries {
            let off_pos = entry_base + idx * 2;
            if off_pos + 2 > data.len() {
                break;
            }
            let item_off = u16::from_be_bytes(data[off_pos..off_pos + 2].try_into().ok()?) as usize;
            if item_off == 0 || base + item_off + 4 > data.len() {
                continue;
            }
            // each item: 1 byte page type (1 = on-page data, 3 = overflow
            // reference, for both btree and hash pages), then length (u16)
            let item_type = data[base + item_off];
            let item_len = u16::from_be_bytes(
                data[base + item_off + 1..base + item_off + 3]
                    .try_into()
                    .ok()?,
            ) as usize;
            let content_start = base + item_off + 3;
            let item = match item_type {
                1 => {
                    if content_start + item_len > data.len() {
                        continue;
                    }
                    data[content_start..content_start + item_len].to_vec()
                }
                3 => {
                    // overflow: page number of the overflow chain
                    if content_start + 4 > data.len() {
                        continue;
                    }
                    let ovfl =
                        u32::from_be_bytes(data[content_start..content_start + 4].try_into().ok()?)
                            as usize;
                    read_overflow(data, page_size, ovfl)
                }
                _ => continue,
            };
            // btree leaf pages interleave key/value entries
            let is_btree = page_type == 13;
            if is_btree {
                if idx % 2 == 0 {
                    continue; // key slot; handled with its value slot
                }
                // pair with previous item
                if let Some(prev_off_pos) = idx.checked_sub(1).map(|i| entry_base + i * 2) {
                    let prev_off =
                        u16::from_be_bytes(data[prev_off_pos..prev_off_pos + 2].try_into().ok()?)
                            as usize;
                    if prev_off == 0 || base + prev_off + 3 > data.len() {
                        continue;
                    }
                    let prev_type = data[base + prev_off];
                    let prev_len = u16::from_be_bytes(
                        data[base + prev_off + 1..base + prev_off + 3]
                            .try_into()
                            .ok()?,
                    ) as usize;
                    let prev_start = base + prev_off + 3;
                    let key = match prev_type {
                        1 => data.get(prev_start..prev_start + prev_len)?.to_vec(),
                        3 => {
                            if prev_start + 4 > data.len() {
                                continue;
                            }
                            let ovfl = u32::from_be_bytes(
                                data[prev_start..prev_start + 4].try_into().ok()?,
                            ) as usize;
                            read_overflow(data, page_size, ovfl)
                        }
                        _ => continue,
                    };
                    records.push((key, item));
                }
            }
        }
    }
    Some(records)
}

/// Follow a BDB overflow page chain and assemble the full item.
fn read_overflow(data: &[u8], page_size: usize, mut page_no: usize) -> Vec<u8> {
    let mut out = Vec::new();
    // bounded walk so a cyclic overflow chain cannot loop forever
    for _ in 0..1000 {
        let base = page_no * page_size;
        if base + 26 > data.len() {
            break;
        }
        // overflow page: the next-page number is the third u32 of the page
        // header (offset 16); item data starts after the 26-byte header
        let next_page =
            u32::from_be_bytes(data[base + 16..base + 20].try_into().unwrap_or([0; 4])) as usize;
        let data_len =
            u16::from_be_bytes(data[base + 26..base + 28].try_into().unwrap_or([0; 2])) as usize;
        let start = base + 26;
        if start + data_len <= data.len() {
            out.extend_from_slice(&data[start..start + data_len]);
        }
        if next_page == 0 {
            break;
        }
        page_no = next_page;
    }
    out
}

/// Minimal reader for wallet record serialization: compact-size integers,
/// length-prefixed byte strings, uint32.
struct RecordStream<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> RecordStream<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Strings are length-prefixed byte blobs, read binary-safe.
    fn read_string(&mut self) -> Result<Vec<u8>> {
        let len = self.read_compact_size()? as usize;
        if self.pos + len > self.data.len() {
            return Err(Error::other("read_string past end"));
        }
        let out = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    fn read_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        if self.pos + n > self.data.len() {
            return Err(Error::other("read_bytes past end"));
        }
        let out = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(out)
    }

    fn read_compact_size(&mut self) -> Result<u64> {
        let Some(&first) = self.data.get(self.pos) else {
            return Err(Error::other("compact size past end"));
        };
        self.pos += 1;
        Ok(match first {
            253 => {
                let v = u16::from_le_bytes(
                    self.data
                        .get(self.pos..self.pos + 2)
                        .ok_or_else(|| Error::other("eof"))?
                        .try_into()
                        .expect("2"),
                ) as u64;
                self.pos += 2;
                v
            }
            254 => {
                let v = u32::from_le_bytes(
                    self.data
                        .get(self.pos..self.pos + 4)
                        .ok_or_else(|| Error::other("eof"))?
                        .try_into()
                        .expect("4"),
                ) as u64;
                self.pos += 4;
                v
            }
            255 => {
                let v = u64::from_le_bytes(
                    self.data
                        .get(self.pos..self.pos + 8)
                        .ok_or_else(|| Error::other("eof"))?
                        .try_into()
                        .expect("8"),
                );
                self.pos += 8;
                v
            }
            n => n as u64,
        })
    }

    fn read_uint32(&mut self) -> Result<u32> {
        let b = self
            .data
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| Error::other("uint32 past end"))?;
        self.pos += 4;
        Ok(u32::from_le_bytes(b.try_into().expect("4")))
    }
}
