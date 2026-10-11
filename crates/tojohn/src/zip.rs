//! Minimal read-only ZIP reader used by the iwork/libreoffice/staroffice
//! format modules. Supports stored and deflate entries via the central
//! directory; local headers are used for data offsets. Encryption flags
//! are surfaced, not decrypted.

use std::io::Read;

use crate::error::{Error, Result};

/// Central-directory file header signature (`PK\x01\x02`).
const CD_HEADER_MAGIC: u32 = 0x0201_4b50;
/// End-of-central-directory record signature (`PK\x05\x06`).
const EOCD_MAGIC: u32 = 0x0605_4b50;
/// Fixed size of the EOCD record without a comment.
const EOCD_MIN_SIZE: usize = 22;
/// Maximum length of the comment the EOCD record may carry.
const EOCD_MAX_COMMENT: usize = 65536;

pub struct ZipArchive<'a> {
    data: &'a [u8],
    entries: Vec<Entry>,
}

struct Entry {
    name: String,
    method: u16,
    flags: u16,
    compressed_size: usize,
    uncompressed_size: usize,
    local_offset: usize,
}

impl<'a> ZipArchive<'a> {
    /// Parse the central directory. Malformed archives map to
    /// [`Error::NotFormat`].
    pub fn new(data: &'a [u8], label: &str) -> Result<Self> {
        if data.len() < EOCD_MIN_SIZE {
            return Err(Error::not_format("zip", label));
        }
        // scan backwards for the EOCD record
        let scan_start = data.len().saturating_sub(EOCD_MIN_SIZE + EOCD_MAX_COMMENT);
        let eocd = (scan_start..=data.len() - EOCD_MIN_SIZE)
            .rev()
            .find(|&offset| {
                u32::from_le_bytes(data[offset..offset + 4].try_into().expect("4 bytes"))
                    == EOCD_MAGIC
            });
        let Some(eocd) = eocd else {
            return Err(Error::not_format("zip", label));
        };
        // +10: total entry count, +16: central-directory offset
        let count = u16::from_le_bytes(data[eocd + 10..eocd + 12].try_into().expect("2")) as usize;
        let cd_offset =
            u32::from_le_bytes(data[eocd + 16..eocd + 20].try_into().expect("4")) as usize;

        let mut entries = Vec::with_capacity(count);
        let mut pos = cd_offset;
        for _ in 0..count {
            if pos + 46 > data.len()
                || u32::from_le_bytes(data[pos..pos + 4].try_into().expect("4")) != CD_HEADER_MAGIC
            {
                return Err(Error::not_format("zip", label));
            }
            let flags = u16::from_le_bytes(data[pos + 8..pos + 10].try_into().expect("2"));
            let method = u16::from_le_bytes(data[pos + 10..pos + 12].try_into().expect("2"));
            let compressed_size =
                u32::from_le_bytes(data[pos + 20..pos + 24].try_into().expect("4")) as usize;
            let uncompressed_size =
                u32::from_le_bytes(data[pos + 24..pos + 28].try_into().expect("4")) as usize;
            let name_len =
                u16::from_le_bytes(data[pos + 28..pos + 30].try_into().expect("2")) as usize;
            let extra_len =
                u16::from_le_bytes(data[pos + 30..pos + 32].try_into().expect("2")) as usize;
            let comment_len =
                u16::from_le_bytes(data[pos + 32..pos + 34].try_into().expect("2")) as usize;
            let local_offset =
                u32::from_le_bytes(data[pos + 42..pos + 46].try_into().expect("4")) as usize;
            let name = String::from_utf8_lossy(&data[pos + 46..pos + 46 + name_len]).to_string();
            entries.push(Entry {
                name,
                method,
                flags,
                compressed_size,
                uncompressed_size,
                local_offset,
            });
            pos += 46 + name_len + extra_len + comment_len;
        }
        Ok(Self { data, entries })
    }

    /// Entry lookup by exact name; `None` when no entry matches.
    pub fn open(&self, name: &str) -> Option<Vec<u8>> {
        let entry = self.entries.iter().find(|e| e.name == name)?;
        Some(self.read(entry))
    }

    /// Entry names in central-directory order.
    pub fn entries(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|e| e.name.as_str())
    }

    /// Whether an entry exists and is flagged encrypted.
    pub fn is_encrypted(&self, name: &str) -> bool {
        self.entries
            .iter()
            .find(|e| e.name == name)
            .is_some_and(|e| e.flags & 0x01 != 0)
    }

    fn read(&self, entry: &Entry) -> Vec<u8> {
        let offset = entry.local_offset;
        if offset + 30 > self.data.len() {
            return Vec::new();
        }
        let name_len =
            u16::from_le_bytes(self.data[offset + 26..offset + 28].try_into().expect("2")) as usize;
        let extra_len =
            u16::from_le_bytes(self.data[offset + 28..offset + 30].try_into().expect("2")) as usize;
        let data_start = offset + 30 + name_len + extra_len;
        let data_end = (data_start + entry.compressed_size).min(self.data.len());
        let compressed = &self.data[data_start..data_end];
        match entry.method {
            0 => compressed.to_vec(), // stored
            8 => {
                // deflate: a truncated stream yields whatever was decoded
                let mut out = Vec::with_capacity(entry.uncompressed_size);
                let mut decoder = flate2::read::DeflateDecoder::new(compressed);
                let _ = decoder.read_to_end(&mut out);
                out
            }
            _ => Vec::new(),
        }
    }
}
