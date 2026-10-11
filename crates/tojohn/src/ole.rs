//! Minimal OLE2/CFB (Compound File Binary) reader for the `office` format
//! module. Supports the 512/4096-byte sector sizes, FAT/directory/FAT-chain
//! parsing, mini-FAT streams and directory entry lookup by name.

use crate::error::{Error, Result};

pub struct OleFile<'a> {
    data: &'a [u8],
    sector_size: usize,
    mini_sector_size: usize,
    fat: Vec<u32>,
    directory: Vec<u8>,
    mini_fat: Vec<u32>,
    mini_stream_start: u32,
    mini_cutoff: usize,
}

const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const FREESECT: u32 = 0xFFFF_FFFF;

impl<'a> OleFile<'a> {
    /// Parse the CFB header and the FAT/directory structures.
    pub fn new(data: &'a [u8], label: &str) -> Result<Self> {
        const MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        if data.len() < 512 || data[..8] != MAGIC {
            return Err(Error::not_format("OLE", label));
        }
        let sector_shift = u16::from_le_bytes(data[30..32].try_into().expect("2")) as usize;
        let mini_shift = u16::from_le_bytes(data[32..34].try_into().expect("2")) as usize;
        let sector_size = 1usize << sector_shift;
        let mini_sector_size = 1usize << mini_shift;
        let _num_fat_sectors = u32::from_le_bytes(data[44..48].try_into().expect("4")) as usize;
        let first_dir_sector = u32::from_le_bytes(data[48..52].try_into().expect("4"));
        let mini_cutoff = u32::from_le_bytes(data[56..60].try_into().expect("4")) as usize;
        let first_mini_fat = u32::from_le_bytes(data[60..64].try_into().expect("4"));
        let num_mini_fat = u32::from_le_bytes(data[64..68].try_into().expect("4")) as usize;
        let difat_start = u32::from_le_bytes(data[68..72].try_into().expect("4"));
        let num_difat = u32::from_le_bytes(data[72..76].try_into().expect("4")) as usize;

        // DIFAT: first 109 entries in the header, then chained DIFAT sectors
        let mut fat_sectors: Vec<u32> = Vec::new();
        for i in 0..109 {
            let v = u32::from_le_bytes(data[76 + i * 4..76 + i * 4 + 4].try_into().expect("4"));
            if v != FREESECT && v != ENDOFCHAIN {
                fat_sectors.push(v);
            }
        }
        let mut difat_sector = difat_start;
        let mut guard = 0;
        while difat_sector != ENDOFCHAIN && difat_sector != FREESECT && guard < num_difat + 8 {
            guard += 1;
            let base = sector(difat_sector, sector_size);
            if base + sector_size > data.len() {
                break;
            }
            for i in 0..sector_size / 4 - 1 {
                let v =
                    u32::from_le_bytes(data[base + i * 4..base + i * 4 + 4].try_into().expect("4"));
                if v != FREESECT && v != ENDOFCHAIN {
                    fat_sectors.push(v);
                }
            }
            difat_sector = u32::from_le_bytes(
                data[base + sector_size - 4..base + sector_size]
                    .try_into()
                    .expect("4"),
            );
        }

        // FAT
        let mut fat = Vec::new();
        for fs in &fat_sectors {
            let base = sector(*fs, sector_size);
            if base + sector_size > data.len() {
                continue;
            }
            for i in 0..sector_size / 4 {
                fat.push(u32::from_le_bytes(
                    data[base + i * 4..base + i * 4 + 4].try_into().expect("4"),
                ));
            }
        }

        // directory chain
        let dir_data = read_chain(data, &fat, first_dir_sector, sector_size, None);

        // mini FAT
        let mini_fat = if first_mini_fat != ENDOFCHAIN && num_mini_fat > 0 {
            let mf = read_chain(data, &fat, first_mini_fat, sector_size, None);
            mf.chunks(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c.get(3).copied().unwrap_or(0xFF)]))
                .collect()
        } else {
            Vec::new()
        };

        // mini stream start: root entry (first directory entry)
        let mini_stream_start = if dir_data.len() >= 128 + 16 {
            u32::from_le_bytes(dir_data[128 + 116..128 + 120].try_into().expect("4"))
        } else {
            ENDOFCHAIN
        };

        Ok(Self {
            data,
            sector_size,
            mini_sector_size,
            fat,
            directory: dir_data,
            mini_fat,
            mini_stream_start,
            mini_cutoff,
        })
    }

    /// List all stream entries (type 2), name + size.
    pub fn list_streams(&self) -> Vec<String> {
        self.directory
            .chunks(128)
            .enumerate()
            .skip(1) // entry 0 is the root storage
            .filter(|(_, e)| e.len() >= 128 && e[66] == 2)
            .map(|(_, e)| decode_dir_name(e))
            .collect()
    }

    fn find_entry(&self, name: &str) -> Option<(u32, u64)> {
        self.directory
            .chunks(128)
            .filter(|e| e.len() >= 128 && e[66] == 2)
            .find(|e| decode_dir_name(e) == name)
            .map(|e| {
                (
                    u32::from_le_bytes(e[116..120].try_into().expect("4")),
                    u64::from_le_bytes(e[120..128].try_into().expect("8")),
                )
            })
    }

    /// Read a stream by exact directory name.
    pub fn open_stream(&self, name: &str) -> Result<Vec<u8>> {
        let (start, size) = self
            .find_entry(name)
            .ok_or_else(|| Error::Other(format!("stream {name} not found")))?;
        if size < self.mini_cutoff as u64 {
            // mini stream: read the root's mini stream, then chain
            let mini = read_chain(
                self.data,
                &self.fat,
                self.mini_stream_start,
                self.sector_size,
                None,
            );
            let mut out = Vec::with_capacity(size as usize);
            let mut sec = start;
            let mut guard = 0;
            while sec != ENDOFCHAIN && sec != FREESECT && guard < 1_000_000 {
                guard += 1;
                let off = sec as usize * self.mini_sector_size;
                if off + self.mini_sector_size > mini.len() {
                    break;
                }
                out.extend_from_slice(&mini[off..off + self.mini_sector_size]);
                if (sec as usize) >= self.mini_fat.len() {
                    break;
                }
                sec = self.mini_fat[sec as usize];
            }
            out.truncate(size as usize);
            Ok(out)
        } else {
            Ok(read_chain(
                self.data,
                &self.fat,
                start,
                self.sector_size,
                Some(size as usize),
            ))
        }
    }
}

fn sector(no: u32, sector_size: usize) -> usize {
    (no as usize + 1) * sector_size
}

fn read_chain(
    data: &[u8],
    fat: &[u32],
    start: u32,
    sector_size: usize,
    exact: Option<usize>,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut sec = start;
    let mut guard = 0;
    while sec != ENDOFCHAIN && sec != FREESECT && guard < 10_000_000 {
        guard += 1;
        let base = sector(sec, sector_size);
        if base + sector_size > data.len() {
            break;
        }
        out.extend_from_slice(&data[base..base + sector_size]);
        if exact.is_some() && out.len() >= exact.unwrap() {
            break;
        }
        if (sec as usize) >= fat.len() {
            break;
        }
        sec = fat[sec as usize];
    }
    if let Some(n) = exact {
        out.truncate(n);
    }
    out
}

fn decode_dir_name(e: &[u8]) -> String {
    let name_len = u16::from_le_bytes(e[64..66].try_into().expect("2")) as usize;
    if !(2..=64).contains(&name_len) {
        return String::new();
    }
    let raw = &e[..name_len - 2]; // UTF-16LE without terminator
    raw.chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect::<Vec<u16>>()
        .iter()
        .map(|&c| char::from_u32(c as u32).unwrap_or('\u{fffd}'))
        .collect()
}
