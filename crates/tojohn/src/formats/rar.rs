//! RAR archive encryption-header parser. RAR3 archives emit `$RAR3$` lines
//! for whole-archive encryption (type 0) and per-file encryption (type 1);
//! RAR5 archives emit `$rar5$` lines from the HEAD_CRYPT block or the
//! file-header FHEXTRA_CRYPT extra record.
//!
//! Output labels use the archive basename. For RAR3 type 1, the gecos field
//! (file names, space separated) is appended.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util::basename;

pub struct Rar;

const RAR3_MAGIC: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_MAGIC: &[u8] = b"Rar!\x1a\x07\x01\x00";
const RAR_OLD_MAGIC: &[u8] = b"RE~~";

/// RAR5 KDF salt length.
const SIZE_SALT50: usize = 16;
/// RAR5 encrypted-header IV length.
const SIZE_INITV: usize = 16;
/// RAR5 password check value length.
const SIZE_PSWCHECK: usize = 8;
/// RAR5 checksum of the password check value.
const SIZE_PSWCHECK_CSUM: usize = 4;
/// Maximum RAR5 PBKDF2 iteration count exponent.
const CRYPT5_KDF_LG2_COUNT_MAX: u8 = 24;

// RAR5 block types
const HEAD_MAIN: u8 = 0x01;
const HEAD_FILE: u8 = 0x02;
const HEAD_SERVICE: u8 = 0x03;
const HEAD_CRYPT: u8 = 0x04;

// RAR5 header flags
const HFL_EXTRA: u64 = 1;
const HFL_DATA: u64 = 2;
// RAR5 file-extra record: encryption info
const FHEXTRA_CRYPT: u64 = 1;
// FHEXTRA_CRYPT flag: password check data present
const FHEXTRA_CRYPT_PSWCHECK: u64 = 1;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn read_byte(&mut self) -> Option<u8> {
        let byte = self.data.get(self.pos).copied();
        if byte.is_some() {
            self.pos += 1;
        }
        byte
    }

    fn u32le(&mut self) -> Option<u32> {
        let mut value = 0u32;
        for shift in [0, 8, 16, 24] {
            value |= (self.read_byte()? as u32) << shift;
        }
        Some(value)
    }

    fn read_bytes(&mut self, count: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.read_byte()?);
        }
        Some(out)
    }

    /// RAR5 variable-length integer (7 bits per byte, little-endian groups).
    fn vuint(&mut self) -> Option<u64> {
        let mut accum = 0u64;
        let mut shift = 0u32;
        for _ in 0..8 {
            let byte = self.read_byte()?;
            accum += ((byte & 0x7f) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return Some(accum);
            }
        }
        None
    }
}

impl Extractor for Rar {
    fn name(&self) -> &'static str {
        "rar"
    }

    fn description(&self) -> &'static str {
        "RAR3/RAR5 encrypted archives"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(RAR3_MAGIC) || input.data.starts_with(RAR5_MAGIC)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let base = basename(input.label());
        let label = input.label();
        if data.starts_with(RAR_OLD_MAGIC) {
            return Err(Error::malformed(
                label,
                "RAR file version too old (pre 1.50), not supported",
            ));
        }
        if data.starts_with(RAR3_MAGIC) {
            return self.rar3(data, base, label);
        }
        if data.starts_with(RAR5_MAGIC) {
            return self.rar5(data, base);
        }
        Err(Error::malformed(label, "not a RAR file"))
    }
}

impl Rar {
    /// RAR3: archive header, then file headers; type 0 (whole-archive
    /// encryption) or type 1 (per-file).
    fn rar3(&self, data: &[u8], base: &str, label: &str) -> Result<Vec<HashLine>> {
        let mut reader = Reader {
            data,
            pos: RAR3_MAGIC.len(),
        };

        // archive header (13 bytes)
        let header = reader
            .read_bytes(13)
            .ok_or_else(|| Error::malformed(base, "not a RAR file"))?;
        if header[2] != 0x73 {
            return Err(Error::malformed(
                base,
                "archive header type byte must be 0x73",
            ));
        }
        let archive_head_flags = u16::from_le_bytes([header[3], header[4]]);
        let head_size = u16::from_le_bytes([header[5], header[6]]);
        if head_size > 13 {
            reader.pos += (head_size - 13) as usize;
        }

        let hp_mode = archive_head_flags & 0x0080 != 0;

        // whole-archive encryption: salt + 16 bytes of known plaintext from
        // the end of file
        if hp_mode {
            if data.len() < 24 {
                return Err(Error::malformed(base, "read failed"));
            }
            let tail = &data[data.len() - 24..];
            // the last field is the archive path as given
            let line = format!(
                "{base}:$RAR3$*0*{}*{}:0::::{}",
                hex::encode(&tail[..8]),
                hex::encode(&tail[8..24]),
                label,
            );
            return Ok(vec![HashLine::new(base.to_string(), line)]);
        }

        // type 1: scan file headers, pick the best encrypted candidate
        let mut best: Option<(u64, u64, u8, String)> = None; // (pack, unp, method, line)

        while let Some(file_header) = reader.read_bytes(32) {
            if file_header[2] != 0x74 {
                break;
            }
            let head_flags = u16::from_le_bytes([file_header[3], file_header[4]]);
            if head_flags & 0x8000 == 0 {
                break;
            }
            let head_size = u16::from_le_bytes([file_header[5], file_header[6]]);
            let mut packed_size = u32::from_le_bytes(file_header[7..11].try_into().unwrap()) as u64;
            let mut unpacked_size =
                u32::from_le_bytes(file_header[11..15].try_into().unwrap()) as u64;
            let mut ext_time_size = head_size as i64 - 32;

            if head_flags & 0x100 != 0 {
                let hi_packed = reader
                    .u32le()
                    .ok_or_else(|| Error::malformed(base, "read failed"))?;
                packed_size += (hi_packed as u64) << 32;
                ext_time_size -= 4;
                let hi_unpacked = reader
                    .u32le()
                    .ok_or_else(|| Error::malformed(base, "read failed"))?;
                unpacked_size += (hi_unpacked as u64) << 32;
                ext_time_size -= 4;
            }

            let file_name_size = u16::from_le_bytes([file_header[26], file_header[27]]);
            let file_name_bytes = reader
                .read_bytes(file_name_size as usize)
                .ok_or_else(|| Error::malformed(base, "read failed"))?;
            let file_name = String::from_utf8_lossy(&file_name_bytes).into_owned();
            ext_time_size -= file_name_size as i64;

            let mut salt = [0u8; 8];
            if head_flags & 0x400 != 0 {
                ext_time_size -= 8;
                salt.copy_from_slice(
                    &reader
                        .read_bytes(8)
                        .ok_or_else(|| Error::malformed(base, "read failed"))?,
                );
            }
            if head_flags & 0x1000 != 0 && ext_time_size > 0 {
                let _ = reader.read_bytes(ext_time_size as usize);
            }

            // solid / directory / not-encrypted / too old: skip data, continue
            if head_flags & 0x10 != 0 {
                reader.pos += packed_size as usize;
                continue;
            }
            if (head_flags & 0xe0) >> 5 == 7 {
                reader.pos += packed_size as usize;
                continue;
            }
            if head_flags & 0x04 == 0 {
                reader.pos += packed_size as usize;
                continue;
            }
            if file_header[24] < 29 {
                reader.pos += packed_size as usize;
                continue;
            }
            let method = file_header[25];

            // candidate preference: smaller pack wins; same pack prefers unp>=8
            let better_exists = best.as_ref().is_some_and(|(bp, bu, bm, _)| {
                ((*bp < packed_size && *bu >= if *bm > 0x30 { 4 } else { 1 })
                    || (*bu > unpacked_size && unpacked_size < if method > 0x30 { 4 } else { 1 }))
                    || (*bp == packed_size
                        && ((*bu > unpacked_size && unpacked_size < 8)
                            || (*bu <= unpacked_size && *bu >= 8)))
            });
            if better_exists {
                reader.pos += packed_size as usize;
                continue;
            }

            let data_bytes = reader
                .read_bytes(packed_size as usize)
                .ok_or_else(|| Error::malformed(base, "error while reading archive"))?;

            let file_crc = &file_header[16..20];
            let mut line = format!(
                "{base}:$RAR3$*1*{}*{}*{packed_size}*{unpacked_size}*1*{}*{method:02x}:1::",
                hex::encode(salt),
                hex::encode(file_crc),
                hex::encode(&data_bytes),
            );
            // gecos: "<name> " is appended at the end of the line (trailing space)
            line.push_str(&file_name);
            line.push(' ');
            best = Some((packed_size, unpacked_size, method, line));
        }

        match best {
            Some((_, _, _, line)) => Ok(vec![HashLine::new(base.to_string(), line)]),
            None => Err(Error::malformed(
                base,
                "did not find a valid encrypted candidate",
            )),
        }
    }

    /// RAR5: walk blocks; HEAD_CRYPT sets globals for the encrypted-header
    /// print; FHEXTRA_CRYPT in a FILE/SERVICE header prints directly.
    fn rar5(&self, data: &[u8], base: &str) -> Result<Vec<HashLine>> {
        let mut reader = Reader {
            data,
            pos: RAR5_MAGIC.len(),
        };
        let mut encrypted = false;
        let mut rar5_iterations = 0u8;
        let mut rar5_salt = vec![0u8; SIZE_SALT50];
        let mut pswcheck = vec![0u8; SIZE_PSWCHECK];

        loop {
            let cur_block_pos = reader.pos;
            // Encrypted header: first 16 bytes are the IV
            if encrypted {
                let Some(iv) = reader.read_bytes(SIZE_INITV) else {
                    break;
                };
                let line = format!(
                    "{base}:$rar5$16${}${rar5_iterations}${}$8${}",
                    hex::encode(&rar5_salt),
                    hex::encode(&iv),
                    hex::encode(&pswcheck)
                );
                return Ok(vec![HashLine::new(base.to_string(), line)]);
            }
            let Some(_) = reader.u32le() else { break }; // head CRC
            let Some(block_size) = reader.vuint() else {
                break;
            };
            // vint length: bytes consumed by the block_size field
            let vint_len = {
                let mut count = 0;
                let mut pos = cur_block_pos + 4;
                while pos < data.len() {
                    count += 1;
                    if data[pos] & 0x80 == 0 {
                        break;
                    }
                    pos += 1;
                }
                count
            };
            let head_size = block_size + 4 + vint_len as u64;
            let Some(header_type) = reader.read_byte() else {
                break;
            };
            let Some(flags) = reader.vuint() else { break };
            let mut extra_size = 0u64;
            let mut data_size = 0u64;
            if flags & HFL_EXTRA != 0 {
                let Some(value) = reader.vuint() else { break };
                extra_size = value;
            }
            if flags & HFL_DATA != 0 {
                let Some(value) = reader.vuint() else { break };
                data_size = value;
            }

            if header_type == HEAD_CRYPT {
                let Some(crypt_version) = reader.vuint() else {
                    break;
                };
                if crypt_version > 0 {
                    return Err(Error::malformed(base, "bad rar crypt version byte"));
                }
                let Some(enc_flags) = reader.vuint() else {
                    break;
                };
                let use_pswcheck = enc_flags & FHEXTRA_CRYPT_PSWCHECK != 0;
                let Some(lg2) = reader.read_byte() else { break };
                if lg2 > CRYPT5_KDF_LG2_COUNT_MAX {
                    return Err(Error::malformed(
                        base,
                        "rar PBKDF2 iteration count too large",
                    ));
                }
                rar5_iterations = lg2;
                match reader.read_bytes(SIZE_SALT50) {
                    Some(salt) => rar5_salt = salt,
                    None => break,
                }
                if use_pswcheck {
                    match reader.read_bytes(SIZE_PSWCHECK) {
                        Some(check) => pswcheck = check,
                        None => break,
                    }
                    let _ = reader.read_bytes(SIZE_PSWCHECK_CSUM);
                }
                encrypted = true;
            } else if header_type == HEAD_MAIN {
                let Some(arc_flags) = reader.vuint() else {
                    break;
                };
                if arc_flags & 1 != 0 {
                    let _volume = reader.vuint();
                }
            } else if header_type == HEAD_FILE || header_type == HEAD_SERVICE {
                let Some(file_flags) = reader.vuint() else {
                    break;
                };
                // RAR5 file flags: 0x01 directory, 0x02 mtime (u32),
                // 0x04 CRC32 (u32), 0x08 unknown unpacked size. The optional
                // mtime/CRC32 u32 fields must be consumed in this order.
                let Some(_) = reader.vuint() else { break }; // unpacked size
                let Some(_) = reader.vuint() else { break }; // attributes
                if file_flags & 0x02 != 0 {
                    let _ = reader.u32le();
                }
                if file_flags & 0x04 != 0 {
                    let _ = reader.u32le();
                }
                let Some(_) = reader.vuint() else { break }; // compression info
                let Some(_) = reader.vuint() else { break }; // host OS
                let Some(name_size) = reader.vuint() else {
                    break;
                };
                reader.pos += name_size as usize;
                if extra_size != 0 {
                    if let Some(line) =
                        process_extra50(&mut reader, extra_size, header_type, base, &mut pswcheck)
                    {
                        return Ok(vec![HashLine::new(base.to_string(), line)]);
                    }
                }
            } else if header_type == 0x05 {
                // HEAD_ENDARC
                break;
            }
            let next = cur_block_pos as u64 + head_size + data_size;
            if next <= cur_block_pos as u64 || next as usize > data.len() {
                break;
            }
            reader.pos = next as usize;
        }
        Err(Error::malformed(
            base,
            "did not find a valid encrypted candidate",
        ))
    }
}

/// Process the RAR5 extra area looking for FHEXTRA_CRYPT; renders the hash
/// line and returns Some on success.
fn process_extra50(
    reader: &mut Reader,
    extra_size: u64,
    header_type: u8,
    base: &str,
    pswcheck_out: &mut Vec<u8>,
) -> Option<String> {
    let mut bytes_left = extra_size as i64;
    loop {
        let start = reader.pos;
        let field_size = reader.vuint()?;
        if reader.pos - start > 3 {
            return None;
        }
        bytes_left -= (reader.pos - start) as i64;
        bytes_left -= field_size as i64;
        if bytes_left < 0 {
            return None;
        }
        let field_type = reader.vuint()?;
        if (header_type == HEAD_FILE || header_type == HEAD_SERVICE) && field_type == FHEXTRA_CRYPT
        {
            let enc_version = reader.vuint()?;
            let flags = reader.vuint()?;
            if enc_version > 0 {
                return None;
            }
            if flags & FHEXTRA_CRYPT_PSWCHECK == 0 {
                return None;
            }
            let lg2count = reader.read_byte()?;
            if lg2count >= CRYPT5_KDF_LG2_COUNT_MAX {
                return None;
            }
            let salt = reader.read_bytes(SIZE_SALT50)?;
            let initv = reader.read_bytes(SIZE_INITV)?;
            let pswcheck = reader.read_bytes(SIZE_PSWCHECK)?;
            let line = format!(
                "{base}:$rar5$16${}${lg2count}${}$8${}",
                hex::encode(salt),
                hex::encode(&initv),
                hex::encode(&pswcheck)
            );
            *pswcheck_out = pswcheck;
            return Some(line);
        }
        // skip unknown field body
        reader.pos += field_size as usize;
        if bytes_left == 0 {
            return None;
        }
    }
}
