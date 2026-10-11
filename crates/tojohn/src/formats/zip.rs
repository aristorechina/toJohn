//! PKZIP/WinZip archive parser emitting `$pkzip2$` lines with the extra TC
//! checksum, plus a `$zip2$` line for WinZip-AES entries (which also
//! contribute a `$pkzip2$` candidate).
//!
//! Flow: locate the End Of Central Directory, walk the central directory,
//! then parse each local file header. Legacy candidates (encrypted,
//! compression 0/8) are ranked by compressed size (smallest first, up to 8);
//! the smallest is emitted "full" (DT=2), the rest as checksum-only
//! (DT=1, 36 leading bytes).

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util::basename;

pub struct Zip;

/// General-purpose bit 0: the file is encrypted.
const FLAG_ENCRYPTED: u16 = 1;
/// General-purpose bit 3: sizes/CRC are only known from the data descriptor
/// that follows the file data.
const FLAG_LOCAL_SIZE_UNKNOWN: u16 = 8;

#[derive(Default, Clone)]
struct ZipPtr {
    version: u16,
    flags: u16,
    compress_type: u16,
    file_name: String,
    offset: u64,
    data_offset: u64,
    compressed_len: u64,
    uncompressed_len: u64,
    crc: u32,
    checksum: String,
    lastmod_time: u16,
    extra_len: u16,
    aes_found: bool,
    aes_vendor_version: u16,
    aes_strength: u8,
    zip64: bool,
}

struct Candidate {
    ptr: ZipPtr,
    hash_data: Vec<u8>,
}

struct Archive<'a> {
    data: &'a [u8],
    pos: usize,
    check_bytes: u32,
    zip64: bool,
}

impl Archive<'_> {
    /// Reads at EOF yield 0xff (the unsigned byte of -1).
    fn read_byte(&mut self) -> u8 {
        let byte = self.data.get(self.pos).copied().unwrap_or(0xff);
        self.pos += 1;
        byte
    }

    fn read_u16le(&mut self) -> u16 {
        let lo = self.read_byte() as u16;
        lo | ((self.read_byte() as u16) << 8)
    }

    fn read_u32le(&mut self) -> u32 {
        let mut value = 0u32;
        for shift in [0, 8, 16, 24] {
            value |= (self.read_byte() as u32) << shift;
        }
        value
    }

    fn read_u64le(&mut self) -> u64 {
        let mut value = 0u64;
        for shift in (0..8).map(|i| 8 * i) {
            value |= (self.read_byte() as u64) << shift;
        }
        value
    }

    /// Read a byte and return whether it equals `expected`.
    fn expect(&mut self, expected: u8) -> bool {
        self.read_byte() == expected
    }

    fn seek(&mut self, to: i64) {
        self.pos = to.max(0) as usize;
    }
}

impl Extractor for Zip {
    fn name(&self) -> &'static str {
        "zip"
    }

    fn description(&self) -> &'static str {
        "PKZIP/WinZip encrypted archives (.zip)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"PK\x03\x04")
            || (input.data.len() > 22 && crate::util::find(&input.data, b"PK\x05\x06").is_some())
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let fname = input.label();
        let mut arch = Archive {
            data: &input.data,
            pos: 0,
            check_bytes: 2,
            zip64: false,
        };
        let mut candidates: Vec<Candidate> = Vec::new();
        let mut lines: Vec<String> = Vec::new();

        scan_central_directory(&mut arch, fname, &mut candidates, &mut lines);
        let out = render_output(&arch, fname, &candidates, lines);
        Ok(out)
    }
}

fn scan_central_directory(
    arch: &mut Archive,
    fname: &str,
    candidates: &mut Vec<Candidate>,
    lines: &mut Vec<String>,
) {
    let filesize = arch.data.len() as i64;
    if filesize > 22 + 65535 {
        arch.seek(filesize - (22 + 65535));
    } else {
        arch.seek(0);
    }

    let mut found = false;
    while arch.pos < arch.data.len() {
        if arch.read_byte() == 0x50 && arch.expect(0x4b) {
            let at = arch.pos as i64;
            let mut zip64 = false;
            let mut disk_ok = false;
            if arch.expect(0x05) && arch.expect(0x06) {
                let this_disk = arch.read_u16le();
                let cd_start_disk = arch.read_u16le();
                if this_disk == 0 && cd_start_disk == 0 {
                    disk_ok = true;
                }
            } else if arch.expect(0x06) && arch.expect(0x06) {
                zip64 = true;
                let _size = arch.read_u64le();
                let _ver_made = arch.read_u16le();
                let _ver_need = arch.read_u16le();
                let this_disk = arch.read_u32le();
                let cd_start_disk = arch.read_u32le();
                if this_disk == 0 && cd_start_disk == 0 {
                    disk_ok = true;
                }
            }
            if disk_ok {
                arch.zip64 = zip64;
                found = true;
                break;
            }
            arch.seek(at);
        }
    }
    if !found {
        return;
    }

    // read the central-directory record counts and start offset
    let (num_records, cd_start_offset) = if arch.zip64 {
        let n = arch.read_u64le();
        let _total = arch.read_u64le();
        let _size = arch.read_u64le();
        let off = arch.read_u64le();
        (n, off)
    } else {
        let n = arch.read_u16le() as u64;
        let _total = arch.read_u16le() as u64;
        let _size = arch.read_u32le() as u64;
        let off = arch.read_u32le() as u64;
        (n, off)
    };

    arch.seek(cd_start_offset as i64);
    if arch.read_u32le() != 0x0201_4b50 {
        return;
    }

    let mut num = num_records;
    while num > 0 {
        num -= 1;
        let mut cur = ZipPtr::default();
        let _ver_made = arch.read_u16le();
        cur.version = arch.read_u16le() & 0xff;
        cur.flags = arch.read_u16le();
        cur.compress_type = arch.read_u16le();
        let _mtime = arch.read_u16le();
        let _mdate = arch.read_u16le();
        cur.crc = arch.read_u32le();
        cur.compressed_len = arch.read_u32le() as u64;
        cur.uncompressed_len = arch.read_u32le() as u64;
        let fn_len = arch.read_u16le();
        let mut extra_len = arch.read_u16le();
        let comment_len = arch.read_u16le();
        let _disk_num = arch.read_u16le();
        let _internal = arch.read_u16le();
        let _external = arch.read_u32le();
        cur.offset = arch.read_u32le() as u64;
        let mut name_bytes = Vec::with_capacity(fn_len as usize);
        for _ in 0..fn_len {
            name_bytes.push(arch.read_byte());
        }
        cur.file_name = String::from_utf8_lossy(&name_bytes).into_owned();

        while extra_len >= 4 {
            let field_id = arch.read_u16le();
            let field_len = arch.read_u16le();
            extra_len -= 4;
            if field_id == 0x0001 {
                parse_zip64_extra(arch, &mut cur, field_len, false);
            } else if field_id == 0x9901 {
                parse_aes_extra(arch, &mut cur, field_len);
            } else {
                arch.seek(arch.pos as i64 + field_len as i64);
            }
            extra_len = extra_len.saturating_sub(field_len);
        }

        let old_pos = arch.pos as i64;
        arch.seek(cur.offset as i64);
        let id = arch.read_u32le();
        if id == 0x0403_4b50 {
            process_file_entry(arch, &mut cur, candidates, lines, fname);
        }
        arch.seek(old_pos + extra_len as i64 + comment_len as i64);
        if num > 0 && arch.read_u32le() != 0x0201_4b50 {
            break;
        }
    }
}

/// Applies a ZIP64 extended-information extra field; `is_local` selects the
/// local-header variant where every size field is always present.
fn parse_zip64_extra(arch: &mut Archive, ptr: &mut ZipPtr, len: u16, is_local: bool) {
    if ptr.zip64 {
        arch.seek(arch.pos as i64 + len as i64);
        return;
    }
    let mut decomp_len = u64::MAX;
    let mut cmp_len = u64::MAX;
    let mut offset = u64::MAX;
    let mut rem_len = len as i64;

    if ptr.uncompressed_len == u32::MAX as u64 || is_local {
        decomp_len = arch.read_u64le();
        if ptr.uncompressed_len != u32::MAX as u64 && decomp_len == 0 {
            decomp_len = u64::MAX;
        }
        rem_len -= 8;
    }
    if ptr.compressed_len == u32::MAX as u64 || is_local {
        cmp_len = arch.read_u64le();
        if ptr.compressed_len != u32::MAX as u64 && cmp_len == 0 {
            cmp_len = u64::MAX;
        }
        rem_len -= 8;
    }
    if ptr.offset == u32::MAX as u64 {
        offset = arch.read_u64le();
        if ptr.offset != u32::MAX as u64 && offset == 0 {
            offset = u64::MAX;
        }
        rem_len -= 8;
    }

    if rem_len >= 0 {
        ptr.zip64 = true;
        if decomp_len != u64::MAX {
            ptr.uncompressed_len = decomp_len;
        }
        if cmp_len != u64::MAX {
            ptr.compressed_len = cmp_len;
        }
        if offset != u64::MAX {
            ptr.offset = offset;
        }
    }
    arch.seek(arch.pos as i64 + rem_len);
}

/// Applies a WinZip AES extra field (vendor id 0x9901).
fn parse_aes_extra(arch: &mut Archive, ptr: &mut ZipPtr, len: u16) {
    if len != 7 {
        arch.seek(arch.pos as i64 + len as i64);
        return;
    }
    ptr.aes_found = true;
    ptr.aes_vendor_version = arch.read_u16le();
    let _vendor_id = arch.read_u16le();
    ptr.aes_strength = arch.read_byte();
    let _compress_type = arch.read_u16le();
}

/// Load the local file header for `ptr` (positioned past the PK\x03\x04).
fn load_local_header(arch: &mut Archive, ptr: &mut ZipPtr) -> bool {
    ptr.offset = arch.pos as u64 - 4;
    ptr.version = arch.read_u16le() & 0xff;
    ptr.flags = arch.read_u16le();
    ptr.compress_type = arch.read_u16le();
    ptr.lastmod_time = arch.read_u16le();
    let _lastmod_date = arch.read_u16le();
    if ptr.flags & FLAG_LOCAL_SIZE_UNKNOWN == 0 {
        let crc = arch.read_u32le();
        let compressed_len = arch.read_u32le();
        let uncompressed_len = arch.read_u32le();
        if !ptr.zip64 {
            if crc != 0 || ptr.crc == 0 {
                ptr.crc = crc;
            }
            if compressed_len != 0 || ptr.compressed_len == 0 {
                ptr.compressed_len = compressed_len as u64;
            }
            if uncompressed_len != 0 || ptr.uncompressed_len == 0 {
                ptr.uncompressed_len = uncompressed_len as u64;
            }
        }
    } else {
        arch.seek(arch.pos as i64 + 12);
    }
    let filename_length = arch.read_u16le();
    ptr.extra_len = arch.read_u16le();
    // the local header's filename overrides the central-directory one
    let mut name_bytes = Vec::with_capacity(filename_length as usize);
    for _ in 0..filename_length {
        name_bytes.push(arch.read_byte());
    }
    ptr.file_name = String::from_utf8_lossy(&name_bytes).into_owned();
    ptr.data_offset = 30 + filename_length as u64 + ptr.extra_len as u64;
    true
}

/// Collects a legacy-encrypted entry as a candidate; returns whether the
/// entry qualified (encrypted, compression 0/8).
fn process_legacy(arch: &mut Archive, ptr: &mut ZipPtr, candidates: &mut Vec<Candidate>) -> bool {
    if ptr.flags & FLAG_ENCRYPTED != 0 && matches!(ptr.version, 10 | 20 | 45) {
        let mut extra_len_used = 0u32;
        while extra_len_used < ptr.extra_len as u32 {
            let field_id = arch.read_u16le();
            let mut field_len = arch.read_u16le();
            if field_id == 0x0001 {
                let before = arch.pos;
                parse_zip64_extra(arch, ptr, field_len, true);
                extra_len_used += field_len as u32;
                field_len = (arch.pos - before) as u16;
            }
            arch.seek(arch.pos as i64 + field_len as i64);
            extra_len_used += 4 + field_len as u32;
        }

        if ptr.version >= 20 {
            arch.check_bytes = 1;
        }

        scan_for_data_descriptor(arch, ptr);

        if !matches!(ptr.compress_type, 0 | 8) {
            return false;
        }

        ptr.checksum = if ptr.flags & FLAG_LOCAL_SIZE_UNKNOWN != 0 {
            format!(
                "{:02x}{:02x}",
                ptr.lastmod_time >> 8,
                ptr.lastmod_time & 0xFF
            )
        } else {
            format!(
                "{:02x}{:02x}",
                (ptr.crc >> 24) & 0xFF,
                (ptr.crc >> 16) & 0xFF
            )
        };

        let mut hash_data = Vec::with_capacity(ptr.compressed_len as usize);
        for _ in 0..ptr.compressed_len {
            hash_data.push(arch.read_byte());
        }
        if candidates.len() < 8 {
            candidates.push(Candidate {
                ptr: ptr.clone(),
                hash_data,
            });
        }
        return true;
    }

    scan_for_data_descriptor(arch, ptr);
    false
}

/// Looks for a data descriptor (signature or following header) when the
/// sizes/CRC are missing from the header; restores the position afterwards.
fn scan_for_data_descriptor(arch: &mut Archive, ptr: &mut ZipPtr) {
    if ptr.compressed_len != 0 && ptr.uncompressed_len != 0 && ptr.crc != 0 {
        return;
    }
    if ptr.compressed_len == 0
        && ptr.uncompressed_len == 0
        && ptr.flags & FLAG_LOCAL_SIZE_UNKNOWN == 0
    {
        return;
    }
    if (ptr.compressed_len != 0 || ptr.uncompressed_len != 0 || ptr.crc != 0)
        && ptr.flags & FLAG_LOCAL_SIZE_UNKNOWN == 0
    {
        return;
    }

    let saved_pos = arch.pos;
    let mut crc = 0u32;
    let mut compressed_len = 0u64;
    let mut uncompressed_len = 0u64;

    while arch.pos < arch.data.len() {
        if arch.read_byte() != 0x50 || !arch.expect(0x4b) {
            continue;
        }
        if arch.expect(0x07) && arch.expect(0x08) {
            crc = arch.read_u32le();
            if arch.zip64 {
                compressed_len = arch.read_u64le();
                uncompressed_len = arch.read_u64le();
            } else {
                compressed_len = arch.read_u32le() as u64;
                uncompressed_len = arch.read_u32le() as u64;
            }
            break;
        }
        if (arch.expect(0x03) && arch.expect(0x04)) || (arch.expect(0x01) && arch.expect(0x02)) {
            if arch.zip64 {
                arch.seek(arch.pos as i64 - 24);
            } else {
                arch.seek(arch.pos as i64 - 16);
            }
            crc = arch.read_u32le();
            if arch.zip64 {
                compressed_len = arch.read_u64le();
                uncompressed_len = arch.read_u64le();
            } else {
                compressed_len = arch.read_u32le() as u64;
                uncompressed_len = arch.read_u32le() as u64;
            }
            break;
        }
    }
    if arch.pos < arch.data.len() {
        if ptr.compressed_len == 0 {
            ptr.compressed_len = compressed_len;
        }
        if ptr.uncompressed_len == 0 {
            ptr.uncompressed_len = uncompressed_len;
        }
        if ptr.crc == 0 {
            ptr.crc = crc;
        }
    }
    arch.seek(saved_pos as i64);
}

fn process_file_entry(
    arch: &mut Archive,
    cur: &mut ZipPtr,
    candidates: &mut Vec<Candidate>,
    lines: &mut Vec<String>,
    fname: &str,
) {
    if !load_local_header(arch, cur) {
        return;
    }
    let is_aes = cur.compress_type == 99;

    if is_aes {
        if cur.version >= 20 {
            arch.check_bytes = 1;
        }
        process_aes(arch, cur, lines, fname);
        // the AES blob is also kept as a pkzip2 candidate, re-read from the
        // start of the data area
        arch.seek((cur.offset + cur.data_offset) as i64);
        let mut hash_data = Vec::with_capacity(cur.compressed_len as usize);
        for _ in 0..cur.compressed_len {
            hash_data.push(arch.read_byte());
        }
        cur.checksum = format!(
            "{:02x}{:02x}",
            (cur.crc >> 24) & 0xFF,
            (cur.crc >> 16) & 0xFF
        );
        if candidates.len() < 8 {
            candidates.push(Candidate {
                ptr: cur.clone(),
                hash_data,
            });
        }
        return;
    }

    process_legacy(arch, cur, candidates);
}

/// Renders a `$zip2$` line for a WinZip-AES entry.
fn process_aes(arch: &mut Archive, ptr: &mut ZipPtr, lines: &mut Vec<String>, fname: &str) {
    let mut ef_remaining = ptr.extra_len;
    while ef_remaining > 0 && arch.pos < arch.data.len() {
        let field_id = arch.read_u16le();
        let field_len = arch.read_u16le();
        ef_remaining = ef_remaining.saturating_sub(4 + field_len);
        if field_id == 0x9901 {
            parse_aes_extra(arch, ptr, field_len);
        } else if field_id == 0x0001 {
            parse_zip64_extra(arch, ptr, field_len, true);
        } else {
            arch.seek(arch.pos as i64 + field_len as i64);
        }
    }
    if !ptr.aes_found {
        return;
    }
    if ptr.aes_vendor_version < 1 || ptr.aes_vendor_version > 2 {
        return;
    }
    if !(1..=3).contains(&ptr.aes_strength) {
        return;
    }

    if ptr.compressed_len == 0 && ptr.flags & FLAG_LOCAL_SIZE_UNKNOWN != 0 {
        scan_for_data_descriptor(arch, ptr);
    }

    let salt_length = 4 + 4 * ptr.aes_strength as usize;
    let mut salt = [0u8; 16];
    for byte in salt.iter_mut().take(salt_length) {
        *byte = arch.read_byte();
    }
    let bname = basename(fname);
    let mut line = format!(
        "{}/{}:$zip2$*0*{:x}*{:x}*",
        bname, ptr.file_name, ptr.aes_strength, 0
    );
    line.push_str(&hex::encode(&salt[..salt_length]));
    line.push('*');
    let mut password_verify = Vec::new();
    for _ in 0..2 {
        password_verify.push(arch.read_byte());
    }
    line.push_str(&hex::encode(&password_verify));

    let overhead = (2 + salt_length + 10) as u64;
    let real_cmpr_len = ptr.compressed_len.saturating_sub(overhead);
    line.push_str(&format!("*{real_cmpr_len:x}*"));

    let mut cipher_data = Vec::with_capacity(real_cmpr_len as usize);
    for _ in 0..real_cmpr_len {
        cipher_data.push(arch.read_byte());
    }
    line.push_str(&hex::encode(&cipher_data));
    line.push('*');
    let mut auth_code = Vec::new();
    for _ in 0..10 {
        auth_code.push(arch.read_byte());
    }
    line.push_str(&hex::encode(&auth_code));
    line.push_str(&format!("*$/zip2$:{}:{}:{}", ptr.file_name, bname, fname));
    lines.push(line);
}

/// Builds the `$pkzip2$` summary line from the collected candidates (the
/// smallest compressed entry full, the rest checksum-only).
fn render_output(
    arch: &Archive,
    fname: &str,
    candidates: &[Candidate],
    mut lines: Vec<String>,
) -> Vec<HashLine> {
    if candidates.is_empty() {
        return lines.into_iter().map(HashLine::new_empty).collect();
    }
    // sort by compressed length ascending (smallest first)
    let mut sorted: Vec<&Candidate> = candidates.iter().collect();
    sorted.sort_by_key(|candidate| candidate.ptr.compressed_len);

    let bname = basename(fname);
    let count = sorted.len();
    let mut out = String::new();

    if count == 1 {
        let file_name = sorted[0].ptr.file_name.replace(':', " ");
        out.push_str(&format!(
            "{bname}/{file_name}:$pkzip2${count:x}*{:x}*",
            arch.check_bytes
        ));
    } else {
        out.push_str(&format!(
            "{bname}:$pkzip2${count:x}*{:x}*",
            arch.check_bytes
        ));
    }

    let filenames = sorted
        .iter()
        .map(|candidate| candidate.ptr.file_name.clone())
        .collect::<Vec<_>>()
        .join(", ")
        .replace(':', " ");

    for candidate in sorted.iter().skip(1) {
        let len = (12 + 24).min(candidate.ptr.compressed_len);
        out.push_str(&format!(
            "1*{:x}*{:x}*{:x}*{}*{:x}*",
            0, candidate.ptr.compress_type, len, candidate.ptr.checksum, candidate.ptr.lastmod_time
        ));
        out.push_str(&hex::encode(&candidate.hash_data[..len as usize]));
        out.push('*');
    }
    // full entry for the smallest
    let best = &sorted[0];
    out.push_str(&format!(
        "{:x}*{:x}*{:x}*{:x}*{:x}*{:x}*{:x}*{:x}*{:x}*{}*{:x}*",
        2,
        0,
        best.ptr.compressed_len,
        best.ptr.uncompressed_len,
        best.ptr.crc,
        best.ptr.offset,
        best.ptr.data_offset,
        best.ptr.compress_type,
        best.ptr.compressed_len,
        best.ptr.checksum,
        best.ptr.lastmod_time
    ));
    out.push_str(&hex::encode(
        &best.hash_data[..best.ptr.compressed_len as usize],
    ));
    out.push('*');

    if count > 1 {
        out.push_str(&format!("$/pkzip2$::{}:{}:{}", bname, filenames, fname));
    } else {
        out.push_str(&format!("$/pkzip2$:{}:{}::{}", filenames, bname, fname));
    }
    lines.push(out);
    lines.into_iter().map(HashLine::new_empty).collect()
}
