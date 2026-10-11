//! 7-Zip container parser.
//!
//! Supported paths:
//! - signature header + parsed header (streams info → pack info, folders,
//!   unpack info, digests, substreams info, files info)
//! - plain (non-encrypted-header) archives with an AES-256 coder
//!   (`06F10701`), including the padding-attack truncation case
//! - compression-type detection for the second coder (LZMA1/2, PPMD, BCJ,
//!   BCJ2, BZIP2, DEFLATE → the `$7z$` "type of data" field)
//!
//! Not supported: SFX self-extractor preambles, encrypted-header archives
//! (LZMA decompression of the header would be required), and the
//! multi-stream shortest-buffer analysis (picking the smallest data buffer
//! across all streams).
//!
//! Format: `<basename>:$7z$<type>$<cycles>$<salt_len>$<salt>$<iv_len>$<iv>
//! $<crc>$<data_len>$<unpack_size>$<data>[$<crc_len>$<coder attrs>]`

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct SevenZip;

const MAGIC: &[u8] = b"7z\xbc\xaf\x27\x1c";

/// Property ids of the 7z header grammar.
const ID_END: u64 = 0x00;
const ID_HEADER: u64 = 0x01;
#[allow(dead_code)]
const ID_ARCHIVE_PROPERTIES: u64 = 0x02;
#[allow(dead_code)]
const ID_ADD_STREAMS_INFO: u64 = 0x03;
#[allow(dead_code)]
const ID_MAIN_STREAMS_INFO: u64 = 0x04;
#[allow(dead_code)]
const ID_FILES_INFO: u64 = 0x05;
const ID_PACK_INFO: u64 = 0x06;
const ID_UNPACK_INFO: u64 = 0x07;
const ID_SUBSTREAMS_INFO: u64 = 0x08;
const ID_SIZE: u64 = 0x09;
const ID_CRC: u64 = 0x0a;
const ID_FOLDER: u64 = 0x0b;
#[allow(dead_code)]
const ID_CODERS_UNPACK_SIZE: u64 = 0x0c;
const ID_NUM_UNPACK_STREAM: u64 = 0x0d;
const ID_UNPACK_SIZE: u64 = 0x0e;
const ID_ENCODED_HEADER: u64 = 0x17;
/// End marker of a folders/bind-pairs list (never read on supported paths).
#[allow(dead_code)]
const ENDOFCHAIN: u64 = u64::MAX;

const AES_CODEC: u64 = 0x06f10701;
const LZMA1_CODEC: u64 = 0x030101;
const LZMA2_CODEC: u64 = 0x21;
const PPMD_CODEC: u64 = 0x030401;
const BCJ_CODEC: u64 = 0x03030103;
const BCJ2_CODEC: u64 = 0x0303011b;
const BZIP2_CODEC: u64 = 0x040202;
const DEFLATE_CODEC: u64 = 0x040108;

/// `$7z$` "type of data" value for plain streams.
const TYPE_UNCOMPRESSED: u64 = 0;
/// `$7z$` "type of data" value for the padding-attack truncation case.
const TYPE_TRUNCATED: u64 = 128;

const NOT_EXTERNAL: u8 = 0x00;

#[derive(Debug, Default, Clone)]
struct Coder {
    codec_id: u64,
    #[allow(dead_code)]
    number_input_streams: u64,
    #[allow(dead_code)]
    number_output_streams: u64,
    attributes: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct Folder {
    coders: Vec<Coder>,
    index_main_stream: i64,
    sum_output_streams: u64,
}

#[derive(Debug, Default)]
struct PackInfo {
    pack_pos: u64,
    pack_sizes: Vec<u64>,
}

#[derive(Debug, Default)]
struct UnpackInfo {
    folders: Vec<Folder>,
    digests: Vec<Option<u32>>,
    unpack_sizes: Vec<u64>,
    coder_unpack_size_base: u64,
}

#[derive(Debug, Default)]
struct SubstreamsInfo {
    #[allow(dead_code)]
    number_unpack_streams: Vec<u64>,
    unpack_sizes: Vec<u64>,
    digests: Vec<Option<u32>>,
    #[allow(dead_code)]
    unpack_stream_numbers: Vec<u64>,
}

#[derive(Debug, Default)]
struct StreamsInfo {
    unpack_info: Option<UnpackInfo>,
    substreams_info: Option<SubstreamsInfo>,
    pack_info: Option<PackInfo>,
}

#[derive(Debug, Default)]
struct Archive {
    streams_info: Option<StreamsInfo>,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn new(data: &[u8], pos: usize) -> Reader<'_> {
        Reader { data, pos }
    }

    fn take(&mut self, count: usize) -> Result<&'_ [u8]> {
        if self.pos + count > self.data.len() {
            return Err(Error::other("7z: unexpected EOF"));
        }
        let out = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// 7z variable-length number encoding.
    fn read_number(&mut self) -> Result<u64> {
        let first = self.byte()?;
        if first & 0x80 == 0 {
            return Ok(first as u64);
        }
        let mut value = self.byte()? as u64;
        for i in 1..8 {
            let mask = 0x80u8 >> i;
            if first & mask == 0 {
                let high = (first & (mask - 1)) as u64;
                value |= high << (i * 8);
                return Ok(value);
            }
            let next = self.byte()? as u64;
            value |= next << (i * 8);
        }
        Ok(value)
    }

    fn read_id(&mut self) -> Result<u64> {
        self.read_number()
    }

    fn u64le(&mut self) -> Result<u64> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().expect("8")))
    }

    fn u32le(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().expect("4")))
    }

    fn skip_data(&mut self) -> Result<()> {
        let len = self.read_number()? as usize;
        self.take(len)?;
        Ok(())
    }

    /// Skip properties until the wanted id appears; false at ID_END.
    fn wait_for(&mut self, want: u64) -> Result<bool> {
        loop {
            let id = self.read_id()?;
            if id == want {
                return Ok(true);
            }
            if id == ID_END {
                return Ok(false);
            }
            self.skip_data()?;
        }
    }

    /// Boolean vector; a nonzero "all defined" flag means every entry true.
    fn boolean_vector_check_all(&mut self, count: usize) -> Result<Vec<bool>> {
        let all_defined = self.byte()?;
        if all_defined == 0 {
            let mut out = Vec::with_capacity(count);
            let mut byte = 0u8;
            let mut mask = 0u8;
            for _ in 0..count {
                if mask == 0 {
                    byte = self.byte()?;
                    mask = 0x80;
                }
                out.push(byte & mask != 0);
                mask >>= 1;
            }
            Ok(out)
        } else {
            Ok(vec![true; count])
        }
    }

    fn digests(&mut self, count: usize) -> Result<Vec<Option<u32>>> {
        let defined = self.boolean_vector_check_all(count)?;
        let mut out = Vec::with_capacity(count);
        for is_defined in defined {
            out.push(if is_defined {
                Some(self.u32le()?)
            } else {
                None
            });
        }
        Ok(out)
    }

    /// Pack info: stream base offset and packed sizes.
    fn pack_info(&mut self) -> Result<PackInfo> {
        let pack_pos = self.read_number()?;
        let number = self.read_number()?;
        if !self.wait_for(ID_SIZE)? {
            return Err(Error::other("7z: pack info: no sizes"));
        }
        let mut pack_sizes = Vec::with_capacity(number as usize);
        for _ in 0..number {
            pack_sizes.push(self.read_number()?);
        }
        loop {
            let id = self.read_id()?;
            if id == ID_END {
                return Ok(PackInfo {
                    pack_pos,
                    pack_sizes,
                });
            }
            if id == ID_CRC {
                self.digests(number as usize)?;
                continue;
            }
            self.skip_data()?;
        }
    }

    /// One folder: coder list, bind pairs, main stream index.
    fn folder(&mut self) -> Result<Folder> {
        let number_coders = self.read_number()?;
        let mut coders = Vec::new();
        let mut bind_pairs: Vec<(u64, u64)> = Vec::new();
        let mut sum_input: u64 = 0;
        let mut sum_output: u64 = 0;
        let sum_packed: u64;

        for _ in 0..number_coders {
            let main_byte = self.byte()?;
            if main_byte & 0xC0 != 0 {
                return Err(Error::other("7z: unsupported coder flags"));
            }
            let codec_id_size = (main_byte & 0xf) as usize;
            if codec_id_size > 8 {
                return Err(Error::other("7z: codec id too large"));
            }
            let codec_id_bytes = self.take(codec_id_size)?;
            let mut codec_id: u64 = 0;
            // codec ids are big-endian byte strings folded into a number
            for &byte in codec_id_bytes {
                codec_id = (codec_id << 8) | byte as u64;
            }
            let (mut nin, mut nout) = (1u64, 1u64);
            if main_byte & 0x10 != 0 {
                nin = self.read_number()?;
                nout = self.read_number()?;
            }
            sum_input += nin;
            sum_output += nout;
            let mut attributes = None;
            if main_byte & 0x20 != 0 {
                let prop_size = self.read_number()? as usize;
                attributes = Some(self.take(prop_size)?.to_vec());
            }
            coders.push(Coder {
                codec_id,
                number_input_streams: nin,
                number_output_streams: nout,
                attributes,
            });
        }

        let mut index_main_stream: i64 = 0;
        if sum_input != 1 || sum_output != 1 {
            let mut input_used = vec![false; sum_input as usize];
            let mut output_used = vec![false; sum_output as usize];
            let number_bind_pairs = sum_output - 1;
            for _ in 0..number_bind_pairs {
                let input_index = self.read_number()? as usize;
                if input_used.get(input_index).copied().unwrap_or(true) {
                    return Err(Error::other("7z: stream used twice"));
                }
                input_used[input_index] = true;
                let output_index = self.read_number()? as usize;
                if output_used.get(output_index).copied().unwrap_or(true) {
                    return Err(Error::other("7z: stream used twice"));
                }
                output_used[output_index] = true;
                bind_pairs.push((input_index as u64, output_index as u64));
            }
            sum_packed = sum_input - number_bind_pairs;
            // more than one packed stream: the packed stream indices follow
            if sum_packed != 1 {
                for _ in 0..sum_packed {
                    self.read_number()?; // packed stream indices, ignored
                }
            }
            index_main_stream = output_used
                .iter()
                .position(|&used| !used)
                .ok_or_else(|| Error::other("7z: no main stream"))?
                as i64;
        }
        Ok(Folder {
            coders,
            index_main_stream,
            sum_output_streams: sum_output,
        })
    }

    /// Unpack info: folders, unpack sizes, digests.
    fn unpack_info(&mut self) -> Result<UnpackInfo> {
        if !self.wait_for(ID_FOLDER)? {
            return Err(Error::other("7z: no folders"));
        }
        let number_folders = self.read_number()?;
        let external = self.byte()?;
        let mut folders = Vec::new();
        let mut sum_coders_output_streams: u64 = 0;
        if external == NOT_EXTERNAL {
            for _ in 0..number_folders {
                let folder = self.folder()?;
                sum_coders_output_streams += folder.sum_output_streams;
                folders.push(folder);
            }
        } else {
            return Err(Error::other("7z: external folders unsupported"));
        }
        if !self.wait_for(ID_UNPACK_SIZE)? {
            return Err(Error::other("7z: no unpack sizes"));
        }
        let mut unpack_sizes = Vec::with_capacity(sum_coders_output_streams as usize);
        for _ in 0..sum_coders_output_streams {
            unpack_sizes.push(self.read_number()?);
        }
        let mut digests: Vec<Option<u32>> = Vec::new();
        loop {
            let id = self.read_id()?;
            if id == ID_END {
                return Ok(UnpackInfo {
                    folders,
                    digests,
                    unpack_sizes,
                    coder_unpack_size_base: 0,
                });
            }
            if id == ID_CRC {
                digests = self.digests(folders.len())?;
                continue;
            }
            self.skip_data()?;
        }
    }

    /// Substreams info: per-stream unpack sizes and digests.
    fn substreams_info(&mut self, unpack_info: &UnpackInfo) -> Result<SubstreamsInfo> {
        let number_folders = unpack_info.folders.len();
        let mut number_unpack_streams = vec![1u64; number_folders];
        let mut unpack_sizes: Vec<u64> = Vec::new();
        let mut digests: Vec<Option<u32>> = Vec::new();
        let mut unpack_stream_numbers: Vec<u64> = Vec::new();

        let mut id;
        loop {
            id = self.read_id()?;
            if id == ID_NUM_UNPACK_STREAM {
                for count in number_unpack_streams.iter_mut() {
                    *count = self.read_number()?;
                }
            } else if matches!(id, ID_CRC | ID_SIZE | ID_END) {
                break;
            } else {
                self.skip_data()?;
            }
        }

        if id == ID_SIZE {
            for (folder_index, stream_count) in number_unpack_streams.iter().enumerate() {
                let number_substreams = *stream_count as usize;
                if number_substreams == 0 {
                    continue;
                }
                let mut sum: u64 = 0;
                for _ in 1..number_substreams {
                    let size = self.read_number()?;
                    unpack_sizes.push(size);
                    sum += size;
                }
                // folder unpack size = main output stream of the folder
                let folder_size = folder_unpack_size(unpack_info, folder_index);
                if folder_size < sum {
                    return Err(Error::other("7z: bad substream sizes"));
                }
                unpack_sizes.push(folder_size - sum);
            }
            id = self.read_id()?;
        } else {
            for (folder_index, stream_count) in number_unpack_streams.iter().enumerate() {
                for _ in 0..*stream_count {
                    unpack_sizes.push(folder_unpack_size(unpack_info, folder_index));
                }
            }
        }

        loop {
            match id {
                ID_END => break,
                ID_CRC => {
                    let total = number_unpack_streams.iter().map(|c| *c as usize).sum();
                    digests = self.digests(total)?;
                    id = self.read_id()?;
                }
                _ => {
                    self.skip_data()?;
                    id = self.read_id()?;
                }
            }
        }

        // unpack_stream_numbers per folder (cumulative file counts)
        let mut position = 0usize;
        for stream_count in &number_unpack_streams {
            position += *stream_count as usize;
            unpack_stream_numbers.push(position as u64);
        }

        Ok(SubstreamsInfo {
            number_unpack_streams,
            unpack_sizes,
            digests,
            unpack_stream_numbers,
        })
    }

    /// Streams-info property block.
    fn streams_info(&mut self) -> Result<StreamsInfo> {
        let mut info = StreamsInfo::default();
        loop {
            let id = self.read_id()?;
            match id {
                ID_PACK_INFO => info.pack_info = Some(self.pack_info()?),
                ID_MAIN_STREAMS_INFO => continue, // nested streams info follows
                ID_UNPACK_INFO => info.unpack_info = Some(self.unpack_info()?),
                ID_SUBSTREAMS_INFO => {
                    let unpack_info = info
                        .unpack_info
                        .as_ref()
                        .ok_or_else(|| Error::other("7z: substreams before unpack"))?;
                    info.substreams_info = Some(self.substreams_info(unpack_info)?);
                }
                ID_END => break,
                other => {
                    return Err(Error::other(format!(
                        "7z: unexpected streams-info id 0x{other:x} at pos {}",
                        self.pos
                    )))
                }
            }
        }
        Ok(info)
    }

    /// Next-header block.
    fn parsed_header(&mut self) -> Result<Archive> {
        let mut archive = Archive::default();
        let id = self.read_id()?;
        if id == ID_HEADER {
            let info = self.streams_info()?;
            archive.streams_info = Some(info);
            return Ok(archive);
        }
        if id == ID_ENCODED_HEADER {
            // encrypted/compressed header: not supported (would need
            // LZMA decode of the header stream)
            return Err(Error::other(
                "7z: encoded (compressed/encrypted) header unsupported",
            ));
        }
        if id == ID_END {
            return Ok(archive);
        }
        Err(Error::other("7z: unexpected header id"))
    }
}

fn folder_unpack_size(unpack_info: &UnpackInfo, folder_index: usize) -> u64 {
    let Some(folder) = unpack_info.folders.get(folder_index) else {
        return 0;
    };
    let base = unpack_info.coder_unpack_size_base;
    let index = base as i64 + folder.index_main_stream;
    if index < 0 {
        return 0;
    }
    unpack_info
        .unpack_sizes
        .get(index as usize)
        .copied()
        .unwrap_or(0)
}

/// AES coder attributes → (salt_len, salt, iv_len, iv, cycle count power).
fn decoder_properties(attributes: &[u8]) -> (usize, Vec<u8>, usize, Vec<u8>, u64) {
    let default_iv = [0u8; 16];
    if attributes.is_empty() {
        return (0, Vec::new(), 16, default_iv.to_vec(), 19);
    }
    let first = attributes[0];
    let cycles = (first & 0x3f) as u64;
    if first & 0xc0 == 0 {
        return (0, Vec::new(), 16, default_iv.to_vec(), cycles);
    }
    let salt_len = (((first >> 7) & 1) + (attributes[1] >> 4)) as usize;
    let iv_len = (((first >> 6) & 1) + (attributes[1] & 0x0f)) as usize;
    let mut offset = 2;
    let salt = attributes
        .get(offset..(offset + salt_len).min(attributes.len()))
        .unwrap_or(&[])
        .to_vec();
    offset += salt_len;
    let mut iv = attributes
        .get(offset..(offset + iv_len).min(attributes.len()))
        .unwrap_or(&[])
        .to_vec();
    // pad the iv with zeros to 16 bytes
    iv.resize(16, 0);
    (salt_len, salt, iv_len, iv, cycles)
}

fn compression_type(codec_id: u64) -> u64 {
    match codec_id {
        LZMA1_CODEC => 1,
        LZMA2_CODEC => 2,
        PPMD_CODEC => 3,
        BCJ_CODEC => 4,
        BCJ2_CODEC => 5,
        BZIP2_CODEC => 6,
        DEFLATE_CODEC => 7,
        _ => 0,
    }
}

impl Extractor for SevenZip {
    fn name(&self) -> &'static str {
        "7z"
    }

    fn description(&self) -> &'static str {
        "7-Zip archives (.7z; standard AES path, non-SFX, non-encrypted-header)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(MAGIC)
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < 32 || !data.starts_with(MAGIC) {
            return Ok(Vec::new());
        }
        // layout: magic(6), version major/minor(2), start header CRC(4),
        // then the start header: next header offset(8), next header
        // size(8), next header CRC(4)
        let mut reader = Reader::new(data, 12);
        let next_header_offset = reader.u64le()?;
        let next_header_size = reader.u64le()?;
        let position_after_header = 32u64;

        // jump to the header
        let header_start = position_after_header + next_header_offset;
        if header_start + next_header_size > data.len() as u64 {
            return Ok(Vec::new());
        }
        let mut header_reader = Reader::new(data, header_start as usize);
        let mut archive = header_reader.parsed_header()?;

        let Some(streams_info) = archive.streams_info.take() else {
            return Ok(Vec::new()); // no streams info present
        };
        let Some(unpack_info) = streams_info.unpack_info else {
            return Ok(Vec::new());
        };
        let Some(pack_info) = streams_info.pack_info else {
            return Ok(Vec::new());
        };
        let substreams_info = streams_info.substreams_info;

        // get the first folder / coder
        let Some(folder) = unpack_info.folders.first() else {
            return Ok(Vec::new());
        };
        // the header is "encrypted" when there is a single coder that is not
        // AES (i.e. only a compression coder on the header stream)
        if folder.coders.len() == 1 && folder.coders[0].codec_id != AES_CODEC {
            return Ok(Vec::new()); // encrypted header unsupported
        }

        // walk to the first folder whose FIRST coder is AES
        let mut current_index = 0usize;
        let mut folder_index = 0usize;
        if folder.coders[0].codec_id != AES_CODEC {
            // scan folders for the first AES coder
            let mut found = false;
            for (candidate_index, candidate) in unpack_info.folders.iter().enumerate() {
                for coder in &candidate.coders {
                    if coder.codec_id == AES_CODEC {
                        found = true;
                        folder_index = candidate_index;
                        break;
                    }
                    current_index += 1;
                }
                if found {
                    break;
                }
            }
            if !found {
                return Err(Error::other("no AES data found in the 7z file"));
            }
        }
        let Some(folder) = unpack_info.folders.get(folder_index) else {
            return Ok(Vec::new());
        };
        // attributes of the AES coder (first coder of the folder)
        let Some(attributes) = folder
            .coders
            .first()
            .and_then(|coder| coder.attributes.clone())
        else {
            return Ok(Vec::new());
        };

        // seek position accumulation (pack sizes of prior streams)
        let mut current_seek_position = position_after_header + pack_info.pack_pos;
        let prior_sizes = current_index.min(pack_info.pack_sizes.len());
        for size in pack_info.pack_sizes.iter().take(prior_sizes) {
            current_seek_position += size;
        }

        let unpack_size = unpack_info
            .unpack_sizes
            .get(current_index)
            .copied()
            .unwrap_or(0);
        let mut data_len = pack_info
            .pack_sizes
            .get(current_index)
            .copied()
            .unwrap_or(0);

        // stream digest: folder digest first, substream digest as fallback
        let crc = unpack_info
            .digests
            .get(current_index)
            .copied()
            .flatten()
            .or_else(|| {
                substreams_info
                    .as_ref()
                    .and_then(|sub| sub.digests.get(current_index).copied().flatten())
            });
        let Some(crc) = crc else {
            return Ok(Vec::new());
        };

        let (salt_len, salt, mut iv_len, mut iv, number_cycles_power) =
            decoder_properties(&attributes);

        // padding-attack truncation
        let mut is_truncated = false;
        let data: Vec<u8>;
        let length_difference = data_len as i64 - unpack_size as i64;
        if length_difference > 3 {
            // truncation allowed (cracker supports padding attack):
            // the last 32 bytes = 16-byte IV + one 16-byte AES block
            let tail = current_seek_position as usize + data_len as usize;
            if data_len >= 32 && tail <= input.data.len() {
                iv = input.data[tail - 32..tail - 16].to_vec();
                iv_len = 16;
                data = input.data[tail - 16..tail].to_vec();
                data_len = 16;
                is_truncated = true;
            } else {
                data = Vec::new();
            }
        } else {
            let start = current_seek_position as usize;
            let end = start + data_len as usize;
            data = input
                .data
                .get(start..end.min(input.data.len()))
                .unwrap_or(&[])
                .to_vec();
        }

        // compression type from the second coder (if any)
        let mut type_of_compression = TYPE_UNCOMPRESSED;
        let mut compression_attributes = String::new();
        for coder in folder.coders.iter().skip(1) {
            let compression = compression_type(coder.codec_id);
            if compression != TYPE_UNCOMPRESSED {
                type_of_compression = compression;
                if let Some(attrs) = &coder.attributes {
                    compression_attributes = hex::encode(attrs);
                }
                break;
            }
        }

        let type_of_data = if is_truncated {
            TYPE_TRUNCATED
        } else {
            type_of_compression
        };

        let mut crc_len = 0u64;
        if type_of_data != TYPE_UNCOMPRESSED && type_of_data != TYPE_TRUNCATED {
            if let Some(sub) = &substreams_info {
                crc_len = sub.unpack_sizes.first().copied().unwrap_or(0);
            }
        }

        let label = util::basename(input.label());
        let mut line = format!(
            "{label}:$7z${type_of_data}${number_cycles_power}${salt_len}${}$\
{iv_len}${}${crc}${data_len}${unpack_size}${}",
            hex::encode(salt),
            hex::encode(iv),
            hex::encode(data)
        );
        if type_of_data != TYPE_UNCOMPRESSED && type_of_data != TYPE_TRUNCATED {
            line.push_str(&format!("${crc_len}${compression_attributes}"));
        }
        Ok(vec![HashLine::new(label, line)])
    }
}
