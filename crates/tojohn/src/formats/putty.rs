//! Extracts `$putty$` hashes from PuTTY private key files (`.ppk`,
//! format versions 1 and 2). Only keys whose `Encryption:` line is
//! `aes256-cbc` produce a hash — unencrypted keys are skipped silently.
//!
//! The reader follows the PPK layout strictly: header names are capped at
//! 39 characters, bodies are newline-terminated (a CRLF pair counts as one
//! terminator), and blob lines must be non-empty multiples of 4 base64
//! characters, at most 64 characters per line.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Putty;

/// Line-oriented reader for the PPK layout.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_byte(&mut self) -> Option<u8> {
        let byte = self.data.get(self.pos).copied();
        if byte.is_some() {
            self.pos += 1;
        }
        byte
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    /// Read a `Name: value` header: reads up to the next `: `, storing at
    /// most 39 characters of the header name. Any CR/LF/EOF before the
    /// colon is failure, as is a colon not followed by a space.
    fn read_header(&mut self) -> Option<String> {
        let mut header = Vec::new();
        let mut len = 39i32;
        loop {
            let c = self.read_byte()?;
            if c == b'\n' || c == b'\r' {
                return None;
            }
            if c == b':' {
                if self.read_byte()? != b' ' {
                    return None;
                }
                return Some(String::from_utf8_lossy(&header).into_owned());
            }
            if len == 0 {
                return None;
            }
            header.push(c);
            len -= 1;
        }
    }

    /// Read one line of text without its terminator. After the terminator
    /// one more char is consumed only when it is another newline — so the
    /// second half of a CRLF pair is swallowed. A line ending at EOF (no
    /// CR/LF seen) yields None.
    fn read_body(&mut self) -> Option<String> {
        let mut text = Vec::new();
        loop {
            let c = self.read_byte()?;
            if c == b'\r' || c == b'\n' {
                if matches!(self.peek(), Some(b'\r') | Some(b'\n')) {
                    self.pos += 1;
                }
                return Some(String::from_utf8_lossy(&text).into_owned());
            }
            text.push(c);
        }
    }

    /// Read `nlines` lines of base64 into a decoded blob.
    fn read_blob(&mut self, nlines: u32) -> Option<Vec<u8>> {
        if nlines > 1024 * 1024 {
            return None;
        }
        let mut blob = Vec::new();
        for _ in 0..nlines {
            let line = self.read_body()?;
            let bytes = line.as_bytes();
            if bytes.len() % 4 != 0 || bytes.len() > 64 {
                return None;
            }
            for atom in bytes.chunks_exact(4) {
                decode_atom(atom, &mut blob)?;
            }
        }
        Some(blob)
    }
}

/// Decode one base64 atom, appending 1-3 bytes; `=` padding is only valid
/// in the trailing positions of the final atom.
fn decode_atom(atom: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let sextet = |c: u8| -> Option<i32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as i32),
            b'a'..=b'z' => Some((c - b'a') as i32 + 26),
            b'0'..=b'9' => Some((c - b'0') as i32 + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(-1),
            _ => None,
        }
    };
    let vals = [
        sextet(atom[0])?,
        sextet(atom[1])?,
        sextet(atom[2])?,
        sextet(atom[3])?,
    ];
    if vals[0] == -1 || vals[1] == -1 {
        return None;
    }
    if vals[2] == -1 && vals[3] != -1 {
        return None;
    }
    let len = if vals[3] != -1 {
        3
    } else if vals[2] != -1 {
        2
    } else {
        1
    };
    let word =
        ((vals[0] << 18) | (vals[1] << 12) | ((vals[2] & 0x3F) << 6) | (vals[3] & 0x3F)) as u32;
    out.push(((word >> 16) & 0xFF) as u8);
    if len > 1 {
        out.push(((word >> 8) & 0xFF) as u8);
    }
    if len > 2 {
        out.push((word & 0xFF) as u8);
    }
    Some(())
}

struct ParsedKey {
    is_legacy: bool,
    cipher_id: u32,
    cipher_block_size: u32,
    is_mac: bool,
    mac: String,
    public_blob: Vec<u8>,
    private_blob: Vec<u8>,
    algorithm: String,
    encryption: String,
    comment: String,
}

/// Full header/blob parse of a PPK file, or None on any format error.
fn parse_key(data: &[u8]) -> Option<ParsedKey> {
    let mut r = Reader::new(data);

    // First header: the key file version.
    let h = r.read_header()?;
    let is_legacy = match h.as_str() {
        "PuTTY-User-Key-File-2" => false,
        "PuTTY-User-Key-File-1" => true,
        _ => return None,
    };
    // Any algorithm string that fits is accepted; unrecognized names
    // never fail here.
    let algorithm = r.read_body()?;

    // Encryption line: only aes256-cbc yields a hash.
    let h = r.read_header()?;
    if h != "Encryption" {
        return None;
    }
    let encryption = r.read_body()?;
    let (cipher_id, cipher_block_size) = match encryption.as_str() {
        "aes256-cbc" => (1, 16),
        "none" => (0, 1),
        _ => return None,
    };

    // Comment line.
    let h = r.read_header()?;
    if h != "Comment" {
        return None;
    }
    let comment = r.read_body()?;

    // Public-Lines header and blob.
    let h = r.read_header()?;
    if h != "Public-Lines" {
        return None;
    }
    let n: u32 = r.read_body()?.trim().parse().ok()?;
    let public_blob = r.read_blob(n)?;

    // Private-Lines header and blob.
    let h = r.read_header()?;
    if h != "Private-Lines" {
        return None;
    }
    let n: u32 = r.read_body()?.trim().parse().ok()?;
    let private_blob = r.read_blob(n)?;

    // Private-MAC (new format) or Private-Hash (legacy format only).
    let h = r.read_header()?;
    let (is_mac, mac) = if h == "Private-MAC" {
        (true, r.read_body()?)
    } else if h == "Private-Hash" && is_legacy {
        (false, r.read_body()?)
    } else {
        return None;
    };

    Some(ParsedKey {
        is_legacy,
        cipher_id,
        cipher_block_size,
        is_mac,
        mac,
        public_blob,
        private_blob,
        algorithm,
        encryption,
        comment,
    })
}

/// Output label: the file name with every trailing `.ppk` removed.
fn output_label(path: &str) -> String {
    let base = util::basename(path);
    let mut name = base.to_string();
    while let Some(stripped) = name.strip_suffix(".ppk") {
        name = stripped.to_string();
    }
    name
}

impl Extractor for Putty {
    fn name(&self) -> &'static str {
        "putty"
    }

    fn description(&self) -> &'static str {
        "PuTTY private key files (.ppk)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"PuTTY-User-Key-File-").is_some()
            && util::find(&input.data, b"aes256-cbc").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        // The file must start with the PuTTY key signature.
        if !input.data.starts_with(b"PuTTY-User-Key-File-") {
            return Err(Error::malformed(
                input.label(),
                "not a PuTTY private key file",
            ));
        }
        let key = match parse_key(&input.data) {
            Some(k) => k,
            None => {
                return Err(Error::malformed(
                    input.label(),
                    "not a valid PuTTY private key file",
                ))
            }
        };
        // Unencrypted keys produce no hash.
        if key.cipher_id == 0 {
            return Ok(Vec::new());
        }
        if !(key.private_blob.len() as u64).is_multiple_of(key.cipher_block_size as u64) {
            return Err(Error::malformed(
                input.label(),
                "encrypted private section is not a multiple of the cipher block size",
            ));
        }

        let mut line = format!(
            "{}:$putty${}*{}*{}*{}*{}*{}*{}*",
            output_label(input.label()),
            key.cipher_id,
            key.cipher_block_size,
            key.is_mac as u8,
            key.is_legacy as u8,
            key.mac,
            key.public_blob.len(),
            hex::encode(&key.public_blob),
        );
        line.push_str(&key.private_blob.len().to_string());
        line.push('*');
        line.push_str(&hex::encode(&key.private_blob));
        if !key.is_legacy {
            line.push_str(&format!(
                "*{}*{}*{}",
                key.algorithm, key.encryption, key.comment
            ));
        }
        let label = line.split(':').next().unwrap_or("").to_string();
        Ok(vec![HashLine { label, line }])
    }
}
