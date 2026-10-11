//! Emits TrueCrypt volume header lines (normal + hidden, one per hash
//! algorithm tag). Boot mode is enabled via "-b" in `input.extra_args`;
//! keyfile PATHS (verbatim in the output, the contents are not read) may be
//! passed as `input.extra_files` labels.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Truecrypt;

/// Size in bytes of the volume header region covered by the hash.
const HEADER_SIZE: usize = 512;
/// Byte offset of the hidden volume's header inside the container.
const HIDDEN_HEADER_OFFSET: usize = 65536;

/// The hash algorithm tags the `$truecrypt$` line supports, in output order.
const TAGS: &[&str] = &[
    "truecrypt_RIPEMD_160",
    "truecrypt_SHA_512",
    "truecrypt_WHIRLPOOL",
];

/// Build one `$truecrypt$` line for a 512-byte header region.
fn header_line(label: &str, tag: &str, header: &[u8], keyfiles: &[&str], kind: &str) -> HashLine {
    let mut line = format!("{}:{}${}", label, tag, hex::encode(header));
    if !keyfiles.is_empty() {
        line += &format!("${}", keyfiles.len());
        for keyfile in keyfiles {
            line += &format!("${keyfile}");
        }
    }
    line += &format!(":{kind}::::{label}");
    HashLine::new(label.to_string(), line)
}

impl Extractor for Truecrypt {
    fn name(&self) -> &'static str {
        "truecrypt"
    }

    fn description(&self) -> &'static str {
        "TrueCrypt volume files (option: -b for boot mode)"
    }

    fn accepts(&self, _input: &Input) -> bool {
        false // encrypted headers have no plain magic
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if data.len() < HEADER_SIZE {
            // too short for a volume header
            return Ok(Vec::new());
        }
        let boot_mode = input.extra_args.iter().any(|arg| arg == "-b");
        let keyfiles: Vec<&str> = input
            .extra_files
            .iter()
            .map(|file| file.label.as_str())
            .collect();
        let label = util::basename(input.label());

        let mut out = Vec::new();
        let tags: &[&str] = if boot_mode { &TAGS[..1] } else { TAGS };
        let header = &data[..HEADER_SIZE];
        for tag in tags {
            out.push(header_line(label, tag, header, &keyfiles, "normal"));
        }

        // try the hidden volume header if the container is large enough
        if data.len() >= HIDDEN_HEADER_OFFSET + HEADER_SIZE {
            let hidden = &data[HIDDEN_HEADER_OFFSET..HIDDEN_HEADER_OFFSET + HEADER_SIZE];
            for tag in TAGS {
                out.push(header_line(label, tag, hidden, &keyfiles, "hidden"));
            }
        }
        Ok(out)
    }
}
