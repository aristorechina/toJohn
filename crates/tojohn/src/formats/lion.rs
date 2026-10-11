//! Mac OS X 10.7 Lion salted SHA-512 hash extractor: pattern-matches the
//! serialized `SALTED-SHA512` node in the binary plist — the hash marker
//! `bplist00...SALTED-SHA512...` followed by 68 raw bytes — and reads the
//! user name between the `:SHA1.` marker (plus 40 bytes) and the closing
//! user-name suffix marker. When no username is found, `UNKNOWN_USERNAME`
//! is emitted.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Lion;

/// Serialized marker: binary-plist header plus the `SALTED-SHA512` key
/// marker; the 68 raw salted-SHA512 bytes follow it.
const HASH_PREFIX: &[u8] = b"bplist00\xd1\x01\x02\x5dSALTED-SHA512\x4f\x10\x44";
/// `:SHA1.` marker: 40 stored-hash bytes and then the user name follow it.
const USER_PREFIX: &[u8] = b"\x3a\x53\x48\x41\x31\x2e"; // ":SHA1."
/// Marker that ends the user name.
const USER_SUFFIX: &[u8] = b"\xa1\x35\x4f\x10";

impl Extractor for Lion {
    fn name(&self) -> &'static str {
        "lion"
    }

    fn description(&self) -> &'static str {
        "Mac OS X 10.7 Lion plists (SALTED-SHA512)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"SALTED-SHA512").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        // hash: fixed prefix + 68 raw bytes
        let Some(hash_pos) = util::find(data, HASH_PREFIX) else {
            // marker not found: no output
            return Ok(Vec::new());
        };
        let hash_start = hash_pos + HASH_PREFIX.len();
        let hash = &data[hash_start..(hash_start + 68).min(data.len())];

        // user: ":SHA1." + 40 bytes + printable name (1..=64 chars) + suffix
        let mut user: Option<Vec<u8>> = None;
        if let Some(prefix_pos) = util::find(data, USER_PREFIX) {
            let name_start = prefix_pos + USER_PREFIX.len() + 40;
            if let Some(suffix_pos) = util::find(&data[name_start..], USER_SUFFIX) {
                let name = &data[name_start..name_start + suffix_pos];
                // printable: ASCII graphics plus space, excluding `:` (the
                // field separator), and any byte >= 0xa0
                let printable =
                    |b: u8| (0x20..=0x39).contains(&b) || (0x3b..=0x7e).contains(&b) || b >= 0xa0;
                if !name.is_empty() && name.len() <= 64 && name.iter().all(|&b| printable(b)) {
                    user = Some(name.to_vec());
                }
            }
        }
        let user = user
            .map(|bytes| String::from_utf8_lossy(&bytes).to_string())
            .unwrap_or_else(|| "UNKNOWN_USERNAME".to_string());

        let line = format!("{user}:{}", hex::encode(hash));
        Ok(vec![HashLine::new(user, line)])
    }
}
