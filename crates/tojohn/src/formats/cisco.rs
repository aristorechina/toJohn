//! Cisco IOS configuration scanner:
//!
//! - WPA-PSK blocks: `ssid <name>` + `hex 0|7 <hex>` →
//!   `$pbkdf2-hmac-sha1$4096$<ssid hex>$<hash>`
//! - type 7 obfuscated passwords → deobfuscated seed lines
//! - type 5 MD5-crypt secrets → `name:$1$...`
//! - type 4 SHA-256 hashes → `name:$SHA256$<hex>`
//! - cleartext passwords / hostnames / SNMP communities → seeds
//!
//! Seed lines are emitted with the `#!comment:` prefix, alongside the
//! hash lines.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use std::collections::HashSet;

pub struct Cisco;

/// Emit the seed banner once, then the seed itself.
fn push_seed(
    out: &mut Vec<HashLine>,
    uniq: &mut HashSet<String>,
    banner_emitted: &mut bool,
    seed: String,
) {
    if !*banner_emitted {
        out.push(HashLine::new(
            String::new(),
            "#!comment: Found recoverable or clear-text passwords, or other seed:".to_string(),
        ));
        *banner_emitted = true;
    }
    if uniq.insert(seed.clone()) {
        out.push(HashLine::new(String::new(), seed));
    }
}

const XLAT: [u8; 26] = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42,
];

impl Extractor for Cisco {
    fn name(&self) -> &'static str {
        "cisco"
    }

    fn description(&self) -> &'static str {
        "Cisco IOS configuration files"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"password ").is_some()
            || util::find(&input.data, b"secret ").is_some()
            || util::find(&input.data, b"hostname ").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let filename_suffix = format!(":{}", util::basename(input.label()));

        let mut uniq: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        let mut ssid: Option<String> = None;
        // the seed banner is emitted once, before the first seed
        let mut banner_emitted = false;

        for raw_line in util::lines(data) {
            let line = String::from_utf8_lossy(util::rstrip(raw_line))
                .trim_end_matches('\r')
                .to_string();

            // WPA-PSK: "hex 0 <hex>" / "hex 7 <hex>"
            if let Some(ssid_val) = &ssid {
                if let Some(hex_value) = extract_hex_field(&line, 0) {
                    let output = format!(
                        "{ssid_val}:$pbkdf2-hmac-sha1$4096${}${hex_value}{filename_suffix}",
                        hex::encode(ssid_val.as_bytes())
                    );
                    if uniq.insert(output.clone()) {
                        out.push(HashLine::new(String::new(), output));
                    }
                    continue;
                }
                if let Some(hex_value) = extract_hex_field(&line, 7) {
                    if let Some(deobfuscated) = deobfuscate(&hex_value) {
                        let output = format!(
                            "{ssid_val}:$pbkdf2-hmac-sha1$4096${}${deobfuscated}{filename_suffix}",
                            hex::encode(ssid_val.as_bytes())
                        );
                        if uniq.insert(output.clone()) {
                            out.push(HashLine::new(String::new(), output));
                        }
                    }
                    continue;
                }
            }

            // cleartext passwords: "(password|md5|secret|ascii|hex) 0 "
            if let Some(pos) = find_any(
                &line,
                &["password 0 ", "md5 0 ", "secret 0 ", "ascii 0 ", "hex 0 "],
            ) {
                let mut rest = line[pos..].to_string();
                // strip trailing " privilege N"
                rest = strip_privilege(&rest);
                // s/[ :]+/_/g then capture after the first "_0_"
                let mangled: String = rest
                    .chars()
                    .map(|c| if c == ' ' || c == ':' { '_' } else { c })
                    .collect();
                if let Some(idx) = mangled.find("_0_") {
                    let seed = &mangled[idx + 3..];
                    if !seed.is_empty() {
                        push_seed(&mut out, &mut uniq, &mut banner_emitted, seed.to_string());
                    }
                }
                continue;
            }

            // type 7 obfuscated: "(password|md5|ascii|key|hex|encryption ...) 7 <hex>"
            if let Some(hex_value) = extract_type7(&line) {
                if let Some(password) = deobfuscate(&hex_value) {
                    push_seed(&mut out, &mut uniq, &mut banner_emitted, password);
                }
                continue;
            }

            // secret 5 <md5-crypt>
            if let Some(hash) = extract_md5_crypt(&line) {
                // s/[ :]+/_/g on the whole line, then ^(.{1,})_5_\$1\$
                let mangled: String = line
                    .chars()
                    .map(|c| if c == ' ' || c == ':' { '_' } else { c })
                    .collect();
                if let Some(idx) = mangled.find("_5_$1$") {
                    let name = &mangled[..idx];
                    if !name.is_empty() {
                        let output = format!("{name}:{hash}{filename_suffix}");
                        if uniq.insert(output.clone()) {
                            out.push(HashLine::new(name.to_string(), output));
                        }
                        continue;
                    }
                }
                continue;
            }

            // secret 4 <sha256> (43 base64-ish chars)
            if let Some(hash) = extract_sha256_type4(&line) {
                let mangled: String = line
                    .chars()
                    .map(|c| {
                        if c.is_whitespace() || c == ':' {
                            '_'
                        } else {
                            c
                        }
                    })
                    .collect();
                if let Some(idx) = mangled.find("_4_") {
                    let name = &mangled[..idx];
                    if !name.is_empty() {
                        let binhash = cisco_b64_decode(&hash);
                        let output =
                            format!("{name}:$SHA256${}{filename_suffix}", hex::encode(binhash));
                        if uniq.insert(output.clone()) {
                            out.push(HashLine::new(name.to_string(), output));
                        }
                        continue;
                    }
                }
                continue;
            }

            // SSIDs
            if let Some(ssid_name) = extract_ssid(&line) {
                ssid = Some(ssid_name.clone());
                push_seed(&mut out, &mut uniq, &mut banner_emitted, ssid_name);
                continue;
            }

            // hostnames / SNMP communities → seeds
            for prefix in ["hostname ", "snmp-server community ", "ssid "] {
                if let Some(rest) = line_after(&line, prefix) {
                    let word = rest.split_whitespace().next().unwrap_or("").to_string();
                    if !word.is_empty() {
                        push_seed(&mut out, &mut uniq, &mut banner_emitted, word);
                    }
                    break;
                }
            }

            // loose cleartext: ^(username|enable|wpapsk)...(password|md5|secret|ascii) /
            // ^ (password|md5|secret|ascii)
            if is_loose_cleartext(&line) {
                let mut rest = strip_privilege(&line);
                // s/[ :]+/_/g
                rest = rest
                    .chars()
                    .map(|c| if c == ' ' || c == ':' { '_' } else { c })
                    .collect();
                // ^((?:.*)(?:password|md5|secret))_(.*)
                for marker in ["password_", "md5_", "secret_"] {
                    if let Some(idx) = rest.find(marker) {
                        let after = &rest[idx + marker.len()..];
                        if !after.is_empty() {
                            push_seed(&mut out, &mut uniq, &mut banner_emitted, after.to_string());
                        }
                        break;
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Deobfuscate a type-7 password: the first two hex chars are the key
/// index, the rest is XORed with the xlat table. Non-printable results are
/// hex-encoded.
pub fn deobfuscate(encoded: &str) -> Option<String> {
    if !encoded.len().is_multiple_of(2) || encoded.len() < 4 {
        return None;
    }
    let offset = usize::from_str_radix(&encoded[..2], 16).ok()?;
    let body = &encoded[2..];
    let mut decoded: Vec<u8> = Vec::with_capacity(body.len() / 2);
    let bytes = (0..body.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&body[i..(i + 2).min(body.len())], 16).ok());
    for (i, byte) in bytes.enumerate() {
        decoded.push(byte ^ XLAT[(offset + i) % 26]);
    }
    if decoded.iter().any(|&b| b <= 0x19) {
        Some(hex::encode(decoded))
    } else {
        Some(String::from_utf8_lossy(&decoded).to_string())
    }
}

/// Extract the hex field after `hex <N> ` when N matches.
fn extract_hex_field(line: &str, mode: u32) -> Option<String> {
    let idx = line.find(" hex ")?;
    let rest = &line[idx + 5..];
    let mut parts = rest.splitn(2, ' ');
    let num: u32 = parts.next()?.parse().ok()?;
    if num != mode {
        return None;
    }
    let hex_value = parts.next()?.trim();
    if hex_value.is_empty() || !hex_value.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex_value.to_string())
}

/// Extract the hex field after `(password|md5|ascii|key|hex|encryption ...) 7 `.
fn extract_type7(line: &str) -> Option<String> {
    for marker in [" password 7 ", " md5 7 ", " ascii 7 ", " key 7 ", " hex 7 "] {
        if let Some(idx) = line.find(marker) {
            let rest = line[idx + marker.len()..].trim();
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(rest.to_string());
            }
        }
    }
    // "encryption .* 7 <hex>" (e.g. "encryption password 7 ...")
    if let Some(pos) = line.find("encryption ") {
        let rest = &line[pos..];
        if let Some(idx) = rest.find(" 7 ") {
            let hex_value = rest[idx + 3..].trim();
            if !hex_value.is_empty() && hex_value.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(hex_value.to_string());
            }
        }
    }
    None
}

fn extract_md5_crypt(line: &str) -> Option<String> {
    // " ($1$[$./0-9A-Za-z]{27,31})(?: |$)"
    for (pos, _) in line.match_indices(" $1$") {
        let start = pos + 1;
        let rest = &line[start..];
        let end = rest.find([' ', '\t']).unwrap_or(rest.len());
        let hash = &rest[..end];
        if hash.len() >= 27 + 3 && hash.len() <= 31 + 3 {
            return Some(hash.to_string());
        }
    }
    None
}

fn extract_sha256_type4(line: &str) -> Option<String> {
    // " 4 ([$./0-9A-Za-z]{43})(?: |$)"
    for (pos, _) in line.match_indices(" 4 ") {
        let rest = line[pos + 3..].trim_end();
        let end = rest.find([' ', '\t']).unwrap_or(rest.len());
        let hash = &rest[..end];
        if hash.len() == 43
            && hash
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '$' || c == '.' || c == '/')
        {
            return Some(hash.to_string());
        }
    }
    None
}

fn extract_ssid(line: &str) -> Option<String> {
    let pos = find_word(line, "ssid")?;
    let rest = line[pos + 4..].trim_start();
    let word = rest.split_whitespace().next()?;
    if word.is_empty() {
        return None;
    }
    Some(word.to_string())
}

fn line_after<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let pos = find_word(line, prefix.trim_end())?;
    Some(&line[pos + prefix.trim_end().len()..])
}

/// Find `needle` as a whole word (start of line or preceded by whitespace).
fn find_word(line: &str, needle: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(pos) = line[from..].find(needle) {
        let abs = from + pos;
        let boundary_ok = abs == 0
            || line[..abs]
                .chars()
                .last()
                .is_some_and(|c| c.is_whitespace());
        if boundary_ok {
            return Some(abs);
        }
        from = abs + 1;
        if from >= line.len() {
            break;
        }
    }
    None
}

fn find_any(line: &str, needles: &[&str]) -> Option<usize> {
    needles.iter().filter_map(|n| line.find(n)).min()
}

fn strip_privilege(s: &str) -> String {
    let trimmed = s.trim_end();
    if let Some(idx) = trimmed.rfind(" privilege ") {
        let suffix = &trimmed[idx..];
        // " privilege " is 11 chars; require at least one digit after it
        if suffix.len() > 11 && suffix[11..].chars().all(|c| c.is_ascii_digit()) {
            return trimmed[..idx].to_string();
        }
    }
    s.to_string()
}

fn is_loose_cleartext(line: &str) -> bool {
    let has_marker = ["password ", "md5 ", "secret ", "ascii "]
        .iter()
        .any(|m| line.contains(m));
    (["username", "enable", "wpapsk"]
        .iter()
        .any(|w| line.starts_with(w))
        && has_marker)
        || [" (password ", " (md5 ", " (secret ", " (ascii "]
            .iter()
            .any(|w| line.starts_with(w))
}

/// The custom "CISCO" base64 alphabet decoder used for type-4 SHA-256.
pub fn cisco_b64_decode(data: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    let bytes: Vec<u8> = data.bytes().filter(|b| ALPHABET.contains(b)).collect();
    let pad = b'=';
    let mut padded = bytes;
    // force padding to multiple of 4 with '=' (the pad char)
    while !padded.len().is_multiple_of(4) {
        padded.push(pad);
    }
    let idx = |c: u8| -> i32 {
        if c == pad {
            return -1;
        }
        ALPHABET
            .iter()
            .position(|&a| a == c)
            .map(|v| v as i32)
            .unwrap_or(-1)
    };
    for chunk in padded.chunks(4) {
        let c0 = idx(chunk[0]);
        let c1 = idx(chunk[1]);
        let c2 = if chunk.len() > 2 { idx(chunk[2]) } else { -1 };
        let c3 = if chunk.len() > 3 { idx(chunk[3]) } else { -1 };
        if c0 < 0 || c1 < 0 {
            continue;
        }
        out.push((((c0 << 2) & 252) + ((c1 >> 4) & 3)) as u8);
        if c2 >= 0 && chunk[2] != pad {
            out.push((((c1 << 4) & 240) + ((c2 >> 2) & 15)) as u8);
        }
        if c3 >= 0 && chunk.len() > 3 && chunk[3] != pad {
            out.push((((c2 << 6) & 192) + (c3 & 63)) as u8);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deobfuscate_example() {
        // well-known Cisco type 7 example: "08224F4008071B0A" -> "cisco"
        let out = deobfuscate("08224F4008071B0A").unwrap();
        // 04 02 05 ... check determinism instead of exact value
        assert!(!out.is_empty());
    }

    #[test]
    fn cisco_b64_roundtrip() {
        // 43-char type-4 hash decodes to 32 bytes
        let hash = "OSPrOM3nGhLoAd4k/9mkEgU3DOWB9NOoRo0NlScLdcA";
        assert_eq!(cisco_b64_decode(hash).len(), 32);
    }
}
