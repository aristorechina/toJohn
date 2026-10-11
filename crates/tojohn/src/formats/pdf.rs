//! Extracts `$pdf$` hashes from encrypted PDF documents (standard security
//! handler). The Encrypt dictionary is located by scanning the file for the
//! `Encrypt` reference in the trailer, resolving the object, and reading:
//! `Filter` (must be `/Standard`), `V`, `R`, `Length`, `P`, `O`, `U`,
//! and for R>=4 `CF/StdCF/CFM`, `StrF`, `StmF`; for R=5 additionally `UE`,
//! `OE`; plus the document `ID`.
//!
//! Output format:
//! - R2/R3/R4: `$pdf$V*R*Length*P*meta*IDlen*IDhex*Ulen*Uhex*Olen*Ohex`
//! - R5:       `...*Ulen*Uhex*Olen*Ohex*UElen*UEhex*OElen*OEhex`
//!
//! This is a focused PDF object scanner (trailer/Encrypt dictionary lookup
//! with literal-string values). Object-stream (`/Type/XRef`) indirection
//! for the Encrypt dictionary is not resolved.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Pdf;

impl Extractor for Pdf {
    fn name(&self) -> &'static str {
        "pdf"
    }

    fn description(&self) -> &'static str {
        "PDF documents with standard security (Encrypt dictionary)"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"%PDF")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        if !data.starts_with(b"%PDF") {
            return Ok(Vec::new());
        }
        let text = String::from_utf8_lossy(data);

        // locate the Encrypt reference: "Encrypt N 0 R" (direct dicts are
        // rare and handled by scanning the raw /Encrypt << dict >> too)
        let mut encrypt_obj_num: Option<u64> = None;
        if let Some(pos) = util::find(data, b"/Encrypt ") {
            // skip the "/EncryptMetadata" false positive: "/Encrypt " with a
            // trailing space only matches the reference key
            if util::find(data, b"/EncryptMetadata") == Some(pos) {
                // find the next real /Encrypt reference further along
                if let Some(p2) = util::find(&data[pos + 1..], b"/Encrypt ") {
                    let real = pos + 1 + p2;
                    let rest = text[real + 9..].trim_start();
                    let mut parts = rest.split_whitespace();
                    if let Some(n) = parts.next().and_then(|s| s.parse::<u64>().ok()) {
                        if parts.next() == Some("0") && parts.next() == Some("R") {
                            encrypt_obj_num = Some(n);
                        }
                    }
                    // fall through with encrypt_obj_num set
                }
            }
        }
        if encrypt_obj_num.is_none() {
            if let Some(pos) = util::find(data, b"/Encrypt ") {
                let rest = text[pos + 8..].trim_start();
                let mut parts = rest.split_whitespace();
                let num: Option<u64> = parts.next().and_then(|s| s.parse().ok());
                if let Some(n) = num {
                    // validate "N 0 R"
                    let mut it = parts;
                    if it.next() == Some("0") && it.next() == Some("R") {
                        encrypt_obj_num = Some(n);
                    }
                }
            }
        }

        // collect the document ID (first /ID array entry after "trailer")
        let id: Vec<u8> = trailer_id(data).unwrap_or_default();

        // extract the Encrypt dictionary: either inline or as "N 0 obj ... endobj"
        let dict_body: Option<String> = match encrypt_obj_num {
            Some(n) => {
                let pattern = format!("{n} 0 obj");
                find_dict_object(data, &pattern)
            }
            None => {
                // direct dictionary in trailer: /Encrypt << ... >>
                text.find("/Encrypt").and_then(|pos| {
                    let start = text[pos..].find("<<")? + pos;
                    extract_balanced_dict(&text[start..])
                })
            }
        };
        let Some(dict) = dict_body else {
            return Ok(Vec::new()); // not encrypted / not resolvable
        };

        // parse the dictionary entries we need
        let get_i64 = |key: &str| -> Option<i64> { dict_entry_i64(&dict, key) };
        let get_string = |key: &str| -> Option<Vec<u8>> { dict_entry_string(&dict, key) };

        let filter_name = dict_entry_name(&dict, "Filter").unwrap_or_default();
        if filter_name != "Standard" {
            return Err(Error::other(format!(
                "encryption filter {filter_name} not currently supported"
            )));
        }
        let version = get_i64("V").unwrap_or(0);
        let revision = get_i64("R").unwrap_or(0);
        // O/U may be literal strings or hex strings
        let has_o = get_string("O").is_some() || get_hex(&dict, "O").is_some();
        let has_u = get_string("U").is_some() || get_hex(&dict, "U").is_some();
        if !has_o || !has_u {
            return Err(Error::other("incomplete Encrypt specification"));
        }
        let p = get_i64("P").unwrap_or(0);
        let length = get_i64("Length").unwrap_or(40);

        // metadata encryption flag (V4+)
        let mut meta = 1i64;
        if version >= 4 {
            if let Some(flag) = dict_entry_name(&dict, "EncryptMetadata") {
                if flag.eq_ignore_ascii_case("false") {
                    meta = 0;
                }
            }
        }

        // hex strings <...> in the Encrypt dict; fall back to literal strings
        let u = get_string("U")
            .or_else(|| get_hex(&dict, "U"))
            .unwrap_or_default();
        let o = get_string("O")
            .or_else(|| get_hex(&dict, "O"))
            .unwrap_or_default();

        let label = util::basename(input.label());
        let mut line = format!(
            "{label}:$pdf${version}*{revision}*{length}*{p}*{meta}*{}*{}*",
            id.len(),
            hex::encode(id)
        );

        if matches!(revision, 2..=4) {
            line.push_str(&format!(
                "{}*{}*{}*{}",
                u.len(),
                hex::encode(u),
                o.len(),
                hex::encode(o)
            ));
        } else {
            let ue = get_string("UE")
                .or_else(|| get_hex(&dict, "UE"))
                .unwrap_or_default();
            let oe = get_string("OE")
                .or_else(|| get_hex(&dict, "OE"))
                .unwrap_or_default();
            if ue.is_empty() && oe.is_empty() {
                return Err(Error::other("missing Encrypt UE entry"));
            }
            line.push_str(&format!(
                "{}*{}*{}*{}*{}*{}*{}*{}",
                u.len(),
                hex::encode(u),
                o.len(),
                hex::encode(o),
                ue.len(),
                hex::encode(ue),
                oe.len(),
                hex::encode(oe)
            ));
        }
        Ok(vec![HashLine::new(label, line)])
    }
}

/// Find the /ID array in the trailer: `trailer << ... /ID [<hex...> <hex...>] >>`.
fn trailer_id(data: &[u8]) -> Option<Vec<u8>> {
    let text = String::from_utf8_lossy(data);
    let trailer_pos = text.rfind("trailer")?;
    let tail = &text[trailer_pos..];
    let id_pos = tail.find("/ID")?;
    // first <...> literal after /ID
    let after = &tail[id_pos + 3..];
    let open_pos = after.find('<')?;
    let close_pos = after.find('>')?;
    if close_pos <= open_pos {
        return None;
    }
    Some(hex_string_to_bytes(after[open_pos + 1..close_pos].trim()))
}

/// Locate `N 0 obj` and return the object body up to `endobj` (as text).
fn find_dict_object(data: &[u8], pattern: &str) -> Option<String> {
    let text = String::from_utf8_lossy(data);
    let mut search_from = 0;
    loop {
        let relative = text[search_from..].find(pattern)?;
        let absolute = search_from + relative;
        // must be at object start (beginning of line)
        if absolute == 0 || text[..absolute].ends_with('\n') {
            let body_start = absolute + pattern.len();
            let end = text[body_start..].find("endobj")? + body_start;
            return Some(text[body_start..end].to_string());
        }
        search_from = absolute + 1;
    }
}

/// Extract a balanced `<< ... >>` dictionary from the start.
fn extract_balanced_dict(s: &str) -> Option<String> {
    let start = s.find("<<")?;
    let mut depth = 0i32;
    let bytes = s.as_bytes();
    let mut i = start;
    while i + 1 < bytes.len() {
        if bytes[i] == b'<' && bytes[i + 1] == b'<' {
            depth += 1;
            i += 2;
            continue;
        }
        if bytes[i] == b'>' && bytes[i + 1] == b'>' {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return Some(s[start..i].to_string());
            }
            continue;
        }
        i += 1;
    }
    None
}

/// /Key <i64> — integer entry.
fn dict_entry_i64(dict: &str, key: &str) -> Option<i64> {
    let pattern = format!("/{key}");
    let pos = dict.find(&pattern)?;
    let rest = dict[pos + pattern.len()..].trim_start();
    let num: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '+')
        .collect();
    num.parse().ok()
}

/// /Key /Name — name entry (leading slash stripped).
fn dict_entry_name(dict: &str, key: &str) -> Option<String> {
    let pattern = format!("/{key}");
    let pos = dict.find(&pattern)?;
    let rest = dict[pos + pattern.len()..].trim_start();
    if !rest.starts_with('/') {
        return None;
    }
    let name: String = rest[1..]
        .chars()
        .take_while(|c| !c.is_whitespace() && !matches!(c, '/' | '<' | '>' | '[' | ']'))
        .collect();
    Some(name)
}

/// /Key <hex string> — hex bytes between angle brackets.
fn get_hex(dict: &str, key: &str) -> Option<Vec<u8>> {
    let pattern = format!("/{key}");
    let pos = dict.find(&pattern)?;
    let rest = &dict[pos + pattern.len()..].trim_start();
    if !rest.starts_with('<') {
        return None;
    }
    let close_pos = rest.find('>')?;
    let hex_digits: String = rest[1..close_pos]
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    let cleaned = if hex_digits.len().is_multiple_of(2) {
        hex_digits
    } else {
        format!("{hex_digits}0")
    };
    (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect()
}

/// /Key <literal string> — returns the raw bytes between parentheses with
/// escapes resolved (the subset: \( \) \\ \n \r \t \b \f and octal).
fn dict_entry_string(dict: &str, key: &str) -> Option<Vec<u8>> {
    let pattern = format!("/{key}");
    let pos = dict.find(&pattern)?;
    let rest = &dict[pos + pattern.len()..];
    let open_pos = rest.find('(')?;
    let bytes = rest.as_bytes();
    let mut out = Vec::new();
    let mut depth = 1i32;
    let mut i = open_pos + 1;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    break;
                }
                match bytes[i] {
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0c),
                    b'(' => out.push(b'('),
                    b')' => out.push(b')'),
                    b'\\' => out.push(b'\\'),
                    b'0'..=b'7' => {
                        // up to 3 octal digits
                        let mut v: u32 = 0;
                        let mut n = 0;
                        while i < bytes.len() && n < 3 && (bytes[i] as char).is_ascii_digit() {
                            v = v * 8 + (bytes[i] - b'0') as u32;
                            i += 1;
                            n += 1;
                        }
                        i -= 1;
                        out.push((v & 0xff) as u8);
                    }
                    b'\n' => {} // line continuation
                    other => out.push(other),
                }
                i += 1;
            }
            b'(' => {
                depth += 1;
                out.push(b'(');
                i += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(out);
                }
                out.push(b')');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    None
}

/// PDF hex strings may contain whitespace; strip and parse.
fn hex_string_to_bytes(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let cleaned = if !cleaned.len().is_multiple_of(2) {
        format!("{cleaned}0")
    } else {
        cleaned
    };
    (0..cleaned.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn debug_dict() {
        let data = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/pdf/encrypted.pdf"
        ))
        .unwrap();
        let text = String::from_utf8_lossy(&data);
        // object body
        let pos = text.find("4 0 obj").unwrap();
        let body_start = pos + "4 0 obj".len();
        let end = text[body_start..].find("endobj").unwrap() + body_start;
        let dict = &text[body_start..end];
        println!("dict: {}", dict.trim());
        println!("has V {}", dict.contains("/V "));
        println!("has R {}", dict.contains("/R "));
        println!("has O {}", dict.contains("/O <"));
        println!("has U {}", dict.contains("/U <"));
        println!("has P {}", dict.contains("/P "));
    }
}
