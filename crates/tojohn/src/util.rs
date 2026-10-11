//! Shared byte-level helpers implementing the text-handling semantics the
//! hash-line formats rely on.

/// Strip trailing whitespace (space, `\t`, `\n`, `\r`, `\x0b`, `\x0c`).
pub fn rstrip(bytes: &[u8]) -> &[u8] {
    let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let end = bytes.iter().rposition(|&b| !is_ws(b)).map_or(0, |i| i + 1);
    &bytes[..end]
}

/// Strip leading and trailing whitespace (same character set as [`rstrip`]).
pub fn strip(bytes: &[u8]) -> &[u8] {
    let is_ws = |b: u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c);
    let start = bytes.iter().position(|&b| !is_ws(b)).unwrap_or(bytes.len());
    let trimmed = &bytes[start..];
    rstrip(trimmed)
}

/// First index of byte slice `needle` inside `haystack`.
pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Split into lines at the ASCII line boundaries: `\n`, `\r\n`, `\r`,
/// `\v`, `\f`, `\x1c`, `\x1d`, `\x1e`.
/// A trailing boundary does not produce a final empty line; an empty input
/// yields no lines. Unicode-only boundaries (NEL etc.) are not split at the
/// byte level — only relevant for non-ASCII input.
pub fn splitlines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let is_boundary = |b: u8| matches!(b, b'\n' | b'\r' | 0x0b | 0x0c | 0x1c..=0x1e);
    let mut end = data.len();
    if end >= 1 && is_boundary(data[end - 1]) {
        end -= 1;
        if data[end] == b'\n' && end >= 1 && data[end - 1] == b'\r' {
            end -= 1;
        }
    }
    let scan = &data[..end];
    let mut start = 0;
    let mut finished = data.is_empty();
    std::iter::from_fn(move || {
        if finished {
            return None;
        }
        match scan[start..].iter().position(|&b| is_boundary(b)) {
            None => {
                finished = true;
                Some(&data[start..end])
            }
            Some(rel) => {
                let i = start + rel;
                let mut next = i + 1;
                if data[i] == b'\r' && next < data.len() && data[next] == b'\n' {
                    next += 1;
                }
                let line = &data[start..i];
                start = next;
                Some(line)
            }
        }
    })
}

/// File name after the last path separator (both Windows and POSIX
/// separators handled).
pub fn basename(path: &str) -> &str {
    match path.rfind(['/', '\\']) {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Percent decoding: `%XX` hex pairs become bytes, malformed sequences
/// are left as-is.
pub fn percent_decode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// Split into `\n`-separated lines: a trailing `\n` does not produce a
/// phantom final empty line (but interior empty lines and a final line
/// without `\n` are preserved).
pub fn lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let end = match data.last() {
        Some(b'\n') => data.len() - 1,
        _ => data.len(),
    };
    let mut iter = data[..end].split(|&b| b == b'\n');
    if data.is_empty() {
        // empty input yields no lines (split yields one empty chunk).
        iter.next();
    }
    iter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rstrip_strips_whitespace() {
        assert_eq!(rstrip(b"abc \r\n\t"), b"abc");
        assert_eq!(rstrip(b"abc"), b"abc");
        assert_eq!(rstrip(b"  \x0b\x0c"), b"");
        assert_eq!(rstrip(b""), b"");
    }

    #[test]
    fn strip_strips_whitespace() {
        assert_eq!(strip(b"  abc \r\n"), b"abc");
        assert_eq!(strip(b"\t abc \t"), b"abc");
        assert_eq!(strip(b"   "), b"");
        assert_eq!(strip(b""), b"");
    }

    #[test]
    fn find_locates_needle() {
        assert_eq!(find(b"a= b= c", b"= "), Some(1));
        assert_eq!(find(b"abc", b"xy"), None);
        assert_eq!(find(b"abc", b""), Some(0));
        assert_eq!(find(b"ab", b"abc"), None);
    }

    #[test]
    fn lines_keeps_interior_and_final() {
        let v: Vec<&[u8]> = lines(b"a\nb\n").collect();
        assert_eq!(v, vec![&b"a"[..], &b"b"[..]]);
        let v: Vec<&[u8]> = lines(b"a\nb").collect();
        assert_eq!(v, vec![&b"a"[..], &b"b"[..]]);
        let v: Vec<&[u8]> = lines(b"a\n\nb").collect();
        assert_eq!(v, vec![&b"a"[..], &b""[..], &b"b"[..]]);
        let v: Vec<&[u8]> = lines(b"\n").collect();
        assert_eq!(v, vec![&b""[..]]);
        assert_eq!(lines(b"").count(), 0);
    }
}
