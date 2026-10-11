//! XMPP SCRAM hash extractor for `ejabberdctl dump` output files, emitting
//! `$xmpp-scram$0$` hash lines. The dump's Erlang terms are parsed with a
//! minimal recursive-descent parser for the needed grammar subset (atoms,
//! quoted atoms, strings, binaries, tuples, lists, maps, numbers, booleans);
//! tuples/lists flatten their child terms, so a binary `<<"x">>` contributes
//! the plain string `x`.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use base64::Engine;

pub struct Ejabberd;

impl Extractor for Ejabberd {
    fn name(&self) -> &'static str {
        "ejabberd"
    }

    fn description(&self) -> &'static str {
        "ejabberdctl dump output files (XMPP SCRAM)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"passwd").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let mut out = Vec::new();
        // records start at a line containing "passwd" and end at the first
        // following line containing "}}." — a trailing unterminated buffer is
        // dropped.
        let mut buf: Vec<&[u8]> = Vec::new();
        for line in util::lines(&input.data) {
            if util::find(line, b"}}.").is_some() {
                buf.push(line);
                let joined: Vec<u8> = buf.concat();
                if let Some(hash) = parse_record(&joined, input.label())? {
                    out.push(hash);
                }
                buf.clear();
            } else if util::find(line, b"passwd").is_some() {
                buf.clear();
                buf.push(line);
            } else {
                buf.push(line);
            }
        }
        Ok(out)
    }
}

/// Decode one record chunk. `Ok(None)` means the chunk was skipped as a
/// "bad line". A parse failure maps to `Err`.
fn parse_record(chunk: &[u8], file: &str) -> Result<Option<HashLine>> {
    let text = std::str::from_utf8(chunk)
        .map_err(|_| Error::malformed(file, "chunk is not valid UTF-8"))?;
    let text = text.replace([' ', '\n'], "");
    // after spaces/newlines are removed, strip everything from the first '%'
    // to the end.
    let text = match text.find('%') {
        Some(i) => &text[..i],
        None => text.as_str(),
    };
    let terms = parse_terms(text)
        .map_err(|e| Error::malformed(file, format!("Erlang term parse error: {e}")))?;

    // mismatched record shapes are skipped.
    let Some(Term::Tuple(fields)) = terms.first() else {
        return Ok(None);
    };
    let [_, who, scram] = fields.as_slice() else {
        return Ok(None);
    };
    // user = the who parts joined with "@"; atoms and binaries both
    // contribute plain strings.
    let Term::Tuple(who_parts) = who else {
        return Ok(None);
    };
    let Some(user) = who_parts
        .iter()
        .map(|part| match part {
            Term::Str(value) | Term::Atom(value) => Some(value.clone()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .map(|parts| parts.join("@"))
    else {
        return Ok(None);
    };

    let Term::Tuple(scram_parts) = scram else {
        return Ok(None);
    };
    // fields: _, stored_key, server_key (unused), salt, iterations
    let [_, stored_key, _server_key, salt, iterations] = scram_parts.as_slice() else {
        return Ok(None);
    };
    let (Term::Str(stored_key) | Term::Atom(stored_key)) = stored_key else {
        return Ok(None);
    };
    let (Term::Str(salt) | Term::Atom(salt)) = salt else {
        return Ok(None);
    };
    let Term::Int(iterations) = iterations else {
        return Ok(None);
    };
    // Lenient base64 would tolerate stray non-alphabet chars; the strict
    // engine treats them as an error, which lands in the "bad line" skip
    // path.
    let engine = base64::engine::general_purpose::STANDARD;
    let Ok(stored) = engine.decode(stored_key) else {
        return Ok(None);
    };
    let Ok(salt_bytes) = engine.decode(salt) else {
        return Ok(None);
    };
    let stored_hex = hex::encode(stored);
    let salt_hex = hex::encode(salt_bytes);
    let salt_len = salt_hex.len() / 2;
    Ok(Some(HashLine::new(
        user.clone(),
        format!("{user}:$xmpp-scram$0${iterations}${salt_len}${salt_hex}${stored_hex}"),
    )))
}

#[derive(Debug, Clone, PartialEq)]
enum Term {
    Atom(String),
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Tuple(Vec<Term>),
    List(Vec<Term>),
    Map(Vec<(Term, Term)>),
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

type PResult<T> = std::result::Result<T, String>;

fn parse_terms(text: &str) -> PResult<Vec<Term>> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let mut terms = Vec::new();
    loop {
        parser.skip_ws();
        if parser.pos >= parser.bytes.len() {
            break;
        }
        terms.push(parser.term()?);
        parser.skip_ws();
        if parser.pos < parser.bytes.len() {
            if parser.bytes[parser.pos] != b'.' {
                return Err(format!("expected '.' at offset {}", parser.pos));
            }
            parser.pos += 1;
        }
    }
    Ok(terms)
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len()
            && matches!(self.bytes[self.pos], b' ' | b'\t' | b'\r' | b'\n')
        {
            self.pos += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn eat(&mut self, token: &[u8]) -> bool {
        if self.bytes[self.pos..].starts_with(token) {
            self.pos += token.len();
            true
        } else {
            false
        }
    }

    fn term(&mut self) -> PResult<Term> {
        match self.peek() {
            Some(b'{') => self.delimited(b'}').map(Term::Tuple),
            Some(b'[') => self.delimited(b']').map(Term::List),
            Some(b'#') if self.bytes[self.pos..].starts_with(b"#{") => self.map(),
            Some(b'"') => self.string().map(Term::Str),
            Some(b'<') if self.bytes[self.pos..].starts_with(b"<<") => self.binary(),
            Some(b'\'') => self.quoted_atom().map(Term::Atom),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) if c.is_ascii_lowercase() => self.word(),
            Some(c) => Err(format!("unexpected byte {c:?} at offset {}", self.pos)),
            None => Err("unexpected end of input".to_string()),
        }
    }

    /// A `,`-delimited term sequence opened by `{` or `[` and closed by
    /// `close`.
    fn delimited(&mut self, close: u8) -> PResult<Vec<Term>> {
        self.pos += 1; // open
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(close) {
            self.pos += 1;
            return Ok(items);
        }
        loop {
            items.push(self.term()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(c) if c == close => {
                    self.pos += 1;
                    return Ok(items);
                }
                _ => {
                    return Err(format!(
                        "expected ',' or '{}' at offset {}",
                        close as char, self.pos
                    ))
                }
            }
        }
    }

    fn map(&mut self) -> PResult<Term> {
        self.pos += 2; // "#
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Term::Map(items));
        }
        loop {
            let key = self.term()?;
            self.skip_ws();
            if !self.eat(b"=>") {
                return Err(format!("expected '=>' at offset {}", self.pos));
            }
            self.skip_ws();
            let value = self.term()?;
            items.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Term::Map(items));
                }
                _ => return Err(format!("expected ',' or '}}' at offset {}", self.pos)),
            }
        }
    }

    /// `"..."` — handles `\"` escapes.
    fn string(&mut self) -> PResult<String> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("unterminated string".to_string()),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') if self.bytes.get(self.pos + 1) == Some(&b'"') => {
                    out.push('"');
                    self.pos += 2;
                }
                Some(_) => {
                    let rest = std::str::from_utf8(&self.bytes[self.pos..])
                        .map_err(|_| "invalid UTF-8 in string")?;
                    let c = rest.chars().next().unwrap();
                    out.push(c);
                    self.pos += c.len_utf8();
                }
            }
        }
    }

    /// `<<"...">>` — contributes its inner string.
    fn binary(&mut self) -> PResult<Term> {
        self.pos += 2; // <<
        self.skip_ws();
        let inner = self.string()?;
        self.skip_ws();
        if !self.eat(b">>") {
            return Err(format!("expected '>>' at offset {}", self.pos));
        }
        Ok(Term::Str(inner))
    }

    fn quoted_atom(&mut self) -> PResult<String> {
        self.pos += 1; // '
        let start = self.pos;
        while self.pos < self.bytes.len() && self.bytes[self.pos] != b'\'' {
            self.pos += 1;
        }
        if self.pos >= self.bytes.len() {
            return Err("unterminated quoted atom".to_string());
        }
        let text = String::from_utf8_lossy(&self.bytes[start..self.pos]).to_string();
        self.pos += 1;
        Ok(format!("'{text}'")) // quoted atoms keep their quotes in the atom text
    }

    /// Atoms and booleans (lowercase-starting words).
    fn word(&mut self) -> PResult<Term> {
        let start = self.pos;
        while self.pos < self.bytes.len()
            && (self.bytes[self.pos].is_ascii_alphanumeric() || self.bytes[self.pos] == b'_')
        {
            self.pos += 1;
        }
        let word = String::from_utf8_lossy(&self.bytes[start..self.pos]).to_string();
        match word.as_str() {
            "true" => Ok(Term::Bool(true)),
            "false" => Ok(Term::Bool(false)),
            _ => Ok(Term::Atom(word)),
        }
    }

    /// `-?[0-9]+(#[0-9a-zA-Z]+)?` or a float with `.`/exponent.
    fn number(&mut self) -> PResult<Term> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.pos += 1;
        }
        let int_part_end = self.pos;
        if self.peek() == Some(b'#') {
            self.pos += 1;
            let base = text_i64(&self.bytes[start..int_part_end])?;
            let digits_start = self.pos;
            while self.peek().is_some_and(|c| c.is_ascii_alphanumeric()) {
                self.pos += 1;
            }
            let digits = String::from_utf8_lossy(&self.bytes[digits_start..self.pos]);
            return i64::from_str_radix(&digits, u32::try_from(base).map_err(|_| "bad base")?)
                .map(Term::Int)
                .map_err(|e| format!("bad base-{base} number: {e}"));
        }
        if matches!(self.peek(), Some(b'.') | Some(b'e') | Some(b'E')) {
            self.pos += 1;
            while self
                .peek()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-' || c == b'+')
            {
                self.pos += 1;
            }
            let text = String::from_utf8_lossy(&self.bytes[start..self.pos]);
            return text
                .parse::<f64>()
                .map(Term::Float)
                .map_err(|e| format!("bad float: {e}"));
        }
        Ok(Term::Int(text_i64(&self.bytes[start..int_part_end])?))
    }
}

fn text_i64(bytes: &[u8]) -> PResult<i64> {
    std::str::from_utf8(bytes)
        .map_err(|_| "invalid number".to_string())?
        .parse::<i64>()
        .map_err(|e| format!("bad integer: {e}"))
}
