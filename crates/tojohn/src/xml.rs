//! Minimal XML DOM parser used by the format modules that parse XML-based
//! containers (encfs, filezilla, libreoffice, staroffice, telegram).
//! Handles elements, attributes, text, comments, processing instructions
//! and the standard entities.

/// An XML element with attributes, text and children (document order kept).
#[derive(Debug, Clone)]
pub struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    pub text: String,
}

impl Element {
    /// Attribute lookup, like `element.get(name)`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// All elements in the subtree (self first), document order — like
    /// `ElementTree.iter()`.
    pub fn iter_all(&self) -> Vec<&Element> {
        let mut out = vec![self];
        for c in &self.children {
            out.extend(c.iter_all());
        }
        out
    }

    /// All descendant elements with the given name, document order — like
    /// `findall(".//name")`.
    pub fn find_all_descendants(&self, name: &str) -> Vec<&Element> {
        self.iter_all()
            .into_iter()
            .filter(|e| e.name == name)
            .collect()
    }

    /// Direct children with the given name — like `findall("name")`.
    pub fn find_children(&self, name: &str) -> Vec<&Element> {
        self.children.iter().filter(|e| e.name == name).collect()
    }
}

fn decode_entities(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

struct Parser<'a> {
    s: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_misc(&mut self) {
        loop {
            self.skip_ws();
            if self.s[self.pos..].starts_with(b"<?") {
                self.skip_until(b"?>");
            } else if self.s[self.pos..].starts_with(b"<!--") {
                self.skip_until(b"-->");
            } else if self.s[self.pos..].starts_with(b"<!DOCTYPE") {
                self.skip_until(b">");
            } else {
                return;
            }
        }
    }

    fn skip_ws(&mut self) {
        while self.pos < self.s.len() && self.s[self.pos].is_ascii_whitespace() {
            self.pos += 1;
        }
    }

    fn skip_until(&mut self, tok: &[u8]) {
        if let Some(p) = crate::util::find(&self.s[self.pos..], tok) {
            self.pos += p + tok.len();
        } else {
            self.pos = self.s.len();
        }
    }

    /// Collect raw character data up to the next '<' (decoding entities).
    fn text(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.s.len() && self.s[self.pos] != b'<' {
            self.pos += 1;
        }
        decode_entities(&String::from_utf8_lossy(&self.s[start..self.pos]))
    }

    fn name(&mut self) -> String {
        let start = self.pos;
        while self.pos < self.s.len()
            && !self.s[self.pos].is_ascii_whitespace()
            && self.s[self.pos] != b'>'
            && self.s[self.pos] != b'/'
            && self.s[self.pos] != b'='
        {
            self.pos += 1;
        }
        String::from_utf8_lossy(&self.s[start..self.pos]).to_string()
    }

    fn attr_value(&mut self) -> String {
        // assumes current byte is the quote
        let quote = self.s[self.pos];
        self.pos += 1;
        let start = self.pos;
        while self.pos < self.s.len() && self.s[self.pos] != quote {
            self.pos += 1;
        }
        let v = decode_entities(&String::from_utf8_lossy(&self.s[start..self.pos]));
        if self.pos < self.s.len() {
            self.pos += 1; // closing quote
        }
        v
    }

    fn element(&mut self) -> Result<Element, String> {
        self.skip_misc();
        if self.pos >= self.s.len() || self.s[self.pos] != b'<' {
            return Err(format!("expected '<' at offset {}", self.pos));
        }
        self.pos += 1;
        let name = self.name();
        let mut attrs = Vec::new();
        loop {
            self.skip_ws();
            match self.s.get(self.pos) {
                None => return Err("unexpected EOF in tag".to_string()),
                Some(b'/') => {
                    self.pos += 1;
                    if self.s.get(self.pos) == Some(&b'>') {
                        self.pos += 1;
                    }
                    return Ok(Element {
                        name,
                        attrs,
                        children: Vec::new(),
                        text: String::new(),
                    });
                }
                Some(b'>') => {
                    self.pos += 1;
                    break;
                }
                Some(_) => {
                    let aname = self.name();
                    self.skip_ws();
                    if self.s.get(self.pos) == Some(&b'=') {
                        self.pos += 1;
                        self.skip_ws();
                        let value = self.attr_value();
                        attrs.push((aname, value));
                    } else {
                        attrs.push((aname, String::new()));
                    }
                }
            }
        }
        // children and text
        let mut children = Vec::new();
        let mut text = String::new();
        loop {
            if self.pos >= self.s.len() {
                return Err(format!("missing end tag for <{name}>"));
            }
            if self.s[self.pos] == b'<' {
                if self.s[self.pos..].starts_with(b"</") {
                    self.skip_until(b">");
                    return Ok(Element {
                        name,
                        attrs,
                        children,
                        text,
                    });
                }
                self.skip_misc();
                if self.pos >= self.s.len() || self.s[self.pos] != b'<' {
                    continue;
                }
                if self.s[self.pos..].starts_with(b"<![CDATA[") {
                    self.pos += 9;
                    let start = self.pos;
                    if let Some(p) = crate::util::find(&self.s[self.pos..], b"]]>") {
                        text += &String::from_utf8_lossy(&self.s[start..start + p]);
                        self.pos += p + 3;
                    } else {
                        self.pos = self.s.len();
                    }
                    continue;
                }
                let child = self.element()?;
                children.push(child);
            } else {
                text += &self.text();
            }
        }
    }
}

/// Parse an XML document; returns the root element.
pub fn parse(data: &[u8]) -> Result<Element, String> {
    let text = String::from_utf8_lossy(data);
    let mut p = Parser {
        s: text.as_bytes(),
        pos: 0,
    };
    p.skip_misc();
    let root = p.element()?;
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_attributes_and_children() {
        let doc = br#"<?xml version="1.0"?><root a="1" b='x&amp;y'><!-- c --><item>text</item><item self="yes"/></root>"#;
        let root = parse(doc).unwrap();
        assert_eq!(root.name, "root");
        assert_eq!(root.get("b"), Some("x&y"));
        let items = root.find_children("item");
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].text, "text");
        assert_eq!(items[1].get("self"), Some("yes"));
        assert_eq!(root.find_all_descendants("item").len(), 2);
    }
}
