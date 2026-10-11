//! LDIF (LDAP Data Interchange Format) hash extractor: records separated by
//! blank lines; each record's `uid`, `userPassword`, `cn` and
//! `homeDirectory` attributes become a Unix-style passwd line:
//!
//! ```text
//! uid:userPassword(or *):<i>:<i>:cn:homeDirectory(or /):/bin/sh
//! ```

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Ldif;

impl Extractor for Ldif {
    fn name(&self) -> &'static str {
        "ldif"
    }

    fn description(&self) -> &'static str {
        "LDIF files (LDAP data interchange format)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"uid:").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let mut out = Vec::new();
        let mut attributes: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut record_number: u32 = 1;

        for raw in util::lines(data) {
            let line = String::from_utf8_lossy(util::rstrip(raw)).to_string();
            if line.is_empty() {
                // blank line: flush the record
                let uid = attributes.get("uid").cloned().unwrap_or_default();
                if !uid.is_empty() {
                    let pw = attributes
                        .get("userPassword")
                        .cloned()
                        .filter(|p| !p.is_empty())
                        .unwrap_or_else(|| "*".to_string());
                    let cn = attributes.get("cn").cloned().unwrap_or_default();
                    let home = attributes
                        .get("homeDirectory")
                        .cloned()
                        .filter(|p| !p.is_empty())
                        .unwrap_or_else(|| "/".to_string());
                    out.push(HashLine::new(
                        uid.clone(),
                        format!("{uid}:{pw}:{record_number}:{record_number}:{cn}:{home}:/bin/sh"),
                    ));
                }
                attributes.clear();
                record_number += 1;
                continue;
            }
            // attributes are "name: value"; a line ending in ":" maps to an
            // empty value
            if let Some((lhs, rhs)) = line.split_once(": ") {
                attributes.insert(lhs.to_string(), rhs.to_string());
            } else if let Some(lhs) = line.strip_suffix(':') {
                attributes.insert(lhs.to_string(), String::new());
            }
        }
        Ok(out)
    }
}
