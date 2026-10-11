//! FileZilla Server.xml hash extractor: emits each user's MD5 hash as a
//! `$dynamic_0$` hash line and each salted SHA-512 hash as a `$dynamic_82$`
//! hash line.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;

pub struct Filezilla;

impl Extractor for Filezilla {
    fn name(&self) -> &'static str {
        "filezilla"
    }

    fn description(&self) -> &'static str {
        "FileZilla Server.xml files"
    }

    fn accepts(&self, input: &Input) -> bool {
        crate::util::find(&input.data, b"<User").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let Ok(root) = crate::xml::parse(&input.data) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for user in root.find_all_descendants("User") {
            let Some(username) = user.get("Name") else {
                continue;
            };
            let mut hash = "";
            let mut salt: Option<&str> = None;
            for option in user.find_children("Option") {
                if option.get("Name") == Some("Pass") {
                    hash = option.text.trim();
                }
                if option.get("Name") == Some("Salt") {
                    salt = Some(option.text.trim());
                }
            }
            if hash.is_empty() {
                continue;
            }
            let hash = hash.to_lowercase();
            if hash.len() == 32 && salt.is_none() {
                out.push(HashLine::new(
                    username.to_string(),
                    format!("{username}:$dynamic_0${hash}"),
                ));
            } else if hash.len() == 128 {
                let Some(salt) = salt else { continue };
                // salt can include ":" characters — hex of its ASCII bytes
                let salt_hex = hex::encode(salt.as_bytes());
                out.push(HashLine::new(
                    username.to_string(),
                    format!("{username}:$dynamic_82${hash}$HEX${salt_hex}"),
                ));
            }
        }
        Ok(out)
    }
}
