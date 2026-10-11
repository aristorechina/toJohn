//! Apple Notes NoteStore.sqlite parser: reads the encrypted-notes table
//! (ZICCLOUDSYNCINGOBJECT) and emits `$ASN$` lines with iteration count,
//! salt, wrapped key and optional password hint.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use rusqlite::Connection;

pub struct Applenotes;

impl Extractor for Applenotes {
    fn name(&self) -> &'static str {
        "applenotes"
    }

    fn description(&self) -> &'static str {
        "Apple Notes NoteStore.sqlite files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"SQLite format 3")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let tmp = temp_write(&input.data)?;
        let db = Connection::open_with_flags(&tmp, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut stmt = db.prepare(
            "SELECT Z_PK, ZCRYPTOITERATIONCOUNT, ZCRYPTOSALT, ZCRYPTOWRAPPEDKEY, \
             ZPASSWORDHINT, ZCRYPTOVERIFIER, ZISPASSWORDPROTECTED \
             FROM ZICCLOUDSYNCINGOBJECT",
        )?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let row_id: i64 = row.get(0)?;
            let iterations: i64 = row.get(1)?;
            let salt: Vec<u8> = row.get(2)?;
            let wrapped_key: Option<Vec<u8>> = row.get(3)?;
            let hint: Option<String> = row.get(4)?;
            let verifier: Option<Vec<u8>> = row.get(5)?;
            let _is_protected: Option<i64> = row.get(6)?;
            let Some(key) = wrapped_key.or(verifier) else {
                continue;
            };
            if iterations == 0 {
                continue;
            }
            let hint = hint.unwrap_or_else(|| "None".to_string());
            let label = util::basename(input.label());
            out.push(HashLine::new(
                label.to_string(),
                format!(
                    "{label}:$ASN$*{row_id}*{iterations}*{}*{}:::::{hint}",
                    hex::encode(salt),
                    hex::encode(key)
                ),
            ));
        }
        Ok(out)
    }
}

/// rusqlite needs a real file path; write the in-memory DB to a temp file.
pub(crate) fn temp_write(data: &[u8]) -> Result<std::path::PathBuf> {
    let path = std::env::temp_dir().join(format!(
        "tojohn-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::write(&path, data)?;
    Ok(path)
}
