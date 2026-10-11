//! NEO client .db3 wallet parser: reads the SQLite `Key` table and emits a
//! `$dynamic_1608$` line for the `PasswordHash` row.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use rusqlite::Connection;

pub struct Neo;

impl Extractor for Neo {
    fn name(&self) -> &'static str {
        "neo"
    }

    fn description(&self) -> &'static str {
        "NEO .db3 wallet files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"SQLite format 3")
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let tmp = super::applenotes::temp_write(&input.data)?;
        let db = Connection::open_with_flags(&tmp, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut stmt = db.prepare("SELECT * FROM Key")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let key: String = row.get(0)?;
            if key != "PasswordHash" {
                continue;
            }
            let password_hash: Vec<u8> = row.get(1)?;
            let label = util::basename(input.label());
            out.push(HashLine::new(
                label.to_string(),
                format!("{label}:$dynamic_1608${}", hex::encode(password_hash)),
            ));
        }
        Ok(out)
    }
}
