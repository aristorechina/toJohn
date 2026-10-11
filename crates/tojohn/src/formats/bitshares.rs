//! BitShares wallet parser with three paths: `.ldb` LevelDB files (checked
//! first via the `checksum` marker, emitted as `$dynamic_84$` lines), SQLite
//! wallet databases (`$BitShares$0*`), and raw backup files (hex of the
//! whole file, `$BitShares$1*`). When the `checksum` marker is absent, the
//! SQLite/backup paths apply.

use crate::error::Result;
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;
use rusqlite::Connection;

pub struct Bitshares;

impl Extractor for Bitshares {
    fn name(&self) -> &'static str {
        "bitshares"
    }

    fn description(&self) -> &'static str {
        "BitShares .ldb / SQLite / backup wallet files"
    }

    fn accepts(&self, input: &Input) -> bool {
        input.data.starts_with(b"SQLite format 3") || util::find(&input.data, b"checksum").is_some()
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        // LevelDB (.ldb) path, checked first
        if let Some(idx) = util::find(data, b"checksum") {
            let start = idx + "checksum".len() + 3;
            let end = (start + 64 * 2).min(data.len());
            let label = util::basename(input.label());
            return Ok(vec![HashLine::new(
                label.to_string(),
                format!(
                    "{label}:$dynamic_84${}",
                    String::from_utf8_lossy(&data[start..end])
                ),
            )]);
        }

        // SQLite wallet path
        if data.starts_with(b"SQLite format 3") {
            let tmp = super::applenotes::temp_write(data)?;
            if let Ok(db) =
                Connection::open_with_flags(&tmp, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            {
                if let Ok(mut stmt) = db.prepare("SELECT key, value from wallet") {
                    if let Ok(mut rows) = stmt.query([]) {
                        let mut out = Vec::new();
                        while let Ok(Some(row)) = rows.next() {
                            let name: String = row.get(0)?;
                            let value: String = row.get(1)?;
                            let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&value)
                            else {
                                continue;
                            };
                            let Some(encryption_key) =
                                parsed.get("encryption_key").and_then(|v| v.as_str())
                            else {
                                continue;
                            };
                            out.push(HashLine::new(
                                name.clone(),
                                format!("{name}:$BitShares$0*{encryption_key}"),
                            ));
                        }
                        if !out.is_empty() {
                            return Ok(out);
                        }
                    }
                }
            }
        }

        // backup-file path: hex of the whole file
        let label = util::basename(input.label());
        Ok(vec![HashLine::new(
            label.to_string(),
            format!("{label}:$BitShares$1*{}", hex::encode(data)),
        )])
    }
}
