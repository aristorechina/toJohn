//! SAP password hash table parser. Input: TAB-separated spreadsheet export
//! of the SAP tables USR02 / USH02 / USRPWDHISTORY (column headers from
//! field names). The first line containing a TAB is the header row; column
//! positions are detected by name (BNAME, BCODE, CODVN, PASSCODE,
//! PWDSALTEDHASH, OCOD1..5, CODV1..5).
//!
//! Hash type selection (`[A|B|D|E|F|H]`, via `input.extra_args[0]`,
//! default "BFH"):
//! - B: BCODE (with CODVN ""/G/I treated as B) → `user:user$<bcode>`
//! - F: PASSCODE → `user:user$<passcode>` (skipping all-zero values)
//! - H: PWDSALTEDHASH → `user:<saltedhash>`
//! - A/D/E: legacy OCOD1..5 columns, emitted like B
//!
//! Emission order per row: BCODE first, then OCOD1..5, PASSCODE,
//! PWDSALTEDHASH — ordered so the easiest format is detected first.

use crate::error::{Error, Result};
use crate::extractor::Extractor;
use crate::hash::HashLine;
use crate::input::Input;
use crate::util;

pub struct Sap;

impl Extractor for Sap {
    fn name(&self) -> &'static str {
        "sap"
    }

    fn description(&self) -> &'static str {
        "SAP USR02/USH02/USRPWDHISTORY TSV table exports (codvn filter via extra arg)"
    }

    fn accepts(&self, input: &Input) -> bool {
        util::find(&input.data, b"BNAME").is_some()
            && (util::find(&input.data, b"BCODE").is_some()
                || util::find(&input.data, b"PASSCODE").is_some()
                || util::find(&input.data, b"PWDSALTEDHASH").is_some())
    }

    fn extract(&self, input: &Input) -> Result<Vec<HashLine>> {
        let data = &input.data;
        let hash_types = input.extra_args.first().cloned().unwrap_or_default();
        if let Some(arg) = input.extra_args.first() {
            if arg.len() == 1 && !matches!(arg.as_str(), "A" | "B" | "D" | "E" | "F" | "H") {
                return Err(Error::other(format!(
                    "invalid optional parameter: \"{arg}\""
                )));
            }
        }

        // find the header row: first line containing a TAB
        let text = String::from_utf8_lossy(data);
        let mut lines = text.split('\n');
        let mut header_line: Option<&str> = None;
        for line in lines.by_ref() {
            if line.contains('\t') {
                header_line = Some(line.trim_end_matches('\r'));
                break;
            }
        }
        let Some(header) = header_line else {
            return Err(Error::other("no password hash columns found"));
        };
        let columns: Vec<&str> = split_tsv(header);
        let pos = |name: &str| columns.iter().position(|column| column.contains(name));

        let pos_bname = pos("BNAME");
        let pos_bcode = pos("BCODE");
        let pos_codvn = pos("CODVN");
        let pos_passcode = pos("PASSCODE");
        let pos_pwdsaltedhash = pos("PWDSALTEDHASH");
        let legacy_columns: Vec<(Option<usize>, Option<usize>)> = (1..=5)
            .map(|n| (pos(&format!("OCOD{n}")), pos(&format!("CODV{n}"))))
            .collect();

        // required-column validation
        if pos_bcode.is_none() && legacy_columns.iter().all(|(ocod, _)| ocod.is_none()) {
            if pos_passcode.is_none() && pos_pwdsaltedhash.is_none() {
                return Err(Error::other("no password hash columns found"));
            }
            if matches!(hash_types.as_str(), "B" | "E" | "D" | "A") {
                return Err(Error::other(
                    "CODVN B, E, D, or A requested, but column BCODE/OCODV[1-5] not found",
                ));
            }
        }
        if pos_bname.is_none() && pos_pwdsaltedhash.is_none() {
            return Err(Error::other(
                "no BNAME column found, but required as salt for BCODE and PASSCODE",
            ));
        }
        if pos_passcode.is_none() && hash_types.contains('F') {
            return Err(Error::other(
                "CODVN F requested, but column PASSCODE not found",
            ));
        }
        if pos_pwdsaltedhash.is_none() && hash_types.contains('H') {
            return Err(Error::other(
                "CODVN H requested, but column PWDSALTEDHASH not found",
            ));
        }

        // default + column-based pruning
        let mut hash_types = if hash_types.is_empty() {
            "BFH".to_string()
        } else {
            hash_types
        };
        if pos_bname.is_none() {
            hash_types = hash_types
                .chars()
                .filter(|c| !matches!(c, 'A' | 'B' | 'D' | 'E' | 'F'))
                .collect();
        }
        if pos_pwdsaltedhash.is_none() {
            hash_types = hash_types.chars().filter(|&c| c != 'H').collect();
        }
        if hash_types.is_empty() {
            return Err(Error::other(
                "not all required columns for requested hash types found",
            ));
        }

        // data rows
        let mut rows: Vec<Vec<String>> = Vec::new();
        for line in lines {
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            let fields: Vec<String> = split_tsv(line)
                .into_iter()
                .map(|field| field.trim_end().to_string())
                .collect();
            rows.push(fields);
        }

        let field = |row: &[String], column: Option<usize>| -> String {
            match column {
                Some(index) if index < row.len() => row[index].clone(),
                _ => String::new(),
            }
        };

        let mut out = Vec::new();
        for row in &rows {
            let bname = field(row, pos_bname);
            let codvn = field(row, pos_codvn);
            // BCODE first (easiest to crack detected first)
            if hash_types
                .chars()
                .any(|c| matches!(c, 'A' | 'B' | 'D' | 'E'))
            {
                let bcodes = std::iter::once(field(row, pos_bcode))
                    .chain(legacy_columns.iter().map(|(ocod, _)| field(row, *ocod)));
                let codvns = std::iter::once(codvn)
                    .chain(legacy_columns.iter().map(|(_, codv)| field(row, *codv)));
                for (bcode, value) in bcodes.zip(codvns) {
                    // CODVN ""/G/I is hashed like B
                    let effective = if value.is_empty() || value == "G" || value == "I" {
                        "B"
                    } else {
                        value.as_str()
                    };
                    if hash_types.contains(effective)
                        && !bcode.is_empty()
                        && bcode != "0000000000000000"
                    {
                        out.push(HashLine::new(
                            bname.clone(),
                            format!("{bname}:{bname}${bcode}"),
                        ));
                    }
                }
            }
            if hash_types.contains('F') && pos_passcode.is_some() {
                let passcode = field(row, pos_passcode);
                if !passcode.is_empty() && passcode != "0000000000000000000000000000000000000000" {
                    out.push(HashLine::new(
                        bname.clone(),
                        format!("{bname}:{bname}${passcode}"),
                    ));
                }
            }
            if hash_types.contains('H') && pos_pwdsaltedhash.is_some() {
                let h = field(row, pos_pwdsaltedhash);
                if !h.is_empty() {
                    out.push(HashLine::new(bname.clone(), format!("{bname}:{h}")));
                }
            }
        }
        Ok(out)
    }
}

/// Split on TAB.
fn split_tsv(line: &str) -> Vec<&str> {
    line.split('\t').collect()
}
