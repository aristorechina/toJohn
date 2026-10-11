//! Golden-file test harness: run an extractor on fixture inputs and compare
//! the concatenated output lines with `fixtures/<case>/expected.txt`.

use std::path::PathBuf;

use tojohn::{Extractor, HashLine, Input};

pub fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

/// Build an input from `fixtures/<case>/<file>`; the label is the bare file
/// name, so output lines reference the file name only.
pub fn read_input(case: &str, file: &str) -> Input {
    let dir = fixtures_root().join(case);
    let data = std::fs::read(dir.join(file)).expect("fixture input");
    Input::from_bytes(file, data)
}

/// The golden output of `fixtures/<case>/expected.txt`, normalized to LF.
pub fn expected(case: &str) -> String {
    std::fs::read_to_string(fixtures_root().join(case).join("expected.txt"))
        .expect("expected.txt")
        .replace("\r\n", "\n")
}

fn render(hashes: &[HashLine]) -> String {
    let mut out = String::new();
    for h in hashes {
        out.push_str(&h.line);
        out.push('\n');
    }
    out
}

/// Compare extractor output for a manually constructed input with the golden
/// file of `case`.
pub fn expect_output(case: &str, hashes: &[HashLine]) {
    assert_eq!(
        render(hashes),
        expected(case),
        "golden mismatch for case {case:?}"
    );
}

/// Run `extractor` on each file of fixture case `case` (in the given order)
/// and compare with `fixtures/<case>/expected.txt`.
pub fn golden(extractor: &dyn Extractor, case: &str, files: &[&str]) {
    let mut all: Vec<HashLine> = Vec::new();
    for &file in files {
        let input = read_input(case, file);
        let hashes = extractor
            .extract(&input)
            .unwrap_or_else(|e| panic!("extract({case}, {file}) failed: {e}"));
        all.extend(hashes);
    }
    assert_eq!(
        render(&all),
        expected(case),
        "golden mismatch for case {case:?}"
    );
}
