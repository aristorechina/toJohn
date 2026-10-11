/// One extracted hash line plus its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashLine {
    /// First field of the output line (file name / user name / ...).
    pub label: String,
    /// The complete output line, without trailing newline.
    pub line: String,
}

impl HashLine {
    pub fn new(label: impl Into<String>, line: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            line: line.into(),
        }
    }

    /// Entry with an empty label (single-line outputs, e.g. the zip formats).
    pub fn new_empty(line: impl Into<String>) -> Self {
        Self {
            label: String::new(),
            line: line.into(),
        }
    }

    /// Build from a complete output line whose label is the first field
    /// before the first `:`.
    pub fn from_line(line: impl Into<String>) -> Self {
        let line = line.into();
        let label = line.split(':').next().unwrap_or("").to_string();
        Self { label, line }
    }
}
