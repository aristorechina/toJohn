use std::path::Path;

/// A named secondary file input (e.g. the `.ecryptfsrc` of the ecryptfs format).
#[derive(Debug, Clone)]
pub struct ExtraFile {
    pub label: String,
    pub data: Vec<u8>,
}

/// Input handed to an [`Extractor`](crate::Extractor).
#[derive(Debug, Clone)]
pub struct Input {
    label: String,
    /// Raw file bytes (for text formats this is the undecoded file content).
    pub data: Vec<u8>,
    /// Decoded text for string-input formats (e.g. an inline ansible-vault value).
    pub text: Option<String>,
    /// Secondary file inputs for formats that take more than one file.
    pub extra_files: Vec<ExtraFile>,
    /// Positional string arguments for formats that take them
    /// (e.g. ikescan's optional norteluser).
    pub extra_args: Vec<String>,
}

impl Input {
    /// Read `path` from disk. The label is the path exactly as given;
    /// formats echo it into their output lines.
    pub fn from_path(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read(path)?;
        Ok(Self {
            label: path.display().to_string(),
            data,
            text: None,
            extra_files: Vec::new(),
            extra_args: Vec::new(),
        })
    }

    /// Build an input from in-memory bytes with an explicit label.
    pub fn from_bytes(label: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            label: label.into(),
            data,
            text: None,
            extra_files: Vec::new(),
            extra_args: Vec::new(),
        }
    }

    /// Build a string-only input for formats that take text rather than files.
    pub fn from_text(text: impl Into<String>) -> Self {
        let text = text.into();
        Self {
            label: "<text>".to_string(),
            data: text.as_bytes().to_vec(),
            text: Some(text),
            extra_files: Vec::new(),
            extra_args: Vec::new(),
        }
    }

    /// The label echoed into output lines by most formats.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Replace the label (used by formats whose output label differs from the
    /// input path, e.g. sspr where the label is the LDAP DN).
    pub fn label_override(&mut self, label: impl Into<String>) {
        self.label = label.into();
    }
}
