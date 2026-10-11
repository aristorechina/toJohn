use std::path::Path;

/// Convenient result alias used throughout `tojohn`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced while extracting hashes.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The input is readable but is not a file of the expected format.
    #[error("{file}: not a {format} file")]
    NotFormat { format: &'static str, file: String },
    /// The input starts out as the expected format but is structurally broken.
    #[error("{file}: {message}")]
    Malformed { file: String, message: String },
    #[error("{0}")]
    Other(String),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
}

impl Error {
    pub fn not_format(format: &'static str, file: impl AsRef<Path>) -> Self {
        Self::NotFormat {
            format,
            file: file.as_ref().display().to_string(),
        }
    }

    pub fn malformed(file: &str, message: impl Into<String>) -> Self {
        Self::Malformed {
            file: file.to_string(),
            message: message.into(),
        }
    }

    pub fn other(message: impl Into<String>) -> Self {
        Self::Other(message.into())
    }
}
