use crate::error::Result;
use crate::hash::HashLine;
use crate::input::Input;

/// One supported hash-extraction format.
pub trait Extractor: Send + Sync {
    /// Canonical short name used by the CLI's `--format` flag.
    fn name(&self) -> &'static str;

    /// Human-readable one-liner shown by `tojohn --list-formats`.
    fn description(&self) -> &'static str;

    /// Best-effort content sniffing used by the CLI's automatic format
    /// detection. Must be cheap and must not read the file again.
    fn accepts(&self, input: &Input) -> bool;

    /// Extract all hashes from `input`, one hash-line string per
    /// crackable secret.
    fn extract(&self, input: &Input) -> Result<Vec<HashLine>>;
}
