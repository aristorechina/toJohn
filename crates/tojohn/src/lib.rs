//! `tojohn` — hash-extraction toolkit: pulls crackable password hashes out
//! of 100+ file formats (archives, databases, disk images, key stores,
//! network captures, ...) and renders them as crackable hash-line strings,
//! one per secret.
//!
//! Every supported format lives in [`formats`] as one [`Extractor`]. Hex
//! encoding is lowercase throughout (like `binascii.hexlify`).

pub mod asn1;
pub mod error;
pub mod extractor;
pub mod formats;
pub mod hash;
pub mod input;
pub mod ole;
pub mod pcap;
pub mod registry;
pub mod util;
pub mod xml;
pub mod zip;

pub use error::{Error, Result};
pub use extractor::Extractor;
pub use hash::HashLine;
pub use input::Input;
