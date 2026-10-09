//! Recover function boundaries from ELF binaries using their `.eh_frame`
//! unwind tables.
//!
//! Stripping a binary removes `.symtab`, but it cannot remove `.eh_frame`:
//! C++ exceptions, Rust panics, backtraces and debuggers all need it at run
//! time. Every Frame Description Entry (FDE) in that table records the exact
//! `[start, end)` range of one function, so walking the table gives a near
//! complete function map of a stripped binary without any disassembly
//! heuristics.
//!
//! ```no_run
//! let bytes = std::fs::read("/usr/bin/ls").unwrap();
//! let report = unwind_map::analysis::analyze(&bytes, &Default::default()).unwrap();
//! for f in &report.functions {
//!     println!("{:#x}..{:#x} {}", f.start, f.end, f.name);
//! }
//! ```

use std::fmt;

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err($crate::Error::new(format!($($arg)*)))
    };
}

pub mod analysis;
pub mod ehframe;
pub mod elf;
mod map;
pub mod output;
mod padding;
mod reader;

/// Error type for every fallible operation in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    pub(crate) fn new(msg: impl Into<String>) -> Self {
        Error(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
