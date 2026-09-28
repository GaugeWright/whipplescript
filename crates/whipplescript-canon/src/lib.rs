//! Syntactic declaration canonicalizers (norm-plane §9, slice C1).
//!
//! Each runs where a cut is minted, on blob content, and needs no analyzable
//! project: a proposal that does not build still gets its identities. Each
//! answers the store's `DeclCanonicalizer` seam for one file class:
//!
//! - identity is kind plus qualified name, reconstructed from the path,
//!   inline nesting and the package directory;
//! - the canonical print drops comments and whitespace, so a reformat and a
//!   comment edit are not changes, and alpha-renames locals wherever their
//!   scoping is resolved exactly, so renaming a local is not a change either;
//! - the rename hash is the print with the unit's own name erased, so a pure
//!   rename, or a move between files with an identical body, is recognisable;
//! - whatever cannot be keyed exactly (macro-generated items, path
//!   attributes, ambient declarations, overloads, duplicate identities,
//!   syntax errors) falls to one `unkeyed` unit for the file rather than
//!   being guessed at. Fuzzy similarity never establishes preservation;
//! - the canonicalizer's version rides in both hashes, so a grammar or
//!   normalizer bump re-keys every unit once, deliberately.

mod alpha;
mod markdown;
mod syntax;

pub use markdown::MarkdownSections;
pub use syntax::{RustItems, TypeScriptItems};

use sha2::{Digest, Sha256};

/// SHA-256/128 over a versioned canonical print, as the store keys content.
pub(crate) fn digest(version: &str, print: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(version.as_bytes());
    hash.update(b"\0");
    hash.update(print.as_bytes());
    hash.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The identity reserved for the units of a file that cannot be keyed.
pub const UNKEYED: &str = "unkeyed";
