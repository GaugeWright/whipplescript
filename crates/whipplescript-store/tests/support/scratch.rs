//! A scratch path that no other fixture in this process shares.
//!
//! Every fixture in this crate once named its temporary directory or file
//! after the pid and the wall clock in nanoseconds. The tests in one binary
//! run on parallel threads, and on macOS two of them read the same instant
//! often enough — 18 of 300 runs of one binary — to share a directory: the
//! first to finish removed it from under the other, or the two held
//! connections to one database. `cargo nextest` runs each test in its own
//! process and never saw it; a plain `cargo test` did.
//!
//! The sequence number is what tells two fixtures in one process apart; the
//! pid and the clock keep the name unique across processes and reruns.
//! Nothing is created here: each fixture keeps its own create and remove, so
//! its meaning is unchanged.
//!
//! The unit tests reach this through a `#[path]` module in `lib.rs`, and each
//! integration test binary includes it the same way, so there is one way to
//! name a scratch path and a grep for `process::id()` in test code finds only
//! this file.

#![allow(dead_code)] // a binary uses the shape its fixtures need

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn name(prefix: &str) -> String {
    format!(
        "{prefix}-{}-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    )
}

/// `<temp dir>/<prefix>-<pid>-<sequence>-<nanos>`, for a fixture that owns a
/// directory.
pub fn path(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(name(prefix))
}

/// [`path`] with an extension, for a fixture that is one database or file.
/// Appended rather than set with `with_extension`, which would take a dot in
/// the prefix for the start of the extension.
pub fn file(prefix: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}.{extension}", name(prefix)))
}
