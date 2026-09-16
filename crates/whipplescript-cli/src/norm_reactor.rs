//! Where the tests that need a built norm reactor find it, and what they do
//! when it is not there.
//!
//! `scripts/check.sh` builds the reactor (`experiments/norm-wasi/prepare.py
//! --fetch`) before it runs a single test, and `preparation_checks.py` refuses
//! to continue without it, so the green bar always exercises these for real.
//!
//! A job that runs this package's suite WITHOUT that step does exist: the
//! `new-refusals` sweep runs `cargo test -p whipplescript` on its own, and
//! every reactor test panicked there. That does not make the sweep wrong --
//! its self test correctly refused to read a suite failing for reasons
//! unrelated to any mutation as a verdict about one -- but it made the gate
//! unrunnable for a whole crate.
//!
//! So: absent, these say so and stand down. The reason it is not a vacuous
//! pass is that their absence is impossible where they are the subject: the
//! green bar fails at `prepare.py` long before `cargo test`, which is exactly
//! what happened twice while this was being fixed.

use std::path::PathBuf;

/// The prepared reactor, or `None` after printing why it is missing.
pub fn prepared_reactor() -> Option<PathBuf> {
    let artifact = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/norm-cpython-observer.wasm");
    if artifact.is_file() {
        return Some(artifact);
    }
    eprintln!(
        "norm reactor absent at {}: standing down. `scripts/check.sh` builds it \
         with `experiments/norm-wasi/prepare.py --fetch` and refuses to run \
         without it, so this is a job that did not prepare, not a missing check.",
        artifact.display()
    );
    None
}
