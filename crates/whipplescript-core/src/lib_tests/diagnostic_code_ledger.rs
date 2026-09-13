//! The append-only ledger of every diagnostic code the workspace emits.
//!
//! spec/error-handling.md "### Code Governance" makes codes stable: one may be
//! added, and never renamed or removed once shipped. Nothing enforced that. A
//! rename is a one-line edit in one `diagnostic_code!` literal, every gate stays
//! green, and the code a user's script or a downstream test pinned silently
//! stops existing — which is exactly the failure the append-only rule is for.
//!
//! So the set is pinned in `spec/diagnostic-codes.txt`, and this test compares
//! it against what the sources actually emit. The comparison runs in both
//! directions on purpose:
//!
//! * a code in the ledger that no source emits FAILS — that is a removal or a
//!   rename, and the ledger is the shipped promise;
//! * a code the sources emit that the ledger does not carry FAILS too, but as a
//!   bookkeeping failure with a one-line fix. Adding a code is allowed; adding
//!   it *invisibly* is not, and requiring the ledger line makes every allocation
//!   a reviewable diff line next to the code that allocates it.
//!
//! The emitted set is READ OUT OF THE SOURCES rather than restated here. A
//! hand-written list would be a second copy of the thing under test, and would
//! drift the same way the codes it guards would.
//!
//! Only `whipplescript-core` can host this: it owns `DiagnosticCode`, and the
//! check links against nothing — it reads text — so it does not invert any
//! dependency to see the crates that emit.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// The workspace root: this crate is `<root>/crates/whipplescript-core`.
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<crate> is two levels below the workspace root")
        .to_path_buf()
}

/// Drop `#[cfg(test)]` and `#[cfg(any())]` blocks, so a code that exists only in
/// a test fixture or a retired module is not counted as shipped. A stacked
/// attribute (`#[cfg(test)] #[path = "..."] mod x;`) declares a single item and
/// is skipped without dropping the rest of the file; only an item whose line
/// ends in `{` opens a block, which then runs to the next `}` at column zero.
fn strip_inactive_blocks(source: &str) -> String {
    const ATTRIBUTES: [&str; 2] = ["#[cfg(test)]", "#[cfg(any())]"];
    let lines: Vec<&str> = source.lines().collect();
    let mut kept = String::new();
    let mut index = 0usize;
    let mut skipping = false;
    while index < lines.len() {
        let line = lines[index];
        if !skipping && ATTRIBUTES.contains(&line) {
            let mut item = index + 1;
            while item < lines.len()
                && (lines[item].trim().is_empty() || lines[item].starts_with("#["))
            {
                item += 1;
            }
            skipping = item < lines.len() && lines[item].trim_end().ends_with('{');
            index = item + 1;
            continue;
        }
        if skipping {
            if line == "}" {
                skipping = false;
            }
            index += 1;
            continue;
        }
        kept.push_str(line);
        kept.push('\n');
        index += 1;
    }
    kept
}

/// Every `<macro>!("…")` literal in `text`.
///
/// Whitespace between `!(` and the literal is skipped: `cargo fmt` breaks a long
/// invocation across lines, and a scanner that matched only `!("` would miss
/// exactly the call sites whose arguments are longest — which is how a code can
/// go unregistered while every scan reports a clean set.
fn codes_in(text: &str, macro_name: &str) -> Vec<String> {
    let open = format!("{macro_name}!(");
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(&open) {
        rest = &rest[at + open.len()..];
        let literal = rest.trim_start();
        let Some(literal) = literal.strip_prefix('"') else {
            continue;
        };
        match literal.find('"') {
            Some(end) => {
                found.push(literal[..end].to_owned());
                rest = &literal[end..];
            }
            None => break,
        }
    }
    found
}

/// The two macro names overlap — `runtime_diagnostic_code!` ENDS in
/// `diagnostic_code!` — so a naive scan for the check plane claims every runtime
/// literal as its own. Take the runtime literals first and blank the invocation
/// out before the check scan runs.
fn planes_in(text: &str) -> (Vec<String>, Vec<String>) {
    let runtime = codes_in(text, "runtime_diagnostic_code");
    let masked = text.replace("runtime_diagnostic_code!(", "RUNTIME_TAKEN(");
    (codes_in(&masked, "diagnostic_code"), runtime)
}

fn rust_sources_under(directory: &Path, into: &mut Vec<PathBuf>) {
    // A `*_tests` directory holds fixtures, not shipped producers.
    if directory.file_name().is_some_and(|name| {
        name.to_str()
            .is_some_and(|name| name.ends_with("_tests") || name == "tests")
    }) {
        return;
    }
    let mut entries: Vec<PathBuf> = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        .map(|entry| entry.expect("directory entry").path())
        .collect();
    entries.sort();
    for entry in entries {
        if entry.is_dir() {
            rust_sources_under(&entry, into);
        } else if entry.extension().is_some_and(|extension| extension == "rs")
            && !entry
                .file_stem()
                .is_some_and(|stem| stem.to_str().is_some_and(|s| s.ends_with("_tests")))
        {
            into.push(entry);
        }
    }
}

/// The codes the workspace's shipped code actually emits, by plane.
fn emitted_codes_by_plane() -> (BTreeSet<String>, BTreeSet<String>) {
    let root = workspace_root();
    let mut crates: Vec<PathBuf> = fs::read_dir(root.join("crates"))
        .expect("crates/ is readable")
        .map(|entry| entry.expect("crate entry").path())
        .collect();
    crates.sort();
    let mut sources = Vec::new();
    for crate_dir in crates {
        let src = crate_dir.join("src");
        if src.is_dir() {
            rust_sources_under(&src, &mut sources);
        }
    }
    assert!(
        sources.len() > 100,
        "found only {} source files — the scan is not seeing the workspace, and an \
         empty scan would report every shipped code as removed",
        sources.len()
    );
    let mut check = BTreeSet::new();
    let mut runtime = BTreeSet::new();
    for path in sources {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let (check_codes, runtime_codes) = planes_in(&strip_inactive_blocks(&source));
        check.extend(check_codes);
        runtime.extend(runtime_codes);
    }
    (check, runtime)
}

fn emitted_codes() -> BTreeSet<String> {
    emitted_codes_by_plane().0
}

const LEDGER: &str = "spec/diagnostic-codes.txt";
const RUNTIME_LEDGER: &str = "spec/diagnostic-codes-runtime.txt";
const REGISTER: &str = "crates/whipplescript-core/src/diagnostic_code_register.rs";

/// The ledger's content lines: `#` comments and blanks are not entries.
fn ledger_lines(ledger: &str) -> Vec<String> {
    let path = workspace_root().join(ledger);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// A ledger entry: the code, and — on the check plane — its coverage marker.
fn ledger_entries(ledger: &str) -> Vec<(String, Option<String>)> {
    ledger_lines(ledger)
        .into_iter()
        .map(|line| match line.split_once(' ') {
            Some((code, marker)) => (code.to_owned(), Some(marker.trim().to_owned())),
            None => (line, None),
        })
        .collect()
}

fn ledger_codes() -> BTreeSet<String> {
    ledger_entries(LEDGER)
        .into_iter()
        .map(|(code, _)| code)
        .collect()
}

/// A shipped code must not stop being emitted, and a new one must arrive with a
/// ledger line naming it.
#[test]
fn the_emitted_codes_are_exactly_the_ledger() {
    let emitted = emitted_codes();
    let ledger = ledger_codes();

    let removed: Vec<&String> = ledger.difference(&emitted).collect();
    assert!(
        removed.is_empty(),
        "these codes are in {LEDGER} but nothing emits them any more: {removed:?}\n\
         Codes are append-only (spec/error-handling.md \"### Code Governance\"). If a \
         diagnostic was renamed, keep the old code as an alias; if a producer was \
         deleted, the code still may not leave the ledger."
    );

    let added: Vec<&String> = emitted.difference(&ledger).collect();
    assert!(
        added.is_empty(),
        "these codes are emitted but absent from {LEDGER}: {added:?}\n\
         Allocating a code is allowed and allocating one invisibly is not — add each \
         line to the ledger (sorted, one per line) in the same commit."
    );
}

/// The ledger is a set, sorted, so a diff against it reads as an allocation
/// rather than as a reordering.
#[test]
fn the_ledger_is_sorted_and_free_of_duplicates() {
    for ledger in [LEDGER, RUNTIME_LEDGER] {
        let lines = ledger_lines(ledger);
        let mut sorted = lines.clone();
        sorted.sort_unstable();
        assert_eq!(lines, sorted, "{ledger} is not sorted");
        let codes: Vec<&str> = lines
            .iter()
            .map(|line| line.split(' ').next().unwrap_or(line))
            .collect();
        let unique: BTreeSet<&&str> = codes.iter().collect();
        assert_eq!(unique.len(), codes.len(), "{ledger} repeats a code");
    }
}

/// Every check-plane entry carries a coverage marker, and it is one of the two
/// the governance rule knows.
///
/// The marker's VALUE is measured by `scripts/regen-diagnostic-codes.sh`, which
/// runs the compiler over the corpus; this test only pins that the column is
/// there and well formed, since a test that links against nothing cannot run a
/// binary over `examples/`.
#[test]
fn every_ledger_entry_carries_a_coverage_marker() {
    for (code, marker) in ledger_entries(LEDGER) {
        let marker = marker.unwrap_or_else(|| {
            panic!(
                "`{code}` in {LEDGER} has no coverage marker — every entry is \
                 `<code> COVERED` or `<code> PROVISIONAL`; run \
                 scripts/regen-diagnostic-codes.sh"
            )
        });
        assert!(
            marker == "COVERED" || marker == "PROVISIONAL",
            "`{code}` in {LEDGER} is marked `{marker}`, which is neither COVERED nor \
             PROVISIONAL"
        );
    }
    // The runtime plane has no corpus to measure against, so it carries no
    // marker at all rather than an unmeasured one.
    for (code, marker) in ledger_entries(RUNTIME_LEDGER) {
        assert!(
            marker.is_none(),
            "`{code}` in {RUNTIME_LEDGER} carries a coverage marker, but nothing \
             measures runtime-plane coverage"
        );
    }
}

/// The register the macros INDEX is the ledger.
///
/// This is what makes the register load-bearing rather than advisory.
/// `DiagnosticCode` has no constructor, so the only codes that exist are the
/// entries of `DIAGNOSTIC_CODES`; if that array and the ledger could disagree,
/// the ledger would be describing a set the compiler does not use.
#[test]
fn the_register_arrays_are_the_ledgers() {
    let register: Vec<&str> = crate::DIAGNOSTIC_CODES
        .iter()
        .map(|code| code.as_str())
        .collect();
    let ledger: Vec<String> = ledger_entries(LEDGER)
        .into_iter()
        .map(|(code, _)| code)
        .collect();
    assert_eq!(
        register,
        ledger.iter().map(String::as_str).collect::<Vec<_>>(),
        "{REGISTER} and {LEDGER} disagree — run scripts/regen-diagnostic-codes.sh"
    );

    let runtime_register: Vec<&str> = crate::RUNTIME_DIAGNOSTIC_CODES
        .iter()
        .map(|code| code.as_str())
        .collect();
    let runtime_ledger = ledger_lines(RUNTIME_LEDGER);
    assert_eq!(
        runtime_register,
        runtime_ledger
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        "{REGISTER} and {RUNTIME_LEDGER} disagree — run scripts/regen-diagnostic-codes.sh"
    );
}

/// The runtime plane gets the same both-directions comparison as the check
/// plane: a runtime code may not stop being emitted, and a new one may not
/// arrive without its ledger line.
#[test]
fn the_emitted_runtime_codes_are_exactly_the_runtime_ledger() {
    let emitted: BTreeSet<String> = emitted_codes_by_plane().1;
    let ledger: BTreeSet<String> = ledger_lines(RUNTIME_LEDGER).into_iter().collect();

    let removed: Vec<&String> = ledger.difference(&emitted).collect();
    assert!(
        removed.is_empty(),
        "these codes are in {RUNTIME_LEDGER} but nothing emits them any more: {removed:?}"
    );
    let added: Vec<&String> = emitted.difference(&ledger).collect();
    assert!(
        added.is_empty(),
        "these runtime codes are emitted but absent from {RUNTIME_LEDGER}: {added:?}"
    );
}

/// Every ledger entry is a code the shape rule accepts — applied to the ledger
/// so a hand-edit cannot introduce an entry no producer could ever have written.
///
/// It asks `DiagnosticCode::validate` rather than restating the rule, because a
/// restatement is a second copy of the thing under test.
#[test]
fn every_ledger_code_is_well_formed_and_in_a_reserved_namespace() {
    for code in ledger_codes() {
        if let Err(fault) = crate::DiagnosticCode::validate(&code) {
            panic!("`{code}` in {LEDGER}: {}", fault.description());
        }
    }
    for code in ledger_lines(RUNTIME_LEDGER) {
        if let Err(fault) = crate::RuntimeDiagnosticCode::validate(&code) {
            panic!("`{code}` in {RUNTIME_LEDGER}: {}", fault.description());
        }
    }
}

const SPEC: &str = "spec/error-handling.md";

/// The backticked names of the spec sentence that starts at `marker` and ends at
/// the first `.` after it.
///
/// The prose is READ rather than restated, for the same reason the emitted codes
/// are read out of the sources: a restatement here would be a second copy of the
/// thing under test, free to drift exactly as the list it guards would.
fn reserved_namespaces_in_spec(marker: &str) -> BTreeSet<String> {
    let path = workspace_root().join(SPEC);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    assert_eq!(
        text.matches(marker).count(),
        1,
        "`{marker}` must name exactly one sentence in {SPEC}"
    );
    let (_, rest) = text
        .split_once(marker)
        .expect("the marker was just counted in the text");
    let sentence = rest.split_once('.').map_or(rest, |(sentence, _)| sentence);
    let names: BTreeSet<String> = sentence
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect();
    assert!(
        names.len() > 5,
        "read only {names:?} out of the `{marker}` sentence in {SPEC}"
    );
    names
}

fn reserved(list: &[&str]) -> BTreeSet<String> {
    list.iter().map(|name| (*name).to_owned()).collect()
}

/// Whether this tree is the published projection, which withholds `SPEC`.
///
/// `scripts/check.sh` runs `cargo test --workspace` on BOTH repositories, and
/// the mirror is default-deny: of `spec/` it publishes the report schemas, the
/// host contract JSONs and the three code registers, never the prose. So a test
/// that reads the prose has to say the absent case out loud instead of dying on
/// it — the precedent is `scripts/check-report-schemas.sh`'s `spec/reporting.md`
/// skip, whose absence killed the mirror's green bar on every sync until it was
/// written.
///
/// The absence has to be PROVED to be the projection, or deleting the document
/// in whipplescript-src would quietly retire this check instead of failing it.
/// `AGENTS.md` is withheld from the mirror too, and is the guard `check.sh`
/// itself uses for its -src-only blocks: absent beside `SPEC` it is the
/// projection, present beside a missing `SPEC` it is an -src tree that has lost
/// a document this test requires.
fn spec_is_withheld_by_the_projection() -> bool {
    let root = workspace_root();
    if root.join(SPEC).exists() {
        return false;
    }
    assert!(
        !root.join("AGENTS.md").exists(),
        "{SPEC} is required in this tree and is not there: AGENTS.md is present, \
         so this is whipplescript-src rather than the published projection, and \
         the two reserved-namespace sentences this test reads against \
         DIAGNOSTIC_NAMESPACES and RUNTIME_DIAGNOSTIC_NAMESPACES are gone"
    );
    eprintln!(
        "skipped: {SPEC} is not in this tree, so the reserved-namespace sentences \
         cannot be read here. The mirror withholds spec/ prose by design; this \
         assertion belongs to whipplescript-src, where the document lives."
    );
    true
}

/// The namespaces the compiler reserves are the ones the spec reserves.
///
/// Both constants say in their doc comments that the list is the spec's and not
/// the module's, and nothing checked it:
/// `every_ledger_code_is_well_formed_and_in_a_reserved_namespace` validates the
/// ledger against the CODE's list, so a namespace that reaches the code and
/// never the prose drifts indefinitely under a green gate. `instance` did,
/// from the run-wide `instance.step_budget.parked` (DR-0082) until this test.
#[test]
fn the_reserved_namespaces_are_the_ones_the_spec_reserves() {
    if spec_is_withheld_by_the_projection() {
        return;
    }
    assert_eq!(
        reserved_namespaces_in_spec("reserved top-level namespaces are:"),
        reserved(crate::DIAGNOSTIC_NAMESPACES),
        "{SPEC} \"## Codes\" and DIAGNOSTIC_NAMESPACES reserve different check-plane \
         namespaces; spec/ is canonical, so the prose says what is reserved and the \
         constant follows it"
    );
    assert_eq!(
        reserved_namespaces_in_spec("own reserved namespaces:"),
        reserved(crate::RUNTIME_DIAGNOSTIC_NAMESPACES),
        "{SPEC} \"### Runtime Plane Codes\" and RUNTIME_DIAGNOSTIC_NAMESPACES reserve \
         different runtime-plane namespaces; spec/ is canonical, so the prose says what \
         is reserved and the constant follows it"
    );
}
