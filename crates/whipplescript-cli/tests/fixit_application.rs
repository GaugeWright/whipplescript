//! Fixits, measured on the surface a consumer actually reads.
//!
//! `spec/error-handling.md` "Suggestions And Fixits" separates a suggestion — a
//! sentence a person judges — from a fixit, which an editor applies on a
//! keystroke and a `--fix` applies with nobody watching. Everything here is
//! about the second kind, and everything here runs the real binary:
//! `whip check --json` is the path a consumer gets, and it is the only path that
//! shows EVERY plane. The parser crate's
//! `fixits_repair_the_program_over_the_example_corpus` measures the same
//! property one plane up, where `graph.unreachable_terminal` and the whole
//! information-flow checker do not exist — which is precisely how a false claim
//! about this property survived a green test.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;
use whipplescript_parser::{Applicability, Fixit, FixitEdit, SourceSpan};

/// `whip check --json <paths>` — stdout parsed as the report array.
///
/// The exit status is deliberately ignored: every interesting program here
/// fails to check, which is why it carries a fixit at all.
fn check_json(paths: &[PathBuf]) -> Vec<Value> {
    let output = Command::new(env!("CARGO_BIN_EXE_whip"))
        .arg("check")
        .arg("--json")
        .args(paths)
        .output()
        .expect("whip check runs");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    serde_json::from_str::<Value>(&stdout)
        .unwrap_or_else(|error| panic!("check report is not JSON ({error}): {stdout}"))
        .as_array()
        .expect("check report is an array")
        .clone()
}

/// The diagnostics of a one-file report, or an empty list when the file checked
/// clean.
fn report_diagnostics(report: &Value) -> Vec<Value> {
    report
        .get("error")
        .and_then(|error| error.get("diagnostics"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn span_of(value: &Value) -> SourceSpan {
    let field = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("span has `{name}`: {value}")) as usize
    };
    SourceSpan {
        start: field("start"),
        end: field("end"),
    }
}

/// The reported fixits of one diagnostic, back in the compiler's own type — so
/// applying them here goes through `Fixit::apply_to`, the ONE applier, rather
/// than a second implementation that could disagree with it.
fn fixits_of(diagnostic: &Value) -> Vec<Fixit> {
    diagnostic
        .get("fixits")
        .and_then(Value::as_array)
        .map(|fixits| {
            fixits
                .iter()
                .map(|fixit| Fixit {
                    title: fixit
                        .get("title")
                        .and_then(Value::as_str)
                        .expect("fixit has a title")
                        .to_owned(),
                    applicability: match fixit.get("applicability").and_then(Value::as_str) {
                        Some("exact") => Applicability::Exact,
                        Some("likely") => Applicability::Likely,
                        other => panic!("unknown applicability {other:?}"),
                    },
                    edits: fixit
                        .get("edits")
                        .and_then(Value::as_array)
                        .expect("fixit has edits")
                        .iter()
                        .map(|edit| FixitEdit {
                            span: span_of(edit.get("source_span").expect("edit has a span")),
                            replacement: edit
                                .get("replacement")
                                .and_then(Value::as_str)
                                .expect("edit has a replacement")
                                .to_owned(),
                        })
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A temp directory removed when the binding drops, panic included.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn temp_dir(tag: &str) -> TempDir {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_nanos();
    let path =
        std::env::temp_dir().join(format!("whip-fixit-{tag}-{stamp}-{}", std::process::id()));
    fs::create_dir_all(&path).expect("temp directory is created");
    TempDir(path)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

// ---------------------------------------------------------------------------
// A fixit's offsets are in the coordinates of the file the report NAMES.
// ---------------------------------------------------------------------------

/// The library file both include tests share: one class, no workflow.
const LIBRARY: &str =
    "class SupportTicket {\n  id string\n  summary string\n  severity string\n}\n";

/// THE `include` DEFECT. `resolve_source_bundle` concatenates the included
/// sources and appends the file's own text AFTER them, so every span leaving the
/// compiler is an offset into that bundle. The primary and related spans are
/// rebased before rendering; a fixit's edits were handed over raw, and a fixit
/// is the one thing here nobody reads before applying.
///
/// This is the shape that broke: the root file is 251 bytes, its typo sits at
/// bundle offset 309, and an editor told to replace bytes 309..316 of a
/// 251-byte file either fails or — with a longer file — rewrites the wrong
/// bytes. So the test does what a consumer does: it reads the file the report
/// NAMES, applies the edits the report gave it, and demands the result be the
/// repaired program.
#[test]
fn a_fixit_applies_to_the_file_the_report_names() {
    let dir = temp_dir("include-root");
    fs::write(dir.0.join("lib.whip"), LIBRARY).expect("library is written");
    let root = dir.0.join("root.whip");
    let source = "include \"lib.whip\"\n\nworkflow TriageTickets\n\ninput ticket SupportTicket\noutput result TriageResult\n\nclass TriageResult {\n  id string\n  queue string\n}\n\nrule triage\n  when SupportTicket as t\n=> {\n  complete result {\n    id t.id\n    queue t.severty\n  }\n}\n";
    fs::write(&root, source).expect("root is written");

    let reports = check_json(std::slice::from_ref(&root));
    let report = reports.first().expect("one report");
    let named = report
        .get("path")
        .and_then(Value::as_str)
        .expect("the report names a file");
    let named_source = fs::read_to_string(named).expect("the named file is readable");

    let mut applied = 0usize;
    for diagnostic in report_diagnostics(report) {
        for fixit in fixits_of(&diagnostic) {
            let patched = fixit.apply_to(&named_source).unwrap_or_else(|| {
                panic!(
                    "fixit `{}` does not apply to the file the report names \
                     ({named}, {} bytes): {:?}",
                    fixit.title,
                    named_source.len(),
                    fixit.edits
                )
            });
            assert_eq!(
                patched,
                source.replace("t.severty", "t.severity"),
                "fixit `{}` did not repair the file the report names",
                fixit.title
            );
            applied += 1;
        }
    }
    assert!(
        applied > 0,
        "the include program stopped carrying a fixit, so this proves nothing"
    );
}

/// The other half of the same rule: an edit that belongs to an INCLUDED file is
/// not this report's to offer.
///
/// The report names one file and a patch carries no filename of its own, so
/// there is nowhere to say "these offsets are in `lib.whip`". Retargeting is not
/// available and guessing is the corruption this whole rung exists to prevent,
/// so the fixit is dropped — and the SUGGESTION stays, because a person reading
/// the sentence can go and fix the library themselves.
#[test]
fn a_fixit_belonging_to_an_included_file_is_not_offered() {
    let dir = temp_dir("include-lib");
    fs::write(
        dir.0.join("lib.whip"),
        format!("{LIBRARY}\nclass Escalation {{\n  ticket SupportTickt\n}}\n"),
    )
    .expect("library is written");
    let root = dir.0.join("root.whip");
    fs::write(
        &root,
        "include \"lib.whip\"\n\nworkflow TriageTickets\n\ninput ticket SupportTicket\noutput result TriageResult\n\nclass TriageResult {\n  id string\n}\n\nrule triage\n  when SupportTicket as t\n=> {\n  complete result {\n    id t.id\n  }\n}\n",
    )
    .expect("root is written");

    let reports = check_json(std::slice::from_ref(&root));
    let report = reports.first().expect("one report");
    let diagnostics = report_diagnostics(report);
    let carrier = diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.get("code").and_then(Value::as_str) == Some("type.unknown_schema")
        })
        .expect("the library's misspelling is reported");
    assert_eq!(
        carrier.get("suggestion").and_then(Value::as_str),
        Some(
            "did you mean `SupportTicket`? otherwise declare `class SupportTickt` or \
             `enum SupportTickt` before using it"
        ),
        "the reader keeps the sentence"
    );
    assert_eq!(
        fixits_of(carrier),
        Vec::new(),
        "an edit into the included file must not be offered against the root path"
    );
}

// ---------------------------------------------------------------------------
// The property that makes a fixit a fixit, over every plane.
// ---------------------------------------------------------------------------

/// Copy a directory tree. The corpus is patched in place during the run, so it
/// is copied first rather than edited under `git`.
fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).expect("destination directory is created");
    for entry in fs::read_dir(from).expect("source directory is readable") {
        let entry = entry.expect("directory entry is readable");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("entry has a type").is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("file is copied");
        }
    }
}

/// Every `.whip` directly under `dir`, sorted — a directory read rather than a
/// list, so a fixture added to the corpus joins this measurement without anyone
/// remembering to add it.
fn whip_files(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "whip")
        })
        .collect();
    paths.sort();
    paths
}

/// A diagnostic reduced to what survives an edit: the code and the sentence.
fn identity(diagnostic: &Value) -> (String, String) {
    let field = |name: &str| {
        diagnostic
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    (field("code"), field("message"))
}

/// Where `fixit`'s replacements END UP in the patched text.
///
/// Not the spans it carries: those address the original, and each replacement
/// shifts everything after it by the difference in length.
fn edited_extents(fixit: &Fixit) -> Vec<(usize, usize)> {
    let mut edits: Vec<&FixitEdit> = fixit.edits.iter().collect();
    edits.sort_by_key(|edit| (edit.span.start, edit.span.end));
    let mut extents = Vec::new();
    let mut shift = 0isize;
    for edit in edits {
        let start = (edit.span.start as isize + shift) as usize;
        extents.push((start, start + edit.replacement.len()));
        shift += edit.replacement.len() as isize - (edit.span.end - edit.span.start) as isize;
    }
    extents
}

/// THE PROPERTY THAT MAKES A FIXIT A FIXIT, over the whole compiler, through
/// `whip check --json`.
///
/// For every fixit the corpus produces: apply it to the file it came from,
/// re-check, and demand
///
///   * ONE FEWER of the diagnostic that carried it. Counted, not tested for
///     absence: a program with the same mistake at five sites prints one
///     sentence five times, and repairing one site must not have to repair all
///     five to count as a repair;
///   * nothing new INSIDE the bytes it wrote — an error about the very text the
///     fixit put there is the fixit's own doing;
///   * nothing new carrying the SAME CODE as the one repaired, anywhere touching
///     what it wrote.
///
/// WHAT IS ALLOWED, AND WHY IT HAD TO BE. The property this replaces was "a
/// fixit may not introduce a diagnostic", and that is false. Over an injected-
/// typo population — 3,983 mutants of this corpus, 844 fixits applied — 153
/// applications reveal a diagnostic, and it is false in the SHIPPED corpus too:
/// `examples/invalid/misspelled-keyword.whip` writes `recrod` for `record`, and
/// repairing it reveals `graph.unreachable_terminal`, because the workflow
/// really does never reach a terminal and the unparseable statement was hiding
/// it. That is the compiler working. Withholding a correct repair because a
/// second fault waits behind it would mean refusing to fix any program more than
/// one edit from correct.
///
/// So a revealed fault elsewhere passes, and the clauses above are what keeps
/// "elsewhere" from meaning "anywhere". THE LINE IS CONTAINMENT. A diagnostic
/// whose span lies inside the replacement is about what the fixit put there. A
/// diagnostic whose span CONTAINS it — the enclosing `case` block, comparison or
/// `after` block — is the check that could not run until the token resolved,
/// which is the repair working. Over those same 844 applications, containment
/// leaves ZERO failures, where overlap would condemn 28 enclosing checks and the
/// old property condemned 153.
///
/// The plane matters as much as the property. `graph.unreachable_terminal` comes
/// from the CLI's workflow-liveness lint, not the parser, so the parser-level
/// version of this test could not see the counterexample sitting in its own
/// corpus. Driving the binary is what makes the measurement honest.
#[test]
fn fixits_repair_the_program_through_the_path_a_user_gets() {
    let corpus = temp_dir("corpus");
    let examples = corpus.0.join("examples");
    copy_tree(&repo_root().join("examples"), &examples);

    let mut paths = whip_files(&examples);
    paths.extend(whip_files(&examples.join("invalid")));
    assert!(
        paths.len() > 100,
        "the example corpus went missing: only {} files were read",
        paths.len()
    );

    let mut applied = 0usize;
    let mut carrying = 0usize;
    for report in check_json(&paths) {
        let path = PathBuf::from(
            report
                .get("path")
                .and_then(Value::as_str)
                .expect("a report names its file"),
        );
        let name = path
            .file_name()
            .expect("a report path has a file name")
            .to_string_lossy()
            .into_owned();
        let diagnostics = report_diagnostics(&report);
        let before: Vec<(String, String)> = diagnostics.iter().map(identity).collect();
        let source = fs::read_to_string(&path).expect("the reported file is readable");

        for diagnostic in &diagnostics {
            let fixits = fixits_of(diagnostic);
            if !fixits.is_empty() {
                carrying += 1;
            }
            let carried = identity(diagnostic);
            for fixit in fixits {
                let patched = fixit.apply_to(&source).unwrap_or_else(|| {
                    panic!(
                        "{name}: fixit `{}` does not apply to the file the report names: {:?}",
                        fixit.title, fixit.edits
                    )
                });
                assert_ne!(
                    patched, source,
                    "{name}: fixit `{}` is a no-op",
                    fixit.title
                );
                fs::write(&path, &patched).expect("the patched file is written");
                let after = check_json(std::slice::from_ref(&path));
                fs::write(&path, &source).expect("the original file is restored");
                applied += 1;

                let after = report_diagnostics(after.first().expect("one report"));
                let carried_count =
                    |set: &[Value]| set.iter().filter(|seen| identity(seen) == carried).count();
                assert!(
                    carried_count(&after) < before.iter().filter(|seen| **seen == carried).count(),
                    "{name}: applying `{}` did not remove an instance of its own \
                     diagnostic: {carried:?}",
                    fixit.title
                );
                // NEW is a multiset question: a second copy of a diagnostic the
                // program already had is as new as one it never had.
                let extents = edited_extents(&fixit);
                let mut remaining = before.clone();
                for seen in &after {
                    let seen_identity = identity(seen);
                    if let Some(index) = remaining.iter().position(|had| *had == seen_identity) {
                        remaining.remove(index);
                        continue;
                    }
                    let span = span_of(seen.get("source_span").expect("a diagnostic has a span"));
                    // An EMPTY span is inside nothing and touches nothing: a
                    // workflow-level diagnostic carries `0..0` because it has no
                    // site, and reading that as "at byte 0" would blame every
                    // fixit that touched the first token.
                    let sized = span.start < span.end;
                    assert!(
                        !sized
                            || !extents
                                .iter()
                                .any(|(start, end)| *start <= span.start && span.end <= *end),
                        "{name}: applying `{}` introduced {seen_identity:?} inside the bytes \
                         it just wrote ({extents:?})",
                        fixit.title
                    );
                    assert!(
                        seen_identity.0 != carried.0
                            || !sized
                            || !extents
                                .iter()
                                .any(|(start, end)| span.start < *end && *start < span.end),
                        "{name}: applying `{}` introduced another `{}` — the code it claimed \
                         to repair — over the span it edited ({extents:?})",
                        fixit.title,
                        carried.0
                    );
                }
            }
        }
    }
    // A floor, not a count. Every assertion above is vacuous if nothing emits a
    // fixit, so a refactor that quietly stopped attaching them would otherwise
    // leave this green. The floor sits below what the corpus produces today so
    // that narrowing a caret — which ADDS fixits — never fails it, while losing
    // the population does.
    assert!(
        applied >= 5 && carrying >= 4,
        "the fixit population collapsed: {applied} fixits over {carrying} diagnostics"
    );
}
