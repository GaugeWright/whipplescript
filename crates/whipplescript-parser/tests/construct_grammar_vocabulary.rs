//! The DR-0011 construct-grammar vocabulary has one owner.
//!
//! `whipplescript-core` declares `CONSTRUCT_GRAMMAR_*`; the kernel's package
//! registry validates authored manifests against it, and this crate's build
//! script transcribes manifests into parse tables against it. The build script
//! used to keep private copies "mirroring" core, and they drifted: core admits
//! `onto` as a `declaration_block` clause connective and the build script's
//! copy did not, so a manifest the kernel accepted panicked the parser's build.
//!
//! These tests hold that shut from both ends — the vocabulary the build script
//! actually validated against, and a fixture manifest tree carrying an `onto`
//! clause that the build script has to transcribe rather than reject.

use std::{fs, path::Path, process::Command};

use whipplescript_core::{
    CONSTRUCT_GRAMMAR_BINDING_MODES, CONSTRUCT_GRAMMAR_CLAUSE_CONNECTIVES,
    CONSTRUCT_GRAMMAR_CLAUSE_KINDS, CONSTRUCT_GRAMMAR_CONNECTIVES, CONSTRUCT_GRAMMAR_SLOT_KINDS,
};

// Written by `emit_build_script_probe` in build.rs: the vocabulary that run
// validated against, and the path of the build-script executable itself.
include!(concat!(env!("OUT_DIR"), "/build_script_probe.rs"));

/// Every vocabulary list the build script validated against is core's list, so
/// a re-introduced private copy fails here the moment it differs by one word.
#[test]
fn the_build_script_validates_against_cores_vocabulary() {
    assert_eq!(BUILD_CONNECTIVES, CONSTRUCT_GRAMMAR_CONNECTIVES);
    assert_eq!(BUILD_SLOT_KINDS, CONSTRUCT_GRAMMAR_SLOT_KINDS);
    assert_eq!(BUILD_BINDING_MODES, CONSTRUCT_GRAMMAR_BINDING_MODES);
    assert_eq!(BUILD_CLAUSE_KINDS, CONSTRUCT_GRAMMAR_CLAUSE_KINDS);
    assert_eq!(
        BUILD_CLAUSE_CONNECTIVES,
        CONSTRUCT_GRAMMAR_CLAUSE_CONNECTIVES
    );
    // The word the two copies had already drifted on.
    assert!(BUILD_CLAUSE_CONNECTIVES.contains(&"onto"));
}

/// End to end over the real build script: a `declaration_block` grammar whose
/// clause is introduced by `onto` — the case the kernel's package registry
/// accepts — is transcribed into the parse table instead of panicking the
/// build. Re-declaring the old seven-word `CLAUSE_CONNECTIVES` in build.rs
/// makes this fail with the build script's own "unsupported connective" panic.
#[test]
fn a_declaration_clause_may_be_introduced_by_onto() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let scratch = std::env::temp_dir().join(format!(
        "whipplescript-grammar-onto-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&scratch);
    copy_tree(
        &crate_dir.join("vendored-std"),
        &scratch.join("vendored-std"),
    )
    .expect("the vendored std manifest tree copies into a scratch directory");

    // Give the tracker grammar one extra clause, introduced by `onto`.
    let grammar_path = scratch.join("vendored-std/grammars/tracker.json");
    let source = fs::read_to_string(&grammar_path).unwrap();
    let onto_clause = r#"{
      "name": "mirror",
      "kind": "identifier",
      "connective": "onto",
      "required": false,
      "list": false,
      "unknown_hint": "fixture clause",
      "missing_summary": "fixture clause"
    },"#;
    let patched = source.replacen("\"clauses\": [", &format!("\"clauses\": [{onto_clause}"), 1);
    assert_ne!(
        patched, source,
        "the tracker grammar fixture no longer has a `clauses` array to extend"
    );
    fs::write(&grammar_path, patched).unwrap();

    let out_dir = scratch.join("out");
    fs::create_dir_all(&out_dir).unwrap();
    let run = Command::new(BUILD_SCRIPT_PATH)
        .env("CARGO_MANIFEST_DIR", &scratch)
        .env("OUT_DIR", &out_dir)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "the build script rejected an `onto` clause connective the kernel accepts:\n{}",
        String::from_utf8_lossy(&run.stderr)
    );

    let table = fs::read_to_string(out_dir.join("declaration_block_grammar.rs")).unwrap();
    assert!(
        table.contains(r#"name: "mirror""#) && table.contains(r#"connective: Some("onto")"#),
        "the `onto` clause did not reach the generated parse table:\n{table}"
    );

    fs::remove_dir_all(&scratch).unwrap();
}

/// The THIRD copy. `spec/report-schemas/package_manifest_v0.schema.json` is the
/// contract external package authors pin, it is projected to the public mirror,
/// and `spec/` outranks `crates/` in this repository's authority chain — so a
/// vocabulary stated there and nowhere checked is the same defect one level up.
/// It had drifted further than the copy this file's other tests closed: two
/// connectives short, which rejected two of the manifests the build script
/// itself transcribes.
///
/// Only the slot connective is pinned here, because that is the list core
/// owns. The schema is stale in other ways that are not about this vocabulary
/// (see `spec/survey-residue-tracker.md`) and this test deliberately does not
/// claim otherwise.
#[test]
fn the_manifest_schema_mirrors_cores_vocabulary() {
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/report-schemas/package_manifest_v0.schema.json");
    let schema: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&schema_path).expect("the package manifest schema is readable"),
    )
    .expect("the package manifest schema is JSON");

    let connectives = schema
        .pointer("/$defs/constructGrammarSlot/properties/connective/enum")
        .and_then(serde_json::Value::as_array)
        .expect("the schema states a slot connective vocabulary")
        .iter()
        .map(|value| value.as_str().expect("a connective is a string").to_owned())
        .collect::<Vec<_>>();

    assert_eq!(
        connectives, CONSTRUCT_GRAMMAR_CONNECTIVES,
        "the manifest schema's slot connectives must be core's, in core's order"
    );
}

fn copy_tree(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
