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
    PLATFORM_CONSTRUCT_CATALOG,
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

/// The manifest schema's construct vocabulary is the PACKAGE-AUTHORABLE slice
/// of core's catalog, and stays that slice.
///
/// This schema is the contract external package authors pin, and it is
/// projected to the public mirror. Its `lowering_target` enum is exactly the
/// lowerings core marks `package_authorable`, and its `construct_family` enum
/// is exactly the families those lowerings are compatible with. The kernel
/// enforces the same line: a construct naming an internal lowering is refused
/// unless the manifest is a byte-identical embedded std copy or holds a
/// platform-catalog privilege tuple.
///
/// So the schema rejecting `resource_effect`, `signal_source`, `signal_emit`
/// and `source_declaration` is the contract working. Two shipped std manifests
/// -- `coord.json` and `ingress.json` -- fail validation for exactly that
/// reason and are supposed to: they are platform-internal and hold a key no
/// third party has. Widening these enums to make them validate would publish
/// permission the kernel refuses, which is the one direction a change here
/// must never go.
///
/// The pin is two-way. If core ever makes an internal lowering authorable, the
/// schema must gain it, and this fails until it does.
#[test]
fn the_manifest_schema_publishes_exactly_the_package_authorable_vocabulary() {
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/report-schemas/package_manifest_v0.schema.json");
    let schema: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&schema_path).expect("the package manifest schema is readable"),
    )
    .expect("the package manifest schema is JSON");

    let enum_at = |pointer: &str| -> Vec<String> {
        schema
            .pointer(pointer)
            .and_then(serde_json::Value::as_array)
            .unwrap_or_else(|| panic!("the schema states a vocabulary at {pointer}"))
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .expect("a vocabulary entry is a string")
                    .to_owned()
            })
            .collect()
    };

    let authorable = PLATFORM_CONSTRUCT_CATALOG
        .lowerings
        .iter()
        .filter(|lowering| lowering.package_authorable)
        .collect::<Vec<_>>();

    let mut expected_lowerings = authorable
        .iter()
        .map(|lowering| lowering.id.to_owned())
        .collect::<Vec<_>>();
    expected_lowerings.sort();
    let mut published_lowerings = enum_at("/$defs/construct/properties/lowering_target/enum");
    published_lowerings.sort();
    assert_eq!(
        published_lowerings, expected_lowerings,
        "the schema's lowering_target enum must be core's package-authorable lowerings"
    );

    let mut expected_families = authorable
        .iter()
        .flat_map(|lowering| lowering.compatible_families.iter().map(|f| (*f).to_owned()))
        .collect::<Vec<_>>();
    expected_families.sort();
    expected_families.dedup();
    let mut published_families = enum_at("/$defs/construct/properties/construct_family/enum");
    published_families.sort();
    assert_eq!(
        published_families, expected_families,
        "the schema's construct_family enum must be the families those lowerings accept"
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
