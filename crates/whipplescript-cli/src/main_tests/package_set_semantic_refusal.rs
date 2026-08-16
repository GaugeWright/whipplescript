//! Extracted verbatim from `main.rs` (module path `package_set_semantic_refusal_tests` is unchanged).

use super::{read_package_set, stable_hash_hex, PACKAGE_SET_SCHEMA};
use serde_json::json;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

/// `read_package_set` decides which manifests a program may load. Its refusals
/// are not shape checks — each encodes a distinct rule about what a package set
/// may claim — and a mutation sweep found none of them exercised.
///
/// `package_source.escapes_project` is the one that matters most: it is the
/// containment boundary on where a package may live.
fn project(slug: &str, set: serde_json::Value, manifests: &[(&str, &str)]) -> (PathBuf, PathBuf) {
    let root = env::temp_dir().join(format!(
        "whipplescript-pkgset-{slug}-{}",
        stable_hash_hex(slug)
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("packages")).expect("packages dir");
    for (name, body) in manifests {
        fs::write(root.join("packages").join(name), body).expect("manifest writes");
    }
    let set_path = root.join("whip.packages.json");
    fs::write(&set_path, serde_json::to_string_pretty(&set).expect("json")).expect("set writes");
    (root, set_path)
}

fn notes_manifest(name: &str) -> String {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/packages/notes.json");
    let text = fs::read_to_string(src).expect("notes manifest");
    let mut value: serde_json::Value = serde_json::from_str(&text).expect("manifest json");
    value["name"] = json!(name);
    serde_json::to_string_pretty(&value).expect("json")
}

fn codes(set: serde_json::Value, slug: &str, manifests: &[(&str, &str)]) -> Vec<&'static str> {
    let (root, set_path) = project(slug, set, manifests);
    let result = read_package_set(&set_path, &root);
    let _ = fs::remove_dir_all(&root);
    match result {
        Ok(_) => Vec::new(),
        Err(diagnostics) => diagnostics.into_iter().map(|d| d.code).collect(),
    }
}

fn entry(name: &str, path: &str) -> serde_json::Value {
    json!({"name": name, "source": {"type": "path", "path": path}})
}

/// The accept case. Without it, a reader that refused every set would satisfy
/// each rejection below.
#[test]
fn a_well_formed_package_set_resolves() {
    let manifest = notes_manifest("notes");
    assert_eq!(
        codes(
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": [entry("notes", "packages/notes.json")]}),
            "ok",
            &[("notes.json", manifest.as_str())],
        ),
        Vec::<&str>::new()
    );
}

#[test]
fn two_packages_of_the_same_name_are_refused() {
    let manifest = notes_manifest("notes");
    assert!(codes(
        json!({"schema": PACKAGE_SET_SCHEMA, "packages": [
            entry("notes", "packages/notes.json"),
            entry("notes", "packages/notes.json")
        ]}),
        "dup",
        &[("notes.json", manifest.as_str())],
    )
    .contains(&"package_set.duplicate_name"));
}

/// Containment, in two layers. A textual escape — `..` or an absolute path —
/// is refused as non-portable before resolution. What reaches
/// `escapes_project` is the escape the text cannot show: a project-relative
/// path that leaves the root through a SYMLINK. Both are asserted, because
/// covering only the textual layer would leave the check that exists
/// precisely for the harder case as unexercised as the sweep found it.
#[test]
fn a_textually_escaping_source_is_refused_as_non_portable() {
    let manifest = notes_manifest("notes");
    for escaping in ["../outside/notes.json", "/etc/hostname"] {
        let found = codes(
            json!({"schema": PACKAGE_SET_SCHEMA, "packages": [entry("notes", escaping)]}),
            "escape-text",
            &[("notes.json", manifest.as_str())],
        );
        assert!(
            found.contains(&"package_source.nonportable_path"),
            "`{escaping}` must be refused as non-portable, got {found:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_source_leaving_the_project_through_a_symlink_is_refused() {
    use std::os::unix::fs::symlink;

    let manifest = notes_manifest("notes");
    let root = env::temp_dir().join(format!(
        "whipplescript-pkgset-symlink-{}",
        stable_hash_hex("symlink")
    ));
    let outside = env::temp_dir().join(format!(
        "whipplescript-pkgset-outside-{}",
        stable_hash_hex("symlink")
    ));
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
    fs::create_dir_all(root.join("packages")).expect("packages dir");
    fs::create_dir_all(&outside).expect("outside dir");
    fs::write(outside.join("notes.json"), &manifest).expect("outside manifest");
    symlink(outside.join("notes.json"), root.join("packages/notes.json")).expect("symlink");

    let set_path = root.join("whip.packages.json");
    fs::write(
        &set_path,
        serde_json::to_string_pretty(&json!({
            "schema": PACKAGE_SET_SCHEMA,
            "packages": [entry("notes", "packages/notes.json")],
        }))
        .expect("json"),
    )
    .expect("set writes");

    let result = read_package_set(&set_path, &root);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);

    let found: Vec<&str> = match result {
        Ok(_) => Vec::new(),
        Err(diagnostics) => diagnostics.into_iter().map(|d| d.code).collect(),
    };
    assert!(
        found.contains(&"package_source.escapes_project"),
        "a symlinked escape must be refused, got {found:?}"
    );
}

#[test]
fn a_manifest_that_does_not_load_is_refused() {
    assert!(codes(
        json!({"schema": PACKAGE_SET_SCHEMA, "packages": [entry("notes", "packages/notes.json")]}),
        "badmanifest",
        &[("notes.json", "{ not json")],
    )
    .contains(&"package_manifest.invalid"));
}

/// The set names a package; the manifest declares its own name. A mismatch
/// means the set is loading something other than what it claims.
#[test]
fn a_manifest_declaring_another_name_is_refused() {
    let manifest = notes_manifest("something-else");
    assert!(codes(
        json!({"schema": PACKAGE_SET_SCHEMA, "packages": [entry("notes", "packages/notes.json")]}),
        "identity",
        &[("notes.json", manifest.as_str())],
    )
    .contains(&"package_set.identity_mismatch"));
}
