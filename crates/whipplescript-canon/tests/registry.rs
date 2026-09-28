//! The workspace's canonicalizer registry keys each path by its file class
//! (norm-plane §9): Rust, TypeScript and Markdown paths get declaration
//! rows, other paths stay path-level, and a rename carries its rename hash
//! into the frontier.

use whipplescript_canon::{MarkdownSections, RustItems, TypeScriptItems};
use whipplescript_store::branches::MAINLINE_BRANCH_ID;
use whipplescript_store::vcs::NativeWorkspaceVcs;

#[test]
fn the_registry_keys_each_path_by_its_file_class() {
    let root = std::env::temp_dir().join(format!(
        "whipplescript-canon-registry-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("scratch");
    let mut vcs =
        NativeWorkspaceVcs::open(root.join("branches.sqlite"), root.join("content.sqlite"))
            .expect("workspace");
    vcs.register_decl_canonicalizer("rs", Box::new(RustItems));
    vcs.register_decl_canonicalizer("ts", Box::new(TypeScriptItems::typescript()));
    vcs.register_decl_canonicalizer("md", Box::new(MarkdownSections));
    vcs.init("t0").expect("init");
    let write = |vcs: &mut NativeWorkspaceVcs, path: &str, body: &str, cut: &str| {
        vcs.write(MAINLINE_BRANCH_ID, path, Some(body), cut, "t1")
            .expect("write");
    };
    write(
        &mut vcs,
        "crates/auth/src/lib.rs",
        "pub fn grant_allows() -> bool { true }\npub fn deny() -> bool { false }\n",
        "c1",
    );
    write(
        &mut vcs,
        "web/src/auth.ts",
        "export function allows(): boolean { return true; }\n",
        "c2",
    );
    write(
        &mut vcs,
        "docs/policy.md",
        "# Policy\n\n## Required\n\nDeny the worker.\n",
        "c3",
    );
    write(&mut vcs, "notes.txt", "prose", "c4");
    // A reformat is no declaration change; a rename is one.
    write(
        &mut vcs,
        "crates/auth/src/lib.rs",
        "pub fn grant_allows() -> bool {\n    true\n}\npub fn deny() -> bool { false }\n",
        "c5",
    );
    write(
        &mut vcs,
        "crates/auth/src/lib.rs",
        "pub fn allows() -> bool {\n    true\n}\npub fn deny() -> bool { false }\n",
        "c6",
    );
    let units = vcs.change_units(MAINLINE_BRANCH_ID, 500).expect("units");
    let decls = |cut: &str| -> Vec<String> {
        units
            .iter()
            .find(|unit| unit.cut_id == cut)
            .map(|unit| {
                unit.decls
                    .iter()
                    .map(|decl| decl.identity.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    assert_eq!(
        decls("c1"),
        ["fn crates/auth::deny", "fn crates/auth::grant_allows"]
    );
    assert_eq!(decls("c2"), ["function web/src/auth::allows"]);
    assert_eq!(
        decls("c3"),
        [
            "section docs/policy.md # Policy",
            "section docs/policy.md # Policy > ## Required"
        ]
    );
    assert!(
        decls("c4").is_empty(),
        "a file class with no canonicalizer stays path-level"
    );
    assert!(
        decls("c5").is_empty(),
        "a reformat is not a declaration change"
    );
    assert_eq!(
        decls("c6"),
        ["fn crates/auth::allows", "fn crates/auth::grant_allows"]
    );
    // The frontier carries the renamed item's rename hash, which the old
    // name's shares: that is what mints `moved_to` for evidence keyed to it.
    let (_, frontier) = vcs
        .frontier_content(MAINLINE_BRANCH_ID)
        .expect("frontier")
        .expect("mainline");
    assert!(frontier.decls.contains_key("fn crates/auth::allows"));
    assert!(!frontier.decls.contains_key("fn crates/auth::grant_allows"));
    drop(vcs);
    std::fs::remove_dir_all(&root).expect("scratch");
}

#[test]
fn renaming_a_local_is_not_a_declaration_change() {
    let root = std::env::temp_dir().join(format!(
        "whipplescript-canon-registry-locals-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("scratch");
    let mut vcs =
        NativeWorkspaceVcs::open(root.join("branches.sqlite"), root.join("content.sqlite"))
            .expect("workspace");
    vcs.register_decl_canonicalizer("rs", Box::new(RustItems));
    vcs.register_decl_canonicalizer("ts", Box::new(TypeScriptItems::typescript()));
    vcs.init("t0").expect("init");
    let write = |vcs: &mut NativeWorkspaceVcs, path: &str, body: &str, cut: &str| {
        vcs.write(MAINLINE_BRANCH_ID, path, Some(body), cut, "t1")
            .expect("write");
    };
    let rust = "pub fn total(bonus: u32) -> u32 { let sum = bonus + 1; sum }\n";
    let typescript =
        "export function total(bonus: number) { const sum = bonus + 1; return sum; }\n";
    write(&mut vcs, "crates/auth/src/lib.rs", rust, "c1");
    write(&mut vcs, "web/src/auth.ts", typescript, "c2");
    let renamed = |source: &str| source.replace("bonus", "extra").replace("sum", "acc");
    write(&mut vcs, "crates/auth/src/lib.rs", &renamed(rust), "c3");
    write(&mut vcs, "web/src/auth.ts", &renamed(typescript), "c4");
    // Using the parameter where the local was is a change.
    write(
        &mut vcs,
        "crates/auth/src/lib.rs",
        &renamed(rust).replace("; acc }", "; extra }"),
        "c5",
    );
    let units = vcs.change_units(MAINLINE_BRANCH_ID, 500).expect("units");
    let decls = |cut: &str| -> Vec<String> {
        units
            .iter()
            .find(|unit| unit.cut_id == cut)
            .map(|unit| {
                unit.decls
                    .iter()
                    .map(|decl| decl.identity.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    assert!(
        decls("c3").is_empty(),
        "a Rust local rename is not a change"
    );
    assert!(
        decls("c4").is_empty(),
        "a TypeScript local rename is not a change"
    );
    assert_eq!(decls("c5"), ["fn crates/auth::total"]);
    drop(vcs);
    std::fs::remove_dir_all(&root).expect("scratch");
}

/// A norm capture carries the host's declaration map (norm-plane §9): each
/// versioned canonicalizer's version by file class, and the identities each
/// file of those classes keys to, so the store's resource inventory can
/// resolve a declaration subject without calling a canonicalizer.
#[test]
fn a_norm_capture_carries_each_versioned_class_and_its_identities() {
    use std::collections::BTreeSet;
    use whipplescript_store::norm_artifact::ArtifactLimits;
    use whipplescript_store::vcs::DeclCanonicalizer;

    let mut vcs = NativeWorkspaceVcs::open(":memory:", ":memory:").expect("workspace");
    vcs.register_decl_canonicalizer("rs", Box::new(RustItems));
    vcs.register_decl_canonicalizer("ts", Box::new(TypeScriptItems::typescript()));
    vcs.register_decl_canonicalizer("tsx", Box::new(TypeScriptItems::tsx()));
    vcs.register_decl_canonicalizer("md", Box::new(MarkdownSections));
    vcs.init("t0").expect("init");
    for (path, body, cut) in [
        (
            "crates/auth/src/lib.rs",
            "pub fn allows() -> bool { true }\n",
            "c1",
        ),
        ("docs/policy.md", "# Policy\n\nDeny the worker.\n", "c2"),
        ("notes.txt", "prose", "c3"),
    ] {
        vcs.write(MAINLINE_BRANCH_ID, path, Some(body), cut, "t1")
            .expect("write");
    }
    let captured = vcs
        .capture_norm_artifact("c3", ArtifactLimits::default())
        .expect("capture");
    let declarations = captured.declarations();
    let versions: Vec<(&str, &str)> = declarations
        .versions
        .iter()
        .map(|(class, version)| (class.as_str(), version.as_str()))
        .collect();
    assert_eq!(
        versions,
        [
            ("md", "whipplescript.canon.markdown/1"),
            ("rs", "whipplescript.canon.rust/2 tree-sitter-rust/0.24"),
            (
                "ts",
                "whipplescript.canon.typescript/2 tree-sitter-typescript/0.23"
            ),
            (
                "tsx",
                "whipplescript.canon.tsx/2 tree-sitter-typescript/0.23"
            ),
        ]
    );
    assert_eq!(RustItems.version(), Some(versions[1].1));
    let keyed = |path: &str| declarations.files[path].clone().expect("a canonical form");
    assert_eq!(
        keyed("crates/auth/src/lib.rs"),
        BTreeSet::from(["fn crates/auth::allows".to_owned()])
    );
    assert_eq!(
        keyed("docs/policy.md"),
        BTreeSet::from(["section docs/policy.md # Policy".to_owned()])
    );
    assert!(
        !declarations.files.contains_key("notes.txt"),
        "a class with no canonicalizer carries path identity only"
    );
}
