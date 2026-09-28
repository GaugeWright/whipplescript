use std::collections::BTreeMap;

use super::*;

fn rust(path: &str, source: &str) -> BTreeMap<String, CanonDecl> {
    RustItems
        .canonical_declarations_at(path, source)
        .expect("a Rust file always has a canonical form")
        .into_iter()
        .map(|decl| (decl.identity.clone(), decl))
        .collect()
}

fn typescript(path: &str, source: &str) -> BTreeMap<String, CanonDecl> {
    TypeScriptItems::typescript()
        .canonical_declarations_at(path, source)
        .expect("a TypeScript file always has a canonical form")
        .into_iter()
        .map(|decl| (decl.identity.clone(), decl))
        .collect()
}

const AUTH: &str = r#"
use crate::grant::Grant;

/// Whether a grant allows the caller.
pub fn grant_allows(grant: &Grant) -> bool {
    // Only an explicit allowing grant allows.
    grant.kind == "allow"
}

pub struct Owner;
pub struct Worker;

impl std::fmt::Display for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "owner") }
}
impl std::fmt::Display for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "worker") }
}

mod checks {
    pub fn deny() -> bool { false }
}
"#;

#[test]
fn rust_items_are_keyed_by_kind_and_qualified_name() {
    let items = rust("crates/auth/src/policy.rs", AUTH);
    for identity in [
        "fn crates/auth::policy::grant_allows",
        "struct crates/auth::policy::Owner",
        "impl crates/auth::policy::std::fmt::Display for Owner",
        "impl crates/auth::policy::std::fmt::Display for Worker",
        "fn crates/auth::policy::checks::deny",
        "use crates/auth::policy",
    ] {
        assert!(
            items.contains_key(identity),
            "{identity}: {:?}",
            items.keys()
        );
    }
    // Two impls of one trait for two types are two units.
    assert_ne!(
        items["impl crates/auth::policy::std::fmt::Display for Owner"].canon_hash,
        items["impl crates/auth::policy::std::fmt::Display for Worker"].canon_hash
    );
    assert!(!items.keys().any(|identity| identity.starts_with(UNKEYED)));
    // The package root's module is the package itself.
    assert!(rust("crates/auth/src/lib.rs", "pub fn f() {}").contains_key("fn crates/auth::f"));
    assert!(rust("crates/auth/src/a/mod.rs", "pub fn f() {}").contains_key("fn crates/auth::a::f"));
}

#[test]
fn rust_reformats_and_comments_are_not_changes_and_a_pure_rename_carries() {
    let path = "crates/auth/src/policy.rs";
    let base = rust(path, AUTH);
    let reformatted = rust(
        path,
        &AUTH
            .replace(
                "// Only an explicit allowing grant allows.",
                "// Reworded comment.",
            )
            .replace("/// Whether a grant allows the caller.", "")
            .replace(
                "grant.kind == \"allow\"",
                "grant.kind\n        ==\n        \"allow\"",
            ),
    );
    assert_eq!(
        reformatted, base,
        "a reformat and a comment edit are not changes"
    );
    let renamed = rust(path, &AUTH.replace("grant_allows", "allows"));
    let before = &base["fn crates/auth::policy::grant_allows"];
    let after = &renamed["fn crates/auth::policy::allows"];
    assert_eq!(
        before.rename_hash, after.rename_hash,
        "a pure rename carries"
    );
    assert_ne!(before.canon_hash, after.canon_hash);
    // Rename plus edit orphans: nothing recognises it as the same unit.
    let edited = rust(
        path,
        &AUTH
            .replace("grant_allows", "allows")
            .replace("\"allow\"", "\"permit\""),
    );
    assert_ne!(
        before.rename_hash,
        edited["fn crates/auth::policy::allows"].rename_hash
    );
    // The same item in another file keeps its rename hash: a move mints
    // `moved_to` through it.
    let moved = rust("crates/auth/src/grants.rs", AUTH);
    assert_eq!(
        moved["fn crates/auth::grants::grant_allows"].rename_hash,
        before.rename_hash
    );
}

#[test]
fn rust_macro_generated_items_path_modules_and_errors_read_unkeyed() {
    let source = r#"
pub fn keyed() {}
lazy_static! { static ref TABLE: u32 = 1; }
#[path = "elsewhere.rs"]
mod moved;
pub fn broken( {
"#;
    let items = rust("src/lib.rs", source);
    assert!(items.contains_key("fn crate::keyed"));
    assert!(items.keys().any(|identity| identity.starts_with(UNKEYED)));
    assert!(!items.keys().any(|identity| identity.contains("moved")));
    // Two inherent impls of one type are one identity twice: neither keyed.
    let twice = rust(
        "src/lib.rs",
        "struct A;\nimpl A { fn a() {} }\nimpl A { fn b() {} }\n",
    );
    assert!(!twice.keys().any(|identity| identity.starts_with("impl")));
    assert!(twice.keys().any(|identity| identity.starts_with(UNKEYED)));
}

#[test]
fn a_grammar_bump_re_keys_without_changing_identity() {
    let source = "pub fn f() -> u32 { 1 }";
    let current = rust("src/lib.rs", source);
    let print = print_of(source);
    let bumped = digest("whipplescript.canon.rust/2 tree-sitter-rust/0.25", &print);
    assert_ne!(current["fn crate::f"].canon_hash, bumped);
    assert_eq!(
        current["fn crate::f"].canon_hash,
        digest(RustItems::VERSION, &print),
        "the version rides in the hash, so a bump re-keys every unit once"
    );
}

fn print_of(source: &str) -> String {
    let mut parser = Parser::new();
    parser.set_language(&RustItems::language()).unwrap();
    let tree = parser.parse(source, None).unwrap();
    let item = tree.root_node().named_child(0).unwrap();
    print(item, source.as_bytes(), RustItems::comment, None)
}

const MODULE: &str = r#"
import { Grant } from "./grant";

/** Whether a grant allows the caller. */
export function grantAllows(grant: Grant): boolean {
  // Only an explicit allowing grant allows.
  return grant.kind === "allow";
}

export class Owner { name = "owner"; }
export interface Caller { id: string }
export type Kind = "allow" | "deny";
export const LIMIT = 3;

namespace checks {
  export function deny(): boolean { return false; }
}

export default grantAllows;
"#;

#[test]
fn typescript_declarations_are_keyed_by_kind_and_qualified_name() {
    let items = typescript("src/auth/policy.ts", MODULE);
    for identity in [
        "function src/auth/policy::grantAllows",
        "class src/auth/policy::Owner",
        "interface src/auth/policy::Caller",
        "type src/auth/policy::Kind",
        "const src/auth/policy::LIMIT",
        "function src/auth/policy::checks::deny",
        "export src/auth/policy::default",
        "import src/auth/policy",
    ] {
        assert!(
            items.contains_key(identity),
            "{identity}: {:?}",
            items.keys()
        );
    }
    assert!(!items.keys().any(|identity| identity.starts_with(UNKEYED)));
    assert!(
        typescript("src/auth/index.ts", "export const A = 1;").contains_key("const src/auth::A")
    );
}

#[test]
fn typescript_reformats_renames_moves_and_unkeyed_declarations() {
    let path = "src/auth/policy.ts";
    let base = typescript(path, MODULE);
    let reformatted = typescript(
        path,
        &MODULE
            .replace("// Only an explicit allowing grant allows.", "")
            .replace("/** Whether a grant allows the caller. */", "// Reworded.")
            .replace(
                "return grant.kind === \"allow\";",
                "return grant.kind\n    === \"allow\";",
            ),
    );
    assert_eq!(reformatted, base);
    let renamed = typescript(
        path,
        &MODULE.replace("function grantAllows", "function allows"),
    );
    assert_eq!(
        renamed["function src/auth/policy::allows"].rename_hash,
        base["function src/auth/policy::grantAllows"].rename_hash
    );
    let moved = typescript("src/auth/grants.ts", MODULE);
    assert_eq!(
        moved["function src/auth/grants::grantAllows"].rename_hash,
        base["function src/auth/policy::grantAllows"].rename_hash
    );
    // Overload signatures and ambient declarations are not keyed.
    let overloaded = typescript(
        path,
        "export function f(a: string): string;\nexport function f(a: number): number;\nexport function f(a: any) { return a; }\ndeclare module \"x\" { const y: number; }\n",
    );
    assert!(
        overloaded
            .keys()
            .any(|identity| identity.starts_with(UNKEYED)),
        "{:?}",
        overloaded.keys()
    );
    assert!(!overloaded
        .keys()
        .any(|identity| identity.starts_with("function")));
}
