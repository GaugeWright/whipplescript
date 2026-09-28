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
    let bumped = digest("whipplescript.canon.rust/3 tree-sitter-rust/0.25", &print);
    assert_ne!(current["fn crate::f"].canon_hash, bumped);
    assert_eq!(
        current["fn crate::f"].canon_hash,
        digest(RustItems::VERSION, &print),
        "the version rides in the hash, so a bump re-keys every unit once"
    );
    // Alpha-renaming locals was such a bump: against what the version-1
    // canonicalizers minted for the same files, every hash moved and no
    // identity did.
    let re_keyed = |current: BTreeMap<String, CanonDecl>, previous: &[(&str, &str, &str)]| {
        assert_eq!(
            current.keys().map(String::as_str).collect::<Vec<_>>(),
            previous
                .iter()
                .map(|(identity, _, _)| *identity)
                .collect::<Vec<_>>(),
            "no identity moved"
        );
        for (identity, canon_hash, rename_hash) in previous {
            let decl = &current[*identity];
            assert_ne!(decl.canon_hash, *canon_hash, "{identity}");
            assert_ne!(decl.rename_hash, *rename_hash, "{identity}");
        }
    };
    re_keyed(rust("crates/auth/src/policy.rs", AUTH), RUST_VERSION_1);
    re_keyed(
        typescript("src/auth/policy.ts", MODULE),
        TYPESCRIPT_VERSION_1,
    );
    re_keyed(
        TypeScriptItems::tsx()
            .canonical_declarations_at("src/auth/policy.tsx", MODULE)
            .expect("a TSX file always has a canonical form")
            .into_iter()
            .map(|decl| (decl.identity.clone(), decl))
            .collect(),
        TSX_VERSION_1,
    );
}

/// What `whipplescript.canon.rust/1` minted for `AUTH`: identity, canonical
/// hash, rename hash.
const RUST_VERSION_1: &[(&str, &str, &str)] = &[
    (
        "fn crates/auth::policy::checks::deny",
        "157afe7ff3f9fe1331a9701e287ece44",
        "755f6de28c55bf89854b4af6230e1e58",
    ),
    (
        "fn crates/auth::policy::grant_allows",
        "2428b5dbfb2200278d5764e67ec85642",
        "238d366b24a589c80612427841cec166",
    ),
    (
        "impl crates/auth::policy::std::fmt::Display for Owner",
        "a09e4069e8daeb625dc344910c81d837",
        "a09e4069e8daeb625dc344910c81d837",
    ),
    (
        "impl crates/auth::policy::std::fmt::Display for Worker",
        "f8e971dbf1dd2e9dd8943c14f475a5c3",
        "f8e971dbf1dd2e9dd8943c14f475a5c3",
    ),
    (
        "struct crates/auth::policy::Owner",
        "8914b63735b532e20ca4d3789da19848",
        "a7b568542fd34c40e91a9732f6b0f003",
    ),
    (
        "struct crates/auth::policy::Worker",
        "5441a300e223c5894bda52bcf7fb40f7",
        "a7b568542fd34c40e91a9732f6b0f003",
    ),
    (
        "use crates/auth::policy",
        "9524b638033d4a5563e2698b0013b505",
        "9524b638033d4a5563e2698b0013b505",
    ),
];

/// What `whipplescript.canon.typescript/1` minted for `MODULE`.
const TYPESCRIPT_VERSION_1: &[(&str, &str, &str)] = &[
    (
        "class src/auth/policy::Owner",
        "ea2434e2150daa610b2e7cd43830fb54",
        "c8e5abc61c0bb74656fa98ec27f86742",
    ),
    (
        "const src/auth/policy::LIMIT",
        "811a8960238d1d35cfa8aea616d34cf2",
        "cd2b5ca6eb10677d30ee73e4e6da5c7c",
    ),
    (
        "export src/auth/policy::default",
        "9a379ff7b009692ecc176d448931c394",
        "9a379ff7b009692ecc176d448931c394",
    ),
    (
        "function src/auth/policy::checks::deny",
        "941b13361357ad6508bf128b99fe3f94",
        "86ea4207a045049f8bb40deaa7fce466",
    ),
    (
        "function src/auth/policy::grantAllows",
        "32daf90ff388b6fde9755ad98782920e",
        "dcd2460888782bbb70dcb660af7f779e",
    ),
    (
        "import src/auth/policy",
        "1a9181bfc9a1747deeffc7be90e6e21f",
        "1a9181bfc9a1747deeffc7be90e6e21f",
    ),
    (
        "interface src/auth/policy::Caller",
        "86b51afba29dad1cb5e6d33a57285a64",
        "4c5bf69179b685d61b0ec1f72a7f8987",
    ),
    (
        "type src/auth/policy::Kind",
        "d73be5b5620d8969aa540854ecea5e22",
        "b3339976a5c65881bbbe0e15ddb98753",
    ),
];

/// What `whipplescript.canon.tsx/1` minted for `MODULE`.
const TSX_VERSION_1: &[(&str, &str, &str)] = &[
    (
        "class src/auth/policy::Owner",
        "dad485ab9876b6594ed90daff64a24fb",
        "f826bada277b14d6dbbe5be67dd4bc7e",
    ),
    (
        "const src/auth/policy::LIMIT",
        "795ae1a6c483ac0641d952ff97576be7",
        "59b07c9855fe61d7081fd912c04097da",
    ),
    (
        "export src/auth/policy::default",
        "bdf72d3f0d9d70a65eb60409041bb66a",
        "bdf72d3f0d9d70a65eb60409041bb66a",
    ),
    (
        "function src/auth/policy::checks::deny",
        "ce3c171eaf895910059c67615cd79481",
        "d437f148579cc6b2417c39e8380aa90b",
    ),
    (
        "function src/auth/policy::grantAllows",
        "b16d36de88d3f045cffdfd89bc9bc9d2",
        "2f9fbadd8171604c45b11f08dce98ded",
    ),
    (
        "import src/auth/policy",
        "7fa8bb7347fbc640dcf9b638e8af1ccc",
        "7fa8bb7347fbc640dcf9b638e8af1ccc",
    ),
    (
        "interface src/auth/policy::Caller",
        "5519238136cb8e30efde100b9e29bc7e",
        "5f372e964fcdb495b8dbf33c3bb6da85",
    ),
    (
        "type src/auth/policy::Kind",
        "9e5e48a73d0ec6ff87b2d6c8d87e20dc",
        "e69a53d3095ec768055f98042365d116",
    ),
];

/// The first item's print as written: what a unit prints when its locals
/// are not renamed.
fn print_of(source: &str) -> String {
    let mut parser = Parser::new();
    parser
        .set_language(&RustItems::language())
        .expect("the Rust grammar loads");
    let tree = parser.parse(source, None).expect("a parse");
    let item = tree.root_node().named_child(0).expect("an item");
    print(item, source.as_bytes(), RustItems::comment, None, None)
}

/// The first item's canonical print, locals renamed where they resolve.
fn canonical_of(source: &str) -> String {
    let mut parser = Parser::new();
    parser
        .set_language(&RustItems::language())
        .expect("the Rust grammar loads");
    let tree = parser.parse(source, None).expect("a parse");
    let item = tree.root_node().named_child(0).expect("an item");
    let locals = alpha::rust(item, source.as_bytes());
    print(
        item,
        source.as_bytes(),
        RustItems::comment,
        None,
        locals.as_ref(),
    )
}

/// The one function `f` in `source`, at the package root.
fn rust_f(source: &str) -> CanonDecl {
    rust("src/lib.rs", source)
        .remove("fn crate::f")
        .expect("a keyed fn f")
}

/// Whether two sources' function `f` hash alike: print and rename hash.
fn rust_alike(a: &str, b: &str) -> bool {
    let (a, b) = (rust_f(a), rust_f(b));
    assert_eq!(
        a.canon_hash == b.canon_hash,
        a.rename_hash == b.rename_hash,
        "the print and the rename hash agree on a unit named alike"
    );
    a.canon_hash == b.canon_hash
}

/// Whether `f` in `source` printed as written, as before locals were renamed.
fn rust_as_written(source: &str) -> bool {
    rust_f(source).canon_hash == digest(RustItems::VERSION, &print_of(source))
}

#[test]
fn rust_locals_and_parameters_are_alpha_renamed() {
    assert_eq!(
        canonical_of("fn f(x: u32) -> u32 { let y = x; y }"),
        "fn f ( #0 : u32 ) -> u32 { let #1 = #0 ; #1 }"
    );
    let total = r#"
pub fn f(items: &[u32], bonus: u32) -> u32 {
    let mut sum = bonus;
    for item in items {
        sum += *item;
    }
    let double = |value: u32| value * 2;
    let label: &str = "total";
    double(sum) + label.len() as u32
}
"#;
    let renamed = total
        .replace("items", "xs")
        .replace("bonus", "extra")
        .replace("sum", "acc")
        .replace("item", "x")
        .replace("double", "twice")
        .replace("value", "v")
        .replace("label", "name");
    assert!(rust_alike(total, &renamed), "{}", canonical_of(&renamed));
    // A method's locals rename inside its impl, and the impl is one unit.
    let method = "struct G;\nimpl G {\n    fn allows(&self, caller: &str) -> bool { let wanted = caller; wanted.is_empty() }\n}\n";
    let path = "src/lib.rs";
    assert_eq!(
        rust(path, method)["impl crate::G"],
        rust(
            path,
            &method.replace("caller", "who").replace("wanted", "w")
        )["impl crate::G"]
    );
    // A pure rename of the function whose locals were also renamed carries.
    let moved = rust(path, &renamed.replace("fn f", "fn g"));
    assert_eq!(moved["fn crate::g"].rename_hash, rust_f(total).rename_hash);
}

#[test]
fn rust_shadowing_resolves_each_use_to_its_binding() {
    // The initializer of a shadowing `let` sees the binding it shadows.
    let shadowed = "fn f(x: u32) -> u32 { let x = x + 1; x }";
    assert_eq!(
        canonical_of(shadowed),
        "fn f ( #0 : u32 ) -> u32 { let #1 = #0 + 1 ; #1 }"
    );
    assert!(rust_alike(
        shadowed,
        "fn f(a: u32) -> u32 { let b = a + 1; b }"
    ));
    assert!(!rust_alike(
        shadowed,
        "fn f(a: u32) -> u32 { let b = a + 1; a }"
    ));
    // A block's binding ends with the block.
    let inner = "fn f(a: u32) -> u32 { let b = { let a = 2; a }; a + b }";
    assert!(rust_alike(
        inner,
        "fn f(p: u32) -> u32 { let q = { let r = 2; r }; p + q }"
    ));
    assert!(!rust_alike(
        inner,
        "fn f(p: u32) -> u32 { let q = { let r = 2; p }; p + q }"
    ));
    // A closure's parameter shadows the function's for its body only.
    let closure = "fn f(x: u32) -> u32 { let g = |x: u32| x + 1; g(x) }";
    assert!(rust_alike(
        closure,
        "fn f(a: u32) -> u32 { let g = |b: u32| b + 1; g(a) }"
    ));
    assert!(!rust_alike(
        closure,
        "fn f(a: u32) -> u32 { let g = |b: u32| a + 1; g(a) }"
    ));
}

#[test]
fn rust_swapping_which_local_is_used_is_a_change() {
    assert!(!rust_alike(
        "fn f(a: String, b: &str) -> String { a + b }",
        "fn f(a: String, b: &str) -> String { b + a }"
    ));
    assert!(!rust_alike(
        "fn f(a: u32, b: u32) -> u32 { let c = a; c - b }",
        "fn f(a: u32, b: u32) -> u32 { let c = b; c - a }"
    ));
}

#[test]
fn rust_unresolved_constructs_print_as_written() {
    // Each pair differs only in a local's name. Renamed, the pair would print
    // alike, and in each first pair it would be a false equality: a macro
    // captures `x` inside a string, and a shorthand field is named by it.
    for (a, b) in [
        (
            "fn f(x: u32) -> String { format!(\"{x}\") }",
            "fn f(y: u32) -> String { format!(\"{x}\") }",
        ),
        (
            "fn f(x: u32) -> P { P { x } }",
            "fn f(y: u32) -> P { P { y } }",
        ),
        (
            "fn f(p: P) -> u32 { let P { x, .. } = p; x }",
            "fn f(p: P) -> u32 { let P { y, .. } = p; y }",
        ),
        (
            "fn f(t: (u32, u32)) -> u32 { let (a, b) = t; a + b }",
            "fn f(t: (u32, u32)) -> u32 { let (c, d) = t; c + d }",
        ),
        (
            "fn f(o: Option<u32>) -> u32 { match o { Some(v) => v, None => 0 } }",
            "fn f(o: Option<u32>) -> u32 { match o { Some(w) => w, None => 0 } }",
        ),
        (
            "fn f(o: Option<u32>) -> u32 { if let Some(v) = o { v } else { 0 } }",
            "fn f(o: Option<u32>) -> u32 { if let Some(w) = o { w } else { 0 } }",
        ),
        (
            "fn f(x: u32) -> u32 { fn g(x: u32) -> u32 { x } g(x) }",
            "fn f(y: u32) -> u32 { fn g(x: u32) -> u32 { x } g(y) }",
        ),
        (
            "fn f(x: u32) -> u32 { #[cfg(test)] let x = 1; x }",
            "fn f(y: u32) -> u32 { #[cfg(test)] let z = 1; y }",
        ),
        // Without `a`, each reads the global its name names.
        (
            "fn f(#[cfg(a)] x: u32) -> u32 { x }",
            "fn f(#[cfg(a)] y: u32) -> u32 { y }",
        ),
        // An upper-case pattern may be a unit struct or a constant.
        (
            "fn f(x: u32) -> u32 { let X = x; X }",
            "fn f(y: u32) -> u32 { let X = y; X }",
        ),
        // A `let ... else` pattern may be refutable.
        (
            "fn f(o: u32) -> u32 { let x = o else { return 0 }; x }",
            "fn f(o: u32) -> u32 { let y = o else { return 0 }; y }",
        ),
    ] {
        assert!(rust_as_written(a), "{a}");
        assert!(rust_as_written(b), "{b}");
        assert!(!rust_alike(a, b), "{a} / {b}");
    }
    // A macro among an impl's members leaves the whole impl as written.
    let path = "src/lib.rs";
    let with_macro = "struct G;\nimpl G {\n    m!();\n    fn a(&self, x: u32) -> u32 { x }\n}\n";
    let impl_hash = |source: &str| rust(path, source)["impl crate::G"].canon_hash.clone();
    assert_ne!(
        impl_hash(with_macro),
        impl_hash(&with_macro.replace('x', "y"))
    );
}

#[test]
fn rust_globals_imports_fields_and_paths_are_not_renamed() {
    let imported = "use crate::config::limit;\nfn f(n: u32) -> u32 { n + limit }\n";
    assert!(rust_alike(
        imported,
        "use crate::config::limit;\nfn f(m: u32) -> u32 { m + limit }\n"
    ));
    assert!(!rust_alike(
        imported,
        "use crate::config::limit;\nfn f(m: u32) -> u32 { m + cap }\n"
    ));
    // A local named alike in another item does not capture the global.
    let beside = format!("fn g(limit: u32) -> u32 {{ limit }}\n{imported}");
    assert_eq!(rust_f(&beside), rust_f(imported));
    assert!(canonical_of(imported).contains("limit"));
    // Nor does one that has gone out of scope: the unit prints as written.
    assert!(rust_as_written(
        "fn f(n: u32) -> u32 { { let limit = n; } limit }"
    ));
    // A field after `.` and a path segment keep their names.
    let fields = "fn f(p: P) -> u32 { let x = p.x; x + P::y() }";
    assert!(rust_alike(
        fields,
        "fn f(q: P) -> u32 { let z = q.x; z + P::y() }"
    ));
    assert!(!rust_alike(
        fields,
        "fn f(q: P) -> u32 { let z = q.z; z + P::y() }"
    ));
    assert!(!rust_alike(
        fields,
        "fn f(q: P) -> u32 { let z = q.x; z + P::z() }"
    ));
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

/// The first declaration of a TypeScript source: printed as written, and
/// with its locals renamed where they resolve.
fn typescript_prints(source: &str, tsx: bool) -> (String, String) {
    let mut parser = Parser::new();
    let language = if tsx {
        Tsx::language()
    } else {
        TypeScript::language()
    };
    parser
        .set_language(&language)
        .expect("the TypeScript grammar loads");
    let tree = parser.parse(source, None).expect("a parse");
    let root = tree.root_node();
    let mut cursor = root.walk();
    let child = root
        .named_children(&mut cursor)
        .find(|child| child.kind() != "import_statement")
        .expect("a declaration");
    let declaration = declared(child).expect("a declaration");
    let locals = alpha::typescript(declaration, source.as_bytes());
    let comment = |kind: &str| kind == "comment";
    (
        print(child, source.as_bytes(), comment, None, None),
        print(child, source.as_bytes(), comment, None, locals.as_ref()),
    )
}

/// The one declaration named `f` in a TypeScript or TSX source.
fn typescript_f(source: &str, tsx: bool) -> CanonDecl {
    let items = if tsx {
        TypeScriptItems::tsx()
    } else {
        TypeScriptItems::typescript()
    };
    items
        .canonical_declarations_at("src/f.ts", source)
        .expect("a canonical form")
        .into_iter()
        .find(|decl| decl.identity.ends_with("src/f::f"))
        .expect("a keyed f")
}

fn typescript_alike(a: &str, b: &str) -> bool {
    let (a, b) = (typescript_f(a, false), typescript_f(b, false));
    assert_eq!(
        a.canon_hash == b.canon_hash,
        a.rename_hash == b.rename_hash,
        "the print and the rename hash agree on a unit named alike"
    );
    a.canon_hash == b.canon_hash
}

fn typescript_as_written(source: &str) -> bool {
    let (written, _) = typescript_prints(source, false);
    typescript_f(source, false).canon_hash == digest(TypeScript::VERSION, &written)
}

#[test]
fn typescript_locals_and_parameters_are_alpha_renamed() {
    assert_eq!(
        typescript_prints("function f(x: number) { const y = x; return y; }", false).1,
        "function f ( #0 : number ) { const #1 = #0 ; return #1 ; }"
    );
    let total = r#"
export function f(items: number[], bonus?: number, ...rest: number[]): number {
  let sum = bonus ?? 0;
  for (const item of items) {
    sum += item;
  }
  for (let index = 0; index < rest.length; index++) {
    sum += rest[index];
  }
  const double = (value: number) => value * 2;
  try {
    return double(sum);
  } catch (error) {
    throw error;
  }
}
"#;
    let renamed = total
        .replace("items", "xs")
        .replace("bonus", "extra")
        .replace("rest", "more")
        .replace("sum", "acc")
        .replace("item", "x")
        .replace("index", "i")
        .replace("double", "twice")
        .replace("value", "v")
        .replace("error", "e");
    assert!(
        typescript_alike(total, &renamed),
        "{}",
        typescript_prints(&renamed, false).1
    );
    // A `const` arrow and a class's methods rename too.
    assert!(typescript_alike(
        "export const f = (a: number, b: number) => a * b;",
        "export const f = (x: number, y: number) => x * y;"
    ));
    assert!(typescript_alike(
        "export class f { scale(by: number) { const next = this.size * by; return next; } }",
        "export class f { scale(k: number) { const n = this.size * k; return n; } }"
    ));
    // TSX: an intrinsic element's name is not a binding; a component's is.
    let component =
        "export function f(props: Props) { const title = props.title; return <div>{title}</div>; }";
    assert_eq!(
        typescript_f(component, true),
        typescript_f(
            &component
                .replace("props", "p")
                .replace("title}", "t}")
                .replace("const title", "const t"),
            true
        )
    );
    assert!(typescript_prints(component, true).1.contains("< div >"));
}

#[test]
fn typescript_shadowing_and_dead_zones_resolve_each_use_to_its_binding() {
    let shadowed = "function f(x: number) { { const x = 2; g(x); } return x; }";
    assert!(typescript_alike(
        shadowed,
        "function f(a: number) { { const b = 2; g(b); } return a; }"
    ));
    assert!(!typescript_alike(
        shadowed,
        "function f(a: number) { { const b = 2; g(a); } return a; }"
    ));
    // A use before a block's `const` is that binding in its dead zone, not
    // the outer one: the first throws and the second does not.
    assert!(!typescript_alike(
        "function f(x: number) { { g(x); const x = 1; } }",
        "function f(x: number) { { g(x); const y = 1; } }"
    ));
    // An arrow's parameter shadows for its body only.
    let arrow = "function f(x: number) { const g = (x: number) => x + 1; return g(x); }";
    assert!(typescript_alike(
        arrow,
        "function f(a: number) { const g = (b: number) => b + 1; return g(a); }"
    ));
    assert!(!typescript_alike(
        arrow,
        "function f(a: number) { const g = (b: number) => a + 1; return g(a); }"
    ));
}

#[test]
fn typescript_swapping_which_local_is_used_is_a_change() {
    assert!(!typescript_alike(
        "function f(a: string, b: string) { return a + b; }",
        "function f(a: string, b: string) { return b + a; }"
    ));
}

#[test]
fn typescript_unresolved_constructs_print_as_written() {
    // Each pair differs only in a local's name. Renamed, each first pair
    // would print alike and be a false equality: a shorthand property is
    // named by its local, and `eval` reads one by name.
    for (a, b) in [
        (
            "function f(x: number) { return { x }; }",
            "function f(y: number) { return { y }; }",
        ),
        (
            "function f(x: number) { return eval(\"x\"); }",
            "function f(y: number) { return eval(\"x\"); }",
        ),
        (
            "function f({ a }: P) { return a; }",
            "function f({ b }: P) { return b; }",
        ),
        (
            "function f(t: [number, number]) { const [a, b] = t; return a + b; }",
            "function f(t: [number, number]) { const [c, d] = t; return c + d; }",
        ),
        (
            "function f() { var x = 1; return x; }",
            "function f() { var y = 1; return y; }",
        ),
        // `var` hoists to the function, so a unit with one is not renamed
        // at all, even where its other locals would resolve.
        (
            "function f(n: number) { var x = 1; return n + x; }",
            "function f(m: number) { var x = 1; return m + x; }",
        ),
        (
            "function f(x: number) { return arguments.length + x; }",
            "function f(y: number) { return arguments.length + y; }",
        ),
        (
            "function f(a: number, b = a) { return b; }",
            "function f(c: number, d = c) { return d; }",
        ),
        (
            "function f(x: number) { function g() { return x; } return g(); }",
            "function f(y: number) { function g() { return y; } return g(); }",
        ),
        (
            "class f { constructor(private x: number) {} }",
            "class f { constructor(private y: number) {} }",
        ),
        (
            "function f({ a }: P, n: number) { return a + n; }",
            "function f({ a }: P, m: number) { return a + m; }",
        ),
        (
            "function f(n: number, ...[a, b]: number[]) { return n + a; }",
            "function f(m: number, ...[a, b]: number[]) { return m + a; }",
        ),
        // Its uses parse as the keyword, so it could not rename with them.
        (
            "function f(undefined: number, n: number) { return n; }",
            "function f(undefined: number, m: number) { return m; }",
        ),
        (
            "function f(xs: number[]) { for (var k of xs) g(k); return xs; }",
            "function f(ys: number[]) { for (var k of ys) g(k); return ys; }",
        ),
    ] {
        assert!(typescript_as_written(a), "{a}");
        assert!(typescript_as_written(b), "{b}");
        assert!(!typescript_alike(a, b), "{a} / {b}");
    }
    // A default that names no parameter still resolves.
    assert!(typescript_alike(
        "function f(a: number, b = 1) { return a + b; }",
        "function f(c: number, d = 1) { return c + d; }"
    ));
}

#[test]
fn typescript_globals_imports_and_properties_are_not_renamed() {
    let imported =
        "import { limit } from \"./config\";\nexport function f(n: number) { return n + limit; }\n";
    assert!(typescript_alike(
        imported,
        &imported.replace("(n", "(m").replace("n +", "m +")
    ));
    assert!(!typescript_alike(
        imported,
        &imported.replace("n + limit", "n + cap")
    ));
    // A local named alike in another declaration does not capture it.
    let beside = format!("{imported}export function g(limit: number) {{ return limit; }}\n");
    assert_eq!(typescript_f(&beside, false), typescript_f(imported, false));
    assert!(typescript_prints(imported, false).1.contains("limit"));
    // Nor does one that has gone out of scope: it prints as written.
    assert!(typescript_as_written(
        "function f(n: number) { { const limit = n; } return limit; }"
    ));
    // A property keeps its name.
    let property = "function f(p: P) { const x = p.x; return x; }";
    assert!(typescript_alike(
        property,
        "function f(q: P) { const y = q.x; return y; }"
    ));
    assert!(!typescript_alike(
        property,
        "function f(q: P) { const y = q.y; return y; }"
    ));
}
