//! Tree-sitter canonicalizers for Rust and TypeScript: exact match only,
//! locals alpha-renamed where `alpha` resolves them exactly.

use std::collections::BTreeMap;

use tree_sitter::{Language, Node, Parser};
use whipplescript_store::vcs::{CanonDecl, DeclCanonicalizer};

use crate::alpha::{self, Renames};
use crate::{digest, UNKEYED};

/// One declaration unit before hashing.
struct Unit {
    identity: String,
    print: String,
    rename: String,
}

/// What one language contributes to the shared engine.
trait Grammar {
    /// The canonicalizer's version: the grammar crate's and the normalizer's.
    const VERSION: &'static str;
    fn language() -> Language;
    fn comment(kind: &str) -> bool;
    /// The module path a file contributes, from its path.
    fn module_path(path: &str) -> String;
    /// The units of one declaration list, into `units`, or into `unkeyed`
    /// when a unit cannot be keyed exactly.
    fn items(
        node: Node<'_>,
        source: &[u8],
        scope: &str,
        units: &mut Vec<Unit>,
        unkeyed: &mut Vec<String>,
    );
}

/// The canonical print of a subtree: its tokens, comments dropped, one space
/// apart. `erase` is a node whose text the rename print replaces with `_`;
/// `locals` gives each alpha-renamed identifier its canonical name.
fn print(
    node: Node<'_>,
    source: &[u8],
    comment: fn(&str) -> bool,
    erase: Option<Node<'_>>,
    locals: Option<&Renames>,
) -> String {
    let mut tokens = Vec::new();
    let mut stack = vec![node];
    while let Some(node) = stack.pop() {
        if comment(node.kind()) {
            continue;
        }
        if Some(node.id()) == erase.map(|erase| erase.id()) {
            tokens.push("_".to_owned());
            continue;
        }
        if let Some(canonical) = locals.and_then(|locals| locals.get(&node.id())) {
            tokens.push(canonical.clone());
            continue;
        }
        if node.child_count() == 0 {
            if let Ok(text) = node.utf8_text(source) {
                if !text.trim().is_empty() {
                    tokens.push(text.to_owned());
                }
            }
            continue;
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
    tokens.join(" ")
}

/// The compact text of a node, for identities: tokens without spaces.
fn compact(node: Node<'_>, source: &[u8], comment: fn(&str) -> bool) -> String {
    print(node, source, comment, None, None).replace(' ', "")
}

fn canonicalize<G: Grammar>(path: &str, source: &str) -> Option<Vec<CanonDecl>> {
    let mut parser = Parser::new();
    parser.set_language(&G::language()).ok()?;
    let tree = parser.parse(source, None)?;
    let mut units = Vec::new();
    let mut unkeyed = Vec::new();
    let module = G::module_path(path);
    G::items(
        tree.root_node(),
        source.as_bytes(),
        &module,
        &mut units,
        &mut unkeyed,
    );
    // Two units with one identity are ambiguous: neither is keyed.
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for unit in &units {
        *seen.entry(unit.identity.clone()).or_default() += 1;
    }
    let mut decls = Vec::new();
    for unit in units {
        if seen[&unit.identity] > 1 {
            unkeyed.push(unit.print);
            continue;
        }
        decls.push(CanonDecl {
            identity: unit.identity,
            canon_hash: digest(G::VERSION, &unit.print),
            rename_hash: digest(G::VERSION, &unit.rename),
        });
    }
    if !unkeyed.is_empty() {
        let print = unkeyed.join("\n");
        decls.push(CanonDecl {
            identity: format!("{UNKEYED} {path}"),
            canon_hash: digest(G::VERSION, &print),
            rename_hash: digest(G::VERSION, &print),
        });
    }
    decls.sort_by(|a, b| a.identity.cmp(&b.identity));
    Some(decls)
}

/// Rust items: functions, types, traits, impls, constants, statics, macros
/// by example and modules, each keyed by kind and qualified name.
pub struct RustItems;

impl Grammar for RustItems {
    const VERSION: &'static str = "whipplescript.canon.rust/2 tree-sitter-rust/0.24";

    fn language() -> Language {
        tree_sitter_rust::LANGUAGE.into()
    }

    fn comment(kind: &str) -> bool {
        matches!(kind, "line_comment" | "block_comment")
    }

    /// `crates/foo/src/bar/mod.rs` is `crates/foo::bar`; `src/lib.rs` and
    /// `src/main.rs` are the package root, named by its directory.
    fn module_path(path: &str) -> String {
        let path = path.trim_start_matches("./");
        let (package, module) = match path.rsplit_once("/src/") {
            Some((package, module)) => (package.to_owned(), module),
            None => match path.strip_prefix("src/") {
                Some(module) => (String::new(), module),
                None => (String::new(), path),
            },
        };
        let module = module.strip_suffix(".rs").unwrap_or(module);
        let mut parts: Vec<&str> = module.split('/').collect();
        if matches!(parts.last(), Some(&"lib" | &"main" | &"mod")) {
            parts.pop();
        }
        std::iter::once(if package.is_empty() {
            "crate"
        } else {
            package.as_str()
        })
        .chain(parts)
        .collect::<Vec<_>>()
        .join("::")
    }

    fn items(
        node: Node<'_>,
        source: &[u8],
        scope: &str,
        units: &mut Vec<Unit>,
        unkeyed: &mut Vec<String>,
    ) {
        let mut cursor = node.walk();
        let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
        let mut uses = Vec::new();
        let mut attributes: Vec<Node<'_>> = Vec::new();
        for child in children {
            let kind = child.kind();
            if Self::comment(kind) {
                continue;
            }
            if kind == "attribute_item" || kind == "inner_attribute_item" {
                attributes.push(child);
                continue;
            }
            let prefix: Vec<String> = attributes
                .drain(..)
                .map(|attribute| print(attribute, source, Self::comment, None, None))
                .collect();
            // A path attribute moves a module out of path-derived identity.
            let pathed = prefix.iter().any(|attribute| attribute.contains("path ="));
            let unkeyable = child.has_error() || pathed;
            let locals = if unkeyable {
                None
            } else {
                alpha::rust(child, source)
            };
            let printed = |erase: Option<Node<'_>>| {
                let mut text = prefix.clone();
                text.push(print(child, source, Self::comment, erase, locals.as_ref()));
                text.join(" ")
            };
            if unkeyable {
                unkeyed.push(printed(None));
                continue;
            }
            let name = child.child_by_field_name("name");
            let named = |kind: &str| {
                name.map(|name| format!("{kind} {scope}::{}", compact(name, source, Self::comment)))
            };
            let identity = match kind {
                "function_item" | "function_signature_item" => named("fn"),
                "struct_item" => named("struct"),
                "enum_item" => named("enum"),
                "union_item" => named("union"),
                "trait_item" => named("trait"),
                "type_item" => named("type"),
                "const_item" => named("const"),
                "static_item" => named("static"),
                "macro_definition" => named("macro"),
                "impl_item" => {
                    // An impl's target is part of its kind: two impls of one
                    // trait for two types are two units.
                    let target = child.child_by_field_name("type");
                    let trait_name = child.child_by_field_name("trait");
                    target.map(|target| match trait_name {
                        Some(trait_name) => format!(
                            "impl {scope}::{} for {}",
                            compact(trait_name, source, Self::comment),
                            compact(target, source, Self::comment)
                        ),
                        None => format!("impl {scope}::{}", compact(target, source, Self::comment)),
                    })
                }
                "mod_item" => {
                    // An inline module nests its items' identities; a module
                    // declaration names the file that holds them.
                    match (name, child.child_by_field_name("body")) {
                        (Some(name), Some(body)) => {
                            let inner =
                                format!("{scope}::{}", compact(name, source, Self::comment));
                            Self::items(body, source, &inner, units, unkeyed);
                            continue;
                        }
                        _ => named("mod"),
                    }
                }
                "use_declaration" | "extern_crate_declaration" => {
                    uses.push(printed(None));
                    continue;
                }
                _ => None,
            };
            match identity {
                Some(identity) => units.push(Unit {
                    identity,
                    print: printed(None),
                    rename: printed(name),
                }),
                // A macro invocation at item level, or anything else this
                // canonicalizer does not key: the file's unkeyed unit.
                None => unkeyed.push(printed(None)),
            }
        }
        if !uses.is_empty() {
            let print = uses.join("\n");
            units.push(Unit {
                identity: format!("use {scope}"),
                rename: print.clone(),
                print,
            });
        }
    }
}

impl DeclCanonicalizer for RustItems {
    fn canonical_declarations(&self, source: &str) -> Option<Vec<CanonDecl>> {
        canonicalize::<Self>("src/lib.rs", source)
    }
    fn canonical_declarations_at(&self, path: &str, source: &str) -> Option<Vec<CanonDecl>> {
        canonicalize::<Self>(path, source)
    }
    fn version(&self) -> Option<&str> {
        Some(<Self as Grammar>::VERSION)
    }
}

/// TypeScript declarations: functions, classes, interfaces, type aliases,
/// enums, variables and namespaces, each keyed by kind and qualified name.
pub struct TypeScriptItems {
    tsx: bool,
}

impl TypeScriptItems {
    pub fn typescript() -> Self {
        Self { tsx: false }
    }
    pub fn tsx() -> Self {
        Self { tsx: true }
    }
}

struct TypeScript;
struct Tsx;

/// What a TypeScript statement declares: `export` wraps a declaration without
/// changing what it declares, and a top-level namespace parses inside an
/// expression statement. `None` for an export with nothing declared.
fn declared(child: Node<'_>) -> Option<Node<'_>> {
    match child.kind() {
        "export_statement" => child.child_by_field_name("declaration"),
        "expression_statement" => child
            .named_child(0)
            .filter(|inner| matches!(inner.kind(), "internal_module" | "module")),
        _ => Some(child),
    }
}

fn typescript_items(
    node: Node<'_>,
    source: &[u8],
    scope: &str,
    units: &mut Vec<Unit>,
    unkeyed: &mut Vec<String>,
) {
    let comment = |kind: &str| kind == "comment";
    let mut cursor = node.walk();
    let children: Vec<Node<'_>> = node.named_children(&mut cursor).collect();
    // An overloaded function is not keyed: neither its signatures nor its
    // implementation.
    let overloaded: std::collections::BTreeSet<String> = children
        .iter()
        .filter_map(|child| declared(*child))
        .filter(|declaration| declaration.kind() == "function_signature")
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .map(|name| compact(name, source, comment))
        .collect();
    let mut imports = Vec::new();
    for child in children {
        if comment(child.kind()) {
            continue;
        }
        let (declaration, exported_default) = match declared(child) {
            Some(declaration) => (declaration, false),
            None => (child, child.kind() == "export_statement"),
        };
        let locals = if child.has_error() || exported_default {
            None
        } else {
            alpha::typescript(declaration, source)
        };
        let printed =
            |erase: Option<Node<'_>>| print(child, source, comment, erase, locals.as_ref());
        if child.has_error() {
            unkeyed.push(printed(None));
            continue;
        }
        if exported_default {
            if child.child_by_field_name("value").is_some() || child.to_sexp().contains("default") {
                units.push(Unit {
                    identity: format!("export {scope}::default"),
                    print: printed(None),
                    rename: printed(None),
                });
            } else {
                imports.push(printed(None));
            }
            continue;
        }
        let name = declaration.child_by_field_name("name");
        let named = |kind: &str| {
            name.map(|name| format!("{kind} {scope}::{}", compact(name, source, comment)))
        };
        let is_overloaded =
            name.is_some_and(|name| overloaded.contains(&compact(name, source, comment)));
        let identity = match declaration.kind() {
            "function_declaration" | "generator_function_declaration" if is_overloaded => None,
            "function_declaration" | "generator_function_declaration" => named("function"),
            "class_declaration" | "abstract_class_declaration" => named("class"),
            "interface_declaration" => named("interface"),
            "type_alias_declaration" => named("type"),
            "enum_declaration" => named("enum"),
            "lexical_declaration" | "variable_declaration" => {
                // One declarator is one unit; several in one statement are
                // not keyed apart.
                let mut declarators = declaration.walk();
                let names: Vec<Node<'_>> = declaration
                    .named_children(&mut declarators)
                    .filter(|declarator| declarator.kind() == "variable_declarator")
                    .filter_map(|declarator| declarator.child_by_field_name("name"))
                    .collect();
                match names.as_slice() {
                    [only] if only.kind() == "identifier" => {
                        let rename = printed(Some(*only));
                        units.push(Unit {
                            identity: format!("const {scope}::{}", compact(*only, source, comment)),
                            print: printed(None),
                            rename,
                        });
                        continue;
                    }
                    _ => None,
                }
            }
            "internal_module" | "module" => match (name, declaration.child_by_field_name("body")) {
                (Some(name), Some(body)) if name.kind() == "identifier" => {
                    let inner = format!("{scope}::{}", compact(name, source, comment));
                    typescript_items(body, source, &inner, units, unkeyed);
                    continue;
                }
                _ => None,
            },
            "import_statement" => {
                imports.push(printed(None));
                continue;
            }
            // Ambient declarations, overload signatures and statements are
            // not keyed.
            _ => None,
        };
        match identity {
            Some(identity) => units.push(Unit {
                identity,
                print: printed(None),
                rename: printed(name),
            }),
            None => unkeyed.push(printed(None)),
        }
    }
    if !imports.is_empty() {
        let print = imports.join("\n");
        units.push(Unit {
            identity: format!("import {scope}"),
            rename: print.clone(),
            print,
        });
    }
}

fn typescript_module_path(path: &str) -> String {
    let path = path.trim_start_matches("./");
    let stem = [".d.ts", ".tsx", ".ts", ".mts", ".cts"]
        .iter()
        .find_map(|extension| path.strip_suffix(extension))
        .unwrap_or(path);
    stem.strip_suffix("/index").unwrap_or(stem).to_owned()
}

impl Grammar for TypeScript {
    const VERSION: &'static str = "whipplescript.canon.typescript/2 tree-sitter-typescript/0.23";
    fn language() -> Language {
        tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
    }
    fn comment(kind: &str) -> bool {
        kind == "comment"
    }
    fn module_path(path: &str) -> String {
        typescript_module_path(path)
    }
    fn items(
        node: Node<'_>,
        source: &[u8],
        scope: &str,
        units: &mut Vec<Unit>,
        unkeyed: &mut Vec<String>,
    ) {
        typescript_items(node, source, scope, units, unkeyed);
    }
}

impl Grammar for Tsx {
    const VERSION: &'static str = "whipplescript.canon.tsx/2 tree-sitter-typescript/0.23";
    fn language() -> Language {
        tree_sitter_typescript::LANGUAGE_TSX.into()
    }
    fn comment(kind: &str) -> bool {
        kind == "comment"
    }
    fn module_path(path: &str) -> String {
        typescript_module_path(path)
    }
    fn items(
        node: Node<'_>,
        source: &[u8],
        scope: &str,
        units: &mut Vec<Unit>,
        unkeyed: &mut Vec<String>,
    ) {
        typescript_items(node, source, scope, units, unkeyed);
    }
}

impl DeclCanonicalizer for TypeScriptItems {
    fn canonical_declarations(&self, source: &str) -> Option<Vec<CanonDecl>> {
        self.canonical_declarations_at("index.ts", source)
    }
    fn canonical_declarations_at(&self, path: &str, source: &str) -> Option<Vec<CanonDecl>> {
        if self.tsx {
            canonicalize::<Tsx>(path, source)
        } else {
            canonicalize::<TypeScript>(path, source)
        }
    }
    fn version(&self) -> Option<&str> {
        Some(if self.tsx {
            Tsx::VERSION
        } else {
            TypeScript::VERSION
        })
    }
}

#[cfg(test)]
#[path = "syntax_tests.rs"]
mod tests;
