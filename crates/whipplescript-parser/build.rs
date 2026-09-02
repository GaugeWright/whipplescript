//! Generates the body parser's `EFFECT_OPERATION_GRAMMAR` table from the
//! canonical embedded std package manifests (`std/manifests/*.json`).
//!
//! The manifests are the single source of construct grammar (DR-0011,
//! spec/construct-grammar.md "Two-Shape Meta-Grammar", Option A): each
//! `effect_operation` construct carries a `grammar` object, and this script
//! transcribes it into the `EffectOperationSpec` rows `parse_effect_operation`
//! reads. The spec types themselves stay hand-written in `body.rs`; only the
//! table const is generated (into `$OUT_DIR/effect_operation_grammar.rs`).
//!
//! A malformed manifest fails the build with a message naming the manifest and
//! the problem — grammar drift is impossible by construction.

use std::{env, fs, path::PathBuf};

use serde_json::Value;
// The DR-0011 grammar vocabulary has exactly one owner, `whipplescript-core`,
// and this script reads it from there instead of re-declaring it. It used to
// keep private copies "mirroring" core, and they drifted: core admitted `onto`
// as a `declaration_block` clause connective and this script did not, so a
// manifest the kernel's package registry accepted panicked the parser's build.
// A build script may depend on a crate in the graph as long as that crate does
// not depend back on the crate being built; `whipplescript-core` is a leaf.
use whipplescript_core::{
    CONSTRUCT_GRAMMAR_BINDING_MODES as BINDING_MODES,
    CONSTRUCT_GRAMMAR_CLAUSE_CONNECTIVES as CLAUSE_CONNECTIVES,
    CONSTRUCT_GRAMMAR_CLAUSE_KINDS as CLAUSE_KINDS, CONSTRUCT_GRAMMAR_CONNECTIVES as CONNECTIVES,
    CONSTRUCT_GRAMMAR_SLOT_KINDS as SLOT_KINDS,
};

/// The std manifests this build script reads, relative to this crate's manifest
/// dir: the ones whose constructs carry an `effect_operation` grammar the body
/// parser has to be able to parse.
///
/// This is NOT a copy of `EMBEDDED_STD_MANIFESTS`, and it must not be made into
/// one. (The constant also does not live where this comment used to say: it is
/// `crates/whipplescript-cli/src/lib.rs`, not `main.rs`.) The two lists answer
/// different questions and are deliberately different sizes:
///
///   this list   4 manifests, paired with DECL_GRAMMARS below — everything the
///               PARSER needs a compiled grammar row for, and nothing else. The
///               grammar-only files have no counterpart in the CLI at all.
///   the CLI's   15 manifests, two of them behind cargo features, and zero
///               grammars — everything a HOST needs to seed capability,
///               provider, profile and contract rows so a workflow runs with no
///               package lock.
///
/// A manifest with no construct grammar has nothing to contribute here, and a
/// grammar file has nothing to contribute to admission seeding. "Syncing" the
/// two would compile grammar rows for constructs the parser does not dispatch
/// on, or drop rows it does. What actually keeps the copies honest is
/// `scripts/check-vendored-std.sh`, below.
///
/// Paths are the crate-local `vendored-std/` copies, NOT the workspace root's
/// `std/`. A published crate tarball contains only files under the crate
/// directory, so a `../../std/...` read builds here and fails on crates.io.
/// The root `std/` stays the single source of truth;
/// `scripts/check-vendored-std.sh` fails the gate if a copy drifts from it.
const STD_MANIFESTS: &[&str] = &[
    // DR-0074 §12: custody is the fifteenth std package, carrying the
    // `custody.seal` effect_operation construct.
    "vendored-std/manifests/custody.json",
    "vendored-std/manifests/memory.json",
    "vendored-std/manifests/messaging.json",
    "vendored-std/manifests/vcs.json",
];

/// The grammar-only manifests (`std/grammars/*.json`) carrying the
/// declaration-family (`declaration_block`, Shape 1) construct grammars. Read
/// ONLY by this build script — deliberately NOT under `std/manifests/` so the
/// authorability-door glob cannot pick them up (blocker B1); NOT embedded in
/// the CLI. See std/grammars/README.md.
const DECL_GRAMMARS: &[&str] = &[
    "vendored-std/grammars/tracker.json",
    "vendored-std/grammars/coord.json",
    "vendored-std/grammars/files.json",
    "vendored-std/grammars/messaging-grammar.json",
    "vendored-std/grammars/memory-grammar.json",
    "vendored-std/grammars/vcs-grammar.json",
    "vendored-std/grammars/custody-grammar.json",
];

fn main() {
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR").expect("cargo always sets CARGO_MANIFEST_DIR"),
    );
    let out_dir = env::var("OUT_DIR").expect("cargo always sets OUT_DIR");

    let mut rows = String::new();
    let mut decl_rows = String::new();
    // Keyword uniqueness is shared across BOTH tables (declaration keywords and
    // effect_operation keywords occupy one namespace — conservative).
    let mut seen_keywords: Vec<(String, String)> = Vec::new();
    for relative in STD_MANIFESTS.iter().chain(DECL_GRAMMARS.iter()) {
        let path = manifest_dir.join(relative);
        println!("cargo:rerun-if-changed={}", path.display());
        let label = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| relative.to_string());
        let json = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "std manifest `{label}` could not be read from `{}`: {error}",
                path.display()
            )
        });
        let manifest: Value = serde_json::from_str(&json)
            .unwrap_or_else(|error| panic!("std manifest `{label}` is not valid JSON: {error}"));
        for library in manifest
            .get("libraries")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for construct in library
                .get("constructs")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                emit_construct_row(
                    &label,
                    construct,
                    &mut seen_keywords,
                    &mut rows,
                    &mut decl_rows,
                );
            }
        }
    }

    let decl_generated = format!(
        "// Generated by build.rs from std/grammars/*.json — do not edit.\n\
         //\n\
         // The compiled-in table of `declaration_block` grammars (DR-0011 Shape 1):\n\
         // each row transcribes one grammar-only std manifest construct's `grammar`\n\
         // object. Head-word dispatch (`declaration_block_spec_at`) reads this table.\n\
         pub(crate) const DECLARATION_BLOCK_GRAMMAR: &[DeclarationBlockSpec] = &[\n{decl_rows}];\n"
    );
    let decl_out_path = PathBuf::from(&out_dir).join("declaration_block_grammar.rs");
    fs::write(&decl_out_path, decl_generated).unwrap_or_else(|error| {
        panic!(
            "could not write generated grammar table `{}`: {error}",
            decl_out_path.display()
        )
    });

    let generated = format!(
        "// Generated by build.rs from std/manifests/*.json — do not edit.\n\
         //\n\
         // The compiled-in table of `effect_operation` grammars (DR-0011): each row\n\
         // transcribes one embedded std manifest construct's `grammar` object. A\n\
         // leading rule-body keyword that matches an entry here is parsed by\n\
         // `parse_effect_operation`.\n\
         const EFFECT_OPERATION_GRAMMAR: &[EffectOperationSpec] = &[\n{rows}];\n"
    );
    let out_path = PathBuf::from(&out_dir).join("effect_operation_grammar.rs");
    fs::write(&out_path, generated).unwrap_or_else(|error| {
        panic!(
            "could not write generated grammar table `{}`: {error}",
            out_path.display()
        )
    });

    emit_build_script_probe(&out_dir);
}

/// Record, for this crate's tests, which vocabulary this run validated against
/// and where this script's own executable is.
///
/// The snapshot consts are formatted from the names in scope above, so a future
/// private re-declaration of any vocabulary list shows up as a snapshot that no
/// longer equals `whipplescript-core`'s constant — which is what
/// `tests/construct_grammar_vocabulary.rs` asserts. The path lets the same test
/// re-run this exact script over a fixture manifest tree, so "the vocabulary is
/// shared" is proved by a manifest that parses rather than by reading the
/// source. Test scaffolding only: nothing in the parser reads this file.
fn emit_build_script_probe(out_dir: &str) {
    let executable = env::current_exe()
        .expect("cargo runs the build script as a file on disk")
        .display()
        .to_string();
    let probe = format!(
        "// Generated by build.rs — do not edit. See `emit_build_script_probe`.\n\
         pub const BUILD_SCRIPT_PATH: &str = {executable:?};\n\
         pub const BUILD_CONNECTIVES: &[&str] = &{CONNECTIVES:?};\n\
         pub const BUILD_SLOT_KINDS: &[&str] = &{SLOT_KINDS:?};\n\
         pub const BUILD_BINDING_MODES: &[&str] = &{BINDING_MODES:?};\n\
         pub const BUILD_CLAUSE_KINDS: &[&str] = &{CLAUSE_KINDS:?};\n\
         pub const BUILD_CLAUSE_CONNECTIVES: &[&str] = &{CLAUSE_CONNECTIVES:?};\n"
    );
    let probe_path = PathBuf::from(out_dir).join("build_script_probe.rs");
    fs::write(&probe_path, probe).unwrap_or_else(|error| {
        panic!(
            "could not write generated build-script probe `{}`: {error}",
            probe_path.display()
        )
    });
}

/// Validate one construct's `grammar` object and append its generated
/// `EffectOperationSpec` row. Mirrors the CLI manifest validation
/// (`package_construct_grammar`): shape/keyword/slot/connective/binding
/// vocabulary plus keyword and target_capability transcription.
fn emit_construct_row(
    label: &str,
    construct: &Value,
    seen_keywords: &mut Vec<(String, String)>,
    rows: &mut String,
    decl_rows: &mut String,
) {
    let construct_id = construct
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("<missing id>");
    let fail = |problem: &str| -> ! {
        panic!("std manifest `{label}` construct `{construct_id}`: {problem}")
    };
    let family = construct
        .get("construct_family")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("missing `construct_family`"));
    // A `declaration_block` construct (Shape 1) is dispatched to the decl-table
    // emitter; only `effect_operation` (Shape 2) follows the path below.
    if family == "declaration_block" {
        emit_declaration_row(label, construct, seen_keywords, decl_rows);
        return;
    }
    if family != "effect_operation" {
        fail(&format!(
            "unsupported construct_family `{family}`; std constructs are `effect_operation` or `declaration_block`"
        ));
    }
    let construct_keyword = construct
        .get("keyword")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("missing `keyword`"));
    let construct_target = construct
        .get("target_capability")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("missing `target_capability`"));
    let grammar = construct.get("grammar").unwrap_or_else(|| {
        fail("missing `grammar` object (the manifests are the single source of parse grammar)")
    });

    let shape = grammar
        .get("shape")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("grammar missing `shape`"));
    // A `declaration_block` shape is dispatched on `construct_family` above, so
    // by here only `effect_operation` is valid.
    if shape != "effect_operation" {
        fail(&format!(
            "grammar uses unsupported shape `{shape}`; expected `effect_operation` (a `declaration_block` construct must set `construct_family` to `declaration_block`)"
        ));
    }
    let keyword = grammar
        .get("keyword")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("grammar missing `keyword`"));
    if keyword != construct_keyword {
        fail(&format!(
            "grammar keyword `{keyword}` does not match the construct keyword `{construct_keyword}`"
        ));
    }
    if let Some((_, previous)) = seen_keywords
        .iter()
        .find(|(seen, _)| seen == construct_keyword)
    {
        fail(&format!(
            "keyword `{construct_keyword}` is already provided by `{previous}`; effect_operation keywords must be unique across the embedded std manifests"
        ));
    }
    seen_keywords.push((construct_keyword.to_owned(), label.to_owned()));

    let mut slot_rows = String::new();
    for slot in grammar
        .get("slots")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail("grammar missing `slots` array"))
    {
        let name = slot
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_else(|| fail("grammar slot missing `name`"));
        let kind = slot
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_else(|| fail("grammar slot missing `kind`"));
        if !SLOT_KINDS.contains(&kind) {
            fail(&format!(
                "grammar slot `{name}` uses unsupported kind `{kind}`; expected one of {SLOT_KINDS:?}"
            ));
        }
        let connective = match slot.get("connective") {
            None | Some(Value::Null) => None,
            Some(connective) => {
                let connective = connective.as_str().unwrap_or_else(|| {
                    fail(&format!(
                        "grammar slot `{name}` connective must be a string"
                    ))
                });
                if !CONNECTIVES.contains(&connective) {
                    fail(&format!(
                        "grammar slot `{name}` uses unsupported connective `{connective}`; expected one of {CONNECTIVES:?}"
                    ));
                }
                Some(connective)
            }
        };
        let kind_variant = if kind == "identifier" {
            "SlotKind::Identifier"
        } else {
            "SlotKind::Expression"
        };
        let connective_expr = match connective {
            Some(connective) => format!("Some({connective:?})"),
            None => "None".to_owned(),
        };
        slot_rows.push_str(&format!(
            "            EffectSlotSpec {{\n\
             \x20               name: {name:?},\n\
             \x20               kind: {kind_variant},\n\
             \x20               connective: {connective_expr},\n\
             \x20           }},\n"
        ));
    }

    let payload_expr = match grammar.get("payload") {
        None | Some(Value::Null) => "None".to_owned(),
        Some(payload) => {
            let mut field_rows = String::new();
            for field in payload
                .get("fields")
                .and_then(Value::as_array)
                .unwrap_or_else(|| fail("grammar payload missing `fields` array"))
            {
                let name = field
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| fail("grammar payload field missing `name`"));
                let kind = field
                    .get("kind")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| fail("grammar payload field missing `kind`"));
                if kind != "expression" {
                    fail(&format!(
                        "grammar payload field `{name}` uses unsupported kind `{kind}`; payload fields are `expression`"
                    ));
                }
                let required = field
                    .get("required")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                field_rows.push_str(&format!(
                    "            PayloadFieldSpec {{\n\
                     \x20               name: {name:?},\n\
                     \x20               required: {required},\n\
                     \x20           }},\n"
                ));
            }
            format!("Some(&[\n{field_rows}        ])")
        }
    };

    let binding = grammar
        .get("binding")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("grammar missing `binding`"));
    if !BINDING_MODES.contains(&binding) {
        fail(&format!(
            "grammar uses unsupported binding `{binding}`; expected one of {BINDING_MODES:?}"
        ));
    }
    let binding_variant = match binding {
        "required" => "BindingMode::Required",
        "optional" => "BindingMode::Optional",
        _ => "BindingMode::None",
    };

    let target_capability = grammar
        .get("target_capability")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("grammar missing `target_capability`"));
    if target_capability != construct_target {
        fail(&format!(
            "grammar target_capability `{target_capability}` does not match the construct target_capability `{construct_target}`"
        ));
    }

    rows.push_str(&format!(
        "    EffectOperationSpec {{\n\
         \x20       keyword: {keyword:?},\n\
         \x20       slots: &[\n{slot_rows}        ],\n\
         \x20       payload: {payload_expr},\n\
         \x20       binding: {binding_variant},\n\
         \x20       target_capability: {target_capability:?},\n\
         \x20   }},\n"
    ));
}

/// Validate one `declaration_block` construct's `grammar` object (Shape 1) and
/// append its generated `DeclarationBlockSpec` row. The order-free analog of
/// `emit_construct_row`: keyword (may be multi-word), clauses[] with a
/// name (may be multi-word), a kind from `CLAUSE_KINDS`, an optional connective
/// from `CLAUSE_CONNECTIVES`, `required`, and `list`. Enforces the 2026-07-08
/// amendment rules (a `flag` carries no value: `list == false` and no
/// connective). Keyword and clause names are split into words at build time.
fn emit_declaration_row(
    label: &str,
    construct: &Value,
    seen_keywords: &mut Vec<(String, String)>,
    decl_rows: &mut String,
) {
    let construct_id = construct
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("<missing id>");
    let fail = |problem: &str| -> ! {
        panic!("std manifest `{label}` construct `{construct_id}`: {problem}")
    };
    let construct_keyword = construct
        .get("keyword")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("missing `keyword`"));
    let grammar = construct.get("grammar").unwrap_or_else(|| {
        fail("missing `grammar` object (the manifests are the single source of parse grammar)")
    });

    let shape = grammar
        .get("shape")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("grammar missing `shape`"));
    if shape != "declaration_block" {
        fail(&format!(
            "declaration_block construct uses grammar shape `{shape}`; expected `declaration_block`"
        ));
    }
    let keyword = grammar
        .get("keyword")
        .and_then(Value::as_str)
        .unwrap_or_else(|| fail("grammar missing `keyword`"));
    if keyword.trim().is_empty() {
        fail("grammar `keyword` must be non-empty");
    }
    if keyword != construct_keyword {
        fail(&format!(
            "grammar keyword `{keyword}` does not match the construct keyword `{construct_keyword}`"
        ));
    }
    if let Some((_, previous)) = seen_keywords.iter().find(|(seen, _)| seen == keyword) {
        fail(&format!(
            "keyword `{keyword}` is already provided by `{previous}`; construct keywords must be unique across the std manifests"
        ));
    }
    seen_keywords.push((keyword.to_owned(), label.to_owned()));

    let keyword_words: Vec<&str> = keyword.split_whitespace().collect();
    let ast_kind = match keyword {
        "tracker" => "DeclAstKind::Tracker",
        "channel" => "DeclAstKind::Channel",
        "counter" => "DeclAstKind::Counter",
        "lease" => "DeclAstKind::Lease",
        "ledger" => "DeclAstKind::Ledger",
        "memory pool" => "DeclAstKind::MemoryPool",
        "file store" => "DeclAstKind::FileStore",
        "stream" => "DeclAstKind::Stream",
        "credential" => "DeclAstKind::Credential",
        "vault" => "DeclAstKind::Vault",
        other => fail(&format!(
            "declaration_block keyword `{other}` has no known DeclAstKind builder seam"
        )),
    };

    let mut clause_rows = String::new();
    for clause in grammar
        .get("clauses")
        .and_then(Value::as_array)
        .unwrap_or_else(|| fail("grammar missing `clauses` array"))
    {
        let name = clause
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_else(|| fail("grammar clause missing `name`"));
        if name.trim().is_empty() {
            fail("grammar clause `name` must be non-empty");
        }
        let kind = clause
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_else(|| fail(&format!("grammar clause `{name}` missing `kind`")));
        if !CLAUSE_KINDS.contains(&kind) {
            fail(&format!(
                "grammar clause `{name}` uses unsupported kind `{kind}`; expected one of {CLAUSE_KINDS:?}"
            ));
        }
        let connective = match clause.get("connective") {
            None | Some(Value::Null) => None,
            Some(connective) => {
                let connective = connective.as_str().unwrap_or_else(|| {
                    fail(&format!(
                        "grammar clause `{name}` connective must be a string"
                    ))
                });
                if !CLAUSE_CONNECTIVES.contains(&connective) {
                    fail(&format!(
                        "grammar clause `{name}` uses unsupported connective `{connective}`; expected one of {CLAUSE_CONNECTIVES:?}"
                    ));
                }
                Some(connective)
            }
        };
        // `required`/`missing_summary` are validated here (fail-fast contract on
        // the grammar manifests) but NOT emitted into the parse table: required-ness
        // is a validation concern the typed-node builder / CLI validator owns, not
        // something the parser needs. Read-and-discard to keep the build-time check.
        clause
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| fail(&format!("grammar clause `{name}` missing bool `required`")));
        let list = clause
            .get("list")
            .and_then(Value::as_bool)
            .unwrap_or_else(|| fail(&format!("grammar clause `{name}` missing bool `list`")));
        // Amendment rule: a flag carries no value, so it can be neither a list
        // nor connective-introduced. `list` is only meaningful for a value kind.
        if kind == "flag" {
            if list {
                fail(&format!(
                    "grammar clause `{name}` is a `flag` and cannot set `list: true` (a flag carries no value)"
                ));
            }
            if connective.is_some() {
                fail(&format!(
                    "grammar clause `{name}` is a `flag` and cannot carry a connective (a flag carries no value)"
                ));
            }
        }
        let unknown_hint = clause
            .get("unknown_hint")
            .and_then(Value::as_str)
            .unwrap_or_else(|| fail(&format!("grammar clause `{name}` missing `unknown_hint`")));
        // Contract-only field (see the `required` note above); validated, not emitted.
        clause
            .get("missing_summary")
            .and_then(Value::as_str)
            .unwrap_or_else(|| {
                fail(&format!(
                    "grammar clause `{name}` missing `missing_summary`"
                ))
            });

        let words: Vec<&str> = name.split_whitespace().collect();
        let words_expr = format!(
            "&[{}]",
            words
                .iter()
                .map(|word| format!("{word:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let kind_variant = match kind {
            "identifier" => "ClauseKind::Identifier",
            "expression" => "ClauseKind::Expression",
            "duration" => "ClauseKind::Duration",
            "glob" => "ClauseKind::Glob",
            "schema" => "ClauseKind::Schema",
            "scalar" => "ClauseKind::Scalar",
            _ => "ClauseKind::Flag",
        };
        let connective_expr = match connective {
            Some(connective) => format!("Some({connective:?})"),
            None => "None".to_owned(),
        };
        clause_rows.push_str(&format!(
            "            ClauseSpec {{\n\
             \x20               name: {name:?},\n\
             \x20               words: {words_expr},\n\
             \x20               connective: {connective_expr},\n\
             \x20               kind: {kind_variant},\n\
             \x20               list: {list},\n\
             \x20               unknown_hint: {unknown_hint:?},\n\
             \x20           }},\n"
        ));
    }

    let keyword_words_expr = format!(
        "&[{}]",
        keyword_words
            .iter()
            .map(|word| format!("{word:?}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    decl_rows.push_str(&format!(
        "    DeclarationBlockSpec {{\n\
         \x20       keyword: {keyword:?},\n\
         \x20       keyword_words: {keyword_words_expr},\n\
         \x20       ast_kind: {ast_kind},\n\
         \x20       clauses: &[\n{clause_rows}        ],\n\
         \x20   }},\n"
    ));
}
