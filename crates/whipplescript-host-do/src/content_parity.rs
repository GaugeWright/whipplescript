//! Parity checks for the content-identity seam: the SHA-256/128 hash twins and
//! the `content_blobs` table declarations.
//!
//! Both are *mirrored* rather than shared. The content id is computed by three
//! separate functions — `whipplescript_store`'s internal `stable_hash_hex` (and
//! its `chunking::content_hash_hex` twin), the kernel's
//! `rule_lowering::stable_hash_hex`, and this crate's `do_store::stable_hash_hex`
//! — because the native and DO backends cannot share a body: one is rusqlite,
//! one is the DO SQL API, and the DO half must stay wasm-safe. The table is
//! declared four times for the same reason. Nothing but comments has been
//! holding them in lockstep, and a content id is a durable identity: a
//! divergence does not fail loudly, it silently re-identifies stored content,
//! so one backend stops finding what the other wrote.
//!
//! This module is the check those comments asked for. It lives here because
//! `whipplescript-host-do` is a leaf that can see every implementation, and
//! because `do_store::stable_hash_hex` is `pub(crate)` — an integration test
//! could not reach it.
//!
//! The DDL check reads the declarations out of their own source files rather
//! than restating them, so it tracks what is actually declared. A copy here
//! would be a fifth copy of the thing under test.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use rusqlite::Connection;

use crate::do_store::stable_hash_hex as do_hash;
use whipplescript_kernel::rule_lowering::stable_hash_hex as kernel_hash;
use whipplescript_store::chunking::content_hash_hex as store_hash;

/// Inputs the twins must agree on. Deliberately includes the shapes that break
/// hand-rolled hashing: empty, multi-byte UTF-8, embedded newlines and quotes,
/// and a body past any plausible small-input fast path.
fn corpus() -> Vec<String> {
    vec![
        String::new(),
        "a".to_owned(),
        "abc".to_owned(),
        "body X".to_owned(),
        "{\"json\": \"payload\", \"n\": 1}".to_owned(),
        "line one\nline two\r\nline three\n".to_owned(),
        "café ☕ 日本語 — em dash".to_owned(),
        "\u{1e}record\u{1e}separator\u{1e}".to_owned(),
        "x".repeat(8192),
        "🙂".repeat(1024),
    ]
}

/// The three content-id functions must return the same digest for the same
/// bytes. They are separate bodies over separate backends, so only a test can
/// hold them together.
#[test]
fn content_id_hashers_agree_across_backends() {
    for input in corpus() {
        let store = store_hash(input.as_bytes());
        let kernel = kernel_hash(&input);
        let durable_object = do_hash(&input);

        let preview: String = input.chars().take(24).collect();
        assert_eq!(
            store,
            kernel,
            "store and kernel content ids diverge for {preview:?} \
             ({} bytes)",
            input.len()
        );
        assert_eq!(
            store,
            durable_object,
            "store and DO content ids diverge for {preview:?} \
             ({} bytes) — the native and hosted backends would stop finding \
             each other's blobs",
            input.len()
        );
    }
}

/// Pin the encoding to the published SHA-256 vectors, truncated to 128 bits.
///
/// `content_id_hashers_agree_across_backends` only proves the three agree with
/// each other; a coordinated change would still pass it. This holds them to the
/// standard, so a swapped digest, a changed truncation, or a different hex
/// encoding fails even if every site is changed together. These ids are a wire
/// format — a changed one re-identifies every stored blob rather than erroring.
#[test]
fn content_id_matches_the_published_sha256_128_vectors() {
    // The first 16 bytes of the published SHA-256 vectors for "" and "abc".
    assert_eq!(store_hash(b""), "e3b0c44298fc1c149afbf4c8996fb924");
    assert_eq!(store_hash(b"abc"), "ba7816bf8f01cfea414140de5dae2223");
    assert_eq!(
        store_hash(b"abc").len(),
        32,
        "16 bytes as 32 lowercase hex digits"
    );
    assert_eq!(kernel_hash("abc"), "ba7816bf8f01cfea414140de5dae2223");
    assert_eq!(do_hash("abc"), "ba7816bf8f01cfea414140de5dae2223");
}

/// One declaration site: where the DDL lives, and how to describe it when it
/// disagrees with the others.
struct Declaration {
    /// Repository-relative path, used in failure messages.
    label: &'static str,
    /// Path relative to this crate's manifest directory.
    relative_path: &'static str,
}

const DECLARATIONS: &[Declaration] = &[
    Declaration {
        label: "crates/whipplescript-store/src/content.rs (workspace VCS)",
        relative_path: "../whipplescript-store/src/content.rs",
    },
    Declaration {
        label: "crates/whipplescript-store/migrations/0001_runtime_store.sql (runtime store)",
        relative_path: "../whipplescript-store/migrations/0001_runtime_store.sql",
    },
    Declaration {
        label: "crates/whipplescript-host-do/src/do_branches.rs (DO VCS mirror)",
        relative_path: "src/do_branches.rs",
    },
    Declaration {
        label: "crates/whipplescript-host-do/src/do_store.rs (DO runtime mirror)",
        relative_path: "src/do_store.rs",
    },
];

/// Columns every backend must declare identically — the blob store's actual
/// contract. `id` is the content hash, so a difference here is a difference in
/// what an id means.
const CORE_COLUMNS: &[&str] = &["id", "body", "byte_len"];

/// Columns a site may carry without failing the check. Bookkeeping only: no
/// content id depends on them. Adding a name here is a deliberate statement
/// that the column cannot affect blob identity or lookup.
const ALLOWED_EXTRA_COLUMNS: &[&str] = &["created_at"];

/// One column as SQLite reports it.
#[derive(Debug, PartialEq, Eq)]
struct Column {
    declared_type: String,
    not_null: bool,
    primary_key: bool,
}

/// Pull the `content_blobs` CREATE TABLE out of a source file and return the
/// statement, whether the file is SQL or a Rust string literal containing SQL.
///
/// Returns `None` when the file declares no such table, which the caller treats
/// as a failure: a renamed or relocated declaration must not quietly reduce this
/// check to a comparison of the sites that still happen to match.
///
/// The table name must end on a token boundary. Matching a bare prefix would
/// accept `content_blobs_v2` as `content_blobs` and compare the wrong table —
/// which is the precise way this check could pass while proving nothing.
fn extract_declaration(source: &str) -> Option<String> {
    const PREFIXES: [&str; 2] = [
        "CREATE TABLE IF NOT EXISTS content_blobs",
        "CREATE TABLE content_blobs",
    ];

    let mut table_at: Option<usize> = None;
    for prefix in PREFIXES {
        let mut searched = 0usize;
        while let Some(found) = source[searched..].find(prefix) {
            let after = searched + found + prefix.len();
            let ends_the_name = source[after..]
                .chars()
                .next()
                .is_none_or(|character| !character.is_alphanumeric() && character != '_');
            if ends_the_name {
                table_at = Some(table_at.map_or(after, |earlier: usize| earlier.min(after)));
                break;
            }
            searched = after;
        }
    }

    let rest = &source[table_at?..];
    let open = rest.find('(')?;
    let mut depth = 0usize;
    let mut close = None;
    for (offset, character) in rest[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(open + offset);
                    break;
                }
            }
            _ => {}
        }
    }

    Some(format!(
        "CREATE TABLE content_blobs {}",
        &rest[open..=close?]
    ))
}

/// Execute a declaration against real SQLite and report the schema it produces.
/// Comparing parsed schemas rather than DDL text lets equivalent spellings —
/// whitespace, column order, `IF NOT EXISTS` — agree, and catches differences
/// that matter even when the text looks similar.
fn columns_of(statement: &str) -> BTreeMap<String, Column> {
    let connection = Connection::open_in_memory().expect("open in-memory SQLite");
    connection
        .execute_batch(statement)
        .unwrap_or_else(|error| panic!("declaration is not valid SQLite: {error}\n{statement}"));

    let mut query = connection
        .prepare("SELECT name, type, \"notnull\", pk FROM pragma_table_info('content_blobs')")
        .expect("prepare table_info");
    let rows = query
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                Column {
                    declared_type: row.get::<_, String>(1)?.to_uppercase(),
                    not_null: row.get::<_, i64>(2)? != 0,
                    primary_key: row.get::<_, i64>(3)? != 0,
                },
            ))
        })
        .expect("read table_info")
        .collect::<Result<BTreeMap<_, _>, _>>()
        .expect("collect table_info");

    assert!(
        !rows.is_empty(),
        "declaration produced no columns:\n{statement}"
    );
    rows
}

/// The four `content_blobs` declarations must agree on the columns that carry
/// blob identity, and may differ only in bookkeeping columns.
///
/// They have drifted before: the DO tables carry no `created_at`, and of the
/// sites that do, one defaults it and one does not. That is tolerated because
/// no content id depends on it. A difference in `id`, `body`, or `byte_len`
/// would instead mean the two backends disagree about what a blob is.
#[test]
fn content_blobs_declarations_agree_across_backends() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut schemas: Vec<(&str, BTreeMap<String, Column>)> = Vec::new();

    for declaration in DECLARATIONS {
        let path = manifest.join(declaration.relative_path);
        let source = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "cannot read {} at {}: {error} — if the declaration moved, update \
                 DECLARATIONS rather than deleting the site from the check",
                declaration.label,
                path.display()
            )
        });
        let statement = extract_declaration(&source).unwrap_or_else(|| {
            panic!(
                "no content_blobs declaration found in {} — a renamed or relocated \
                 table must not silently drop a backend from this check",
                declaration.label
            )
        });
        schemas.push((declaration.label, columns_of(&statement)));
    }

    assert_eq!(
        schemas.len(),
        DECLARATIONS.len(),
        "every declaration site must contribute a schema"
    );

    let (reference_label, reference) = &schemas[0];

    for (label, schema) in &schemas[1..] {
        for column in CORE_COLUMNS {
            let expected = reference.get(*column).unwrap_or_else(|| {
                panic!("{reference_label} does not declare the core column `{column}`")
            });
            let actual = schema.get(*column).unwrap_or_else(|| {
                panic!(
                    "{label} does not declare the core column `{column}`, which \
                     {reference_label} does — the backends disagree about what a \
                     blob is"
                )
            });
            assert_eq!(
                expected, actual,
                "core column `{column}` differs between {reference_label} and \
                 {label}; a blob written by one backend would not read back \
                 identically under the other"
            );
        }
    }

    for (label, schema) in &schemas {
        for name in schema.keys() {
            let known = CORE_COLUMNS.contains(&name.as_str())
                || ALLOWED_EXTRA_COLUMNS.contains(&name.as_str());
            assert!(
                known,
                "{label} declares `{name}`, which is neither a core column nor a \
                 known bookkeeping column. If it cannot affect blob identity or \
                 lookup, add it to ALLOWED_EXTRA_COLUMNS; otherwise every backend \
                 must declare it."
            );
        }
    }

    // A bookkeeping column that two sites both carry must at least mean the same
    // thing at both. Presence may differ; type may not.
    for extra in ALLOWED_EXTRA_COLUMNS {
        let declared: Vec<(&str, &Column)> = schemas
            .iter()
            .filter_map(|(label, schema)| schema.get(*extra).map(|column| (*label, column)))
            .collect();
        if let Some(((first_label, first), rest)) = declared.split_first() {
            for (label, column) in rest {
                assert_eq!(
                    first.declared_type, column.declared_type,
                    "`{extra}` is declared as {} in {first_label} but {} in {label}",
                    first.declared_type, column.declared_type
                );
            }
        }
    }
}
