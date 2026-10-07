//! The classified population of store operations that admit a program
//! version (RC-2, WS-159).
//!
//! Every store method that writes or reuses a `program_versions` row must be
//! listed here with the kind of `program_import_operations` row it records:
//! `Checked` with an exact import witness, or `Unwitnessed`, an explicit
//! record that the acceptance has none. The native and hosted inventory tests
//! read their own sources and refuse an admitting method or raw version write
//! that this list does not classify, and drive every listed method against
//! both stores to prove it records exactly the declared row.
//!
//! The third kind, `LegacyGap`, is not a method: an upgraded store records it
//! once for each version admitted before the ledger existed.

use super::ProgramImportOperationKind;

/// One version-admitting store method and the operation row it records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionAdmittingOperation {
    pub method: &'static str,
    pub records: ProgramImportOperationKind,
}

/// Every `RuntimeStore` method that admits a program version.
pub const VERSION_ADMITTING_OPERATIONS: &[VersionAdmittingOperation] = &[
    VersionAdmittingOperation {
        method: "create_program_version",
        records: ProgramImportOperationKind::Unwitnessed,
    },
    VersionAdmittingOperation {
        method: "create_program_version_with_import_witness",
        records: ProgramImportOperationKind::Checked,
    },
    VersionAdmittingOperation {
        method: "create_program_version_with_import_witness_at_id",
        records: ProgramImportOperationKind::Checked,
    },
    VersionAdmittingOperation {
        method: "reattest_instance_program",
        records: ProgramImportOperationKind::Unwitnessed,
    },
    VersionAdmittingOperation {
        method: "reattest_instance_program_with_import_witness",
        records: ProgramImportOperationKind::Checked,
    },
    VersionAdmittingOperation {
        method: "reattest_instance_program_with_import_witness_at_id",
        records: ProgramImportOperationKind::Checked,
    },
];

/// A store method whose signature names one of these types admits a version.
pub const VERSION_ADMISSION_RETURN_TYPES: &[&str] =
    &["ProgramVersionRecord", "ProgramImportAdmissionRecord"];

/// SQL spellings that write a program version row. Matched against source
/// with whitespace collapsed to single spaces.
pub const VERSION_ROW_WRITES: &[&str] = &["INTO program_versions", "UPDATE program_versions"];

/// The SQL spelling that records an accepting operation.
pub const OPERATION_ROW_WRITE: &str = "INTO program_import_operations";

/// Rust source with comments and `#[cfg(test)]` items blanked and whitespace
/// collapsed, so an inventory scan sees only production code. String
/// contents are kept because the SQL being inventoried lives in them.
#[doc(hidden)]
pub fn production_source(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let mut kept = String::with_capacity(source.len());
    let mut index = 0;
    while index < chars.len() {
        if starts_with(&chars, index, "#[cfg(test)]")
            || starts_with(&chars, index, "#[cfg(all(test")
        {
            index = skip_item(&chars, index);
            kept.push(' ');
            continue;
        }
        let next = skip_token(&chars, index);
        if starts_with(&chars, index, "//") || starts_with(&chars, index, "/*") {
            kept.push(' ');
        } else {
            kept.extend(&chars[index..next]);
        }
        index = next;
    }
    kept.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The function names enclosing each occurrence of `needle` in collapsed
/// production source, in order of occurrence.
#[doc(hidden)]
pub fn enclosing_functions(production: &str, needle: &str) -> Vec<String> {
    production
        .match_indices(needle)
        .map(|(at, _)| {
            let mut search = &production[..at];
            loop {
                let Some(found) = search.rfind("fn ") else {
                    return String::new();
                };
                let boundary = production[..found]
                    .chars()
                    .next_back()
                    .is_none_or(|before| !(before.is_alphanumeric() || before == '_'));
                if boundary {
                    return production[found + 3..]
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                }
                search = &search[..found];
            }
        })
        .collect()
}

/// The body of `header { ... }` in collapsed production source.
#[doc(hidden)]
pub fn item_body<'a>(production: &'a str, header: &str) -> Option<&'a str> {
    let start = production.find(header)? + header.len();
    let open = start + production[start..].find('{')?;
    let mut depth = 0usize;
    for (offset, c) in production[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&production[open + 1..open + offset]);
                }
            }
            _ => {}
        }
    }
    None
}

/// `(name, signature)` for each `fn` in `body`, where the signature runs to
/// the first `{` or `;` after the name. With `public_only`, only `pub fn`.
#[doc(hidden)]
pub fn function_signatures(body: &str, public_only: bool) -> Vec<(String, String)> {
    body.match_indices("fn ")
        .filter(|(at, _)| {
            let before = &body[..*at];
            before
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
                && (!public_only || before.ends_with("pub "))
        })
        .filter_map(|(at, _)| {
            let rest = &body[at + 3..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let end = rest.find(['{', ';'])?;
            (!name.is_empty()).then(|| (name, rest[..end].to_owned()))
        })
        .collect()
}

/// Names of the functions in `body` whose signatures name a version-admission
/// return type.
#[doc(hidden)]
pub fn admitting_functions(body: &str, public_only: bool) -> Vec<String> {
    function_signatures(body, public_only)
        .into_iter()
        .filter(|(_, signature)| {
            VERSION_ADMISSION_RETURN_TYPES
                .iter()
                .any(|marker| signature.contains(marker))
        })
        .map(|(name, _)| name)
        .collect()
}

/// Follow a raw version writer back through private helpers to its callers
/// until each path ends at a classified method. An error names the first
/// unclassified caller or a writer nothing classified reaches.
#[doc(hidden)]
pub fn reached_only_from(
    production: &str,
    function: &str,
    classified: &std::collections::BTreeSet<&str>,
    seen: &mut std::collections::BTreeSet<String>,
) -> Result<(), String> {
    if classified.contains(function) || !seen.insert(function.to_owned()) {
        return Ok(());
    }
    let callers: Vec<String> = enclosing_functions(production, &format!("{function}("))
        .into_iter()
        .filter(|caller| caller != function)
        .collect();
    if callers.is_empty() {
        return Err(format!(
            "`{function}` writes a version but no classified method reaches it"
        ));
    }
    for caller in callers {
        if caller.is_empty() {
            return Err(format!("`{function}` is reached outside any function"));
        }
        reached_only_from(production, &caller, classified, seen)
            .map_err(|error| format!("{error} (via `{function}`)"))?;
    }
    Ok(())
}

fn starts_with(chars: &[char], index: usize, text: &str) -> bool {
    text.chars()
        .enumerate()
        .all(|(offset, c)| chars.get(index + offset) == Some(&c))
}

/// Skip one lexical token that may contain braces: a comment, a string, a
/// raw string or a character literal. Anything else advances one char.
fn skip_token(chars: &[char], index: usize) -> usize {
    let len = chars.len();
    if starts_with(chars, index, "//") {
        let mut end = index;
        while end < len && chars[end] != '\n' {
            end += 1;
        }
        return end;
    }
    if starts_with(chars, index, "/*") {
        let mut depth = 0;
        let mut end = index;
        while end < len {
            if starts_with(chars, end, "/*") {
                depth += 1;
                end += 2;
            } else if starts_with(chars, end, "*/") {
                depth -= 1;
                end += 2;
                if depth == 0 {
                    return end;
                }
            } else {
                end += 1;
            }
        }
        return len;
    }
    let identifier_before =
        index > 0 && (chars[index - 1].is_alphanumeric() || chars[index - 1] == '_');
    if !identifier_before && (chars[index] == 'r' || starts_with(chars, index, "br")) {
        let mut cursor = index + if chars[index] == 'b' { 2 } else { 1 };
        let mut hashes = 0;
        while cursor < len && chars[cursor] == '#' {
            hashes += 1;
            cursor += 1;
        }
        if cursor < len && chars[cursor] == '"' {
            cursor += 1;
            while cursor < len {
                if chars[cursor] == '"'
                    && (0..hashes).all(|offset| chars.get(cursor + 1 + offset) == Some(&'#'))
                {
                    return cursor + 1 + hashes;
                }
                cursor += 1;
            }
            return len;
        }
    }
    if chars[index] == '"' {
        let mut cursor = index + 1;
        while cursor < len {
            match chars[cursor] {
                '\\' => cursor += 2,
                '"' => return cursor + 1,
                _ => cursor += 1,
            }
        }
        return len;
    }
    if chars[index] == '\'' {
        if chars.get(index + 1) == Some(&'\\') {
            let mut cursor = index + 2;
            while cursor < len && cursor < index + 12 {
                if chars[cursor] == '\'' {
                    return cursor + 1;
                }
                cursor += 1;
            }
        } else if chars.get(index + 2) == Some(&'\'') {
            return index + 3;
        }
    }
    index + 1
}

/// Skip a `#[cfg(test)]`-style attribute and the item it annotates: further
/// attributes, then everything to the item's closing brace or semicolon.
fn skip_item(chars: &[char], index: usize) -> usize {
    let len = chars.len();
    let mut cursor = index;
    let mut depth = 0usize;
    let mut opened = false;
    while cursor < len {
        let next = skip_token(chars, cursor);
        if next > cursor + 1 {
            cursor = next;
            continue;
        }
        match chars[cursor] {
            '[' | '(' => depth += 1,
            ']' | ')' => depth = depth.saturating_sub(1),
            '{' => {
                depth += 1;
                opened = true;
            }
            '}' => {
                depth = depth.saturating_sub(1);
                if opened && depth == 0 {
                    return cursor + 1;
                }
            }
            ';' if depth == 0 && !opened => return cursor + 1,
            _ => {}
        }
        cursor += 1;
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_source_drops_test_items_and_comments_but_keeps_sql() {
        let source = r##"
// INTO program_versions in a comment
fn real() { let sql = "INSERT INTO program_versions (a) VALUES ('{')"; }
#[cfg(test)]
mod tests { fn fixture() { "INSERT INTO program_versions"; let c = '}'; } }
#[cfg(all(test, feature = "native"))]
mod more;
/* block { INTO program_versions */
fn later() { r#"UPDATE program_versions {"#; }
"##;
        let production = production_source(source);
        assert_eq!(
            enclosing_functions(&production, "INTO program_versions"),
            vec!["real".to_owned()]
        );
        assert_eq!(
            enclosing_functions(&production, "UPDATE program_versions"),
            vec!["later".to_owned()]
        );
        assert!(!production.contains("fixture"));
        assert!(!production.contains("mod more"));
    }

    #[test]
    fn admitting_functions_follow_their_return_types() {
        let production = production_source(
            "pub trait Store { fn plain(&self) -> u8; fn admit(&mut self) -> StoreResult<ProgramVersionRecord>; \
             fn witnessed(&mut self) -> StoreResult<program_imports::ProgramImportAdmissionRecord> { todo!() } }",
        );
        let body = item_body(&production, "pub trait Store").expect("trait body");
        assert_eq!(admitting_functions(body, false), vec!["admit", "witnessed"]);
        assert!(admitting_functions(body, true).is_empty());
    }

    /// WS-159: the native store has no version-admitting method or raw
    /// version write that the inventory does not classify. A new path fails
    /// here until it is added to `VERSION_ADMITTING_OPERATIONS` and records
    /// its operation row.
    #[cfg(feature = "native")]
    #[test]
    fn native_store_admits_versions_only_through_classified_operations() {
        use std::collections::BTreeSet;

        let lib = production_source(include_str!("../lib.rs"));
        let classified: BTreeSet<&str> = VERSION_ADMITTING_OPERATIONS
            .iter()
            .map(|operation| operation.method)
            .collect();
        assert_eq!(classified.len(), VERSION_ADMITTING_OPERATIONS.len());

        let trait_body = item_body(&lib, "pub trait RuntimeStore").expect("RuntimeStore trait");
        let trait_methods: BTreeSet<String> =
            admitting_functions(trait_body, false).into_iter().collect();
        assert_eq!(
            trait_methods,
            classified.iter().map(|name| (*name).to_owned()).collect(),
            "every RuntimeStore method that admits a program version must be classified"
        );
        let public: BTreeSet<String> = admitting_functions(&lib, true).into_iter().collect();
        assert_eq!(
            public, trait_methods,
            "a public native admission method outside the trait is unclassified"
        );

        let writers: BTreeSet<String> = VERSION_ROW_WRITES
            .iter()
            .flat_map(|write| enclosing_functions(&lib, write))
            .collect();
        assert_eq!(
            writers,
            BTreeSet::from([
                "create_program_version_retained".to_owned(),
                "reattest_instance_program_retained".to_owned(),
            ]),
            "a raw program version write is outside the classified native writers"
        );
        let recorders: BTreeSet<String> = enclosing_functions(&lib, OPERATION_ROW_WRITE)
            .into_iter()
            .collect();
        for writer in &writers {
            assert!(
                recorders.contains(writer),
                "`{writer}` writes a version without recording its operation"
            );
            reached_only_from(&lib, writer, &classified, &mut BTreeSet::new())
                .unwrap_or_else(|error| panic!("{error}"));
        }

        for (name, source) in [
            ("native_stores.rs", include_str!("../native_stores.rs")),
            ("program_imports.rs", include_str!("../program_imports.rs")),
            ("host_actions.rs", include_str!("../host_actions.rs")),
        ] {
            let production = production_source(source);
            for write in VERSION_ROW_WRITES {
                assert!(
                    enclosing_functions(&production, write).is_empty(),
                    "{name} writes program versions outside the classified writers"
                );
            }
        }
        let native_stores = production_source(include_str!("../native_stores.rs"));
        let delegated: BTreeSet<String> = admitting_functions(
            item_body(&native_stores, "impl RuntimeStore for NativeStores")
                .expect("NativeStores RuntimeStore impl"),
            false,
        )
        .into_iter()
        .collect();
        assert_eq!(delegated, trait_methods);
    }

    #[test]
    fn an_unclassified_writer_is_reported() {
        let production = production_source(
            "fn create_program_version() { helper(); } fn helper() { \"INSERT INTO program_versions\"; } \
             fn sneaky() { helper(); } fn orphan() { \"UPDATE program_versions\"; }",
        );
        let classified = std::collections::BTreeSet::from(["create_program_version"]);
        assert!(
            reached_only_from(&production, "helper", &classified, &mut Default::default())
                .unwrap_err()
                .contains("`sneaky`")
        );
        assert!(
            reached_only_from(&production, "orphan", &classified, &mut Default::default())
                .unwrap_err()
                .contains("no classified method reaches it")
        );
        let top_level = production_source(
            "static EAGER: () = helper(); fn helper() { \"INSERT INTO program_versions\"; }",
        );
        assert!(
            reached_only_from(&top_level, "helper", &classified, &mut Default::default())
                .unwrap_err()
                .contains("reached outside any function")
        );
    }
}
