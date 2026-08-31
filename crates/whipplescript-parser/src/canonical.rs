//! DR-0054 alpha-equivalence canonicalization: the one declaration-identity
//! answer serving merge refinement, evidence keying, and declaration-level
//! attribution (modeled in alpha-canonicalization.maude).
//!
//! Two relations, never one: **identity** is kind + top-level name (the
//! normalized header line merge already keys by — a rename is a detected
//! event, not something the scheme survives invisibly), and
//! **content-equivalence** is the canonical hash. The canonical form is:
//!
//! - **L1 format**: the `whip fmt` printer's output (reindent, fixed clause
//!   order for AST-rebuilt bodies), with blank lines dropped;
//! - **L2 comments**: stripped lexically before parsing;
//! - **L3 alpha**: rule-local bindings renamed positionally (`wsc__0`,
//!   `wsc__1`, … in binding-site order: `when … as` intros first, then body
//!   bindings). Renaming rides the structured machinery built for `action`
//!   hygiene (`rename_bindings` for definitions and `after` references,
//!   `print_statement_rn` so field and schema names are never touched) plus
//!   a dot-guarded reference renamer for `when` guards — a rename must never
//!   collapse two semantically different declarations into one hash, so
//!   every uncertainty degrades that declaration to L1+L2 instead
//!   (deterministic per content: a depth mismatch between two sides only
//!   ever produces false *inequality*, never a bogus certificate);
//! - **L4 order**: free where the formatter rebuilds a declaration block
//!   from the AST in fixed clause order; rule `when` order stays significant.
//!
//! A source that does not parse has no canonical form (`None`) — every
//! client falls back to its byte-level behavior, fail-closed.

use std::collections::BTreeSet;

use crate::action_expand::{collect_bindings, rename_bindings};
use crate::body::parse_rule_body;
use crate::body_print::print_statement_rn;
use crate::{
    binding_after_as, format_description, format_item, format_tags, format_workflow, lex_comments,
    parse_program, push_line, split_when_guard, stable_hash, Item, RuleDecl, WhenClause,
};

/// One declaration's canonical identity and content hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeclCanon {
    /// The normalized header line — merge's identity key (`rule triage`,
    /// `class Report`, `use std.vcs`).
    pub identity: String,
    /// SHA-256/128 over the canonical print (blank lines dropped, lines
    /// trailing-trimmed).
    pub canon_hash: String,
    /// SHA-256/128 over the canonical print with the header line's NAME
    /// replaced by `_` — the rename-detection key (Decision 3): a deleted
    /// and an added declaration of the same kind whose `rename_hash`es are
    /// identical are one declaration renamed.
    pub rename_hash: String,
    /// Whether the L3 alpha pass applied (false = degraded to L1+L2 for
    /// this declaration; still deterministic per content).
    pub alpha: bool,
}

/// The reserved positional-binding namespace. A source that already uses it
/// anywhere in a rule refuses alpha for that rule rather than risking
/// capture.
const CANON_PREFIX: &str = "wsc__";

/// Canonicalize every top-level declaration of `source`. `None` when the
/// source does not parse or the declaration identities are ambiguous
/// (duplicates) — callers fail closed to their pre-DR behavior. A
/// multi-workflow program's `workflow X { … }` blocks are single units
/// (matching merge's depth-0 split), with alpha applied to their nested
/// rules.
pub fn canonical_declarations(source: &str) -> Option<Vec<DeclCanon>> {
    let stripped = strip_comments(source);
    let parsed = parse_program(&stripped);
    if !parsed.diagnostics.is_empty() {
        return None;
    }
    let program = parsed.program;

    let mut chunks: Vec<(String, bool)> = Vec::new();
    if let Some(workflow) = program.workflow {
        let mut chunk = String::new();
        format_tags(&program.workflow_tags, &mut chunk);
        format_description(program.workflow_description.as_ref(), &mut chunk);
        push_line(&mut chunk, format!("workflow {}", workflow.name));
        chunks.push((chunk, true));
    }
    let mut top_level: Vec<Item> = Vec::new();
    top_level.extend(program.patterns.into_iter().map(Item::Pattern));
    top_level.extend(program.items);
    for item in top_level {
        chunks.push(canonical_item_chunk(item));
    }
    for mut workflow in program.workflows {
        let mut alpha = true;
        workflow.items = workflow
            .items
            .into_iter()
            .map(|item| match item {
                Item::Rule(rule) => {
                    let (rule, applied) = alpha_rule(rule);
                    alpha &= applied;
                    Item::Rule(rule)
                }
                other => other,
            })
            .collect();
        let mut chunk = String::new();
        format_workflow(workflow, &mut chunk);
        chunks.push((chunk, alpha));
    }

    let mut seen = BTreeSet::new();
    let mut declarations = Vec::with_capacity(chunks.len());
    for (chunk, alpha) in chunks {
        let canonical = normalize_chunk(&chunk);
        if canonical.is_empty() {
            continue;
        }
        let identity = identity_of(&canonical)?;
        if !seen.insert(identity.clone()) {
            return None;
        }
        let rename_hash = stable_hash(&name_normalized(&canonical, &identity));
        declarations.push(DeclCanon {
            identity,
            canon_hash: stable_hash(&canonical),
            rename_hash,
            alpha,
        });
    }
    Some(declarations)
}

/// The canonical program hash: SHA-256/128 over the sorted
/// `(identity, canon_hash)` pairs — insensitive to formatting, comments,
/// declaration order, and rule-binding names. `None` when the source has no
/// canonical form.
pub fn canonical_program_hash(source: &str) -> Option<String> {
    let mut declarations = canonical_declarations(source)?;
    declarations.sort_by(|a, b| a.identity.cmp(&b.identity));
    let mut manifest = String::new();
    for declaration in &declarations {
        manifest.push_str(&declaration.identity);
        manifest.push('\t');
        manifest.push_str(&declaration.canon_hash);
        manifest.push('\n');
    }
    Some(stable_hash(&manifest))
}

fn canonical_item_chunk(item: Item) -> (String, bool) {
    let (item, alpha) = match item {
        Item::Rule(rule) => {
            let (rule, applied) = alpha_rule(rule);
            (Item::Rule(rule), applied)
        }
        other => (other, true),
    };
    let mut chunk = String::new();
    format_item(item, &mut chunk);
    (chunk, alpha)
}

/// Remove comments lexically (the lexer is string-aware, so `#` inside a
/// prompt string survives). Whole-line comments leave blank lines, which
/// `normalize_chunk` drops.
fn strip_comments(source: &str) -> String {
    let comments = lex_comments(source);
    if comments.is_empty() {
        return source.to_owned();
    }
    let mut stripped = String::with_capacity(source.len());
    let mut cursor = 0;
    let mut spans: Vec<_> = comments.iter().map(|comment| comment.span).collect();
    spans.sort_by_key(|span| span.start);
    for span in spans {
        if span.start < cursor {
            continue;
        }
        stripped.push_str(&source[cursor..span.start]);
        cursor = span.end.max(span.start);
    }
    stripped.push_str(&source[cursor..]);
    stripped
}

/// Canonical text normalization: trailing-trim every line, drop blank lines
/// (blank placement is formatting, and stripped whole-line comments leave
/// blanks behind).
fn normalize_chunk(chunk: &str) -> String {
    let mut normalized = String::with_capacity(chunk.len());
    for line in chunk.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        normalized.push_str(trimmed);
        normalized.push('\n');
    }
    normalized
}

/// The identity is the declaration's header line: the first canonical line
/// that is not a tag or description, with any trailing `{` normalized away —
/// byte-compatible with merge's `DeclBlock.identity`.
fn identity_of(canonical: &str) -> Option<String> {
    canonical
        .lines()
        .find(|line| !line.starts_with('@') && !line.starts_with('"'))
        .map(|line| line.trim_end().trim_end_matches('{').trim_end().to_owned())
}

/// The canonical text with the header line's NAME token (the identity's
/// last whitespace token) replaced by `_` — the rename-detection key.
/// Header-line-only: a body mentioning the declaration's own name is not a
/// pattern the language has (rules and classes do not self-reference), and
/// leaving the body untouched keeps the key conservative — a missed match
/// only forfeits a carry, never fabricates one.
fn name_normalized(canonical: &str, identity: &str) -> String {
    let Some(name) = identity.split_whitespace().last() else {
        return canonical.to_owned();
    };
    let mut out = String::with_capacity(canonical.len());
    for (index, line) in canonical.lines().enumerate() {
        let is_header = canonical
            .lines()
            .position(|candidate| !candidate.starts_with('@') && !candidate.starts_with('"'))
            == Some(index);
        if is_header {
            if let Some(position) = line.rfind(name) {
                out.push_str(&line[..position]);
                out.push('_');
                out.push_str(&line[position + name.len()..]);
            } else {
                out.push_str(line);
            }
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Positionally rename a rule's local bindings. Returns the (possibly
/// rewritten) rule and whether alpha applied; every uncertainty returns the
/// rule unchanged with `false` — degrading to L1+L2 is always sound, a
/// wrong rename never is.
fn alpha_rule(rule: RuleDecl) -> (RuleDecl, bool) {
    match try_alpha_rule(&rule) {
        Some(renamed) => (renamed, true),
        None => (rule, false),
    }
}

fn try_alpha_rule(rule: &RuleDecl) -> Option<RuleDecl> {
    // The reserved namespace must be absent from the whole rule.
    let full_text = format!(
        "{}\n{}",
        rule.whens
            .iter()
            .map(|when| when.text.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        rule.body.text
    );
    if full_text.contains(CANON_PREFIX) {
        return None;
    }

    let (mut ast, diagnostics) = parse_rule_body(&rule.body.text, rule.body.body_base());
    if !diagnostics.is_empty() {
        return None;
    }
    // Losslessness gate: the body parser + printer must round-trip the
    // original text (modulo the same whitespace normalization the canonical
    // hash applies). A body the printer cannot faithfully reproduce refuses
    // alpha — a lossy reprint could collapse two different rules.
    let identity_renamer = |text: &str| text.to_owned();
    let mut reprinted = String::new();
    for statement in &ast.statements {
        print_statement_rn(statement, 0, &identity_renamer, &mut reprinted);
    }
    if normalize_body(&reprinted) != normalize_body(&rule.body.text) {
        return None;
    }

    // Binding-site order: `when … as` intros first, then body bindings.
    let mut bindings: Vec<String> = Vec::new();
    for when in &rule.whens {
        let (pattern, _) = split_when_guard(&when.text);
        if let Some(binding) = binding_after_as(pattern) {
            if !bindings.contains(&binding) {
                bindings.push(binding);
            }
        }
    }
    let mut body_bindings = Vec::new();
    collect_bindings(&ast.statements, &mut body_bindings);
    for binding in body_bindings {
        if !bindings.contains(&binding) {
            bindings.push(binding);
        }
    }
    if bindings.is_empty() {
        return Some(rule.clone());
    }

    let renames: Vec<(String, String)> = bindings
        .iter()
        .enumerate()
        .map(|(index, binding)| (binding.clone(), format!("{CANON_PREFIX}{index}")))
        .collect();

    // `when` clauses: the pattern part may mention a binding ONLY as its
    // `as <binding>` intro (a binding shadowing a sugar word or schema name
    // in pattern position refuses alpha); the guard renames dot-guarded.
    let mut whens = Vec::with_capacity(rule.whens.len());
    for when in &rule.whens {
        let (pattern, guard) = split_when_guard(&when.text);
        let mut new_pattern = pattern.to_owned();
        for (from, to) in &renames {
            let occurrences = count_word(&new_pattern, from);
            if occurrences == 0 {
                continue;
            }
            let intro = format!("as {from}");
            if occurrences != 1 || !new_pattern.contains(&intro) {
                return None;
            }
            new_pattern = new_pattern.replace(&intro, &format!("as {to}"));
        }
        let new_text = match guard {
            Some(guard) => {
                let mut renamed_guard = guard.to_owned();
                for (from, to) in &renames {
                    renamed_guard = rename_reference(&renamed_guard, from, to);
                }
                format!("{new_pattern} where {renamed_guard}")
            }
            None => new_pattern,
        };
        whens.push(WhenClause {
            text: new_text,
            span: when.span,
        });
    }

    // Body: structured rename for definitions and `after` references, the
    // dot-guarded reference renamer for value/expression positions (field
    // and schema names are emitted verbatim by the printer).
    rename_bindings(&mut ast.statements, &renames);
    let value_renames = renames.clone();
    let renamer = move |text: &str| {
        let mut current = text.to_owned();
        for (from, to) in &value_renames {
            current = rename_reference(&current, from, to);
        }
        current
    };
    let mut body = String::new();
    for statement in &ast.statements {
        print_statement_rn(statement, 0, &renamer, &mut body);
    }

    let mut renamed = rule.clone();
    renamed.whens = whens;
    // Alpha-renamed reprint: the text is no longer the file's.
    renamed.body.rewrite(body);
    Some(renamed)
}

fn normalize_body(body: &str) -> String {
    let mut normalized = String::with_capacity(body.len());
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        normalized.push_str(trimmed);
        normalized.push('\n');
    }
    normalized
}

fn count_word(text: &str, word: &str) -> usize {
    let bytes = text.as_bytes();
    let needle = word.as_bytes();
    let mut count = 0;
    let mut index = 0;
    while index + needle.len() <= bytes.len() {
        let at_start = index == 0
            || !(bytes[index - 1].is_ascii_alphanumeric()
                || bytes[index - 1] == b'_'
                || bytes[index - 1] == b'.');
        if at_start
            && bytes[index..].starts_with(needle)
            && !bytes
                .get(index + needle.len())
                .is_some_and(|next| next.is_ascii_alphanumeric() || *next == b'_')
        {
            count += 1;
            index += needle.len();
            continue;
        }
        index += 1;
    }
    count
}

/// Whole-word reference rename like `body_print::rename_text`, with one
/// extra guard: an occurrence preceded by `.` is a FIELD position
/// (`t.status`), never a binding reference — renaming it would collapse two
/// semantically different declarations, the one direction canonicalization
/// must never err in. String-literal content is preserved except inside
/// `{{ … }}` template interpolations, where bindings are real references.
fn rename_reference(source: &str, binding: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let needle = binding.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut in_template = false;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"{{") {
            in_template = true;
            out.push_str("{{");
            index += 2;
            continue;
        }
        if bytes[index..].starts_with(b"}}") {
            in_template = false;
            out.push_str("}}");
            index += 2;
            continue;
        }
        if bytes[index] == b'"' && !in_template {
            in_string = !in_string;
            out.push('"');
            index += 1;
            continue;
        }
        let renameable = !in_string || in_template;
        let at_word_start = index == 0
            || !(bytes[index - 1].is_ascii_alphanumeric()
                || bytes[index - 1] == b'_'
                || bytes[index - 1] == b'.');
        if renameable
            && at_word_start
            && bytes[index..].starts_with(needle)
            && !bytes
                .get(index + needle.len())
                .is_some_and(|next| next.is_ascii_alphanumeric() || *next == b'_')
        {
            out.push_str(replacement);
            index += needle.len();
            continue;
        }
        out.push(bytes[index] as char);
        index += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "workflow Demo\n\noutput result Report\n\nclass Report {\n  message string\n}\n\nclass Ticket {\n  status string\n}\n\nrule triage\n  when started\n=> {\n  record Ticket {\n    status \"open\"\n  }\n}\n\nrule close\n  when Ticket as t where t.status == \"open\"\n=> {\n  complete result {\n    message \"done: {{ t.status }}\"\n  }\n}\n";

    #[test]
    fn formatting_comments_and_binding_names_share_a_canon_class() {
        let base = canonical_declarations(BASE).expect("canonical");
        // Reformat + comment + binding rename: same canonical declarations.
        let noisy = BASE
            .replace("rule close\n", "# closes the ticket\nrule close\n")
            .replace(" as t where t.status", " as ticket where ticket.status")
            .replace("{{ t.status }}", "{{ ticket.status }}")
            .replace("  message string", "  message   string");
        let noisy_canon = canonical_declarations(&noisy).expect("canonical");
        assert_eq!(base, noisy_canon);
        assert_eq!(canonical_program_hash(BASE), canonical_program_hash(&noisy));
    }

    #[test]
    fn semantic_edits_change_the_canon_hash() {
        let edited = BASE.replace("status \"open\"", "status \"reopened\"");
        let base = canonical_declarations(BASE).expect("canonical");
        let after = canonical_declarations(&edited).expect("canonical");
        let hash_of = |declarations: &[DeclCanon], identity: &str| {
            declarations
                .iter()
                .find(|declaration| declaration.identity == identity)
                .map(|declaration| declaration.canon_hash.clone())
        };
        assert_ne!(
            hash_of(&base, "rule triage"),
            hash_of(&after, "rule triage")
        );
        assert_eq!(hash_of(&base, "rule close"), hash_of(&after, "rule close"));
    }

    #[test]
    fn field_named_like_a_binding_never_collapses() {
        // Binding `status` collides with the FIELD `status`: the dot-guarded
        // renamer must leave `t.status`-style field positions alone — here
        // the field name inside the record block stays verbatim while the
        // binding renames, so the two rules below stay canon-DIFFERENT.
        let with_status_binding = "workflow Demo\n\nclass Ticket {\n  status string\n}\n\nrule watch\n  when Ticket as status\n=> {\n  record Ticket {\n    status \"seen: {{ status.status }}\"\n  }\n}\n";
        let with_other_field =
            with_status_binding.replace("{{ status.status }}", "{{ status.id }}");
        let a = canonical_declarations(with_status_binding).expect("canonical");
        let b = canonical_declarations(&with_other_field).expect("canonical");
        let rule_a = a.iter().find(|d| d.identity == "rule watch").unwrap();
        let rule_b = b.iter().find(|d| d.identity == "rule watch").unwrap();
        assert_ne!(rule_a.canon_hash, rule_b.canon_hash);
    }

    #[test]
    fn rename_hash_matches_across_a_pure_rename_only() {
        let renamed = BASE.replace("rule close\n", "rule closed_out\n");
        let base = canonical_declarations(BASE).expect("canonical");
        let after = canonical_declarations(&renamed).expect("canonical");
        let close = base.iter().find(|d| d.identity == "rule close").unwrap();
        let closed_out = after
            .iter()
            .find(|d| d.identity == "rule closed_out")
            .unwrap();
        assert_ne!(close.canon_hash, closed_out.canon_hash);
        assert_eq!(close.rename_hash, closed_out.rename_hash);

        // Rename + edit: the rename key must NOT match (fail-closed).
        let rename_and_edit =
            renamed.replace("message \"done: {{ t.status }}\"", "message \"finished\"");
        let edited = canonical_declarations(&rename_and_edit).expect("canonical");
        let edited_rule = edited
            .iter()
            .find(|d| d.identity == "rule closed_out")
            .unwrap();
        assert_ne!(close.rename_hash, edited_rule.rename_hash);
    }

    #[test]
    fn unparseable_source_has_no_canonical_form() {
        assert_eq!(canonical_declarations("not whip at all"), None);
        assert_eq!(canonical_program_hash("rule {"), None);
    }

    #[test]
    fn reserved_namespace_degrades_alpha_not_correctness() {
        let reserved = BASE
            .replace(" as t where t.status", " as wsc__9 where wsc__9.status")
            .replace("{{ t.status }}", "{{ wsc__9.status }}");
        let declarations = canonical_declarations(&reserved).expect("canonical");
        let rule = declarations
            .iter()
            .find(|declaration| declaration.identity == "rule close")
            .unwrap();
        assert!(!rule.alpha);
    }
}
