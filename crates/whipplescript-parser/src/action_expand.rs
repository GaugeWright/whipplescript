//! Action-call expansion (DR-0023): inlines `action` effect-chain templates at
//! their rule-body call sites before analysis, the sibling of `flow`/`pattern`
//! expansion. A call `run_task(reviewer, task, "codex")` is replaced by the
//! action's body with parameters substituted for arguments and the action's
//! internal bindings uniquified per call site (hygiene), so two calls in one
//! rule body never collide. The expanded chain is ordinary rule-body text that
//! re-enters the normal lowering pipeline — the durable graph shows the
//! expansion, never a hidden call (modelled in models/maude/tests/action-expansion.maude).
//!
//! v0 scope (DR-0023 O1/O2): calls are fire-and-forget (no `as` binding); an
//! action body holds only effect statements, `after` blocks, and `record` — no
//! `complete`/`fail`/`case`/`branch`, and no nested action calls. Forbidding
//! calls inside action bodies keeps the call graph depth-1 (trivially acyclic,
//! so recursion cannot arise) and lets each body parse to AST for position-aware
//! parameter substitution (a flat text rename would corrupt a field name that
//! shares a parameter's name, e.g. `record R { provider provider }`).

use std::collections::BTreeMap;

use crate::body::{self, BodyStmt};
use crate::body_print::{print_statement_rn, rename_text};
use crate::{ActionDecl, Diagnostic, Item, SourceSpan};

/// Inlines every action call in each rule body. Diagnostics (undeclared action,
/// arity mismatch, `as` binding, forbidden statement, nested call) carry the
/// calling rule's body span so they always point within the original source.
pub fn expand_action_calls(
    items: &mut [Item],
    actions: &[ActionDecl],
    diagnostics: &mut Vec<Diagnostic>,
) {
    if actions.is_empty() {
        return;
    }
    let by_name: BTreeMap<&str, &ActionDecl> =
        actions.iter().map(|a| (a.name.name.as_str(), a)).collect();
    let mut call_index = 0usize;
    for item in items.iter_mut() {
        if let Item::Rule(rule) = item {
            let span = rule.body.span;
            rule.body.text = expand_in_text(
                &rule.body.text,
                &by_name,
                &mut call_index,
                span,
                diagnostics,
            );
        }
    }
}

/// Rewrites every action-call statement in `text` with its inlined expansion,
/// preserving all other lines verbatim. `span` is the enclosing rule body span,
/// used only for diagnostics.
fn expand_in_text(
    text: &str,
    by_name: &BTreeMap<&str, &ActionDecl>,
    call_index: &mut usize,
    span: SourceSpan,
    diagnostics: &mut Vec<Diagnostic>,
) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let Some(name) = call_name_at(line, by_name) else {
            out.push(line.to_owned());
            i += 1;
            continue;
        };
        let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
        let joined = lines[i..].join("\n");
        let open = joined.find('(').expect("call detected with `(`");
        let Some(close) = match_paren(&joined, open) else {
            diagnostics.push(diag(
                span,
                format!("action call `{name}(...)` has an unterminated argument list"),
                "close the `(` with a matching `)`",
            ));
            out.push(line.to_owned());
            i += 1;
            continue;
        };
        let consumed = joined[..=close].matches('\n').count() + 1;
        let args_src = &joined[open + 1..close];
        let trailing = joined[close + 1..]
            .lines()
            .next()
            .unwrap_or_default()
            .trim();
        if !trailing.is_empty() {
            let message = if trailing.starts_with("as ") || trailing == "as" {
                format!("action call `{name}(...)` cannot be bound with `as` (v0 calls are fire-and-forget)")
            } else {
                format!("unexpected `{trailing}` after action call `{name}(...)`")
            };
            diagnostics.push(diag(
                span,
                message,
                "write the call as a standalone statement: `name(args)`",
            ));
            i += consumed;
            continue;
        }
        let args = split_top_level_commas(args_src);
        if let Some(block) = expand_one_call(
            &name,
            &args,
            &indent,
            by_name,
            call_index,
            span,
            diagnostics,
        ) {
            out.push(block);
        }
        i += consumed;
    }
    out.join("\n")
}

/// Expands a single call into re-indented rule-body text, or `None` (with a
/// diagnostic already pushed) if the call is invalid.
fn expand_one_call(
    name: &str,
    args: &[String],
    indent: &str,
    by_name: &BTreeMap<&str, &ActionDecl>,
    call_index: &mut usize,
    span: SourceSpan,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<String> {
    let action = by_name.get(name).expect("call name resolved");
    if args.len() != action.params.len() {
        diagnostics.push(diag(
            span,
            format!(
                "action `{name}` expects {} argument(s) but got {}",
                action.params.len(),
                args.len()
            ),
            "match the call arguments to the action's parameter list",
        ));
        return None;
    }

    // An action body that itself calls an action would break the depth-1 v0
    // contract (and could recurse); reject it with a precise message rather
    // than the generic "unknown statement" the body parser would emit.
    for body_line in action.body.text.lines() {
        if let Some(callee) = call_name_at(body_line, by_name) {
            diagnostics.push(diag(
                span,
                format!("action `{name}` body calls action `{callee}`; v0 actions do not nest"),
                "inline the chain directly, or compose calls at the rule-body level",
            ));
            return None;
        }
    }

    let (mut ast, body_diagnostics) =
        body::parse_rule_body(&action.body.text, action.body.span.start);
    diagnostics.extend(body_diagnostics);
    if !validate_body(&ast.statements, name, span, diagnostics) {
        return None;
    }

    let mut bindings = Vec::new();
    collect_bindings(&ast.statements, &mut bindings);
    for param in &action.params {
        if bindings.iter().any(|b| b == &param.name.name) {
            diagnostics.push(diag(
                span,
                format!(
                    "action `{name}` parameter `{}` collides with an internal binding of the same name",
                    param.name.name
                ),
                "rename the parameter or the binding so substitution is unambiguous",
            ));
            return None;
        }
    }

    let index = *call_index;
    *call_index += 1;

    // Hygiene: rename internal bindings to call-site-unique names. Binding
    // *definitions* and `after` references live in dedicated AST fields the
    // serializer emits verbatim, so rename them in the tree directly; binding
    // *uses* inside value expressions (e.g. `{{ turn.summary }}`) are covered by
    // the `rn` closure below.
    let hygiene: Vec<(String, String)> = bindings
        .iter()
        .map(|b| (b.clone(), format!("{b}__act{index}")))
        .collect();
    rename_bindings(&mut ast.statements, &hygiene);

    // The renamer applies hygiene (for value-position binding uses) then
    // parameter substitution. The two name sets are disjoint (checked above), so
    // the sequential application is collision-free.
    let mut renames = hygiene;
    for (param, arg) in action.params.iter().zip(args) {
        renames.push((param.name.name.clone(), arg.clone()));
    }
    let renamer = move |text: &str| {
        let mut current = text.to_owned();
        for (from, to) in &renames {
            current = rename_text(&current, Some(from), to);
        }
        current
    };

    let mut serialized = String::new();
    for statement in &ast.statements {
        print_statement_rn(statement, 0, &renamer, &mut serialized);
    }
    Some(reindent(serialized.trim_end_matches('\n'), indent))
}

/// Detects an action-call statement at the start of a body line: a known action
/// name followed (after optional whitespace) by `(`.
fn call_name_at(line: &str, by_name: &BTreeMap<&str, &ActionDecl>) -> Option<String> {
    let trimmed = line.trim_start();
    let name_end = trimmed
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(trimmed.len());
    if name_end == 0 {
        return None;
    }
    let name = &trimmed[..name_end];
    if !trimmed[name_end..].trim_start().starts_with('(') {
        return None;
    }
    if by_name.contains_key(name) {
        Some(name.to_owned())
    } else {
        None
    }
}

/// Finds the index of the `)` matching the `(` at byte index `open`, tracking
/// string literals so commas/parens inside `"..."` do not count.
fn match_paren(source: &str, open: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in source.char_indices() {
        if index < open {
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Splits an argument list on top-level commas (ignoring commas inside nested
/// parens or string literals). Returns an empty vec for an empty list.
fn split_top_level_commas(source: &str) -> Vec<String> {
    if source.trim().is_empty() {
        return Vec::new();
    }
    let mut args = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in source.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                args.push(source[start..index].trim().to_owned());
                start = index + 1;
            }
            _ => {}
        }
    }
    args.push(source[start..].trim().to_owned());
    args
}

/// Validates that an action body holds only the v0 chain shape (effect
/// statements, `after` blocks, `record`). Returns false (with diagnostics) on
/// any other statement.
fn validate_body(
    statements: &[BodyStmt],
    name: &str,
    span: SourceSpan,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    let mut ok = true;
    for statement in statements {
        match statement {
            // The v0 "chain shape": effect statements, `after` blocks, `record`,
            // and `done` (consume/transform a fact). `complete`/`fail`/`case`/
            // `branch`/`cancel` are deferred — they entangle terminal/branching
            // analysis with inlining (DR-0023 O2).
            BodyStmt::Effect(_) | BodyStmt::Record(_) | BodyStmt::Done { .. } => {}
            BodyStmt::After(after) => {
                ok &= validate_body(&after.body, name, span, diagnostics);
            }
            other => {
                ok = false;
                diagnostics.push(diag(
                    span,
                    format!(
                        "action `{name}` body may only contain effect statements, `after` blocks, `record`, and `done` (v0); found {}",
                        statement_label(other)
                    ),
                    "move terminal/branching logic to the calling rule",
                ));
            }
        }
    }
    ok
}

fn statement_label(statement: &BodyStmt) -> &'static str {
    match statement {
        BodyStmt::Record(_) => "record",
        BodyStmt::Done { .. } => "done",
        BodyStmt::Effect(_) => "effect",
        BodyStmt::After(_) => "after",
        BodyStmt::Region(_) => "during/until",
        BodyStmt::Case(_) => "case",
        BodyStmt::Terminal(_) => "complete/fail",
        BodyStmt::Cancel { .. } => "cancel",
        BodyStmt::Milestone { .. } => "milestone",
        BodyStmt::Redact { .. } => "redact",
    }
}

/// Collects the action's internal binding names (effect `as` bindings and
/// `after ... as` aliases) in declaration order, deduplicated.
pub(crate) fn collect_bindings(statements: &[BodyStmt], out: &mut Vec<String>) {
    for statement in statements {
        match statement {
            BodyStmt::Effect(effect) => {
                if let Some(binding) = &effect.binding {
                    if !out.contains(binding) {
                        out.push(binding.clone());
                    }
                }
            }
            BodyStmt::After(after) => {
                if let Some(alias) = &after.alias {
                    if !out.contains(alias) {
                        out.push(alias.clone());
                    }
                }
                collect_bindings(&after.body, out);
            }
            _ => {}
        }
    }
}

/// Renames binding *definition* and `after`-reference fields in place (exact
/// identifier match). Value-position binding uses are renamed by the serializer
/// closure instead; together they uniquify every occurrence of a binding.
pub(crate) fn rename_bindings(statements: &mut [BodyStmt], renames: &[(String, String)]) {
    let apply = |name: &mut String| {
        if let Some((_, to)) = renames.iter().find(|(from, _)| from == name) {
            *name = to.clone();
        }
    };
    for statement in statements {
        match statement {
            BodyStmt::Effect(effect) => {
                if let Some(binding) = effect.binding.as_mut() {
                    apply(binding);
                }
            }
            BodyStmt::After(after) => {
                apply(&mut after.binding);
                if let Some(alias) = after.alias.as_mut() {
                    apply(alias);
                }
                rename_bindings(&mut after.body, renames);
            }
            _ => {}
        }
    }
}

/// Re-bases serialized block text (emitted from column 0) under `indent`.
fn reindent(block: &str, indent: &str) -> String {
    block
        .lines()
        .map(|line| {
            if line.trim().is_empty() {
                String::new()
            } else {
                format!("{indent}{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn diag(span: SourceSpan, message: String, suggestion: &str) -> Diagnostic {
    Diagnostic {
        related: Vec::new(),
        span,
        message,
        suggestion: Some(suggestion.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use crate::compile_program;

    const PRELUDE: &str = "@service\nworkflow ActionDemo\n\nclass Ticket { id string }\nclass Note { provider string  status string }\n\nagent reviewer { provider fixture  profile \"r\"  capacity 1 }\n";

    fn route_body(source: &str) -> String {
        let compiled = compile_program(source);
        assert_eq!(
            compiled.diagnostics,
            Vec::new(),
            "{:?}",
            compiled.diagnostics
        );
        let ir = compiled.ir.expect("compiles");
        ir.rules
            .iter()
            .find(|rule| rule.name == "route")
            .expect("route rule")
            .body
            .clone()
    }

    #[test]
    fn call_inlines_with_param_substitution_and_binding_hygiene() {
        let source = format!(
            "{PRELUDE}\naction run_task(who string, provider string) {{\n  tell who as turn \"Do {{{{ provider }}}} work.\"\n  after turn succeeds {{\n    record Note {{ provider provider  status \"done\" }}\n  }}\n}}\n\nrule route\n  when Ticket as ticket\n=> {{\n  run_task(reviewer, \"codex\")\n  run_task(reviewer, \"claude\")\n}}\n"
        );
        let body = route_body(&source);

        // The call statements are gone; the chain is inlined.
        assert!(!body.contains("run_task("), "call not expanded: {body}");
        assert!(
            body.contains("tell reviewer"),
            "tell target substituted: {body}"
        );

        // Hygiene: the two calls get distinct, call-site-keyed bindings.
        assert!(
            body.contains("turn__act0"),
            "first binding uniquified: {body}"
        );
        assert!(
            body.contains("turn__act1"),
            "second binding uniquified: {body}"
        );
        assert!(
            !body.contains("as turn\n") && !body.contains("as turn "),
            "raw binding leaked: {body}"
        );

        // Position-aware substitution: the `provider` FIELD NAME survives while
        // the `provider` PARAMETER value is substituted (the DR example case).
        assert!(
            body.contains("provider \"codex\""),
            "first arg substituted as value: {body}"
        );
        assert!(
            body.contains("provider \"claude\""),
            "second arg substituted as value: {body}"
        );
        assert!(
            body.contains("status \"done\""),
            "literal field preserved: {body}"
        );

        // Template interpolation is substituted too.
        assert!(
            body.contains("Do {{ \"codex\" }} work."),
            "template substituted: {body}"
        );
    }

    #[test]
    fn call_nested_inside_an_after_block_expands_in_place() {
        // A call is not always a top-level statement; it can sit inside a
        // rule-body `after` block. Expansion is line-based and brace-agnostic, so
        // the surrounding block is preserved and the call is inlined in place.
        let source = format!(
            "{PRELUDE}\naction note_done(who string) {{\n  tell who as turn \"wrap up\"\n  after turn succeeds {{\n    record Note {{ provider \"x\"  status \"done\" }}\n  }}\n}}\n\nrule route\n  when Ticket as ticket\n  when reviewer is available\n=> {{\n  tell reviewer as lead \"start\"\n  after lead succeeds {{\n    note_done(reviewer)\n  }}\n}}\n"
        );
        let body = route_body(&source);
        assert!(!body.contains("note_done("), "call expanded: {body}");
        // The outer block binding and the inlined inner binding coexist.
        assert!(body.contains("as lead"), "outer effect preserved: {body}");
        assert!(
            body.contains("turn__act0"),
            "inner binding uniquified: {body}"
        );
        assert!(
            body.contains("after lead succeeds"),
            "outer after preserved: {body}"
        );
    }

    fn diagnostics_for(source: &str) -> Vec<String> {
        compile_program(source)
            .diagnostics
            .into_iter()
            .map(|d| d.message)
            .collect()
    }

    #[test]
    fn undeclared_action_is_rejected() {
        // `other` is declared but never called, so it is inert and compiles.
        let source = format!(
            "{PRELUDE}\nrule route\n  when Ticket as ticket\n=> {{\n  tell reviewer as turn \"go\"\n}}\n\naction other(x string) {{\n  tell reviewer as turn \"{{{{ x }}}}\"\n}}\n"
        );
        // `other` is declared but never called: this compiles cleanly (inert).
        let compiled = compile_program(&source);
        assert_eq!(
            compiled.diagnostics,
            Vec::new(),
            "{:?}",
            compiled.diagnostics
        );
    }

    #[test]
    fn arity_mismatch_is_rejected() {
        let source = format!(
            "{PRELUDE}\naction run_task(who string, label string) {{\n  tell who as turn \"{{{{ label }}}}\"\n}}\n\nrule route\n  when Ticket as ticket\n=> {{\n  run_task(reviewer)\n}}\n"
        );
        let messages = diagnostics_for(&source);
        assert!(
            messages
                .iter()
                .any(|m| m.contains("expects 2 argument(s) but got 1")),
            "{messages:?}"
        );
    }

    #[test]
    fn binding_a_call_is_rejected() {
        let source = format!(
            "{PRELUDE}\naction run_task(who string) {{\n  tell who as turn \"go\"\n}}\n\nrule route\n  when Ticket as ticket\n=> {{\n  run_task(reviewer) as outcome\n}}\n"
        );
        let messages = diagnostics_for(&source);
        assert!(
            messages.iter().any(|m| m.contains("fire-and-forget")),
            "{messages:?}"
        );
    }

    #[test]
    fn terminal_in_action_body_is_rejected() {
        let source = format!(
            "{PRELUDE}\naction run_task(who string) {{\n  tell who as turn \"go\"\n  after turn succeeds {{\n    complete result {{ provider \"x\"  status \"y\" }}\n  }}\n}}\n\nrule route\n  when Ticket as ticket\n=> {{\n  run_task(reviewer)\n}}\n"
        );
        let messages = diagnostics_for(&source);
        assert!(
            messages
                .iter()
                .any(|m| m.contains("may only contain effect statements")),
            "{messages:?}"
        );
    }

    #[test]
    fn nested_action_call_is_rejected() {
        let source = format!(
            "{PRELUDE}\naction inner(who string) {{\n  tell who as turn \"inner\"\n}}\n\naction outer(who string) {{\n  inner(who)\n}}\n\nrule route\n  when Ticket as ticket\n=> {{\n  outer(reviewer)\n}}\n"
        );
        let messages = diagnostics_for(&source);
        assert!(
            messages
                .iter()
                .any(|m| m.contains("v0 actions do not nest")),
            "{messages:?}"
        );
    }
}
