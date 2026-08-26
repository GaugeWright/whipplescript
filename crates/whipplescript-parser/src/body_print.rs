//! AST-to-text serialization of effect statements, used by `then` expansion
//! to re-serialize a chained effect with its synthetic handle binding.
//! (Extracted from the deleted flow expansion, where it round-tripped flow
//! steps; the coverage is the full `BodyEffectKind` surface.)

use crate::body::{self, BodyEffectKind, BodyStmt, FieldValue, Prompt, RecordStmt, TerminalStmt};

pub(crate) fn push_stmt_line(out: &mut String, indent: usize, line: &str) {
    for _ in 0..indent {
        out.push_str("  ");
    }
    out.push_str(line);
    out.push('\n');
}

fn print_fields(
    fields: &[body::FieldAssign],
    indent: usize,
    rn: &dyn Fn(&str) -> String,
    out: &mut String,
) {
    for field in fields {
        match &field.value {
            FieldValue::Shorthand => push_stmt_line(out, indent, &field.name),
            FieldValue::Expr { source, .. } => {
                push_stmt_line(out, indent, &format!("{} {}", field.name, rn(source)))
            }
            FieldValue::Nested { schema, fields } => {
                push_stmt_line(out, indent, &format!("{} {schema} {{", field.name));
                print_fields(fields, indent + 1, rn, out);
                push_stmt_line(out, indent, "}");
            }
        }
    }
}

fn format_access_grants(
    access_grants: &[body::AccessGrant],
    rn: &dyn Fn(&str) -> String,
) -> String {
    access_grants
        .iter()
        .map(|grant| {
            let ops = grant
                .operations
                .iter()
                .map(|op| {
                    let mut clause = op.operation.clone();
                    if let Some(target) = &op.target {
                        clause.push_str(&format!(" for {}", rn(target)));
                    }
                    if !op.globs.is_empty() {
                        clause.push_str(&format!(
                            " [{}]",
                            op.globs
                                .iter()
                                .map(|glob| format!("{glob:?}"))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                    clause
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!(" with access to {} {{ {ops} }}", grant.resource)
        })
        .collect::<String>()
}

pub(crate) fn print_effect(
    effect: &body::EffectStmt,
    indent: usize,
    rn: &dyn Fn(&str) -> String,
    out: &mut String,
) {
    let binding = effect
        .binding
        .as_ref()
        .map(|binding| format!(" as {binding}"))
        .unwrap_or_default();
    let requires = if effect.requires.is_empty() {
        String::new()
    } else {
        format!(
            " requires [{}]",
            effect
                .requires
                .iter()
                .map(|capability| format!("{capability:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let timeout = effect
        .timeout_seconds
        .map(|seconds| format!(" timeout {seconds}s"))
        .unwrap_or_default();
    let header = match &effect.kind {
        BodyEffectKind::HttpRequest {
            method,
            url,
            headers,
            body,
            signed_with,
        } => {
            let mut lines = Vec::new();
            for header in headers {
                let value = match &header.value {
                    body::RequestHeaderValue::Credential {
                        presentation,
                        handle,
                    } => format!("{} {}", presentation.as_str(), rn(handle)),
                    body::RequestHeaderValue::Expr { source, .. } => rn(source),
                };
                lines.push(format!("    header {:?} {value}", header.name));
            }
            if let Some((source, _)) = body {
                lines.push(format!("    body {}", rn(source)));
            }
            let block = if lines.is_empty() {
                " {}".to_owned()
            } else {
                format!(" {{\n{}\n  }}", lines.join("\n"))
            };
            let signed = signed_with
                .as_ref()
                .map(|handle| format!(" signed with {}", rn(handle)))
                .unwrap_or_default();
            format!("request {method} {url:?}{block}{signed}")
        }
        BodyEffectKind::Tell {
            target,
            access_grants,
            skills,
            on_stream,
        } => {
            // Re-serialize `with access to <resource> { <op clauses> }` grants so a
            // flow `tell` preserves its access metadata. `for <target>` refs are flow
            // bindings (renamed); resource names and globs are literals.
            let grants = format_access_grants(access_grants, rn);
            // Re-serialize `with skills [...]` (Phase 7) so a flow `tell` preserves
            // its turn-scoped skill pins (string literals, not renamed).
            let skills = if skills.is_empty() {
                String::new()
            } else {
                let list = skills
                    .iter()
                    .map(|skill| format!("{skill:?}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(" with skills [{list}]")
            };
            // Re-serialize `on stream <name>` (std.vcs) so a flow `tell`
            // preserves its per-turn homing.
            let homing = on_stream
                .as_ref()
                .map(|stream| format!(" on stream {stream}"))
                .unwrap_or_default();
            format!(
                "tell {}{requires}{binding}{timeout}{grants}{skills}{homing}",
                rn(target)
            )
        }
        BodyEffectKind::Prompt { provider } => {
            let using = provider
                .as_ref()
                .map(|provider| format!(" using {provider}"))
                .unwrap_or_default();
            let (text, content_type) = effect
                .prompt
                .as_ref()
                .map(|prompt| (prompt.text.as_str(), prompt.content_type.as_deref()))
                .unwrap_or(("", None));
            let annotation = content_type.unwrap_or_default();
            push_stmt_line(out, indent, &format!("prompt \"\"\"{annotation}"));
            for line in rn(text).lines() {
                push_stmt_line(out, indent, line);
            }
            push_stmt_line(
                out,
                indent,
                &format!("\"\"\"{using}{requires}{binding}{timeout}"),
            );
            return;
        }
        BodyEffectKind::Coerce {
            name,
            args,
            endorsed,
            declassified,
        } => {
            let args = args
                .iter()
                .map(|arg| rn(arg))
                .collect::<Vec<_>>()
                .join(", ");
            // preserve the source-crossing markers through flow expansion (trailing).
            let endorsed = if *endorsed { " endorsed" } else { "" };
            let declassified = if *declassified { " declassified" } else { "" };
            push_stmt_line(
                out,
                indent,
                &format!("coerce {name}({args}){binding}{timeout}{endorsed}{declassified}"),
            );
            return;
        }
        BodyEffectKind::Decide { result_fields } => {
            let shape = result_fields
                .iter()
                .map(|(name, ty)| format!("{name} {ty}"))
                .collect::<Vec<_>>()
                .join(", ");
            let prompt = effect
                .prompt
                .as_ref()
                .map(|p| p.text.clone())
                .unwrap_or_default();
            push_stmt_line(
                out,
                indent,
                &format!(
                    "decide {:?} -> {{ {shape} }}{binding}{timeout}",
                    rn(&prompt)
                ),
            );
            return;
        }
        BodyEffectKind::Call {
            capability,
            argument,
        } => {
            let argument = argument
                .as_ref()
                .map(|argument| format!(" for {}", rn(argument)))
                .unwrap_or_default();
            push_stmt_line(
                out,
                indent,
                &format!("call {capability}{argument}{binding}{timeout}"),
            );
            return;
        }
        BodyEffectKind::ConstructCapabilityCall {
            keyword, fields, ..
        } => {
            if keyword == "recall" {
                let pool = fields
                    .iter()
                    .find(|field| field.name == "pool")
                    .map(|field| field.source.as_str())
                    .unwrap_or_default();
                let query = fields
                    .iter()
                    .find(|field| field.name == "query")
                    .map(|field| field.source.as_str())
                    .unwrap_or_default();
                push_stmt_line(
                    out,
                    indent,
                    &format!("recall {pool} for {query}{binding}{timeout}"),
                );
            } else {
                let field_source = fields
                    .iter()
                    .map(|field| field.source.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                push_stmt_line(
                    out,
                    indent,
                    &format!("{keyword} {field_source}{binding}{timeout}"),
                );
            }
            return;
        }
        BodyEffectKind::Invoke {
            workflow,
            payload,
            access_grants,
        } => {
            push_stmt_line(out, indent, &format!("invoke {workflow} {{"));
            print_fields(payload, indent + 1, &rn, out);
            let grants = format_access_grants(access_grants, rn);
            push_stmt_line(
                out,
                indent,
                &format!("}}{requires}{binding}{timeout}{grants}"),
            );
            return;
        }
        BodyEffectKind::Timer {
            duration_seconds,
            until,
            ..
        } => {
            match until {
                Some(deadline) => push_stmt_line(
                    out,
                    indent,
                    &format!("timer until {:?}{binding}", rn(deadline)),
                ),
                None => push_stmt_line(out, indent, &format!("timer {duration_seconds}s{binding}")),
            }
            return;
        }
        BodyEffectKind::Exec {
            target,
            parse_target,
        } => {
            let parse = match parse_target {
                Some(parse) if parse.each => format!(" -> each {}", parse.schema),
                Some(parse) => format!(" -> {}", parse.schema),
                None => String::new(),
            };
            let head = match target {
                crate::body::ExecTarget::RawCommand(command) => format!("exec {command:?}"),
                crate::body::ExecTarget::Capability {
                    name,
                    stdin_binding,
                } => format!("exec {name} with {stdin_binding}"),
            };
            push_stmt_line(out, indent, &format!("{head}{parse}{binding}{timeout}"));
            return;
        }
        BodyEffectKind::TrackerFile { queue, fields } => {
            push_stmt_line(out, indent, &format!("file issue into {queue} {{"));
            print_fields(fields, indent + 1, &rn, out);
            push_stmt_line(out, indent, &format!("}}{binding}"));
            return;
        }
        BodyEffectKind::TrackerClaim {
            item,
            ttl_seconds,
            endorsed,
        } => {
            let ttl = ttl_seconds
                .map(|seconds| format!(" ttl {seconds}s"))
                .unwrap_or_default();
            // The marker prints last, as it parses (DR-0051 §2).
            let endorsed = if *endorsed { " endorsed" } else { "" };
            format!("claim {}{ttl}{binding}{timeout}{endorsed}", rn(item))
        }
        BodyEffectKind::TrackerRelease { item } => format!("release {}", rn(item)),
        BodyEffectKind::LeaseAcquire {
            resource,
            key_expr,
            until_ttl,
            wait_seconds,
        } => {
            let until = if *until_ttl { " until ttl" } else { "" };
            let wait = wait_seconds
                .map(|seconds| format!(" wait {seconds}s"))
                .unwrap_or_default();
            format!(
                "acquire {resource} for {}{until}{wait}{binding}",
                rn(key_expr)
            )
        }
        BodyEffectKind::LeaseRenew {
            acquire_binding,
            ttl_seconds,
        } => {
            let until = ttl_seconds
                .map(|seconds| format!(" until {seconds}s"))
                .unwrap_or_default();
            format!("renew {}{until}{binding}", rn(acquire_binding))
        }
        BodyEffectKind::LedgerAppend {
            ledger,
            schema,
            fields,
        } => {
            push_stmt_line(out, indent, &format!("append {schema} {{"));
            print_fields(fields, indent + 1, &rn, out);
            push_stmt_line(out, indent, &format!("}} to {ledger}{binding}"));
            return;
        }
        BodyEffectKind::CounterConsume {
            counter,
            key_expr,
            amount_expr,
        } => format!(
            "consume {counter} for {} amount {}{binding}",
            rn(key_expr),
            rn(amount_expr)
        ),
        BodyEffectKind::Notify {
            target_expr,
            event,
            from,
            fields,
        } => {
            let from = from
                .as_ref()
                .map(|binding| format!(" from {}", rn(binding)))
                .unwrap_or_default();
            push_stmt_line(
                out,
                indent,
                &format!("emit signal {event} to {}{from} {{", rn(target_expr)),
            );
            print_fields(fields, indent + 1, &rn, out);
            push_stmt_line(out, indent, &format!("}}{binding}"));
            return;
        }
        BodyEffectKind::TrackerFinish { item, fields } => {
            if fields.is_empty() {
                format!("finish {}", rn(item))
            } else {
                push_stmt_line(out, indent, &format!("finish {} {{", rn(item)));
                print_fields(fields, indent + 1, &rn, out);
                // The binding must survive the round-trip: `then x <- finish
                // item { … }` re-serializes through here with the synthetic
                // `as __then_x` handle, and dropping it orphans the desugared
                // `after __then_x succeeds` block.
                push_stmt_line(out, indent, &format!("}}{binding}"));
                return;
            }
        }
        BodyEffectKind::FileRead {
            format,
            store,
            path,
        } => {
            format!(
                "read {format} from {} at {}{requires}{binding}{timeout}",
                rn(store),
                rn(path)
            )
        }
        BodyEffectKind::FileWrite {
            format,
            store,
            path,
            body,
            mode,
        } => {
            push_stmt_line(
                out,
                indent,
                &format!("write {format} to {} at {} {{", rn(store), rn(path)),
            );
            push_stmt_line(out, indent + 1, &format!("body {}", rn(body)));
            push_stmt_line(out, indent + 1, &format!("mode {mode}"));
            push_stmt_line(out, indent, &format!("}}{requires}{binding}{timeout}"));
            return;
        }
        BodyEffectKind::FileImport {
            format,
            schema,
            store,
            path,
        } => {
            format!(
                "import {format} {schema} from {} at {}{requires}{binding}{timeout}",
                rn(store),
                rn(path)
            )
        }
        BodyEffectKind::FileExport {
            format,
            schema,
            store,
            path,
            predicate,
            mode,
        } => {
            push_stmt_line(
                out,
                indent,
                &format!(
                    "export {format} {schema} to {} at {} {{",
                    rn(store),
                    rn(path)
                ),
            );
            if let Some(predicate) = predicate {
                push_stmt_line(out, indent + 1, &format!("where {}", rn(predicate)));
            }
            push_stmt_line(out, indent + 1, &format!("mode {mode}"));
            push_stmt_line(out, indent, &format!("}}{requires}{binding}{timeout}"));
            return;
        }
    };
    match &effect.prompt {
        Some(Prompt { text, content_type }) => {
            let annotation = content_type.clone().unwrap_or_default();
            push_stmt_line(out, indent, &format!("{header} \"\"\"{annotation}"));
            for line in rn(text).lines() {
                push_stmt_line(out, indent, line);
            }
            push_stmt_line(out, indent, "\"\"\"");
        }
        None => push_stmt_line(out, indent, &header),
    }
}

/// Rewrites references to `binding` (paths and bare uses) to `replacement`,
/// as whole-word matches. String-literal content is preserved EXCEPT inside
/// `{{ ... }}` template interpolations, where bindings are real references
/// that must be renamed. This prevents corrupting a literal value like
/// `event_type "ticket"` while still rewriting `"... {{ ticket.title }} ..."`.
///
/// `pub(crate)` so `action_expand` reuses the exact same reference-renaming
/// semantics for parameter substitution and binding hygiene.
pub(crate) fn rename_text(source: &str, binding: Option<&str>, replacement: &str) -> String {
    let Some(binding) = binding else {
        return source.to_owned();
    };
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let needle = binding.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut in_template = false; // inside `{{ ... }}`, even within a string
    while index < bytes.len() {
        // Track `{{` / `}}` template fences (they appear inside strings).
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
        // Rename only where the token is a live reference: outside string
        // literals, or inside a `{{ }}` template.
        let renameable = !in_string || in_template;
        let at_word_start =
            index == 0 || !(bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'_');
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

/// Prints a body statement back to source text, parameterized by an arbitrary
/// reference renamer `rn`. Field names and schema names are emitted verbatim;
/// only value/expression positions pass through `rn`. `action_expand` reuses
/// this to apply parameter substitution + binding hygiene without corrupting
/// field names that happen to share a parameter's name
/// (e.g. `record R { provider provider }`).
pub(crate) fn print_statement_rn(
    statement: &BodyStmt,
    indent: usize,
    rn: &dyn Fn(&str) -> String,
    out: &mut String,
) {
    match statement {
        BodyStmt::Record(record) => print_record(record, indent, &rn, out, "record"),
        BodyStmt::Done {
            binding,
            replacement,
            ..
        } => {
            if let Some(record) = replacement {
                push_stmt_line(out, indent, &format!("done {} ->", rn(binding)));
                print_record(record, indent, &rn, out, "record");
            } else {
                push_stmt_line(out, indent, &format!("done {}", rn(binding)));
            }
        }
        BodyStmt::Terminal(terminal) => print_terminal(terminal, indent, &rn, out),
        BodyStmt::Cancel { binding, .. } => {
            push_stmt_line(out, indent, &format!("cancel {binding}"));
        }
        BodyStmt::Effect(effect) => {
            print_effect(effect, indent, &rn, out);
        }
        BodyStmt::After(after) => {
            let alias = after
                .alias
                .as_ref()
                .map(|alias| format!(" as {alias}"))
                .unwrap_or_default();
            // `reaches` carries a quoted milestone name (Family C); every other
            // predicate is the bare keyword.
            let predicate = match &after.milestone {
                Some(name) => format!("{} {:?}", after.predicate.as_str(), name),
                None => after.predicate.as_str().to_owned(),
            };
            push_stmt_line(
                out,
                indent,
                &format!("after {} {predicate}{alias} {{", after.binding),
            );
            for statement in &after.body {
                print_statement_rn(statement, indent + 1, rn, out);
            }
            push_stmt_line(out, indent, "}");
        }
        BodyStmt::Region(region) => {
            let keyword = if region.until { "until" } else { "during" };
            push_stmt_line(out, indent, &format!("{keyword} {} {{", region.condition));
            for statement in &region.body {
                print_statement_rn(statement, indent + 1, rn, out);
            }
            let view = region
                .lapse_binding
                .as_ref()
                .map(|binding| format!(" as {binding}"))
                .unwrap_or_default();
            push_stmt_line(out, indent, &format!("}} on lapse{view} {{"));
            for statement in &region.lapse_body {
                print_statement_rn(statement, indent + 1, rn, out);
            }
            push_stmt_line(out, indent, "}");
        }
        BodyStmt::Case(case) => {
            push_stmt_line(out, indent, &format!("case {} {{", rn(&case.scrutinee)));
            for branch in &case.branches {
                let binding = branch
                    .binding
                    .as_ref()
                    .map(|binding| format!(" {binding}"))
                    .unwrap_or_default();
                push_stmt_line(
                    out,
                    indent + 1,
                    &format!("{}{binding} => {{", branch.pattern),
                );
                for statement in &branch.body {
                    print_statement_rn(statement, indent + 2, rn, out);
                }
                push_stmt_line(out, indent + 1, "}");
            }
            push_stmt_line(out, indent, "}");
        }
        BodyStmt::Milestone {
            name,
            payload_class,
            fields,
            ..
        } => {
            let of = payload_class
                .as_ref()
                .map(|class| format!(" of {class}"))
                .unwrap_or_default();
            if fields.is_empty() {
                push_stmt_line(out, indent, &format!("emit milestone {name:?}{of}"));
            } else {
                push_stmt_line(out, indent, &format!("emit milestone {name:?}{of} {{"));
                print_fields(fields, indent + 1, rn, out);
                push_stmt_line(out, indent, "}");
            }
        }
        BodyStmt::Redact {
            source,
            keep,
            binding,
            ..
        } => {
            push_stmt_line(
                out,
                indent,
                &format!(
                    "redact {} keep [{}] as {}",
                    rn(source),
                    keep.join(", "),
                    rn(binding)
                ),
            );
        }
    }
}

fn print_record(
    record: &RecordStmt,
    indent: usize,
    rn: &dyn Fn(&str) -> String,
    out: &mut String,
    keyword: &str,
) {
    let from = record
        .from
        .as_ref()
        .map(|binding| format!(" from {}", rn(binding)))
        .unwrap_or_default();
    push_stmt_line(
        out,
        indent,
        &format!("{keyword} {}{from} {{", record.schema),
    );
    print_fields(&record.fields, indent + 1, rn, out);
    push_stmt_line(out, indent, "}");
}

fn print_terminal(
    terminal: &TerminalStmt,
    indent: usize,
    rn: &dyn Fn(&str) -> String,
    out: &mut String,
) {
    let keyword = match terminal.kind {
        body::TerminalKind::Complete => "complete",
        body::TerminalKind::Fail => "fail",
    };
    // A bare scalar payload serializes as `complete <name> <value>` with no block.
    if let Some(FieldValue::Expr { source, .. }) = &terminal.scalar {
        push_stmt_line(
            out,
            indent,
            &format!("{keyword} {} {}", terminal.name, rn(source)),
        );
        return;
    }
    let from = terminal
        .from
        .as_ref()
        .map(|binding| format!(" from {}", rn(binding)))
        .unwrap_or_default();
    push_stmt_line(
        out,
        indent,
        &format!("{keyword} {}{from} {{", terminal.name),
    );
    print_fields(&terminal.fields, indent + 1, rn, out);
    push_stmt_line(out, indent, "}");
}
