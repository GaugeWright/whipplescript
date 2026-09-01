//! Source formatting: rendering the AST back to canonical WhippleScript text.
//!
//! Moved verbatim out of `lib.rs`; `use super::*` keeps the IR types and
//! helpers it already resolved against in scope.

use super::*;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormatOutput {
    pub formatted: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Formats the syntax tree without lowering or analyzing rule bodies.
pub fn format_program(source: &str) -> FormatOutput {
    let parsed = parse_program(source);
    if !parsed.diagnostics.is_empty() {
        return FormatOutput {
            formatted: None,
            diagnostics: parsed.diagnostics,
        };
    }

    FormatOutput {
        formatted: Some(format_syntax(parsed.program)),
        diagnostics: Vec::new(),
    }
}

/// Format `source` while preserving comments where they can be placed safely:
/// top-level **leading** comments (a `# …` or `// …` line above a declaration, or
/// a file-header block) and **trailing** comments on a single-line top-level
/// declaration (`workflow Demo  # …`, attached to that element's line); comments
/// inside raw-body declarations (`rule`/`apply`/`coerce`/`table`, carried by
/// the body substring); and comments inside `class`/`agent`/`enum` bodies, including a
/// data-carrying `enum` variant's nested field block — both own-line (interleaved
/// by source position) and trailing comments on a field/variant line (appended to
/// it), and `signal`/`queue`/`file store` bodies the same way — even though those
/// bodies rebuild from the AST. Returns `None` when the program does not parse, or
/// when a comment has nowhere to attach — e.g. one trailing a declaration's
/// opening-brace line, with no field on that line. The caller refuses such files
/// rather than dropping comments.
pub fn format_program_preserving_comments(source: &str) -> Option<String> {
    let parsed = parse_program(source);
    if !parsed.diagnostics.is_empty() {
        return None;
    }
    let mut comments = lex_comments(source);
    if comments.is_empty() {
        return Some(format_syntax(parsed.program));
    }
    // Both the top-level interleave and the per-body interleave below assume
    // ascending source order.
    comments.sort_by_key(|comment| comment.span.start);
    let program = parsed.program;

    // Each top-level element as (source span, formatted chunk), in source order.
    let mut elements: Vec<(SourceSpan, String)> = Vec::new();
    if let Some(workflow) = program.workflow {
        let mut chunk = String::new();
        format_tags(&program.workflow_tags, &mut chunk);
        format_description(program.workflow_description.as_ref(), &mut chunk);
        push_line(&mut chunk, format!("workflow {}", workflow.name));
        elements.push((workflow.span, chunk));
    }
    for pattern in program.patterns {
        let span = pattern.span;
        let mut chunk = String::new();
        format_pattern(pattern, &mut chunk);
        elements.push((span, chunk));
    }
    for item in program.items {
        let span = item.span();
        let mut chunk = String::new();
        // Field-list bodies (`class`/`agent`/`enum`) rebuild from the AST, which
        // drops comments. Interleave their own-line body comments here; a body
        // comment that cannot be placed safely refuses the whole file (the
        // raw-body formatters — rule/coerce/table — already carry their comments).
        let placed = match &item {
            Item::Class(class_decl) => Some(try_format_class_with_comments(
                class_decl, source, &comments, &mut chunk,
            )),
            Item::Agent(agent) => Some(try_format_agent_with_comments(
                agent, source, &comments, &mut chunk,
            )),
            Item::Enum(enum_decl) => Some(try_format_enum_with_comments(
                enum_decl, source, &comments, &mut chunk,
            )),
            Item::Event(event) => Some(try_format_event_with_comments(
                event, source, &comments, &mut chunk,
            )),
            Item::Tracker(queue) => Some(try_format_tracker_with_comments(
                queue, source, &comments, &mut chunk,
            )),
            Item::FileStore(file_store) => Some(try_format_filestore_with_comments(
                file_store, source, &comments, &mut chunk,
            )),
            _ => None,
        };
        match placed {
            Some(true) => {}
            Some(false) => return None,
            None => format_item(item, &mut chunk),
        }
        elements.push((span, chunk));
    }
    for workflow in program.workflows {
        let span = workflow.span;
        let mut chunk = String::new();
        format_workflow(workflow, &mut chunk);
        elements.push((span, chunk));
    }
    elements.sort_by_key(|(span, _)| span.start);

    // Classify top-level comments. A comment INSIDE an element's span is preserved
    // by that element's body formatter — a raw `body.text` substring
    // (rule/coerce/table) or the per-body interleave above (class/agent/enum) — so
    // emitting it here too would duplicate it; skip it. Otherwise an own-line
    // comment is `leading` (interleaved between elements by position), and a
    // trailing comment (code before it) attaches to the element whose last source
    // line it shares — typically a single-line declaration (`workflow Demo  # x`).
    // A trailing comment with no such element has nowhere to attach, so the file is
    // refused rather than dropping it.
    let mut leading: Vec<&Comment> = Vec::new();
    let mut element_trailing: Vec<Option<&Comment>> = vec![None; elements.len()];
    for comment in &comments {
        let in_body = elements
            .iter()
            .any(|(span, _)| span.start < comment.span.start && comment.span.start < span.end);
        if in_body {
            continue;
        }
        let line_start = source[..comment.span.start]
            .rfind('\n')
            .map(|newline| newline + 1)
            .unwrap_or(0);
        if source[line_start..comment.span.start].trim().is_empty() {
            leading.push(comment);
            continue;
        }
        let comment_line = line_index(source, comment.span.start);
        let mut placed = false;
        for (index, (span, _)) in elements.iter().enumerate() {
            if line_index(source, span.end.saturating_sub(1)) == comment_line {
                if element_trailing[index].is_some() {
                    return None;
                }
                element_trailing[index] = Some(comment);
                placed = true;
                break;
            }
        }
        if !placed {
            return None;
        }
    }

    let mut out = String::new();
    let mut next_comment = 0;
    let element_count = elements.len();
    for (index, (span, chunk)) in elements.iter().enumerate() {
        while next_comment < leading.len() && leading[next_comment].span.start < span.start {
            push_line(&mut out, format_comment(leading[next_comment]));
            next_comment += 1;
        }
        match element_trailing[index] {
            Some(comment) => {
                out.push_str(chunk.strip_suffix('\n').unwrap_or(chunk));
                out.push_str(&format!("  {}\n", format_comment(comment)));
            }
            None => out.push_str(chunk),
        }
        if index + 1 < element_count {
            out.push('\n');
        }
    }
    if next_comment < leading.len() {
        if element_count > 0 {
            out.push('\n');
        }
        while next_comment < leading.len() {
            push_line(&mut out, format_comment(leading[next_comment]));
            next_comment += 1;
        }
    }

    // Safety net against silent data loss: in-body comments are left to each
    // element's body formatter, and some formatters rebuild from the AST (which
    // drops comments). The idempotency self-check can't catch a *consistent*
    // drop, so verify here that every source comment survives — refuse otherwise.
    if lex_comments(&out).len() != comments.len() {
        return None;
    }
    Some(out)
}

pub(crate) fn format_comment(comment: &Comment) -> String {
    let marker = match comment.marker {
        CommentMarker::Hash => "#",
        CommentMarker::Slash => "//",
    };
    let text = comment.text.trim();
    if text.is_empty() {
        marker.to_owned()
    } else {
        format!("{marker} {text}")
    }
}

fn format_syntax(program: Program) -> String {
    let mut formatted = String::new();
    if let Some(workflow) = program.workflow {
        format_tags(&program.workflow_tags, &mut formatted);
        format_description(program.workflow_description.as_ref(), &mut formatted);
        push_line(&mut formatted, format!("workflow {}", workflow.name));
        formatted.push('\n');
    }

    let mut top_level_items = Vec::new();
    top_level_items.extend(program.patterns.into_iter().map(Item::Pattern));
    top_level_items.extend(program.items);
    format_items(top_level_items, &mut formatted);

    if !formatted.is_empty() && !program.workflows.is_empty() {
        formatted.push('\n');
    }
    let workflow_count = program.workflows.len();
    for (index, workflow) in program.workflows.into_iter().enumerate() {
        format_workflow(workflow, &mut formatted);
        if index + 1 < workflow_count {
            formatted.push('\n');
        }
    }

    formatted
}

fn format_items(items: Vec<Item>, formatted: &mut String) {
    let item_count = items.len();
    for (index, item) in items.into_iter().enumerate() {
        format_item(item, formatted);
        if index + 1 < item_count {
            formatted.push('\n');
        }
    }
}

pub(crate) fn format_item(item: Item, formatted: &mut String) {
    match item {
        Item::Include(include) => {
            push_line(formatted, format!("include {:?}", include.path.value));
        }
        Item::Use(use_decl) => {
            push_line(formatted, format!("use {}", use_decl.name.value));
        }
        Item::Measure(measure) => {
            let bound = match &measure.bound {
                crate::MeasureDeclBound::Literal(value) => value.to_string(),
                crate::MeasureDeclBound::Field(field) => {
                    format!("{}.{field}", measure.class.name)
                }
            };
            let direction = if measure.rising { "up" } else { "down" };
            push_line(
                formatted,
                format!(
                    "measure {}.{} {direction} to {bound}",
                    measure.class.name, measure.field.name
                ),
            );
        }
        Item::Tracker(queue) => {
            push_line(formatted, format!("tracker {} {{", queue.name.name));
            push_line(formatted, format!("  provider {}", queue.provider.name));
            push_line(formatted, "}");
        }
        Item::Stream(stream) => {
            push_line(formatted, format!("stream {} {{", stream.name.name));
            push_line(
                formatted,
                format!(
                    "  members [{}]",
                    stream
                        .members
                        .iter()
                        .map(|member| member.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
            if let Some(seconds) = stream.staleness_seconds {
                push_line(formatted, format!("  staleness {seconds}s"));
            }
            push_line(formatted, "}");
        }
        Item::Mark(mark) => {
            push_line(
                formatted,
                format!("mark {:?} after {}", mark.name.value, mark.site),
            );
        }
        Item::Region(region) => {
            push_line(formatted, format!("region {} {{", region.name.name));
            push_line(formatted, format!("  select {:?}", region.select));
            push_line(formatted, "}");
        }
        Item::Gauge(gauge) => {
            let mut header = format!("gauge {}", gauge.name.name);
            if let Some(site) = &gauge.site {
                header.push_str(&format!(" on {site}"));
            }
            header.push_str(" {");
            push_line(formatted, header);
            let judge = match &gauge.judge {
                GaugeJudge::Coerce(target, args) if args.is_empty() => {
                    format!("coerce {}", target.name)
                }
                GaugeJudge::Coerce(target, args) => {
                    format!("coerce {}({})", target.name, args.join(", "))
                }
                GaugeJudge::Prompt(template) => format!("prompt {:?}", template.value),
                GaugeJudge::Exec(command) => format!("exec {:?}", command.value),
                GaugeJudge::Labels(source) => format!("labels {:?}", source.value),
            };
            push_line(formatted, format!("  judge via {judge}"));
            if let Some(bar) = &gauge.expect {
                let subject = match &bar.subject {
                    GaugeBarSubject::Chance { field } => format!("P({})", field.name),
                    GaugeBarSubject::Stat { stat } => stat.name.clone(),
                };
                let direction = if bar.at_least { "at least" } else { "at most" };
                push_line(
                    formatted,
                    format!("  expect {subject} {direction} {}", bar.threshold),
                );
            }
            if !gauge.inputs.is_empty() {
                let names = gauge
                    .inputs
                    .iter()
                    .map(|input| input.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                push_line(formatted, format!("  inputs {names}"));
            }
            push_line(formatted, "}");
        }
        Item::Campaign(campaign) => {
            push_line(formatted, format!("campaign {} {{", campaign.name.name));
            if !campaign.ascend.is_empty() {
                let names = campaign
                    .ascend
                    .iter()
                    .map(|gauge| gauge.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                push_line(formatted, format!("  ascend {names}"));
            }
            for reach in &campaign.reach {
                let direction = if reach.at_least {
                    "at least"
                } else {
                    "at most"
                };
                let unit = reach.unit.as_deref().unwrap_or("");
                push_line(
                    formatted,
                    format!(
                        "  reach {} {direction} {}{unit}",
                        reach.gauge.name, reach.threshold
                    ),
                );
            }
            for guard in &campaign.guard {
                push_line(
                    formatted,
                    format!(
                        "  guard {} within {} percent",
                        guard.gauge.name, guard.band_percent
                    ),
                );
            }
            if !campaign.sacrifice.is_empty() {
                let names = campaign
                    .sacrifice
                    .iter()
                    .map(|gauge| gauge.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                push_line(formatted, format!("  sacrifice {names}"));
            }
            if campaign.proposer_redacted {
                push_line(formatted, "  proposer redacted");
            }
            push_line(formatted, "}");
        }
        Item::Channel(channel) => {
            push_line(formatted, format!("channel {} {{", channel.name.name));
            push_line(formatted, format!("  provider {}", channel.provider.name));
            if let Some(workspace) = &channel.workspace {
                push_line(formatted, format!("  workspace {}", workspace.name));
            }
            if let Some(destination) = &channel.destination {
                push_line(formatted, format!("  destination {:?}", destination.value));
            }
            push_line(formatted, "}");
        }
        Item::Vault(vault) => {
            push_line(formatted, format!("vault {} {{", vault.name.name));
            push_line(formatted, format!("  kind {}", vault.kind.name));
            push_line(
                formatted,
                format!(
                    "  allow [{}]",
                    vault
                        .allow
                        .iter()
                        .map(|entry| entry.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            );
            if let Some(retain) = &vault.retain {
                push_line(formatted, format!("  retain {}", retain.name));
            }
            if let Some(provider) = &vault.provider {
                push_line(formatted, format!("  provider {}", provider.name));
            }
            push_line(formatted, "}");
        }
        Item::Credential(credential) => {
            push_line(formatted, format!("credential {} {{", credential.name.name));
            push_line(formatted, format!("  kind {}", credential.kind.name));
            if !credential.allow.is_empty() {
                push_line(
                    formatted,
                    format!(
                        "  allow [{}]",
                        credential
                            .allow
                            .iter()
                            .map(|entry| entry.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
            }
            push_line(formatted, "}");
        }
        Item::FileStore(file_store) => {
            push_line(formatted, format!("file store {} {{", file_store.name.name));
            push_line(formatted, format!("  root {:?}", file_store.root));
            let format_globs = |formatted: &mut String, direction: &str, globs: &[String]| {
                if !globs.is_empty() {
                    let rendered = globs
                        .iter()
                        .map(|glob| format!("{glob:?}"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    push_line(formatted, format!("  allow {direction} [{rendered}]"));
                }
            };
            format_globs(formatted, "read", &file_store.read_globs);
            format_globs(formatted, "write", &file_store.write_globs);
            if let Some(provider) = &file_store.provider {
                push_line(formatted, format!("  provider {}", provider.name));
            }
            push_line(formatted, "}");
        }
        Item::MemoryPool(pool) => {
            push_line(formatted, format!("memory pool {} {{", pool.name.name));
            if let Some(limit) = pool.context_limit {
                push_line(formatted, format!("  context limit {limit}"));
            }
            push_line(formatted, "}");
        }
        Item::Action(action) => {
            let params = action
                .params
                .iter()
                .map(|param| format!("{} {}", param.name.name, param.ty.to_source()))
                .collect::<Vec<_>>()
                .join(", ");
            push_line(
                formatted,
                format!("action {}({params}) {{", action.name.name),
            );
            for line in action.body.text.lines() {
                if line.trim().is_empty() {
                    push_line(formatted, "");
                } else {
                    push_line(formatted, line.trim_end());
                }
            }
            push_line(formatted, "}");
        }
        Item::Pattern(pattern) => format_pattern(pattern, formatted),
        Item::Apply(apply) => format_apply(apply, formatted),
        Item::WorkflowContract(contract) => {
            push_line(
                formatted,
                format!(
                    "{} {} {}",
                    contract.kind.as_str(),
                    contract.name.name,
                    contract.ty.to_source()
                ),
            );
        }
        Item::Harness(harness) => format_harness(harness, formatted),
        Item::Agent(agent) => format_agent(agent, formatted),
        Item::Enum(enum_decl) => format_enum(enum_decl, formatted),
        Item::Event(event) => format_event(event, formatted),
        Item::Source(source) => format_source(*source, formatted),
        Item::Test(test) => format_test(test, formatted),
        Item::Lease(lease) => {
            push_line(formatted, format!("lease {} {{", lease.name.name));
            if lease.shared {
                push_line(formatted, "  shared");
            }
            push_line(formatted, format!("  key {}", lease.key_type.name));
            push_line(formatted, format!("  slots {}", lease.slots));
            push_line(formatted, format!("  ttl {}s", lease.ttl_seconds));
            push_line(formatted, "}");
        }
        Item::Ledger(ledger) => {
            push_line(formatted, format!("ledger {} {{", ledger.name.name));
            if ledger.shared {
                push_line(formatted, "  shared");
            }
            push_line(formatted, format!("  entry {}", ledger.entry_schema.name));
            push_line(
                formatted,
                format!("  partition by {}", ledger.partition_field.name),
            );
            push_line(formatted, format!("  retain {}s", ledger.retain_seconds));
            push_line(formatted, "}");
        }
        Item::Counter(counter) => {
            push_line(formatted, format!("counter {} {{", counter.name.name));
            if counter.shared {
                push_line(formatted, "  shared");
            }
            push_line(formatted, format!("  key {}", counter.key_type.name));
            push_line(formatted, format!("  cap {}", counter.cap));
            push_line(formatted, format!("  reset {}", counter.reset));
            push_line(formatted, "}");
        }
        Item::Class(class_decl) => format_class(class_decl, formatted),
        Item::Table(table) => format_table(table, formatted),
        Item::Coerce(coerce) => format_coerce(coerce, formatted),
        Item::Assert(assertion) => {
            format_tags(&assertion.tags, formatted);
            format_description(assertion.description.as_ref(), formatted);
            push_line(formatted, format!("assert {}", assertion.expr));
        }
        Item::Rule(rule) => format_rule(rule, formatted),
    }
}

pub(crate) fn format_tags(tags: &[TagDecl], formatted: &mut String) {
    for tag in tags {
        push_line(formatted, format!("@{}", tag.name));
    }
}

pub(crate) fn format_description(description: Option<&StringLiteral>, formatted: &mut String) {
    if let Some(description) = description {
        push_line(formatted, format!("description {:?}", description.value));
    }
}

fn format_pattern(pattern: PatternDecl, formatted: &mut String) {
    let params = if pattern.type_params.is_empty() {
        String::new()
    } else {
        format!(
            "<{}>",
            pattern
                .type_params
                .iter()
                .map(|param| param.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    push_line(
        formatted,
        format!("pattern {}{} {{", pattern.name.name, params),
    );
    let mut inner = String::new();
    format_items(pattern.items, &mut inner);
    for line in inner.lines() {
        if line.is_empty() {
            formatted.push('\n');
        } else {
            push_line(formatted, format!("  {line}"));
        }
    }
    push_line(formatted, "}");
}

fn format_apply(apply: ApplyDecl, formatted: &mut String) {
    let args = if apply.type_args.is_empty() {
        String::new()
    } else {
        format!(
            "<{}>",
            apply
                .type_args
                .iter()
                .map(TypeSyntax::to_source)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    push_line(
        formatted,
        format!(
            "apply {}{} as {} {{",
            apply.pattern.name, args, apply.alias.name
        ),
    );
    format_block_body(&apply.body.text, formatted);
    push_line(formatted, "}");
}

pub(crate) fn format_workflow(workflow: WorkflowDecl, formatted: &mut String) {
    format_tags(&workflow.tags, formatted);
    format_description(workflow.description.as_ref(), formatted);
    push_line(formatted, format!("workflow {} {{", workflow.name.name));
    let mut inner = String::new();
    format_items(workflow.items, &mut inner);
    for line in inner.lines() {
        if line.is_empty() {
            formatted.push('\n');
        } else {
            push_line(formatted, format!("  {line}"));
        }
    }
    push_line(formatted, "}");
}

fn format_harness(harness: HarnessDecl, formatted: &mut String) {
    push_line(
        formatted,
        format!("harness {}: {}", harness.name.name, harness.kind.name),
    );
}

fn format_agent(agent: AgentDecl, formatted: &mut String) {
    let harness = agent
        .harness
        .as_ref()
        .map(|harness| format!(" using {}", harness.name))
        .or_else(|| {
            agent
                .delegated_to
                .as_ref()
                .map(|delegate| format!(" delegated to {}", delegate.name))
        })
        .unwrap_or_default();
    push_line(
        formatted,
        format!("agent {}{} {{", agent.name.name, harness),
    );
    for field in agent.fields {
        match field {
            AgentField::Provider(provider) => {
                push_line(formatted, format!("  provider {}", provider.name));
            }
            AgentField::Profile(profile) => {
                push_line(formatted, format!("  profile {:?}", profile.value));
            }
            AgentField::Capacity(capacity, _) => {
                push_line(formatted, format!("  capacity {capacity}"));
            }
            AgentField::Skills(skills, _) => {
                let skills = skills
                    .into_iter()
                    .map(|skill| format!("{:?}", skill.value))
                    .collect::<Vec<_>>()
                    .join(", ");
                push_line(formatted, format!("  skills [{skills}]"));
            }
            AgentField::Capabilities(capabilities, _) => {
                let capabilities = capabilities
                    .into_iter()
                    .map(|capability| format!("{:?}", capability.value))
                    .collect::<Vec<_>>()
                    .join(", ");
                push_line(formatted, format!("  capabilities [{capabilities}]"));
            }
            AgentField::Requires(classes, _) => {
                let classes = classes
                    .into_iter()
                    .map(|class| class.name)
                    .collect::<Vec<_>>()
                    .join(", ");
                push_line(formatted, format!("  requires [{classes}]"));
            }
            AgentField::Tools(tools, _) => {
                let tools = tools
                    .into_iter()
                    .map(|tool| tool.name)
                    .collect::<Vec<_>>()
                    .join(", ");
                push_line(formatted, format!("  tools [{tools}]"));
            }
            AgentField::Compaction(strategy) => {
                push_line(formatted, format!("  compaction {}", strategy.name));
            }
            AgentField::Thread(mode) => {
                push_line(formatted, format!("  thread {}", mode.name));
            }
            AgentField::Settings(sources) => {
                push_line(formatted, format!("  settings {}", sources.name));
            }
            AgentField::Unknown { name, .. } => {
                push_line(formatted, format!("  {}", name.name));
            }
        }
    }
    push_line(formatted, "}");
}

fn format_enum(enum_decl: EnumDecl, formatted: &mut String) {
    push_line(formatted, format!("enum {} {{", enum_decl.name.name));
    for variant in enum_decl.variants {
        if variant.fields.is_empty() {
            push_line(formatted, format!("  {}", variant.name.name));
            continue;
        }
        push_line(formatted, format!("  {} {{", variant.name.name));
        for field in variant.fields {
            push_line(
                formatted,
                format!("    {} {}", field.name.name, field.ty.to_source()),
            );
        }
        push_line(formatted, "  }");
    }
    push_line(formatted, "}");
}

fn format_time_of_day(time: TimeOfDay) -> String {
    format!("{:02}:{:02}", time.hour, time.minute)
}

fn format_weekday(day: Weekday) -> &'static str {
    match day {
        Weekday::Monday => "monday",
        Weekday::Tuesday => "tuesday",
        Weekday::Wednesday => "wednesday",
        Weekday::Thursday => "thursday",
        Weekday::Friday => "friday",
        Weekday::Saturday => "saturday",
        Weekday::Sunday => "sunday",
    }
}

fn format_recurrence(recurrence: &Recurrence) -> String {
    match recurrence {
        Recurrence::At { time, .. } => format!("at {}", format_time_of_day(*time)),
        Recurrence::EveryDuration { source, .. } => format!("every {source}"),
        Recurrence::EveryCalendar { pattern, time, .. } => {
            let pattern = match pattern {
                CalendarPattern::Day => "day".to_owned(),
                CalendarPattern::Weekday => "weekday".to_owned(),
                CalendarPattern::Weekly(day) => format_weekday(*day).to_owned(),
            };
            format!("every {pattern} at {}", format_time_of_day(*time))
        }
    }
}

fn format_source_value(value: &SourceValue) -> String {
    match value {
        SourceValue::Path {
            binding, segments, ..
        } => {
            let mut text = binding.name.clone();
            for segment in segments {
                text.push('.');
                text.push_str(&segment.name);
            }
            text
        }
        SourceValue::String(literal) => format!("{:?}", literal.value),
        SourceValue::Number(number, _) => number.clone(),
    }
}

fn format_test_fields(fields: &[TestField], formatted: &mut String) {
    for field in fields {
        push_line(
            formatted,
            format!("    {} {}", field.name.name, field.value),
        );
    }
}

fn format_test(test: TestDecl, formatted: &mut String) {
    push_line(formatted, format!("test {:?} {{", test.name.value));
    if let Some(workflow) = &test.workflow {
        push_line(formatted, format!("  workflow {}", workflow.name));
    }
    for clause in &test.clauses {
        match clause {
            TestClause::Given(given) => match given {
                GivenClause::Input { fields, .. } => {
                    push_line(formatted, "  given input {");
                    format_test_fields(fields, formatted);
                    push_line(formatted, "  }");
                }
                GivenClause::Fact { ty, fields, .. } => {
                    push_line(formatted, format!("  given fact {} {{", ty.name));
                    format_test_fields(fields, formatted);
                    push_line(formatted, "  }");
                }
                GivenClause::Signal { name, fields, .. } => {
                    push_line(formatted, format!("  given signal {name} {{"));
                    format_test_fields(fields, formatted);
                    push_line(formatted, "  }");
                }
                GivenClause::Clock { at, .. } => {
                    push_line(formatted, format!("  given clock at {:?}", at.value));
                }
                GivenClause::Tracker {
                    tracker, fields, ..
                } => {
                    push_line(formatted, format!("  given tracker {tracker} issue {{"));
                    format_test_fields(fields, formatted);
                    push_line(formatted, "  }");
                }
                GivenClause::File {
                    store,
                    path,
                    content,
                    ..
                } => {
                    push_line(
                        formatted,
                        format!(
                            "  given file {store} at {:?} {:?}",
                            path.value, content.value
                        ),
                    );
                }
            },
            TestClause::Stub(stub) => {
                let surface = stub.surface.join(" ");
                match &stub.payload {
                    Some(StubPayload::Message(message)) => push_line(
                        formatted,
                        format!("  stub {surface} {} {:?}", stub.outcome, message.value),
                    ),
                    Some(StubPayload::Record(fields)) => {
                        push_line(formatted, format!("  stub {surface} {} {{", stub.outcome));
                        format_test_fields(fields, formatted);
                        push_line(formatted, "  }");
                    }
                    None => push_line(formatted, format!("  stub {surface} {}", stub.outcome)),
                }
            }
            TestClause::Run(run) => {
                let text = match &run.kind {
                    RunKind::UntilIdle => "run until idle".to_owned(),
                    RunKind::UntilWorkflowCompleted => "run until workflow completed".to_owned(),
                    RunKind::UntilWorkflowFailed => "run until workflow failed".to_owned(),
                    RunKind::ForSteps(steps) => format!("run for {steps} steps"),
                };
                push_line(formatted, format!("  {text}"));
            }
            TestClause::Expect(expect) => {
                push_line(
                    formatted,
                    format!("  {}", format_expect_target(&expect.target)),
                );
            }
        }
    }
    push_line(formatted, "}");
}

fn format_expect_target(target: &ExpectTarget) -> String {
    match target {
        ExpectTarget::WorkflowCompleted => "expect workflow completed".to_owned(),
        ExpectTarget::WorkflowFailed { failure: None } => "expect workflow failed".to_owned(),
        ExpectTarget::WorkflowFailed {
            failure: Some(failure),
        } => format!("expect workflow failed with {}", failure.name),
        ExpectTarget::Rule { name, status } => {
            let status = match status {
                RuleStatus::Fired => "fired".to_owned(),
                RuleStatus::FiredTimes(count) => format!("fired {count} times"),
                RuleStatus::DidNotFire => "did not fire".to_owned(),
            };
            format!("expect rule {} {status}", name.name)
        }
        ExpectTarget::Effect { name, status } => {
            let status = match status {
                EffectStatus::Requested => "requested",
                EffectStatus::Completed => "completed",
                EffectStatus::Failed => "failed",
            };
            format!("expect effect {name} {status}")
        }
        ExpectTarget::Diagnostic { code } => format!("expect diagnostic {code}"),
        ExpectTarget::NoEffect { name } => format!("expect no {name}"),
        ExpectTarget::Projection(query) => format!("expect {}", format_proj_query(query)),
    }
}

fn format_proj_query(query: &ProjQuery) -> String {
    match &query.kind {
        ProjQueryKind::Exists => format!("{} exists", query.noun),
        ProjQueryKind::Count { predicate, count } => {
            format!("{} count where {predicate} is {count}", query.noun)
        }
        ProjQueryKind::Where { predicate } => {
            format!("{} where {predicate}", query.noun)
        }
    }
}

fn format_source(source: SourceDecl, formatted: &mut String) {
    push_line(
        formatted,
        format!("source {} as {} {{", source.provider.name, source.name.name),
    );
    if let Some(clock) = &source.clock {
        push_line(
            formatted,
            format!("  {}", format_recurrence(&clock.recurrence)),
        );
        if let Some(timezone) = &clock.timezone {
            push_line(formatted, format!("  timezone {:?}", timezone.value));
        }
        match clock.missed {
            Some(MissedPolicy::Skip) => push_line(formatted, "  missed skip"),
            Some(MissedPolicy::Coalesce) => push_line(formatted, "  missed coalesce"),
            Some(MissedPolicy::CatchUp { limit }) => {
                push_line(formatted, format!("  missed catch_up limit {limit}"))
            }
            None => {}
        }
    }
    if let Some(path) = &source.path {
        push_line(formatted, format!("  path {:?}", path.value));
    }
    if let Some(watch) = &source.watch {
        push_line(formatted, format!("  watch {:?}", watch.value));
    }
    if let Some(url) = &source.url {
        push_line(formatted, format!("  url {:?}", url.value));
    }
    if let Some(dedup) = &source.dedup {
        push_line(formatted, format!("  dedup {}", format_source_value(dedup)));
    }
    // An inbound source's endpoint prints as `path`, which is the spelling it
    // was written in — the IR splits it from the file `path` so nothing has to
    // know the provider kind, and the formatter puts it back.
    if let Some(endpoint) = &source.endpoint {
        push_line(formatted, format!("  path {:?}", endpoint.value));
    }
    if let Some(auth) = &source.auth {
        push_line(
            formatted,
            format!("  auth {} secret {}", auth.mode.as_str(), auth.secret),
        );
    }
    if let Some(correlate) = &source.correlate {
        push_line(
            formatted,
            format!("  correlate {}", format_source_value(correlate)),
        );
    }
    push_line(
        formatted,
        format!("  observe as {}", source.observe_binding.name),
    );
    let from = source
        .emit
        .from
        .as_ref()
        .map(|ident| format!(" from {}", ident.name))
        .unwrap_or_default();
    if source.emit.fields.is_empty() && source.emit.from.is_some() {
        push_line(formatted, format!("  emit {}{from}", source.emit.signal));
    } else {
        push_line(formatted, format!("  emit {}{from} {{", source.emit.signal));
        for field in &source.emit.fields {
            push_line(
                formatted,
                format!(
                    "    {} {}",
                    field.name.name,
                    format_source_value(&field.value)
                ),
            );
        }
        push_line(formatted, "  }");
    }
    push_line(formatted, "}");
}

fn format_event(event: EventDecl, formatted: &mut String) {
    push_line(formatted, format!("signal {} {{", event.name));
    for field in event.fields {
        push_line(
            formatted,
            format!("  {} {}", field.name.name, field.ty.to_source()),
        );
    }
    push_line(formatted, "}");
}

fn format_class(class_decl: ClassDecl, formatted: &mut String) {
    push_line(formatted, format!("class {} {{", class_decl.name.name));
    for field in class_decl.fields {
        let key = if field.is_key { " @key" } else { "" };
        push_line(
            formatted,
            format!("  {} {}{key}", field.name.name, field.ty.to_source()),
        );
    }
    push_line(formatted, "}");
}

fn format_table(table: TableDecl, formatted: &mut String) {
    format_tags(&table.tags, formatted);
    format_description(table.description.as_ref(), formatted);
    push_line(
        formatted,
        format!("table {} as {} [", table.name.name, table.schema.name),
    );
    for row in table.rows {
        push_line(formatted, "  {");
        for line in row.body.text.lines() {
            if line.trim().is_empty() {
                formatted.push('\n');
            } else {
                // `trim()` (not `trim_end()`): normalize the field to a fixed
                // 4-space indent rather than prepending to the row's existing
                // indent, which compounded every pass. Row bodies are flat field
                // lists, so a fixed indent is the canonical form.
                push_line(formatted, format!("    {}", line.trim()));
            }
        }
        push_line(formatted, "  }");
    }
    push_line(formatted, "]");
}

fn format_coerce(coerce: CoerceDecl, formatted: &mut String) {
    let params = coerce
        .params
        .into_iter()
        .map(|param| format!("{} {}", param.name.name, param.ty.to_source()))
        .collect::<Vec<_>>()
        .join(", ");
    push_line(
        formatted,
        format!(
            "coerce {}({}) -> {} {{",
            coerce.name.name,
            params,
            coerce.output.to_source()
        ),
    );
    format_block_body(&coerce.body.text, formatted);
    push_line(formatted, "}");
}

fn format_rule(rule: RuleDecl, formatted: &mut String) {
    format_tags(&rule.tags, formatted);
    format_description(rule.description.as_ref(), formatted);
    push_line(
        formatted,
        format!("{} {}", rule.kind.keyword(), rule.name.name),
    );
    for when in rule.whens {
        push_line(formatted, format!("  when {}", when.text));
    }
    push_line(formatted, "=> {");
    format_block_body(&rule.body.text, formatted);
    push_line(formatted, "}");
}

/// Re-indent a rule/apply body to a canonical form derived from brace nesting,
/// so `whip fmt` is idempotent. Two concerns make this non-trivial:
///   - **Bracket nesting:** code lines are indented by their `{`/`[`/`(` depth
///     (string-aware via `scan_braces`), not by a flat prepend that compounds on
///     nested `record`/`complete` blocks.
///   - **Multi-line `"""..."""` strings:** the content is dedented to its common
///     indent and re-indented to the block depth (preserving relative structure).
///     This matches the single-pass canonical form AND is stable across passes,
///     where the old flat prepend grew the string content every time.
fn format_block_body(body: &str, formatted: &mut String) {
    if body.trim().is_empty() {
        return;
    }
    let lines: Vec<&str> = body.lines().collect();
    let mut index = 0;
    let mut depth: i32 = 1;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.is_empty() {
            formatted.push('\n');
            index += 1;
            continue;
        }
        let opens_with_closer = trimmed
            .chars()
            .next()
            .is_some_and(|ch| matches!(ch, '}' | ']' | ')'));
        let line_depth = if opens_with_closer {
            (depth - 1).max(0)
        } else {
            depth
        };
        let prefix = "  ".repeat(line_depth as usize);
        let (delta, opens_triple) = scan_braces(trimmed);
        push_line(formatted, format!("{prefix}{trimmed}"));
        if opens_triple {
            // Collect the string content up to the closing `"""`.
            let mut end = index + 1;
            while end < lines.len() && lines[end].matches("\"\"\"").count().is_multiple_of(2) {
                end += 1;
            }
            let content = &lines[index + 1..end];
            let common = content
                .iter()
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.len() - line.trim_start().len())
                .min()
                .unwrap_or(0);
            for line in content {
                if line.trim().is_empty() {
                    formatted.push('\n');
                } else {
                    push_line(formatted, format!("{prefix}{}", &line[common..]));
                }
            }
            if end < lines.len() {
                // The closing-delimiter line, re-indented to the block depth.
                push_line(formatted, format!("{prefix}{}", lines[end].trim()));
            }
            index = end + 1;
        } else {
            index += 1;
        }
        depth = (depth + delta).max(0);
    }
}
