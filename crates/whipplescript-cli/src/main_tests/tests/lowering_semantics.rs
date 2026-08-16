//! Lowering and runtime semantics: effect input shapes, clocks, prompts, terminal cases.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
#[test]
fn capability_call_lowering_requires_target_capability() {
    let effects = parse_effect_statements(
        "call memory.query for task as context",
        &RuleContext::default(),
        &[],
        &[],
        &whipplescript_kernel::rule_lowering::empty_ir_program(),
    );

    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].kind, "capability.call");
    assert_eq!(effects[0].target.as_deref(), Some("memory.query"));
    assert_eq!(
        effects[0].required_capabilities_json(),
        r#"["memory.query"]"#
    );
}

#[test]
fn recall_form_lowers_to_memory_query_capability_call() {
    let effects = parse_effect_statements(
        "recall project_memory for task as context",
        &RuleContext::default(),
        &[],
        &[],
        &whipplescript_kernel::rule_lowering::empty_ir_program(),
    );

    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].kind, "capability.call");
    assert_eq!(effects[0].name.as_deref(), Some("recall"));
    assert_eq!(effects[0].target.as_deref(), Some("memory.query"));
    assert_eq!(
        effects[0].args,
        vec!["project_memory".to_owned(), "task".to_owned()]
    );
    assert_eq!(
        effects[0].required_capabilities_json(),
        r#"["memory.query"]"#
    );
}

#[test]
fn parse_effect_statements_skips_record_block_fields() {
    // A record field named like an effect keyword (`prompt`, `release`, ...)
    // must not be scanned as an effect statement — six same-shaped rows in a
    // fixture table produced colliding effect idempotency keys (the
    // provider-language e2e regression).
    let body = r#"
record LanguageTask {
  provider codex
  prompt "Write a four-line original poem about rain."
  release "not-an-effect"
  status "queued"
}
record LanguageTask {
  provider claude
  prompt "Write a four-line original poem about snow."
  status "queued"
}
done task -> record Archived {
  prompt "still not an effect"
}
prompt "Summarize {{ ticket.title }}" as summary
"#;
    let effects = parse_effect_statements(
        body,
        &RuleContext::default(),
        &[],
        &[],
        &whipplescript_kernel::rule_lowering::empty_ir_program(),
    );
    assert_eq!(effects.len(), 1, "only the real prompt effect: {effects:?}");
    assert_eq!(effects[0].kind, "schema.coerce");
    assert_eq!(effects[0].name.as_deref(), Some("prompt"));
    assert_eq!(effects[0].binding.as_deref(), Some("summary"));
}

#[test]
fn parse_effect_statements_covers_accepted_body_surface() {
    let body = r#"
tell worker as turn "go"
coerce classify(ticket.title) as review
prompt "Summarize {{ ticket.title }}" using fixture as summary
decide "fixed?" -> { fixed bool } as verdict
call memory.query for ticket as called
recall project_memory for ticket.title as memories
send via ops_room { text ticket.title } as sent
invoke Child { item ticket.title } as child
timer 5m as wait
timer until ticket.due_at as deadline
exec "echo hi" as run
file issue into backlog { title ticket.title body "body" } as filed
claim item as lease
release item
finish item { summary ticket.title }
acquire workspace_slot for workspace until ttl as slot
append LedgerEntry { area ticket.id text ticket.title } to review_log as entry
consume request_budget for ticket amount ticket.amount as spend
emit signal deploy.finished to ticket.id { service ticket.title status "ok" } as signal_sent
read text from docs at "note.md" as file_read
write text to docs at "out.md" { body ticket.title mode create } as file_write
import json Row from docs at "rows.json" as imported
export json Row to docs at "rows.json" { mode create } as exported
"#;

    let effects = parse_effect_statements(
        body,
        &RuleContext::default(),
        &[],
        &[],
        &whipplescript_kernel::rule_lowering::empty_ir_program(),
    );
    let expected = [
        ("agent.tell", Some("turn")),
        ("schema.coerce", Some("review")),
        ("schema.coerce", Some("summary")),
        ("schema.coerce", Some("verdict")),
        ("capability.call", Some("called")),
        ("capability.call", Some("memories")),
        ("capability.call", Some("sent")),
        ("workflow.invoke", Some("child")),
        ("timer.wait", Some("wait")),
        ("timer.wait", Some("deadline")),
        ("exec.command", Some("run")),
        ("tracker.file", Some("filed")),
        ("tracker.claim", Some("lease")),
        ("tracker.release", None),
        ("tracker.finish", None),
        ("lease.acquire", Some("slot")),
        ("ledger.append", Some("entry")),
        ("counter.consume", Some("spend")),
        ("signal.emit", Some("signal_sent")),
        ("file.read", Some("file_read")),
        ("file.write", Some("file_write")),
        ("file.import", Some("imported")),
        ("file.export", Some("exported")),
    ];

    assert_eq!(effects.len(), expected.len(), "{effects:?}");
    for (kind, binding) in expected {
        assert!(
            effects
                .iter()
                .any(|effect| effect.kind == kind && effect.binding.as_deref() == binding),
            "missing {kind} / {binding:?} in {effects:?}"
        );
    }

    let prompt = effects
        .iter()
        .find(|effect| effect.binding.as_deref() == Some("summary"))
        .expect("prompt effect");
    assert_eq!(prompt.name.as_deref(), Some("prompt"));
    assert_eq!(prompt.target.as_deref(), Some("fixture"));
    assert_eq!(
        prompt.prompt.as_deref(),
        Some("Summarize {{ ticket.title }}")
    );
}

#[test]
fn whipplescript_author_skill_has_discovery_frontmatter() {
    let source = include_str!("../../../../../skills/whipplescript-author/SKILL.md");
    let metadata = parse_skill_frontmatter(source).expect("skill frontmatter parses");

    assert_eq!(metadata.name.as_deref(), Some("whipplescript-author"));

    let description = metadata.description.expect("description is present");
    assert!(
        (1..=1024).contains(&description.len()),
        "description must be 1..=1024 chars, got {}",
        description.len()
    );

    for term in [
        "durable orchestration",
        "parallelizable",
        "long-running",
        "recurring",
        "scheduled",
        "timers",
        "queues",
        "retries",
        "human approvals",
        "multi-agent",
        "fan-out/fan-in",
        "plugin",
        "child workflows",
        "typed model decisions",
        "atomically commit",
        "durable effects",
    ] {
        assert!(
            description.contains(term),
            "description should route on `{term}`"
        );
    }
}

#[test]
fn parses_trace_check_option() {
    let options =
        TraceOptions::parse(&["ins_123".to_owned(), "--check".to_owned()]).expect("parse");

    assert_eq!(options.instance_id, "ins_123");
    assert!(options.check);
}

#[test]
fn assertion_reports_typed_error_for_invalid_external_duration_value() {
    let source = r#"
workflow DurationAssertionExternalInvalid

class Window {
  elapsed duration
  limit duration
}

assert exists(Window where elapsed < limit)
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let facts = vec![FactView {
        fact_id: "fact-invalid-duration".to_owned(),
        program_version_id: None,
        revision_epoch: 0,
        name: "Window".to_owned(),
        key: "fact-invalid-duration".to_owned(),
        value_json: r#"{"elapsed":"bad-duration","limit":"PT1H"}"#.to_owned(),
        provenance_class: "external".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    }];

    let assertions = eval_assertions(&ir, &facts, &[], None, &AssertionTagFilter::default());

    assert_eq!(assertions.len(), 1);
    assert_eq!(assertions[0].status, AssertionStatus::Error);
    assert!(assertions[0]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("invalid duration value `bad-duration`")));
    assert!(assertions[0]
        .failure_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("invalid duration value `bad-duration`")));
}

#[test]
fn lowering_consumes_matched_fact_binding() {
    let source = r#"
workflow ConsumeTask

class Task {
  status "queued"
}

class Done {
  status "done"
}

rule finish
  when Task as task where task.status == "queued"
=> {
  done task
  record Done {
    status "done"
  }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let fact = FactView {
        fact_id: "fact-task".to_owned(),
        program_version_id: None,
        revision_epoch: 0,
        name: "Task".to_owned(),
        key: "Task:queued".to_owned(),
        value_json: r#"{"status":"queued"}"#.to_owned(),
        provenance_class: "rule".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    };
    let facts = vec![fact];
    let effects = Vec::new();
    let ready = ready_contexts(&ir, &ir.rules[0], &facts, &effects, None);
    assert_eq!(ready.contexts.len(), 1);

    let lowering = lower_rule(
        "ins_test",
        "ver_test",
        "0",
        "fixture",
        &ir,
        &ir.rules[0],
        &ready.contexts[0],
        &facts,
        &effects,
        None,
    );

    assert_eq!(lowering.consumed_fact_ids, vec!["fact-task"]);
    assert_eq!(lowering.facts.len(), 1);
}

/// DR-0014 amendment (modeled in models/maude/effect-key.maude): the
/// `schema.coerce` admission key commits to the coercion name, declared
/// prompt template, synthesized output schema, and the host-supplied
/// config fingerprint — and ONLY schema.coerce keys see the fingerprint.
#[test]
fn schema_coerce_admission_key_commits_to_template_and_config_fingerprint() {
    let source_template_a = r#"
workflow CoerceKeyCommitments

class Review {
  accepted bool
}

output result Review

coerce reviewArtifact() -> Review {
  prompt """
  Review the artifact.
  """
}

agent scribe {
  provider fixture
  profile "issue-triager"
  capacity 1
}

rule start
  when started
=> {
  coerce reviewArtifact() as review
  tell scribe as note """
  Note the review.
  """

  after review succeeds as r {
    complete result { accepted r.accepted }
  }
}
"#;
    let source_template_b =
        source_template_a.replace("Review the artifact.", "Audit the artifact.");
    let lower = |source: &str, fingerprint: &str| {
        let ir = whipplescript_parser::compile_program(source)
            .ir
            .expect("compile");
        let lowering = lower_rule(
            "ins_test",
            "ver_test",
            "0",
            fingerprint,
            &ir,
            &ir.rules[0],
            &RuleContext::default(),
            &[],
            &[],
            None,
        );
        let key_of = |kind: &str| {
            lowering
                .effects
                .iter()
                .find(|effect| effect.kind == kind)
                .map(|effect| effect.idempotency_key.clone())
                .expect(kind)
        };
        (key_of("schema.coerce"), key_of("agent.tell"))
    };

    let (coerce_a1, tell_a1) = lower(source_template_a, "fixture");
    let (coerce_a2, tell_a2) = lower(source_template_a, "fixture");
    // Unchanged program + config dedups (same key both lowerings).
    assert_eq!(coerce_a1, coerce_a2);
    assert_eq!(tell_a1, tell_a2);

    // A changed prompt template is a distinct coercion even under the SAME
    // pinned program version literal (the prefix-replay hazard).
    let (coerce_b, _) = lower(&source_template_b, "fixture");
    assert_ne!(coerce_a1, coerce_b);

    // A changed coercion config re-keys schema.coerce — and nothing else.
    let (coerce_c, tell_c) = lower(source_template_a, "key_anthropic_sonnet");
    assert_ne!(coerce_a1, coerce_c);
    assert_eq!(tell_a1, tell_c);
}

#[test]
fn effect_id_carries_program_version_for_cross_revision_distinctness() {
    // The effect idempotency key is fixed at creation from the commit
    // identity, which includes program_version + revision_epoch
    // (spec/execution-contract.md). So the same rule firing under one version
    // dedups to the same effect key, but a re-fire under a NEW program_version
    // is a DISTINCT effect — a revised effect is never deduped against the
    // stale one. (Modeled in models/maude/effect-key.maude.)
    let source = r#"
workflow EffectKey

output result R

class R {
  x string
}

rule run
  when started
=> {
  exec "echo hi" as e

  after e succeeds as ran {
    complete result {
      x "ok"
    }
  }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let facts: Vec<FactView> = Vec::new();
    let effects: Vec<EffectView> = Vec::new();
    let ready = ready_contexts(&ir, &ir.rules[0], &facts, &effects, Some("evt-started"));
    assert_eq!(ready.contexts.len(), 1);
    let context = &ready.contexts[0];

    let effect_ids = |version: &str, epoch: &str| {
        lower_rule(
            "ins_test",
            version,
            epoch,
            "fixture",
            &ir,
            &ir.rules[0],
            context,
            &facts,
            &effects,
            None,
        )
        .effects
        .into_iter()
        .map(|effect| effect.effect_id)
        .collect::<Vec<_>>()
    };

    let v1 = effect_ids("ver_a", "0");
    assert!(!v1.is_empty(), "rule should lower an exec effect");
    assert_eq!(
        v1,
        effect_ids("ver_a", "0"),
        "same program version + epoch yields the same effect key (dedup holds)"
    );
    assert_ne!(
        v1,
        effect_ids("ver_b", "0"),
        "a new program version yields a distinct effect key"
    );
    assert_ne!(
        v1,
        effect_ids("ver_a", "1"),
        "a new revision epoch yields a distinct effect key"
    );
}

#[test]
fn coerce_json_schema_maps_types_to_strict_structured_output() {
    let source = r#"
@service
workflow SchemaShape

class Pick {
  kind "a" | "b"
  note string
  score int
  tag string?
}

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compiles");
    let schema = whipplescript_kernel::coerce_native::json_schema_for_type(
        &IrType::Ref("Pick".to_owned()),
        &ir.schemas,
    );
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], json!(false));
    // string-literal union -> enum
    assert_eq!(
        schema["properties"]["kind"],
        json!({ "type": "string", "enum": ["a", "b"] })
    );
    assert_eq!(schema["properties"]["score"]["type"], "integer");
    // optional -> nullable
    assert_eq!(
        schema["properties"]["tag"],
        json!({ "anyOf": [{ "type": "string" }, { "type": "null" }] })
    );
    // strict: every field is required
    let required: Vec<&str> = schema["required"]
        .as_array()
        .expect("required array")
        .iter()
        .map(|value| value.as_str().expect("string"))
        .collect();
    for field in ["kind", "note", "score", "tag"] {
        assert!(required.contains(&field), "missing required {field}");
    }
}

#[test]
fn select_clock_occurrences_applies_missed_policy() {
    let due = vec!["t1".to_owned(), "t2".to_owned(), "t3".to_owned()];
    // Default (no declared policy) = coalesce: one fact at the latest instant,
    // missed_count folding the earlier ticks.
    assert_eq!(
        select_clock_occurrences(&due, None),
        vec![("t3".to_owned(), 2)]
    );
    assert_eq!(
        select_clock_occurrences(&due, Some(&MissedPolicy::Coalesce)),
        vec![("t3".to_owned(), 2)]
    );
    // skip: only the latest, missed ticks dropped (not folded).
    assert_eq!(
        select_clock_occurrences(&due, Some(&MissedPolicy::Skip)),
        vec![("t3".to_owned(), 0)]
    );
    // catch_up: one fact per occurrence, newest `limit` of them.
    assert_eq!(
        select_clock_occurrences(&due, Some(&MissedPolicy::CatchUp { limit: 2 })),
        vec![("t2".to_owned(), 0), ("t3".to_owned(), 0)]
    );
    // No due occurrences admits nothing.
    assert!(select_clock_occurrences(&[], None).is_empty());
}

#[test]
fn due_calendar_occurrences_enumerates_daily_in_window() {
    // `every day at 09:00` America/New_York; March 2026 is EDT (UTC-4), so
    // 09:00 local = 13:00Z. Window (10th 00:00Z, 13th 00:00Z] => 10th/11th/12th.
    let due = due_calendar_occurrences(
        "2026-03-10T00:00:00Z",
        "2026-03-13T00:00:00Z",
        "America/New_York",
        CalendarPattern::Day,
        time_of_day(9, 0),
    );
    assert_eq!(
        due,
        vec![
            "2026-03-10T13:00:00Z".to_owned(),
            "2026-03-11T13:00:00Z".to_owned(),
            "2026-03-12T13:00:00Z".to_owned(),
        ]
    );
}

#[test]
fn due_calendar_occurrences_is_dst_correct_across_spring_forward() {
    // DST begins 2026-03-08 in America/New_York. 09:00 local is 14:00Z under EST
    // (UTC-5) before, and 13:00Z under EDT (UTC-4) after — the helper must shift.
    let due = due_calendar_occurrences(
        "2026-03-06T00:00:00Z",
        "2026-03-09T00:00:00Z",
        "America/New_York",
        CalendarPattern::Day,
        time_of_day(9, 0),
    );
    assert_eq!(
        due,
        vec![
            "2026-03-06T14:00:00Z".to_owned(), // EST
            "2026-03-07T14:00:00Z".to_owned(), // EST
            "2026-03-08T13:00:00Z".to_owned(), // EDT (after spring-forward)
        ]
    );
}

#[test]
fn due_calendar_occurrences_weekday_skips_weekends() {
    // 2026-03-09 is a Monday; `every weekday at 09:00` over Mon..Sun yields Mon-Fri.
    let due = due_calendar_occurrences(
        "2026-03-09T00:00:00Z",
        "2026-03-14T00:00:00Z",
        "America/New_York",
        CalendarPattern::Weekday,
        time_of_day(9, 0),
    );
    assert_eq!(
        due,
        vec![
            "2026-03-09T13:00:00Z".to_owned(),
            "2026-03-10T13:00:00Z".to_owned(),
            "2026-03-11T13:00:00Z".to_owned(),
            "2026-03-12T13:00:00Z".to_owned(),
            "2026-03-13T13:00:00Z".to_owned(),
        ]
    );
}

#[test]
fn due_calendar_occurrences_weekly_matches_only_that_weekday() {
    // `every monday at 09:00` over two weeks => the two Mondays (09th, 16th).
    let due = due_calendar_occurrences(
        "2026-03-08T00:00:00Z",
        "2026-03-23T00:00:00Z",
        "America/New_York",
        CalendarPattern::Weekly(Weekday::Monday),
        time_of_day(9, 0),
    );
    assert_eq!(
        due,
        vec![
            "2026-03-09T13:00:00Z".to_owned(),
            "2026-03-16T13:00:00Z".to_owned(),
        ]
    );
}

#[test]
fn due_calendar_occurrences_empty_when_now_not_after_cursor() {
    assert!(due_calendar_occurrences(
        "2026-03-10T00:00:00Z",
        "2026-03-10T00:00:00Z",
        "America/New_York",
        CalendarPattern::Day,
        time_of_day(9, 0),
    )
    .is_empty());
}

#[test]
fn lowering_preserves_multiline_prompt_content_type_metadata() {
    let source = r#"
workflow PromptContentType

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule start
  when started
=> {
  tell worker as turn """markdown
  Write a short report.
  """
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let lowering = lower_rule(
        "ins_test",
        "ver_test",
        "0",
        "fixture",
        &ir,
        &ir.rules[0],
        &RuleContext::default(),
        &[],
        &[],
        None,
    );

    assert_eq!(lowering.effects.len(), 1);
    let input = json_from_str(&lowering.effects[0].input_json);
    assert_eq!(
        input.get("prompt").and_then(Value::as_str),
        Some("Write a short report.")
    );
    assert_eq!(
        input.get("prompt_content_type").and_then(Value::as_str),
        Some("markdown")
    );
}

#[test]
fn lowering_preserves_coerce_prompt_content_type_metadata() {
    let source = r#"
workflow CoercePromptContentType

class Review {
  accepted bool
}

coerce reviewArtifact() -> Review {
  prompt """markdown
  Review the artifact.
  """
}

rule start
  when started
=> {
  coerce reviewArtifact() as review
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let lowering = lower_rule(
        "ins_test",
        "ver_test",
        "0",
        "fixture",
        &ir,
        &ir.rules[0],
        &RuleContext::default(),
        &[],
        &[],
        None,
    );

    assert_eq!(lowering.effects.len(), 1);
    let input = json_from_str(&lowering.effects[0].input_json);
    assert_eq!(
        input.get("prompt_template").and_then(Value::as_str),
        Some("Review the artifact.")
    );
    assert_eq!(
        input.get("prompt_content_type").and_then(Value::as_str),
        Some("markdown")
    );
}

#[test]
fn prompt_effect_input_json_uses_plain_string_shape() {
    let source = r#"
workflow PromptInput

class Done {
  ok bool
}

output result Done

rule start
  when started
=> {
  complete result { ok true }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let effect = ParsedEffect {
        kind: "schema.coerce".to_owned(),
        target: Some("fixture".to_owned()),
        name: Some("prompt".to_owned()),
        binding: Some("answer".to_owned()),
        args: Vec::new(),
        prompt: Some("Summarize this.".to_owned()),
        prompt_content_type: Some("markdown".to_owned()),
        prompt_template: Some("Summarize this.".to_owned()),
        required_capabilities: Vec::new(),
        after: None,
        timeout_seconds: None,
    };
    let mut errors = Vec::new();
    let input_json = parsed_effect_input_json(
        &ir,
        &ir.rules[0],
        &effect,
        &RuleContext::default(),
        &std::collections::BTreeMap::new(),
        &mut errors,
        &[],
        &[],
    );

    assert_eq!(errors, Vec::<String>::new());
    let input = json_from_str(&input_json);
    assert_eq!(
        input.get("function_name").and_then(Value::as_str),
        Some("prompt")
    );
    assert_eq!(
        input.get("output_type").and_then(Value::as_str),
        Some("string")
    );
    assert_eq!(
        input.get("prompt").and_then(Value::as_str),
        Some("Summarize this.")
    );
    assert_eq!(
        input.get("prompt_template").and_then(Value::as_str),
        Some("Summarize this.")
    );
    assert_eq!(
        input.get("provider").and_then(Value::as_str),
        Some("fixture")
    );
    assert_eq!(
        input.get("prompt_content_type").and_then(Value::as_str),
        Some("markdown")
    );
}

#[test]
fn agent_tell_input_json_carries_turn_access_grants() {
    let source = r#"
workflow OwnedGrantInput

agent coder {
  provider owned
  profile "repo-writer"
  capacity 1
}

file store project_files {
  root "."
  allow read ["src/**"]
}

rule start
  when started
=> {
  tell coder as turn
    with access to project_files {
      read ["src/**"]
    }
    with access to command {
      run
    }
    "work"
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let lowering = lower_rule(
        "ins_test",
        "ver_test",
        "0",
        "fixture",
        &ir,
        &ir.rules[0],
        &RuleContext::default(),
        &[],
        &[],
        None,
    );
    let tell = lowering
        .effects
        .iter()
        .find(|effect| effect.kind == "agent.tell")
        .expect("agent tell effect");
    let input = json_from_str(&tell.input_json);
    let grants = input
        .get("access_grants")
        .and_then(Value::as_array)
        .expect("access grants");

    assert_eq!(grants.len(), 2);
    assert_eq!(
        grants[0].get("resource").and_then(Value::as_str),
        Some("project_files")
    );
    assert_eq!(
        grants[0]
            .pointer("/operations/0/operation")
            .and_then(Value::as_str),
        Some("read")
    );
    assert_eq!(
        grants[0].pointer("/operations/0/globs"),
        Some(&json!(["src/**"]))
    );
    assert_eq!(
        grants[1].get("resource").and_then(Value::as_str),
        Some("command")
    );
    assert_eq!(
        grants[1]
            .pointer("/operations/0/operation")
            .and_then(Value::as_str),
        Some("run")
    );
    // Q3 fix: the file-store grant carries the store's own policy snapshot so
    // the harness can intersect the turn grant against the store's authority.
    assert_eq!(
        grants[0]
            .pointer("/store_policy/root")
            .and_then(Value::as_str),
        Some(".")
    );
    assert_eq!(
        grants[0].pointer("/store_policy/allow_read"),
        Some(&json!(["src/**"]))
    );
    assert_eq!(
        grants[0].pointer("/store_policy/allow_write"),
        Some(&json!([]))
    );
    // The non-file `command` grant carries no store policy.
    assert!(grants[1].get("store_policy").is_none());
}

#[test]
fn workflow_invoke_input_json_carries_start_access_grants() {
    let source = r#"
class Done { ok bool }

workflow Parent {
  output result Done
  rule start
    when started
  => {
    invoke Child { }
      with access to child_authority {
        invoke
      }
      as child
    complete result { ok true }
  }
}

workflow Child {
  output result Done
  rule start
    when started
  => {
    complete result { ok true }
  }
}
"#;
    let ir = whipplescript_parser::compile_program_with_root(source, Some("Parent"))
        .ir
        .expect("compile");
    let lowering = lower_rule(
        "ins_test",
        "ver_test",
        "0",
        "fixture",
        &ir,
        &ir.rules[0],
        &RuleContext::default(),
        &[],
        &[],
        None,
    );
    let invoke = lowering
        .effects
        .iter()
        .find(|effect| effect.kind == "workflow.invoke")
        .expect("workflow invoke effect");
    let input = json_from_str(&invoke.input_json);
    let grants = input
        .get("access_grants")
        .and_then(Value::as_array)
        .expect("access grants");
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0].get("resource").and_then(Value::as_str),
        Some("child_authority")
    );
    assert_eq!(
        grants[0]
            .pointer("/operations/0/operation")
            .and_then(Value::as_str),
        Some("invoke")
    );
}

#[test]
fn multiline_prompt_single_word_opening_tail_stays_prompt_text() {
    let lines = ["tell worker \"\"\"hello", "world", "\"\"\""];
    let (prompt, cursor) = parse_prompt_from_lines(&lines, 0, lines[0]);

    assert_eq!(cursor, 2);
    assert_eq!(
        prompt,
        ParsedPrompt {
            text: "hello\nworld".to_owned(),
            content_type: None,
        }
    );
}

#[test]
fn ready_contexts_match_queue_ready_item_alias_to_projected_fact() {
    let source = r#"
workflow QueueReadyAlias

tracker backlog {
  provider builtin
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule claim_ready
  when backlog has ready issue as item
  when worker is available
=> {
  claim item as lease
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let fact = FactView {
        fact_id: "fact-queue-item".to_owned(),
        program_version_id: None,
        revision_epoch: 0,
        name: "tracker.issue.ready".to_owned(),
        key: "backlog:WS-1:gen".to_owned(),
        value_json: r#"{"queue":"backlog","id":"WS-1","title":"Ready item","body":"Do work"}"#
            .to_owned(),
        provenance_class: "queue".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    };
    let other_queue = FactView {
        fact_id: "fact-other-item".to_owned(),
        program_version_id: None,
        revision_epoch: 0,
        name: "tracker.issue.ready".to_owned(),
        key: "other:WS-2:gen".to_owned(),
        value_json: r#"{"queue":"other","id":"WS-2","title":"Other","body":""}"#.to_owned(),
        provenance_class: "queue".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    };
    let facts = vec![fact, other_queue];
    let effects = Vec::new();
    let ready = ready_contexts(&ir, &ir.rules[0], &facts, &effects, None);

    assert_eq!(ready.contexts.len(), 1);
    assert_eq!(ready.contexts[0].bindings[0].0, "item");
    assert_eq!(ready.contexts[0].bindings[0].1.key, "backlog:WS-1:gen");
}

/// DR-0052 grammar pass slice 2: the std.vcs readiness sugar — each
/// phrase lowers to its `vcs.*` fact; the stream guard filters by the
/// leading word; `by others` excludes exactly the matching instance's
/// own principal.
#[test]
fn vcs_readiness_sugar_lowers_guards_and_excludes_own_writes() {
    let source = r#"
@service
workflow VcsSugar

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

stream triage {
  members [worker]
}

class Note { body string }
rule on_change
  when line changed by others as c
=> {
  record Note { body c.path }
}
rule on_contention
  when triage has contention as x
=> {
  record Note { body x.slice }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let cut_fact = |id: &str, by: &str| FactView {
        fact_id: format!("fact-{id}"),
        program_version_id: None,
        revision_epoch: 0,
        name: "vcs.cut.recorded".to_owned(),
        key: id.to_owned(),
        value_json: format!(r#"{{"branch":"line","cut":"{id}","path":"src/a.rs","by":"{by}"}}"#),
        provenance_class: "external".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    };
    let own = cut_fact("c-own", "instance:i-1");
    let other = cut_fact("c-other", "s:sess-9");
    let facts = vec![own, other];
    // `line changed by others`: with the instance's own principal in
    // scope, only the foreign cut matches.
    let ready = whipplescript_kernel::rule_lowering::ready_contexts_for(
        &ir,
        &ir.rules[0],
        &facts,
        &[],
        None,
        Some("instance:i-1"),
    );
    assert_eq!(ready.contexts.len(), 1);
    assert_eq!(ready.contexts[0].bindings[0].1.key, "c-other");
    // Without an own-principal (projection contexts) both match.
    let ready = ready_contexts(&ir, &ir.rules[0], &facts, &[], None);
    assert_eq!(ready.contexts.len(), 2);
    // Stream guard: `triage has contention` matches only facts whose
    // payload names triage.
    let contention = |id: &str, stream: &str| FactView {
        fact_id: format!("fact-{id}"),
        program_version_id: None,
        revision_epoch: 0,
        name: "vcs.contention.predicted".to_owned(),
        key: id.to_owned(),
        value_json: format!(r#"{{"branch":"line","stream":"{stream}","slice":["src/a.rs"]}}"#),
        provenance_class: "external".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    };
    let facts = vec![contention("k-1", "triage"), contention("k-2", "hotfix")];
    let ready = ready_contexts(&ir, &ir.rules[1], &facts, &[], None);
    assert_eq!(ready.contexts.len(), 1);
    assert_eq!(ready.contexts[0].bindings[0].1.key, "k-1");
}

#[test]
fn selects_failed_terminal_case_branch_and_binds_payload() {
    let body = r#"
case classification {
  Completed as result => {
    record TerminalRoute {
      branch "completed"
      detail result.summary
    }
  }
  Failed as failure => {
    record TerminalRoute {
      branch "failed"
      detail failure.reason
    }
  }
}
"#;
    let mut context = RuleContext::default();
    push_effect_binding(
        &mut context,
        "classification",
        "effect",
        json!({
            "tag": "Failed",
            "status": "failed",
            "error": {
                "reason": "fixture coerce failure"
            }
        }),
    );

    let (selected, selected_context, reports) = selected_rule_body(body, &context);

    assert!(selected.contains("branch \"failed\""));
    assert!(!selected.contains("branch \"completed\""));
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].status, BranchStatus::Matched);
    assert_eq!(
        parse_field_value("failure.reason", &selected_context),
        Value::String("fixture coerce failure".to_owned())
    );
}

#[test]
fn terminal_case_guard_error_selects_no_sibling_branch() {
    let body = r#"
case classification {
  Completed as result where result.summary => {
    tell worker "should not commit"
  }
  Failed as failure => {
    tell worker "failed sibling"
  }
}
"#;
    let mut context = RuleContext::default();
    push_effect_binding(
        &mut context,
        "classification",
        "effect",
        json!({
            "tag": "Completed",
            "status": "completed",
            "value": {
                "summary": "Fixture classification"
            }
        }),
    );

    let (selected, _selected_context, reports) = selected_rule_body(body, &context);

    assert!(selected.is_empty() || !selected.contains("tell worker \"should not commit\""));
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].status, BranchStatus::Error);
    assert!(reports[0]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("did not evaluate to bool")));
}
