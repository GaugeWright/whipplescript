//! Extracted verbatim from `lib.rs` (module path `tests` is unchanged).

use super::*;

#[test]
fn parser_scaffold_links_to_core() {
    assert_eq!(parser_stage(), "release");
}

#[test]
fn declaration_block_grammar_table_is_complete() {
    // Drift canary for the build.rs-generated DECLARATION_BLOCK_GRAMMAR
    // table (D2.0 scaffolding). The table exists and is validated here; no
    // dispatch consumes it yet.
    let keywords: Vec<&str> = DECLARATION_BLOCK_GRAMMAR
        .iter()
        .map(|spec| spec.keyword)
        .collect();
    assert_eq!(
        keywords.len(),
        9,
        "expected exactly 9 declaration_block specs"
    );
    for expected in [
        "tracker",
        "channel",
        "counter",
        "lease",
        "ledger",
        "file store",
        "memory pool",
        "stream",
        "credential",
    ] {
        assert!(
            keywords.contains(&expected),
            "missing declaration_block keyword `{expected}`; got {keywords:?}"
        );
    }

    let find = |keyword: &str| -> &DeclarationBlockSpec {
        DECLARATION_BLOCK_GRAMMAR
            .iter()
            .find(|spec| spec.keyword == keyword)
            .unwrap_or_else(|| panic!("no spec for `{keyword}`"))
    };
    let clause = |keyword: &str, name: &str| -> &ClauseSpec {
        find(keyword)
            .clauses
            .iter()
            .find(|clause| clause.name == name)
            .unwrap_or_else(|| panic!("no clause `{name}` on `{keyword}`"))
    };

    // Multi-word keywords split into two words; single-word into one.
    assert_eq!(find("memory pool").keyword_words, &["memory", "pool"]);
    assert_eq!(find("file store").keyword_words, &["file", "store"]);
    assert_eq!(find("tracker").keyword_words, &["tracker"]);

    // ledger `partition by` is the M2 connective clause.
    assert_eq!(clause("ledger", "partition").connective, Some("by"));

    // lease `shared` is a flag (no value).
    assert!(matches!(clause("lease", "shared").kind, ClauseKind::Flag));
    assert!(!clause("lease", "shared").list);
    assert_eq!(clause("lease", "shared").connective, None);

    // file-store `allow read`/`allow write` are multi-word glob lists.
    for (name, words) in [
        ("allow read", ["allow", "read"]),
        ("allow write", ["allow", "write"]),
    ] {
        let allow = clause("file store", name);
        assert!(allow.list, "`{name}` must be list:true");
        assert_eq!(allow.words, words);
        assert!(matches!(allow.kind, ClauseKind::Glob));
    }

    // Exercise the head-word peek so the scaffolding method is live.
    let mut parser = Parser {
        source: "memory pool p { }",
        tokens: lex("memory pool p { }").tokens,
        pos: 0,
        diagnostics: Vec::new(),
        pending_contract_classes: Vec::new(),
    };
    let spec = parser
        .declaration_block_spec_at()
        .expect("head word `memory` must resolve to the memory pool spec");
    assert_eq!(spec.keyword, "memory pool");
    // It only peeks — position is unchanged.
    assert_eq!(parser.pos, 0);
    parser.diagnostics.clear();
}

const SEND_PROGRAM: &str = r##"
@service
workflow Notify

class Trigger { id string }

agent worker { provider fixture  profile "r"  capacity 1 }

channel alerts { provider fixture  destination "#ops" }

table seed as Trigger [ { id "t" } ]

rule notify
  when Trigger as t
=> {
  send via alerts {
    text "hello"
  } as sent
}
"##;

#[test]
fn send_lowers_to_messaging_capability_call_without_builtin_registration() {
    // `send via <channel>` lowers to a `messaging.send` capability.call
    // construct use. The construct/contract registration itself is NOT a
    // parser builtin any more: it comes from the embedded `std.messaging`
    // manifest, merged by the CLI when the program imports the package
    // (`use std.messaging`). The parser still registers the `std.messaging`
    // standard library from the `channel` declaration (the ambient decl tier).
    let compiled = compile_program(SEND_PROGRAM);
    assert_eq!(
        compiled.diagnostics,
        Vec::new(),
        "{:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("lowered IR");
    let uses = ir.construct_uses();
    assert_eq!(uses.len(), 1);
    assert_eq!(uses[0].keyword, "send");
    assert_eq!(uses[0].target_capability, "messaging.send");
    let registry = ir.contract_registry();
    assert!(
        registry.constructs.is_empty(),
        "the parser registers no builtin constructs: {:?}",
        registry.constructs
    );
    assert!(
        !registry
            .effect_contracts
            .iter()
            .any(|c| c.id == "messaging.send"),
        "the messaging.send contract comes from the embedded manifest, not the parser"
    );
    assert!(
        registry
            .libraries
            .iter()
            .any(|lib| lib.id == "std.messaging" && lib.standard),
        "the channel declaration still registers the std.messaging standard library"
    );
}

#[test]
fn send_to_unknown_channel_is_rejected() {
    let source = SEND_PROGRAM.replace("send via alerts", "send via ghost");
    let compiled = compile_program(&source);
    let violations: Vec<&Diagnostic> = compiled
        .diagnostics
        .iter()
        .filter(|d| d.message.contains("unknown channel"))
        .collect();
    assert_eq!(violations.len(), 1, "{:?}", compiled.diagnostics);
    assert!(violations[0].message.contains("ghost"));
}

#[test]
fn derives_contract_registry_from_imports_and_effects() {
    let source = r#"
workflow RegistrySlice

use memory

class Task {
  title string
}

class Review {
  accepted bool
}

coerce reviewTask(title string) -> Review {
  prompt """
  Review {{ title }}
  """
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule start
  when Task as task
=> {
  tell worker as turn """
  Work on {{ task.title }}
  """

  after turn succeeds {
    coerce reviewTask(task.title) as review
  }
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    let registry = ir.contract_registry();
    assert_eq!(registry.validate(), Vec::new());

    assert!(registry
        .libraries
        .iter()
        .any(|library| library.id == "memory" && !library.standard));
    assert!(registry
        .libraries
        .iter()
        .any(|library| library.id == "std.agent" && library.standard));
    assert!(registry
        .libraries
        .iter()
        .any(|library| library.id == "std.coercion" && library.standard));

    let coerce = registry
        .effect_contracts
        .iter()
        .find(|contract| contract.id == "schema.coerce")
        .expect("coerce contract");
    assert_eq!(coerce.library_id, "std.coercion");
    assert_eq!(coerce.validation, TypedOutputValidation::RuntimeBoundary);
    assert!(coerce.source_forms.contains(&"coerce".to_owned()));
    assert!(coerce.source_forms.contains(&"prompt".to_owned()));
    assert!(coerce
        .required_capabilities
        .contains(&"schema.coerce".to_owned()));
    assert_eq!(coerce.provider_kinds, vec!["schema_coercer".to_owned()]);

    let agent = registry
        .effect_contracts
        .iter()
        .find(|contract| contract.id == "agent.tell")
        .expect("agent contract");
    assert_eq!(agent.library_id, "std.agent");
    assert_eq!(agent.output_schema.as_deref(), Some("AgentTurn"));
}

#[test]
fn capability_calls_require_the_target_capability() {
    let source = r#"
workflow PackageCall

use memory

class Task {
  title string
}

rule start
  when Task as task
=> {
  call memory.query for task as context
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    let effect = ir.rules[0]
        .metadata
        .effects
        .iter()
        .find(|effect| effect.kind == IrEffectKind::CapabilityCall)
        .expect("capability call effect");
    assert_eq!(
        effect.required_capabilities,
        vec!["memory.query".to_owned()]
    );

    let registry = ir.contract_registry();
    let contract = registry
        .effect_contracts
        .iter()
        .find(|contract| contract.id == "capability.call")
        .expect("capability call contract");
    assert!(contract
        .required_capabilities
        .contains(&"memory.query".to_owned()));
    assert!(!contract
        .required_capabilities
        .contains(&"capability.call".to_owned()));
}

#[test]
fn package_recall_form_lowers_to_capability_call_marker() {
    let source = r#"
workflow PackageRecall

use memory

memory pool project_memory {
  context limit 8
}

class Task {
  title string
}

rule start
  when Task as task
=> {
  recall project_memory for task as context
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    let effect = ir.rules[0]
        .metadata
        .effects
        .iter()
        .find(|effect| effect.kind == IrEffectKind::CapabilityCall)
        .expect("capability call effect");
    assert_eq!(effect.binding.as_deref(), Some("context"));
    assert_eq!(
        effect.required_capabilities,
        vec!["memory.query".to_owned()]
    );
    assert_eq!(
        effect.construct_use,
        Some(IrConstructUse {
            keyword: "recall".to_owned(),
            scope: "rule_body".to_owned(),
            construct_family: "effect_operation".to_owned(),
            lowering_target: "capability_call".to_owned(),
            target_capability: "memory.query".to_owned(),
        })
    );
    assert_eq!(ir.construct_uses().len(), 1);
    assert!(ir.to_snapshot().contains("construct=recall->memory.query"));
}

fn b1g_body_matrix_program(body: &str) -> String {
    r#"
workflow B1gMatrix {
  use memory

  memory pool project_memory {
    context limit 8
  }

  output result Done
  failure error Failed

  class Ticket {
    id string
    title string
    due_at time
    amount int
  }

  class TicketPublic {
    id string
    title string
  }

  class Workspace {
    id string
  }

  class Note {
    text string
  }

  class Done {
    ok bool
  }

  class Failed {
    reason string
  }

  class Review {
    summary string
    fixed bool
  }

  class LedgerEntry {
    area string
    text string
  }

  class Row {
    title string
  }

  signal deploy.finished {
    service string
    status string
  }

  tracker backlog {
    provider builtin
  }

  lease workspace_slot {
    key Workspace
    slots 1
    ttl 30m
  }

  ledger review_log {
    entry LedgerEntry
    partition by area
    retain 30d
  }

  counter request_budget {
    key Ticket
    cap 10
    reset daily
  }

  file store docs {
    root "./data"
    allow write ["**"]
  }

  channel ops_room {
    provider fixture
  }

  agent worker {
    provider fixture
    profile "repo-writer"
    capacity 1
  }

  coerce classify(title string) -> Review {
    prompt "classify"
  }

  rule probe
    when Ticket as ticket
    when Workspace as workspace
    when backlog has ready issue as item
    when worker is available
  => {
__BODY__
  }
}

workflow Child {
  input task ChildTask
  output result ChildResult

  class ChildTask {
    title string
  }

  class ChildResult {
    summary string
  }

  rule finish
    when ChildTask as task
  => {
    complete result {
      summary task.title
    }
  }
}
"#
    .replace("__BODY__", body)
}

#[test]
fn coordination_shared_declarations_lower_to_ir() {
    let source = r#"
workflow SharedCoord

class Key {
  id string
}

class Entry {
  area string
}

lease shared_slot {
  shared
  key Key
  slots 1
  ttl 30m
}

ledger shared_log {
  shared
  entry Entry
  partition by area
  retain 30d
}

counter shared_budget {
  shared
  key Key
  cap 10
  reset daily
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "unexpected diagnostics: {:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("valid IR");
    assert!(ir
        .leases
        .iter()
        .any(|lease| lease.name == "shared_slot" && lease.shared && lease.ttl_seconds == 1800));
    assert!(ir
        .ledgers
        .iter()
        .any(|ledger| ledger.name == "shared_log" && ledger.shared));
    assert!(ir
        .counters
        .iter()
        .any(|counter| counter.name == "shared_budget" && counter.shared));
}

#[test]
fn file_store_clause_spans_are_first_word_tokens() {
    // HARD INVARIANT: root_span/read_span/write_span are the FIRST
    // clause-name-word token span (`root`/`allow`/`allow`), not the value or
    // a joined multi-word span. These serialize into FileStoreDecl and feed
    // `whip fmt`; the `.ir` golden does not witness them, so assert directly
    // (mirrors examples/file-store-demo.whip).
    let source = r#"
workflow FileSpanProbe
file store notes_store {
  root "./data"
  allow read ["notes/**"]
  allow write ["notes/**"]
}
"#;
    let parsed = parse_program(source);
    assert_eq!(
        parsed.diagnostics,
        Vec::new(),
        "unexpected diagnostics: {:?}",
        parsed.diagnostics
    );
    let store = parsed
        .program
        .items
        .iter()
        .find_map(|item| match item {
            Item::FileStore(decl) => Some(decl),
            _ => None,
        })
        .expect("file store decl");
    let text_at = |span: SourceSpan| &source[span.start..span.end];
    assert_eq!(text_at(store.root_span.expect("root span")), "root");
    assert_eq!(text_at(store.read_span.expect("read span")), "allow");
    assert_eq!(text_at(store.write_span.expect("write span")), "allow");
    // No `provider` clause: the decl records None (the runtime default is
    // `local`), and the `.ir` snapshot stays provider-free (F5 zero-churn).
    assert_eq!(store.provider, None);
    let ir = compile_program(source).ir.expect("valid IR");
    assert_eq!(ir.file_stores[0].provider, None);
    assert!(!ir.to_snapshot().contains("provider"));
}

#[test]
fn file_store_provider_clause_parses_and_unknown_is_rejected() {
    // spec/std-files.md "Surface" (slice F5): the optional block-internal
    // `provider <ident>` clause parses (aligning with the channel
    // declaration's provider clause), serializes into the snapshot, and
    // an identifier outside the v1 provider list is a check error.
    let source = r#"
workflow FileProviderProbe
file store notes_store {
  root "./data"
  allow read ["notes/**"]
  provider local
}
"#;
    let compiled = compile_program(source);
    assert_eq!(
        compiled.diagnostics,
        Vec::new(),
        "unexpected diagnostics: {:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("valid IR");
    assert_eq!(ir.file_stores[0].provider.as_deref(), Some("local"));
    assert!(ir.to_snapshot().contains("    provider local"));

    let unknown = source.replace("provider local", "provider s3");
    let compiled = compile_program(&unknown);
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("file store `notes_store` names unknown provider `s3`")
        }),
        "unknown provider must be a check error: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn formatter_preserves_file_store_provider_clause() {
    let source = r#"
workflow FileProviderFmt
file store notes_store { root "./data" provider local }
"#;
    let formatted = format_program(source);
    assert_eq!(formatted.diagnostics, Vec::new());
    let formatted = formatted.formatted.expect("formats");
    assert!(
        formatted.contains("file store notes_store {\n  root \"./data\"\n  provider local\n}"),
        "{formatted}"
    );
}

#[test]
fn formatter_preserves_shared_coordination_declarations() {
    let source = r#"
workflow SharedCoord
class Key { id string }
lease shared_slot { shared key Key slots 1 ttl 30m }
"#;
    let formatted = format_program(source);
    assert_eq!(formatted.diagnostics, Vec::new());
    let formatted = formatted.formatted.expect("formats");
    assert!(formatted.contains("lease shared_slot {\n  shared\n  key Key"));
}

fn b1g_probe_rule(case_name: &str, body: &str) -> IrRule {
    let source = b1g_body_matrix_program(body);
    let compiled = compile_program_with_root(&source, Some("B1gMatrix"));
    assert!(
        compiled.diagnostics.is_empty(),
        "{case_name} emitted diagnostics: {:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("valid matrix IR");
    ir.rules
        .into_iter()
        .find(|rule| rule.name == "probe")
        .expect("probe rule")
}

fn b1g_effect<'a>(
    rule: &'a IrRule,
    kind: IrEffectKind,
    binding: Option<&str>,
    case_name: &str,
) -> &'a IrEffectNode {
    rule.metadata
        .effects
        .iter()
        .find(|effect| effect.kind == kind && effect.binding.as_deref() == binding)
        .unwrap_or_else(|| {
            panic!(
                "{case_name} did not lower {kind:?} / {binding:?}; effects: {:?}",
                rule.metadata.effects
            )
        })
}

#[test]
fn accepted_rule_body_matrix_has_no_silent_noops() {
    let effect_cases = [
        (
            "tell",
            r#"    tell worker as turn "go""#,
            IrEffectKind::AgentTell,
            Some("turn"),
        ),
        (
            "coerce",
            r#"    coerce classify(ticket.title) as review"#,
            IrEffectKind::SchemaCoerce,
            Some("review"),
        ),
        (
            "prompt",
            r#"    prompt "Summarize {{ ticket.title }}" using fixture as summary"#,
            IrEffectKind::SchemaCoerce,
            Some("summary"),
        ),
        (
            "decide",
            r#"    decide "fixed?" -> { fixed bool } as verdict"#,
            IrEffectKind::SchemaCoerce,
            Some("verdict"),
        ),
        (
            "call",
            r#"    call memory.query for ticket as called"#,
            IrEffectKind::CapabilityCall,
            Some("called"),
        ),
        (
            "recall",
            r#"    recall project_memory for ticket.title as memories"#,
            IrEffectKind::CapabilityCall,
            Some("memories"),
        ),
        (
            "send",
            r#"    send via ops_room { text ticket.title } as sent"#,
            IrEffectKind::CapabilityCall,
            Some("sent"),
        ),
        (
            "invoke",
            r#"    invoke Child { task { title ticket.title } } as child"#,
            IrEffectKind::WorkflowInvoke,
            Some("child"),
        ),
        (
            "timer_duration",
            r#"    timer 5m as wait"#,
            IrEffectKind::TimerWait,
            Some("wait"),
        ),
        (
            "timer_until",
            r#"    timer until ticket.due_at as deadline"#,
            IrEffectKind::TimerWait,
            Some("deadline"),
        ),
        (
            "exec_raw",
            r#"    exec "echo hi" as run"#,
            IrEffectKind::ExecCommand,
            Some("run"),
        ),
        (
            "queue_file",
            r#"    file issue into backlog { title ticket.title body "body" } as filed"#,
            IrEffectKind::TrackerFile,
            Some("filed"),
        ),
        (
            "queue_claim",
            r#"    claim item as lease"#,
            IrEffectKind::TrackerClaim,
            Some("lease"),
        ),
        (
            "queue_release",
            r#"    release item"#,
            IrEffectKind::TrackerRelease,
            None,
        ),
        (
            "queue_finish",
            r#"    finish item { summary ticket.title }"#,
            IrEffectKind::TrackerFinish,
            None,
        ),
        (
            "lease_acquire",
            r#"    acquire workspace_slot for workspace until ttl as slot"#,
            IrEffectKind::LeaseAcquire,
            Some("slot"),
        ),
        (
            "ledger_append",
            r#"    append LedgerEntry { area ticket.id text ticket.title } to review_log as entry"#,
            IrEffectKind::LedgerAppend,
            Some("entry"),
        ),
        (
            "counter_consume",
            r#"    consume request_budget for ticket amount ticket.amount as spend

    after spend ok {
      record Note { text "ok" }
    }

    after spend over {
      record Note { text "over" }
    }"#,
            IrEffectKind::CounterConsume,
            Some("spend"),
        ),
        (
            "notify",
            r#"    emit signal deploy.finished to ticket.id { service ticket.title status "ok" } as signal_sent"#,
            IrEffectKind::SignalEmit,
            Some("signal_sent"),
        ),
        (
            "file_read",
            r#"    read text from docs at "note.md" as file_read"#,
            IrEffectKind::FileRead,
            Some("file_read"),
        ),
        (
            "file_write",
            r#"    write text to docs at "out.md" { body ticket.title mode create } as file_write"#,
            IrEffectKind::FileWrite,
            Some("file_write"),
        ),
        (
            "file_import",
            r#"    import json Row from docs at "rows.json" as imported"#,
            IrEffectKind::FileImport,
            Some("imported"),
        ),
        (
            "file_export",
            r#"    export json Row to docs at "rows.json" { mode create } as exported"#,
            IrEffectKind::FileExport,
            Some("exported"),
        ),
    ];

    for (case_name, body, kind, binding) in effect_cases {
        let rule = b1g_probe_rule(case_name, body);
        let effect = b1g_effect(&rule, kind, binding, case_name);
        match case_name {
            "send" => {
                assert_eq!(effect.resource.as_deref(), Some("ops_room"));
                assert_eq!(
                    effect
                        .construct_use
                        .as_ref()
                        .map(|use_| use_.keyword.as_str()),
                    Some("send")
                );
            }
            "notify" => {
                assert_eq!(effect.resource.as_deref(), Some("signal:deploy.finished"));
            }
            "file_read" | "file_write" | "file_import" | "file_export" => {
                assert_eq!(effect.resource.as_deref(), Some("docs"));
            }
            _ => {}
        }
    }

    let record = b1g_probe_rule("record", r#"    record Note { text ticket.title }"#);
    assert!(record
        .metadata
        .fact_writes
        .contains(&"schema:Note".to_owned()));
    assert!(record
        .metadata
        .egress_payload_reads
        .get("fact:Note")
        .is_some_and(|roots| roots.contains("ticket")));

    let done = b1g_probe_rule("done", r#"    done ticket"#);
    assert!(done
        .metadata
        .fact_consumes
        .contains(&"schema:Ticket".to_owned()));

    let done_replacement = b1g_probe_rule(
        "done_replacement",
        r#"    done ticket -> record Note { text ticket.title }"#,
    );
    assert!(done_replacement
        .metadata
        .fact_consumes
        .contains(&"schema:Ticket".to_owned()));
    assert!(done_replacement
        .metadata
        .fact_writes
        .contains(&"schema:Note".to_owned()));

    let complete = b1g_probe_rule("complete", r#"    complete result { ok true }"#);
    assert!(complete
        .metadata
        .terminal_completes
        .contains(&"result".to_owned()));

    let fail = b1g_probe_rule("fail", r#"    fail error { reason "bad" }"#);
    assert_eq!(fail.metadata.effects, Vec::new());

    let exec_each = b1g_probe_rule("exec_each", r#"    exec "printf '{}'" -> each Row"#);
    b1g_effect(&exec_each, IrEffectKind::ExecCommand, None, "exec_each");
    assert!(exec_each
        .metadata
        .fact_writes
        .contains(&"schema:Row".to_owned()));

    let bounded = b1g_probe_rule(
        "bounded_record",
        r#"    record TicketPublic from ticket {
      id
      title
    }"#,
    );
    assert!(
        bounded
            .metadata
            .bounded_egresses
            .iter()
            .any(|egress| egress.sink == "fact:TicketPublic"
                && egress.keep == vec!["id".to_owned(), "title".to_owned()]),
        "{:?}",
        bounded.metadata.bounded_egresses
    );

    let redaction = b1g_probe_rule(
        "redaction",
        r#"    redact ticket keep [id, title] as safe
    record TicketPublic from safe {
      id
      title
    }"#,
    );
    assert!(redaction
        .metadata
        .redactions
        .iter()
        .any(|projection| projection.source == "ticket" && projection.binding == "safe"));
    assert!(redaction
        .metadata
        .fact_writes
        .contains(&"schema:TicketPublic".to_owned()));
}

#[test]
fn prompt_lowers_to_coerce_with_string_payload() {
    let source = r#"
workflow PromptText

output result string

class Ticket {
  title string
}

rule ask
  when Ticket as ticket
=> {
  prompt "Summarize {{ ticket.title }}" using fixture as answer

  after answer succeeds as text {
    complete result text
  }
}
"#;

    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "prompt program diagnostics: {:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("program compiles");
    let rule = ir
        .rules
        .iter()
        .find(|rule| rule.name == "ask")
        .expect("ask rule");
    let effect = rule
        .metadata
        .effects
        .iter()
        .find(|effect| effect.binding.as_deref() == Some("answer"))
        .expect("prompt effect");
    assert_eq!(effect.kind, IrEffectKind::SchemaCoerce);

    let coerce = ir
        .contract_registry()
        .effect_contracts
        .into_iter()
        .find(|contract| contract.id == "schema.coerce")
        .expect("coerce contract");
    assert!(coerce.source_forms.contains(&"prompt".to_owned()));
}

#[test]
fn parses_schema_agent_and_rule_slice() {
    let source = r#"
workflow QueueWorkerSlice

use memory

tracker backlog {
  provider builtin
}

enum ReviewStatus {
  Accept
  Revise
}

class WorkReview {
  state "accepted" | "rejected"
  status ReviewStatus
  followups string[]
  maybeReason string?
  scores map<int>
}

coerce reviewWork(issueTitle string, changedFiles string[]) -> WorkReview {
  prompt """
  Review {{ issueTitle }} with files {{ changedFiles }}
  """
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
  skills ["repo-user"]
}

rule start_ready_item
  when backlog has ready issue as item
  when worker is available
=> {
  claim item as claim

  after claim succeeds {
    tell worker """
    Implement {{ item.title }}
    """
  }
}
"#;

    let parsed = parse_program(source);
    assert_eq!(parsed.diagnostics, Vec::new());
    let workflow = parsed
        .program
        .workflow
        .as_ref()
        .map(|ident| ident.name.as_str());
    assert_eq!(workflow, Some("QueueWorkerSlice"));
    assert_eq!(parsed.program.items.len(), 7);

    let coerce = parsed.program.items.iter().find_map(|item| match item {
        Item::Coerce(coerce) => Some(coerce),
        _ => None,
    });
    let coerce = match coerce {
        Some(coerce) => coerce,
        None => panic!("expected coerce item"),
    };
    assert_eq!(coerce.params.len(), 2);

    let rule = parsed.program.items.iter().find_map(|item| match item {
        Item::Rule(rule) => Some(rule),
        _ => None,
    });
    let rule = match rule {
        Some(rule) => rule,
        None => panic!("expected rule item"),
    };
    assert_eq!(rule.whens.len(), 2);
    assert_eq!(rule.whens[0].text, "backlog has ready issue as item");
    assert!(rule.body.text.contains("after claim succeeds"));
}

#[test]
fn parses_and_lowers_static_table_rows() {
    let source = r#"
workflow TableSeed

agent codex {
  provider codex
  profile "repo-writer"
  capacity 1
}

class Task {
  provider AgentRef<codex>
  title string
  priority int
  status "queued"
}

table tasks as Task [
  {
    provider codex
    title "Review parser"
    priority 1
    status "queued"
  }

  {
    provider codex
    title "Review runtime"
    priority 2
    status "queued"
  }
]
"#;

    let parsed = parse_program(source);
    assert_eq!(parsed.diagnostics, Vec::new());
    let table = parsed
        .program
        .items
        .iter()
        .find_map(|item| match item {
            Item::Table(table) => Some(table),
            _ => None,
        })
        .expect("table item");
    assert_eq!(table.rows.len(), 2);
    let row_spans = table.rows.iter().map(|row| row.span).collect::<Vec<_>>();

    let compiled = compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let table_rule = ir
        .rules
        .iter()
        .find(|rule| rule.name == "table_tasks")
        .expect("table lowers to generated started rule");
    assert_eq!(table_rule.whens[0].pattern, "started");
    assert!(table_rule.body.contains("record Task"));
    assert_eq!(table_rule.metadata.fact_writes, vec!["schema:Task"]);
    assert_eq!(table_rule.metadata.record_sources.len(), 2);
    assert_eq!(
        table_rule
            .metadata
            .record_sources
            .iter()
            .map(|source| (
                source.schema.as_str(),
                source.construct.as_str(),
                source.span
            ))
            .collect::<Vec<_>>(),
        row_spans
            .iter()
            .map(|span| ("Task", "table_row", *span))
            .collect::<Vec<_>>()
    );
}

#[test]
fn rejects_old_matrix_declarations() {
    let source = r#"
workflow MatrixSeed

class Task {
  title string
  status "queued"
}

matrix tasks as Task [
  {
    title "Review parser"
    status "queued"
  }
]
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("expected top-level declaration, found identifier `matrix`")
    }));
}

#[test]
fn rejects_table_rows_that_violate_row_schema() {
    let source = r#"
workflow BadTable

agent codex {
  provider codex
  profile "repo-writer"
  capacity 1
}

class Task {
  provider AgentRef<codex>
  status "queued"
}

table tasks as Task [
  {
    provider "codex"
    status "done"
  }
]
"#;

    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("expects an AgentRef value, not string `codex`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("expects literal string `queued`")));
}

#[test]
fn parses_formats_and_lowers_source_tags_as_metadata() {
    let source = r#"
@fixture
@release-gate
workflow Tagged

class Task {
  status "queued"
}

@seed
table tasks as Task [
  {
    status "queued"
  }
]

@acceptance
assert count(Task where status == "queued") == 1

@dispatch
rule consume_task
  when Task as task
=> {
  done task
}
"#;

    let parsed = parse_program(source);
    assert_eq!(parsed.diagnostics, Vec::new());
    assert_eq!(
        parsed
            .program
            .workflow_tags
            .iter()
            .map(|tag| tag.name.as_str())
            .collect::<Vec<_>>(),
        vec!["fixture", "release-gate"]
    );

    let formatted = format_program(source).formatted.expect("formats");
    assert!(formatted.contains("@fixture\n@release-gate\nworkflow Tagged"));
    assert!(formatted.contains("@seed\ntable tasks as Task"));
    assert!(formatted.contains("@acceptance\nassert count"));
    assert!(formatted.contains("@dispatch\nrule consume_task"));

    let compiled = compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let tags = ir
        .source_tags
        .iter()
        .map(|tag| {
            (
                tag.name.as_str(),
                tag.target_kind.as_str(),
                tag.target.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert!(tags.contains(&("fixture", "workflow", "Tagged")));
    assert!(tags.contains(&("release-gate", "workflow", "Tagged")));
    assert!(tags.contains(&("seed", "table", "tasks")));
    assert!(tags.contains(&("dispatch", "rule", "consume_task")));
    assert!(ir
        .source_tags
        .iter()
        .any(|tag| tag.name == "acceptance" && tag.target_kind == "assertion"));
}

#[test]
fn parses_formats_and_lowers_source_descriptions_as_metadata() {
    let source = r#"
@fixture
description "Fixture-backed acceptance workflow"
workflow Described

class Task {
  status "queued"
}

description "Static task seed rows"
table tasks as Task [
  {
    status "queued"
  }
]

description "All seed tasks were consumed"
assert count(Task where status == "queued") == 0

description "Consume one queued task"
rule consume_task
  when Task as task
=> {
  done task
}
"#;

    let parsed = parse_program(source);
    assert_eq!(parsed.diagnostics, Vec::new());
    assert_eq!(
        parsed
            .program
            .workflow_description
            .as_ref()
            .map(|description| description.value.as_str()),
        Some("Fixture-backed acceptance workflow")
    );

    let formatted = format_program(source).formatted.expect("formats");
    assert!(formatted.contains(
        "@fixture\ndescription \"Fixture-backed acceptance workflow\"\nworkflow Described"
    ));
    assert!(formatted.contains("description \"Static task seed rows\"\ntable tasks as Task"));
    assert!(formatted.contains("description \"All seed tasks were consumed\"\nassert count"));
    assert!(formatted.contains("description \"Consume one queued task\"\nrule consume_task"));

    let compiled = compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let descriptions = ir
        .source_descriptions
        .iter()
        .map(|description| {
            (
                description.value.as_str(),
                description.target_kind.as_str(),
                description.target.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert!(descriptions.contains(&(
        "Fixture-backed acceptance workflow",
        "workflow",
        "Described"
    )));
    assert!(descriptions.contains(&("Static task seed rows", "table", "tasks")));
    assert!(descriptions.contains(&("Consume one queued task", "rule", "consume_task")));
    assert!(ir
        .source_descriptions
        .iter()
        .any(
            |description| description.value == "All seed tasks were consumed"
                && description.target_kind == "assertion"
        ));
}

#[test]
fn rejects_descriptions_on_unsupported_declarations_for_now() {
    let source = r#"
workflow BadDescriptions

description "Task schema"
class Task {
  status "queued"
}
"#;

    let parsed = parse_program(source);

    assert_eq!(parsed.diagnostics.len(), 1);
    assert_eq!(
        parsed.diagnostics[0].message,
        "description cannot be attached to class"
    );
}

#[test]
fn rejects_tags_on_unsupported_declarations_for_now() {
    let source = r#"
workflow BadTags

@schema
class Task {
  status "queued"
}
"#;

    let parsed = parse_program(source);

    assert_eq!(parsed.diagnostics.len(), 1);
    assert_eq!(
        parsed.diagnostics[0].message,
        "tag `@schema` cannot be attached to class"
    );
}

#[test]
fn use_short_form_imports_package_libraries_and_rejects_removed_kinds() {
    let parsed = parse_program("workflow Imports\n\nuse memory\n");
    assert_eq!(parsed.diagnostics, Vec::new());
    let use_decl = parsed.program.items.iter().find_map(|item| match item {
        Item::Use(use_decl) => Some(use_decl),
        _ => None,
    });
    assert_eq!(
        use_decl.map(|decl| decl.name.value.as_str()),
        Some("memory")
    );

    let removed_plugin = parse_program("workflow Imports\n\nuse plugin \"memory\"\n");
    assert_eq!(removed_plugin.diagnostics.len(), 1);
    assert_eq!(
        removed_plugin.diagnostics[0].message,
        "`use plugin` is no longer supported"
    );

    let removed_skill = parse_program("workflow Imports\n\nuse skill \"repo-user\"\n");
    assert_eq!(removed_skill.diagnostics.len(), 1);
    assert_eq!(
        removed_skill.diagnostics[0].message,
        "`use skill` is no longer supported"
    );
}

#[test]
fn parses_include_declarations_and_records_ir_metadata() {
    let source = r#"include "library.whip"

workflow Imports

class Task {
  id string
}
"#;
    let parsed = parse_program(source);
    assert_eq!(parsed.diagnostics, Vec::new());
    let include = parsed.program.items.iter().find_map(|item| match item {
        Item::Include(include) => Some(include),
        _ => None,
    });
    assert_eq!(
        include.map(|decl| decl.path.value.as_str()),
        Some("library.whip")
    );

    let compiled = compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    assert_eq!(ir.includes[0].path, "library.whip");
    assert!(ir.to_snapshot().contains("includes\n  library.whip\n"));
}

#[test]
fn parses_explicit_workflow_block_and_contracts() {
    let source = r#"
workflow ReviewPhase {
  input phase PhaseReviewRequest
  output result PhaseReviewResult
  failure error ReviewFailure

  class PhaseReviewRequest {
    title string
  }

  class PhaseReviewResult {
    accepted bool
  }

  class ReviewFailure {
    reason string
  }

  rule noop
    when started
  => {
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("source compiles");
    assert_eq!(ir.workflow, "ReviewPhase");
    assert_eq!(ir.workflow_contracts.len(), 3);
    let snapshot = ir.to_snapshot();
    assert!(snapshot.contains("workflow_contracts\n  input phase ref<PhaseReviewRequest>"));
    assert!(snapshot.contains("  output result ref<PhaseReviewResult>"));
    assert!(snapshot.contains("  failure error ref<ReviewFailure>"));
}

#[test]
fn revision_fixture_bundles_compile_with_expected_contract_shapes() {
    let compatible_v1 = compile_program(include_str!("../../fixtures/revision-compatible-v1.whip"));
    let compatible_v2 = compile_program(include_str!("../../fixtures/revision-compatible-v2.whip"));
    let incompatible_v2 =
        compile_program(include_str!("../../fixtures/revision-incompatible-v2.whip"));
    for compiled in [&compatible_v1, &compatible_v2, &incompatible_v2] {
        assert_eq!(compiled.diagnostics, Vec::new());
    }
    let compatible_v1 = compatible_v1.ir.expect("compatible v1 compiles");
    let compatible_v2 = compatible_v2.ir.expect("compatible v2 compiles");
    let incompatible_v2 = incompatible_v2.ir.expect("incompatible v2 compiles");

    assert_eq!(compatible_v1.workflow, "RevisionFixture");
    assert_eq!(compatible_v2.workflow, "RevisionFixture");
    assert_eq!(incompatible_v2.workflow, "RevisionFixture");
    assert_eq!(
        compatible_v1
            .workflow_contracts
            .iter()
            .map(|contract| (&contract.kind, contract.name.as_str(), &contract.ty))
            .collect::<Vec<_>>(),
        compatible_v2
            .workflow_contracts
            .iter()
            .map(|contract| (&contract.kind, contract.name.as_str(), &contract.ty))
            .collect::<Vec<_>>()
    );
    assert_ne!(
        compatible_v1
            .workflow_contracts
            .iter()
            .map(|contract| (&contract.kind, contract.name.as_str(), &contract.ty))
            .collect::<Vec<_>>(),
        incompatible_v2
            .workflow_contracts
            .iter()
            .map(|contract| (&contract.kind, contract.name.as_str(), &contract.ty))
            .collect::<Vec<_>>()
    );
    assert!(compatible_v2
        .schemas
        .iter()
        .any(|schema| matches!(schema, IrSchema::Class(class) if class.name == "AuditTrail")));
}

#[test]
fn expands_pattern_applications_with_hygienic_names() {
    let source = r#"
pattern Review<Input> {
  class Result {
    item Input
  }

  rule dispatch
    when Input as item
  => {
  }
}

workflow Root {
  class Task {
    title string
  }

  apply Review<Task> as taskReview {
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("source compiles");
    let snapshot = ir.to_snapshot();
    assert!(snapshot.contains("pattern_applications\n  Review as taskReview<ref<Task>>"));
    assert!(snapshot.contains("    generated class:taskReview_Result"));
    assert!(snapshot.contains("    generated rule:taskReview_dispatch"));
    assert!(snapshot.contains("class taskReview_Result"));
    assert!(snapshot.contains("    item ref<Task>"));
    assert!(snapshot.contains("rule taskReview_dispatch"));
    assert!(snapshot.contains("    when Task as item"));
}

#[test]
fn pattern_application_records_definition_and_application_spans() {
    let source = r#"
pattern Review<Input> {
  rule dispatch
    when Input as item
  => {
  }
}

workflow Root {
  class Task {
    title string
  }

  apply Review<Task> as taskReview {
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("source compiles");
    let application = ir
        .pattern_applications
        .first()
        .expect("one pattern application");

    // The recorded definition span must cover the `pattern Review<...> { ... }`
    // declaration, and the application span the `apply ... as ... { ... }` site.
    let definition = &source[application.definition_span.start..application.definition_span.end];
    assert!(definition.starts_with("pattern Review"));
    assert!(definition.ends_with('}'));
    let application_site =
        &source[application.application_span.start..application.application_span.end];
    assert!(application_site.starts_with("apply Review<Task> as taskReview"));
    assert!(application_site.ends_with('}'));

    let snapshot = ir.to_snapshot();
    assert!(snapshot.contains(&format!(
        "    defined-at {}..{}",
        application.definition_span.start, application.definition_span.end
    )));
    assert!(snapshot.contains(&format!(
        "    applied-at {}..{}",
        application.application_span.start, application.application_span.end
    )));
}

#[test]
fn rejects_terminal_statement_in_pattern_body() {
    let source = r#"
pattern Finisher<Input> {
  rule wrap_up
    when Input as item
  => {
    complete result {
      done 1
    }
  }
}

workflow Root {
  output result Summary

  class Summary {
    done int
  }

  class Task {
    title string
  }

  apply Finisher<Task> as finish {
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("cannot reach a workflow terminal")));
}

#[test]
fn rejects_workflow_contract_in_pattern_body() {
    let source = r#"
pattern Contracted<Input> {
  output result Input

  rule dispatch
    when Input as item
  => {
  }
}

workflow Root {
  class Task {
    title string
  }

  apply Contracted<Task> as contracted {
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("workflow contracts are not allowed in pattern bodies")));
}

#[test]
fn parses_workflow_invoke_effect_metadata() {
    let source = r#"
workflow Parent {
  class Task {
    title string
  }

  rule dispatch
    when Task as task
  => {
    invoke Child { task task } as child
  }
}

workflow Child {
  input task Task

  class Task {
    title string
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("source compiles");
    let rule = ir
        .rules
        .iter()
        .find(|rule| rule.name == "dispatch")
        .expect("dispatch rule lowers");
    assert_eq!(rule.metadata.effects.len(), 1);
    assert_eq!(rule.metadata.effects[0].kind, IrEffectKind::WorkflowInvoke);
    assert_eq!(rule.metadata.effects[0].binding.as_deref(), Some("child"));
    assert_eq!(
        rule.metadata.effects[0].workflow_target.as_deref(),
        Some("Child")
    );
    assert!(ir
        .to_snapshot()
        .contains("child kind=workflow.invoke binding=child"));
}

#[test]
fn rejects_unknown_workflow_invocation_target() {
    let source = r#"
workflow Parent {
  class Task {
    title string
  }

  rule dispatch
    when Task as task
  => {
    invoke Missing { task task } as child
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("invokes unknown workflow `Missing`")));
}

#[test]
fn validates_workflow_invocation_inputs_against_target_contract() {
    let source = r#"
workflow Parent {
  class Task {
    title string
  }

  rule dispatch
    when Task as task
  => {
    invoke Child { wrong task } as child
  }
}

workflow Child {
  input task Task

  class Task {
    title string
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(compiled.ir.is_none());
    let messages = compiled
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect::<Vec<_>>();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("workflow `Child` has no input `wrong`")),
        "{messages:#?}"
    );
    assert!(
        messages
            .iter()
            .any(|message| message.contains("workflow invocation `Child` is missing input `task`")),
        "{messages:#?}"
    );
}

#[test]
fn validates_nested_workflow_invocation_input_payloads() {
    let source = r#"
workflow Parent {
  class Task {
    title string
  }

  rule dispatch
    when Task as task
  => {
    invoke Child { task { count "bad" } } as child
  }
}

workflow Child {
  input task ChildTask

  class ChildTask {
    count int
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("field `ChildTask.count` expects `int`")
    }));
}

#[test]
fn rejects_direct_recursive_workflow_invocation() {
    let source = r#"
workflow Parent {
  input task Task

  class Task {
    title string
  }

  rule dispatch
    when Task as task
  => {
    invoke Parent { task task } as next
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("recursively invokes workflow `Parent`")
    }));
}

/// Substitution hygiene: a type argument must not be captured by a
/// pattern-local declaration of the same name. Under the multi-pass form
/// the type pass inserted `Task` and the local-name pass then rewrote that
/// very text to the pattern's gensym, so this program was REFUSED with
/// `unknown readiness pattern 'taskReview_Task as item'` — a name the
/// author never wrote. The caller's `Task` and the pattern's own `Task` are
/// distinct and must both survive.
#[test]
fn pattern_type_argument_is_not_captured_by_a_local_of_the_same_name() {
    let source = r#"
pattern Review<Input> {
  class Task {
    note string
  }

  rule dispatch
    when Input as item
  => {
  }
}

workflow Root {
  class Task {
    title string
  }

  apply Review<Task> as taskReview {
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(
        compiled.diagnostics,
        Vec::new(),
        "capture refused the program"
    );
    let snapshot = compiled.ir.expect("source compiles").to_snapshot();
    assert!(
        snapshot.contains("when Task as item"),
        "the rule matches the CALLER's Task, not the pattern's local: {snapshot}"
    );
    assert!(
        snapshot.contains("taskReview_Task"),
        "the pattern's own Task still gets its hygienic name: {snapshot}"
    );
}

/// Value-argument keys are unvalidated identifiers from the apply body and
/// ran last, so under the multi-pass form a key colliding with the type
/// argument rewrote text the type pass had just inserted — refusing the
/// program with `matches unknown class 'Bogus'`. A key naming no pattern
/// parameter now substitutes nothing.
#[test]
fn pattern_value_argument_key_cannot_rewrite_the_type_argument() {
    let source = r#"
pattern Review<Input> {
  rule dispatch
    when Input as item
  => {
  }
}

workflow Root {
  class Task {
    title string
  }

  apply Review<Task> as taskReview {
    Task Bogus
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let snapshot = compiled.ir.expect("source compiles").to_snapshot();
    assert!(
        snapshot.contains("when Task as item"),
        "the type argument survives a colliding value-argument key: {snapshot}"
    );
    // `Bogus` still appears in the recorded arg list — that is provenance,
    // not substitution. What must not happen is it reaching the rule.
    assert!(
        !snapshot.contains("when Bogus"),
        "a key naming no pattern parameter substitutes nothing: {snapshot}"
    );
}

#[test]
fn expands_pattern_application_value_arguments() {
    let source = r#"
pattern Review<Input> {
  rule dispatch
    when Input as item
  => {
  }
}

workflow Root {
  class Task {
    title string
  }

  apply Review<Task> as taskReview {
    item task
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let snapshot = compiled.ir.expect("source compiles").to_snapshot();
    assert!(snapshot.contains("    arg item task"));
}

#[test]
fn rejects_malformed_pattern_application_arguments() {
    let source = r#"
pattern Review<Input> {
  rule dispatch
    when Input as item
  => {
  }
}

workflow Root {
  class Task {
    title string
  }

  apply Review<Task> as taskReview {
    item
    item task
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("argument `item` is missing a value")));
}

#[test]
fn rejects_unknown_workflow_terminal_actions() {
    let source = r#"
workflow BadTerminal {
  output result Result

  class Result {
    status "ok"
  }

  rule bad
    when started
  => {
    complete missing {
      status "ok"
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("completes unknown workflow terminal `missing`")));
}

#[test]
fn rejects_duplicate_workflow_inputs() {
    let source = r#"
workflow DuplicateInput {
  input phase PhaseRequest
  input phase PhaseRequest

  class PhaseRequest {
    title string
  }

  rule noop
    when started
  => {
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("workflow declares input `phase` more than once")));
}

#[test]
fn rejects_with_as_rule_readiness_alias() {
    let source = r#"
workflow WithIsNotWhen

rule bad
  with started
=> {
}
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("`with` is not a rule readiness clause")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .suggestion
        .as_deref()
        .is_some_and(|suggestion| suggestion.contains("use `when` for rule conditions"))));
}

#[test]
fn parses_grouped_when_clauses_as_ordinary_readiness_clauses() {
    let source = r#"
workflow GroupedWhen

class Task {
  status "queued"
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule start
  when {
    Task as task where task.status == "queued"
    worker is available
  }
=> {
  tell worker "do it"
}
"#;
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("program compiles");
    let rule = &ir.rules[0];

    assert_eq!(rule.whens.len(), 2);
    assert_eq!(rule.whens[0].pattern, "Task as task");
    assert_eq!(
        rule.whens[0]
            .guard
            .as_ref()
            .map(|guard| guard.expr.to_snapshot()),
        Some("task.status == \"queued\"".to_owned())
    );
    assert_eq!(rule.whens[1].pattern, "worker is available");
    assert!(ir
        .to_snapshot()
        .contains("    when Task as task where task.status == \"queued\""));
    assert!(ir.to_snapshot().contains("    when worker is available"));
}

#[test]
fn accepts_harness_declarations_and_agent_bindings() {
    let source = r#"
workflow HarnessTopology

harness coder: codex
harness reviewer: claude

agent implementer using coder {
  profile "repo-writer"
  capacity 1
}

agent critic using reviewer {
  profile "repo-reader"
  capacity 1
}

rule start
  when started
=> {
  tell implementer as turn "implement"
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    assert_eq!(ir.harnesses.len(), 2);
    assert_eq!(ir.harnesses[0].name, "coder");
    assert_eq!(ir.harnesses[0].kind, "codex");
    assert_eq!(
        ir.agents
            .iter()
            .find(|agent| agent.name == "implementer")
            .and_then(|agent| agent.harness.as_deref()),
        Some("coder")
    );
    let snapshot = ir.to_snapshot();
    assert!(snapshot.contains("harness coder kind=codex"));
    assert!(snapshot.contains("agent implementer harness=coder"));
}

#[test]
fn rejects_agent_binding_to_unknown_harness() {
    let source = r#"
workflow UnknownHarness

agent worker using missing {
  profile "repo-writer"
  capacity 1
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("agent `worker` uses unknown harness `missing`")));
}

#[test]
fn rejects_duplicate_harness_declarations_and_accepts_kinds_structurally() {
    let source = r#"
workflow BadHarnesses

harness coder: spaceship
harness coder: codex

agent worker using coder {
  profile "repo-writer"
  capacity 1
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    let messages = compiled
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect::<Vec<_>>();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("harness `coder` is declared more than once")),
        "{messages:#?}"
    );
    // Kind validity is registry-derived and validated by the CLI
    // (spec/std-agent.md "Open provider registry"): the parser no longer
    // holds a compiled-in kind set, so `spaceship` draws no parser
    // diagnostic here.
    assert!(
        !messages
            .iter()
            .any(|message| message.contains("unsupported kind")),
        "{messages:#?}"
    );
}

#[test]
fn validates_workflow_terminal_payload_fields() {
    let source = r#"
workflow BadTerminalPayload {
  output result Result

  class Result {
    status "ok"
    summary string
  }

  rule bad
    when started
  => {
    complete result {
      status "bad"
      extra "ignored"
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("field `Result.status` expects literal string `ok`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("class `Result` has no field `extra`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("workflow terminal `result` is missing required field `Result.summary`")));
}

#[test]
fn accepts_workflow_terminal_actions_in_header_style_workflows() {
    let source = r#"
workflow ImplicitTerminal

output result Result

class Result {
  status "ok"
}

rule finish
  when started
=> {
  complete result {
    status "ok"
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("header-style terminals compile");
    assert_eq!(ir.workflow_contracts.len(), 1);
}

#[test]
fn rejects_header_style_terminal_for_undeclared_contract() {
    let source = r#"
workflow ImplicitTerminal

class Result {
  status "ok"
}

rule bad
  when started
=> {
  complete result {
    status "ok"
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("completes unknown workflow terminal `result`")));
}

#[test]
fn scalar_terminal_contract_accepts_bare_value() {
    // A scalar output contract takes a bare scalar terminal payload.
    let source = r#"
workflow ScalarTerminal {
  output result float
  failure error string

  rule good
    when started
  => {
    complete result 0.9
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "scalar terminal payload rejected: {:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some());
}

#[test]
fn scalar_terminal_contract_rejects_a_field_block() {
    // A scalar contract with a `{ ... }` block is a shape mismatch.
    let source = r#"
workflow ScalarTerminal {
  output result float

  rule bad
    when started
  => {
    complete result {
      value 0.9
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("has a scalar payload contract but is given a field block")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn class_terminal_contract_rejects_a_bare_scalar() {
    // A class contract given a bare scalar value is a shape mismatch.
    let source = r#"
workflow ClassTerminal {
  output result Score
  class Score { value number }

  rule bad
    when started
  => {
    complete result 0.9
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("has a class payload contract `Score` but is given a bare scalar value")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn scalar_terminal_value_is_typechecked_against_the_contract() {
    // A string literal against a `number` scalar contract is a type error.
    let source = r#"
workflow ScalarTerminal {
  output result float

  rule bad
    when started
  => {
    complete result "not a number"
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("result.value") || d.message.contains("number")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn selects_root_from_multiple_explicit_workflows() {
    let source = r#"
class Shared {
  id string
}

workflow First {
  rule one
    when started
  => {
    record Shared {
      id "first"
    }
  }
}

workflow Second {
  rule two
    when started
  => {
    record Shared {
      id "second"
    }
  }
}
"#;
    let ambiguous = compile_program(source);
    assert!(ambiguous.ir.is_none());
    assert!(ambiguous.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("multiple workflow declarations require an explicit root")));

    let compiled = compile_program_with_root(source, Some("Second"));
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("selected root compiles");
    assert_eq!(ir.workflow, "Second");
    assert_eq!(ir.rules.len(), 1);
    assert_eq!(ir.rules[0].name, "two");
    assert!(ir.to_snapshot().contains("class Shared"));
}

#[test]
fn reports_recoverable_diagnostics() {
    let source = r#"
workflow Broken

agent worker {
  provider fixture
  profile 42
  capacity nope
}

rule missing_body
  when started
=>
"#;

    let parsed = parse_program(source);
    assert!(parsed.diagnostics.len() >= 3);
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("profile string")));
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.suggestion.as_deref()
            == Some("write `profile \"profile-name\"`")));
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("capacity value")));
    assert!(parsed
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("`{`")));
}

#[test]
fn lowers_and_formats_agent_tools_grant() {
    // DR-0025: an agent may declare a `tools [...]` grant of workflows it can
    // invoke as typed tools. The grant lowers to `IrAgent.tools`, survives a
    // format round-trip, and de-duplicates entries with a diagnostic.
    let source = r#"
workflow GrantHost

agent worker {
  provider owned
  profile "repo-writer"
  capacity 1
  tools [WordCount, OpenPr]
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("valid ir");
    let agent = ir
        .agents
        .iter()
        .find(|agent| agent.name == "worker")
        .expect("worker agent");
    assert_eq!(
        agent.tools,
        vec!["WordCount".to_owned(), "OpenPr".to_owned()]
    );

    let formatted = format_program(source).formatted.expect("formats");
    assert!(
        formatted.contains("tools [WordCount, OpenPr]"),
        "formatted: {formatted}"
    );

    // A duplicate grant entry is rejected.
    let dup = compile_program(
        "workflow Dup\nagent a {\n  provider owned\n  profile \"p\"\n  tools [X, X]\n}\n",
    );
    assert!(
        dup.diagnostics
            .iter()
            .any(|d| d.message.contains("grants tool `X` more than once")),
        "diagnostics: {:?}",
        dup.diagnostics
    );
}

#[test]
fn harness_class_classifies_managed_vs_delegated_and_emits_only_delegated() {
    // Classifier is total: owned/fixture Managed, the rest Delegated.
    assert_eq!(harness_class("owned"), HarnessClass::Managed);
    assert_eq!(harness_class("fixture"), HarnessClass::Managed);
    assert_eq!(harness_class("claude"), HarnessClass::Delegated);
    assert_eq!(harness_class("codex"), HarnessClass::Delegated);
    assert_eq!(harness_class("native-fixture"), HarnessClass::Delegated);
    assert_eq!(harness_class("command"), HarnessClass::Delegated);

    // A `provider owned` agent lowers Managed and emits NO class token (default).
    let managed = compile_program(
        "workflow W\nagent m {\n  provider owned\n  profile \"p\"\n  capacity 1\n}\n",
    );
    let managed_ir = managed.ir.expect("ir");
    assert_eq!(managed_ir.agents[0].harness_class, HarnessClass::Managed);
    assert!(!managed_ir.to_snapshot().contains("class="));

    // A `provider claude` agent lowers Delegated and emits `class=delegated`.
    let delegated = compile_program(
        "workflow W\nagent d {\n  provider claude\n  profile \"repo-writer\"\n  capacity 1\n}\n",
    );
    let delegated_ir = delegated.ir.expect("ir");
    assert_eq!(
        delegated_ir.agents[0].harness_class,
        HarnessClass::Delegated
    );
    assert!(delegated_ir.to_snapshot().contains("class=delegated"));

    // `using <harness>` resolves the class through the harness's kind.
    let via_harness = compile_program(
            "workflow W\nharness box: claude\nagent d using box {\n  profile \"repo-writer\"\n  capacity 1\n}\n",
        );
    let via_ir = via_harness.ir.expect("ir");
    assert_eq!(via_ir.agents[0].harness_class, HarnessClass::Delegated);
}

#[test]
fn tell_with_skills_lowers_to_effect_turn_skills_and_ir_snapshot() {
    let source = concat!(
            "workflow W\n",
            "agent coder {\n  provider owned\n  profile \"p\"\n  capacity 1\n}\n",
            "class Task {\n  note string\n}\n",
            "rule go\n  when Task as t\n=> {\n  tell coder with skills [\"review\", \"lint\"] \"do it\" as turn\n}\n",
        );
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("ir");
    let effect = ir
        .rules
        .iter()
        .flat_map(|rule| &rule.metadata.effects)
        .find(|effect| effect.kind == IrEffectKind::AgentTell)
        .expect("tell effect");
    assert_eq!(
        effect.turn_skills,
        vec!["review".to_owned(), "lint".to_owned()]
    );
    // The .ir snapshot carries the pin (appended only when present).
    assert!(
        ir.to_snapshot().contains("skills=review,lint"),
        "{}",
        ir.to_snapshot()
    );
}

#[test]
fn agent_compaction_strategy_parses_lowers_formats_and_validates() {
    let source = compile_program(
            "workflow C\nagent w {\n  provider owned\n  profile \"p\"\n  capacity 1\n  compaction hard_reset\n}\n",
        );
    assert!(source.diagnostics.is_empty(), "{:?}", source.diagnostics);
    let ir = source.ir.expect("ir");
    let agent = ir.agents.iter().find(|a| a.name == "w").expect("agent");
    assert_eq!(agent.compaction.as_deref(), Some("hard_reset"));

    // Round-trips through the formatter and the .ir snapshot.
    let formatted = format_program(
            "workflow C\nagent w {\n  provider owned\n  profile \"p\"\n  capacity 1\n  compaction hard_reset\n}\n",
        )
        .formatted
        .expect("formats");
    assert!(formatted.contains("compaction hard_reset"), "{formatted}");
    assert!(ir.to_snapshot().contains("compaction=hard_reset"));

    // An unknown strategy is a diagnostic (not silently accepted).
    let bad = compile_program(
            "workflow C\nagent w {\n  provider owned\n  profile \"p\"\n  capacity 1\n  compaction squish\n}\n",
        );
    assert!(
        bad.diagnostics
            .iter()
            .any(|d| d.message.contains("unknown compaction strategy `squish`")),
        "diagnostics: {:?}",
        bad.diagnostics
    );

    // An agent with no compaction field lowers to None and adds no .ir token.
    let plain = compile_program(
        "workflow C\nagent w {\n  provider owned\n  profile \"p\"\n  capacity 1\n}\n",
    );
    let plain_ir = plain.ir.expect("ir");
    assert_eq!(plain_ir.agents[0].compaction, None);
    assert!(!plain_ir.to_snapshot().contains("compaction="));
}

#[test]
fn agent_settings_source_parses_lowers_formats_and_validates() {
    // DR-0034 Decision 4: the delegated ambient-config knob.
    let source = compile_program(
            "workflow C\nagent w {\n  provider claude\n  profile \"p\"\n  capacity 1\n  settings project\n}\n",
        );
    assert!(source.diagnostics.is_empty(), "{:?}", source.diagnostics);
    let ir = source.ir.expect("ir");
    let agent = ir.agents.iter().find(|a| a.name == "w").expect("agent");
    assert_eq!(agent.settings.as_deref(), Some("project"));

    // Round-trips through the formatter and the .ir snapshot.
    let formatted = format_program(
            "workflow C\nagent w {\n  provider claude\n  profile \"p\"\n  capacity 1\n  settings project\n}\n",
        )
        .formatted
        .expect("formats");
    assert!(formatted.contains("settings project"), "{formatted}");
    assert!(ir.to_snapshot().contains("settings=project"));

    // An unknown source is a diagnostic (not silently accepted).
    let bad = compile_program(
            "workflow C\nagent w {\n  provider claude\n  profile \"p\"\n  capacity 1\n  settings everything\n}\n",
        );
    assert!(
        bad.diagnostics
            .iter()
            .any(|d| d.message.contains("unknown settings source `everything`")),
        "diagnostics: {:?}",
        bad.diagnostics
    );

    // Declaring settings twice is a diagnostic.
    let dup = compile_program(
            "workflow C\nagent w {\n  provider claude\n  profile \"p\"\n  capacity 1\n  settings project\n  settings user\n}\n",
        );
    assert!(
        dup.diagnostics
            .iter()
            .any(|d| d.message.contains("declares settings more than once")),
        "diagnostics: {:?}",
        dup.diagnostics
    );

    // An agent with no settings field lowers to None and adds no .ir token —
    // unset means the provider's own default, not the empty set.
    let plain = compile_program(
        "workflow C\nagent w {\n  provider claude\n  profile \"p\"\n  capacity 1\n}\n",
    );
    let plain_ir = plain.ir.expect("ir");
    assert_eq!(plain_ir.agents[0].settings, None);
    assert!(!plain_ir.to_snapshot().contains("settings="));
}

#[test]
fn agent_thread_mode_parses_lowers_and_partitions() {
    // `thread continue` on a Managed agent lowers into the IR.
    let source = "workflow ChatDemo\n\noutput result Done\n\nclass Done {\n  ok int\n}\n\n\
             agent helper {\n  provider owned\n  profile \"repo-reader\"\n  capacity 1\n  thread continue\n}\n\n\
             rule go\n  when started\n=> {\n  tell helper as reply \"\"\"\n  Hi.\n  \"\"\"\n\n\
             \x20 after reply succeeds {\n    complete result { ok 1 }\n  }\n}\n";
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("thread continue compiles");
    let agent = ir
        .agents
        .iter()
        .find(|agent| agent.name == "helper")
        .expect("agent lowered");
    assert_eq!(agent.thread.as_deref(), Some("continue"));

    // An unknown mode is a diagnostic.
    let bad = source.replace("thread continue", "thread sometimes");
    let compiled = compile_program(&bad);
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("unknown thread mode `sometimes`")));

    // `thread` on a Delegated agent is a managed-knob partition error.
    let delegated = source.replace("provider owned", "provider codex");
    let compiled = compile_program(&delegated);
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("is delegated; `thread` is a managed-harness knob")),
        "{:?}",
        compiled
            .diagnostics
            .iter()
            .map(|d| &d.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn agent_knobs_partition_by_harness_class() {
    // DR-0034 Decision 3: each class admits only its meaningful knobs; the
    // other class rejects them with a diagnostic, never a silent no-op.

    // `compaction` on a Delegated agent is an error — you cannot tell Claude
    // how to compact; it does its own.
    let bad = compile_program(
            "workflow C\nagent w {\n  provider claude\n  profile \"p\"\n  capacity 1\n  compaction summarize\n}\n",
        );
    assert!(
        bad.diagnostics.iter().any(|d| d
            .message
            .contains("is delegated; `compaction` is a managed-harness knob")),
        "diagnostics: {:?}",
        bad.diagnostics
    );

    // `settings` on a Managed agent is an error — WhippleScript already
    // assembles the context; there is nothing foreign to configure.
    let bad = compile_program(
            "workflow C\nagent w {\n  provider owned\n  profile \"p\"\n  capacity 1\n  settings project\n}\n",
        );
    assert!(
        bad.diagnostics.iter().any(|d| d
            .message
            .contains("is managed; `settings` is a delegated-harness knob")),
        "diagnostics: {:?}",
        bad.diagnostics
    );

    // The class resolves through a `using <harness>` binding too.
    let bad = compile_program(
            "workflow C\nharness box: claude\nagent w using box {\n  profile \"p\"\n  capacity 1\n  compaction summarize\n}\n",
        );
    assert!(
        bad.diagnostics.iter().any(|d| d
            .message
            .contains("is delegated; `compaction` is a managed-harness knob")),
        "diagnostics: {:?}",
        bad.diagnostics
    );

    // The right-class pairings stay legal.
    let good = compile_program(
            "workflow C\nagent m {\n  provider owned\n  profile \"p\"\n  capacity 1\n  compaction summarize\n}\nagent d {\n  provider claude\n  profile \"p\"\n  capacity 1\n  settings project\n}\n",
        );
    assert!(good.diagnostics.is_empty(), "{:?}", good.diagnostics);

    // An agent with no provider binding is Managed by default (D8-5), so a
    // managed-only knob is legal on it.
    let unbound = compile_program(
        "workflow C\nagent w {\n  profile \"p\"\n  capacity 1\n  compaction summarize\n}\n",
    );
    assert!(
        !unbound
            .diagnostics
            .iter()
            .any(|d| d.message.contains("managed-harness knob")),
        "diagnostics: {:?}",
        unbound.diagnostics
    );
}

/// `requires [<feature.class>]` (spec/std-agent.md slice 6): dotted
/// taxonomy classes parse into `IrAgent::requires`, render in the .ir
/// snapshot only when declared, format canonically, and a non-taxonomy
/// class or duplicate is a lowering diagnostic.
#[test]
fn agent_requires_parses_taxonomy_classes() {
    let program = "workflow R\n\nagent a {\n  provider owned\n  profile \"repo-reader\"\n  capacity 1\n  requires [session.resume, turn.cancel]\n}\n";
    let compiled = compile_program(program);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("ir");
    let agent = ir.agents.first().expect("agent");
    assert_eq!(
        agent.requires,
        vec!["session.resume".to_owned(), "turn.cancel".to_owned()]
    );
    assert!(ir
        .to_snapshot()
        .contains("requires=[session.resume, turn.cancel]"));

    // The formatter preserves the field.
    let formatted = format_program(program).formatted.expect("formats");
    assert!(
        formatted.contains("  requires [session.resume, turn.cancel]"),
        "{formatted}"
    );

    // Agents without `requires` keep an unchanged snapshot (no ripple).
    let plain = compile_program(
        "workflow R\n\nagent a {\n  provider owned\n  profile \"p\"\n  capacity 1\n}\n",
    );
    assert!(!plain.ir.expect("ir").to_snapshot().contains("requires="));

    // Taxonomy membership bites (DR-0015): a made-up class is rejected.
    let unknown = compile_program(
            "workflow R\n\nagent a {\n  provider owned\n  profile \"p\"\n  capacity 1\n  requires [warp.drive]\n}\n",
        );
    assert!(
        unknown.diagnostics.iter().any(|d| d
            .message
            .contains("requires unknown feature class `warp.drive`")),
        "{:?}",
        unknown.diagnostics
    );

    // Duplicates are rejected.
    let duplicate = compile_program(
            "workflow R\n\nagent a {\n  provider owned\n  profile \"p\"\n  capacity 1\n  requires [turn.cancel, turn.cancel]\n}\n",
        );
    assert!(
        duplicate.diagnostics.iter().any(|d| d
            .message
            .contains("requires feature class `turn.cancel` more than once")),
        "{:?}",
        duplicate.diagnostics
    );
}

#[test]
fn agent_delegated_to_sugar_and_managed_default() {
    // `agent d delegated to <provider>` is the Delegated surface spelling
    // (DR-0034 Decision 2); it names the provider kind directly.
    let program = "workflow C\nagent d delegated to claude {\n  profile \"p\"\n  capacity 1\n  settings project\n}\n";
    let source = compile_program(program);
    assert!(source.diagnostics.is_empty(), "{:?}", source.diagnostics);
    let ir = source.ir.expect("ir");
    let agent = ir.agents.iter().find(|a| a.name == "d").expect("agent");
    assert_eq!(agent.provider.as_deref(), Some("claude"));
    assert_eq!(agent.harness_class, HarnessClass::Delegated);
    assert!(ir.to_snapshot().contains("class=delegated"));

    // The formatter preserves the sugar.
    let formatted = format_program(program).formatted.expect("formats");
    assert!(
        formatted.contains("agent d delegated to claude {"),
        "{formatted}"
    );

    // `delegated to owned` is a contradiction — owned is the managed substrate.
    let bad = compile_program(
        "workflow C\nagent d delegated to owned {\n  profile \"p\"\n  capacity 1\n}\n",
    );
    assert!(
        bad.diagnostics.iter().any(|d| d
            .message
            .contains("delegates to `owned`, which is a managed kind")),
        "diagnostics: {:?}",
        bad.diagnostics
    );

    // An unknown delegate kind parses structurally: kind existence is
    // registry-validated by the CLI (spec/std-agent.md "Open provider
    // registry"), and an unrecognized kind classifies Delegated (never
    // Managed), so `delegated to mystery` draws no parser diagnostic.
    let unknown = compile_program(
        "workflow C\nagent d delegated to mystery {\n  profile \"p\"\n  capacity 1\n}\n",
    );
    assert!(
        !unknown
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unsupported provider")),
        "diagnostics: {:?}",
        unknown.diagnostics
    );

    // `delegated to` plus a `provider` field is an error, not a silent pick.
    let both = compile_program(
            "workflow C\nagent d delegated to claude {\n  provider codex\n  profile \"p\"\n  capacity 1\n}\n",
        );
    assert!(
        both.diagnostics.iter().any(|d| d
            .message
            .contains("declares both `delegated to` and direct provider")),
        "diagnostics: {:?}",
        both.diagnostics
    );

    // A bare `agent m { … }` is Managed by default (Decision 6: managed is
    // the substrate) — it lowers to the owned provider with no diagnostic.
    let plain = compile_program("workflow C\nagent m {\n  profile \"p\"\n  capacity 1\n}\n");
    assert!(plain.diagnostics.is_empty(), "{:?}", plain.diagnostics);
    let plain_ir = plain.ir.expect("ir");
    assert_eq!(plain_ir.agents[0].provider.as_deref(), Some("owned"));
    assert_eq!(plain_ir.agents[0].harness_class, HarnessClass::Managed);
}

#[test]
fn accepts_agent_ref_dynamic_tell_targets() {
    let source = r#"
workflow AgentRefRouting

agent codex {
  provider codex
  profile "repo-writer"
  capacity 1
  capabilities ["agent.tell"]
}

agent claude {
  provider claude
  profile "repo-writer"
  capacity 1
  capabilities ["agent.tell"]
}

class LanguageTask {
  provider AgentRef<codex | claude>
  prompt string
}

rule run_task
  when LanguageTask as task
  when task.provider is available
=> {
  tell task.provider requires ["agent.tell"] as turn "{{ task.prompt }}"
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("valid ir");
    let rule = ir
        .rules
        .iter()
        .find(|rule| rule.name == "run_task")
        .expect("run_task");
    assert_eq!(rule.metadata.effects.len(), 1);
    assert_eq!(rule.metadata.effects[0].kind, IrEffectKind::AgentTell);
}

#[test]
fn rejects_agent_ref_targets_missing_required_capabilities() {
    let source = r#"
workflow BadAgentRefCapabilities

agent codex {
  provider codex
  profile "repo-writer"
  capacity 1
  capabilities ["agent.tell", "repo.write"]
}

agent claude {
  provider claude
  profile "repo-reader"
  capacity 1
  capabilities ["agent.tell"]
}

class LanguageTask {
  provider AgentRef<codex | claude>
  prompt string
}

rule run_task
  when LanguageTask as task
=> {
  tell task.provider requires ["repo.write"] as turn """
  {{ task.prompt }}
  """
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("agent `claude` requiring undeclared capability `repo.write`")));
}

#[test]
fn rejects_plain_string_dynamic_tell_targets() {
    let source = r#"
workflow BadAgentRefRouting

agent codex {
  provider codex
  profile "repo-writer"
  capacity 1
}

class LanguageTask {
  provider string
}

rule run_task
  when LanguageTask as task
=> {
  tell task.provider "bad"
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("non-AgentRef dynamic tell target `task.provider`")));
}

#[test]
fn rejects_unknown_agent_ref_domain_values() {
    let source = r#"
workflow BadAgentRefDomain

agent codex {
  provider codex
  profile "repo-writer"
  capacity 1
}

class LanguageTask {
  provider AgentRef<codex | ghost>
}

rule seed
  when started
=> {
  record LanguageTask {
    provider claude
  }
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("AgentRef references unknown agent `ghost`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("field `LanguageTask.provider` cannot reference agent `claude`")));
}

#[test]
fn rejects_quoted_agent_ref_record_values() {
    let source = r#"
workflow BadQuotedAgentRef

agent codex {
  provider codex
  profile "repo-writer"
  capacity 1
}

class LanguageTask {
  provider AgentRef<codex>
}

rule seed
  when started
=> {
  record LanguageTask {
    provider "codex"
  }
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("expects an AgentRef value, not string `codex`")));
}

#[test]
fn requires_presence_proof_for_optional_field_access() {
    let source = r#"
workflow OptionalProof

class Person {
  name string
}

class Issue {
  assignee Person?
}

rule unsafe_optional
  when Issue as issue where issue.assignee.name == "Ada"
=> {
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("unsafe optional path `issue.assignee.name`")));
}

#[test]
fn accepts_presence_proof_before_optional_field_access() {
    let source = r#"
workflow OptionalProof

class Person {
  name string
}

class Issue {
  assignee Person?
}

rule safe_optional
  when Issue as issue where issue.assignee != null && issue.assignee.name == "Ada"
=> {
}

rule safe_exists
  when Issue as issue where exists issue.assignee && issue.assignee.name == "Ada"
=> {
}

rule safe_not_null
  when Issue as issue where !(issue.assignee == null) && issue.assignee.name == "Ada"
=> {
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn parses_expression_kernel_surface() {
    let cases = [
        ("true || false && !ready", "true || (false && !ready)"),
        (
            "count(task.labels) == 0 || exists(Result where status == \"done\")",
            "(count(task.labels) == 0) || exists(Result where status == \"done\")",
        ),
        (
            "task.labels[\"priority\"] == [\"high\", \"urgent\"][0]",
            "task.labels[\"priority\"] == [\"high\", \"urgent\"][0]",
        ),
        (
            "exists issue.assignee && issue.assignee.name == \"Ada\"",
            "exists(issue.assignee) && (issue.assignee.name == \"Ada\")",
        ),
        (
            "{title task.title, metadata {phase \"kernel\"}}",
            "{title task.title, metadata {phase \"kernel\"}}",
        ),
        (
            "count(effect agent.tell where target == \"worker\") >= 1",
            "count(effect agent.tell where target == \"worker\") >= 1",
        ),
    ];

    for (source, expected) in cases {
        let expr = parse_expression(source).expect(source);
        assert_eq!(expr.to_snapshot(), expected);
    }

    for source in ["task.labels[", "count(Result where)", "[1,,2]"] {
        assert!(
            parse_expression(source).is_err(),
            "{source} unexpectedly parsed"
        );
    }
}

/// Every expression form in the spec's grammar (expression-kernel.md
/// "Expression Forms") parses and renders to a pinned snapshot, so parser
/// precedence and snapshot parenthesization are locked for each form.
#[test]
fn deeply_nested_expression_errors_instead_of_overflowing_the_stack() {
    // Run on a production-sized stack (compile happens on the 8 MB main
    // thread, not a 2 MB test thread): a pathologically nested guard
    // expression must return a normal Err diagnostic, not abort the
    // process with a stack overflow.
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let deep = format!("{}task.done{}", "(".repeat(8000), ")".repeat(8000));
            let result = parse_expression(&deep);
            assert!(
                result
                    .as_ref()
                    .err()
                    .is_some_and(|message| message.contains("nested too deeply")),
                "expected a depth-limit diagnostic, got {result:?}"
            );
            // A reasonably nested expression still parses (guard is generous).
            let ok = format!("{}task.done{}", "(".repeat(64), ")".repeat(64));
            assert!(parse_expression(&ok).is_ok(), "64-deep nesting must parse");
        })
        .expect("spawn")
        .join()
        .expect("nested-expression parse must not crash");
}

#[test]
fn parses_every_expression_form_with_pinned_precedence() {
    let cases = [
        // Literals.
        ("\"text\"", "\"text\""),
        ("42", "42"),
        ("2.5", "2.5"),
        ("true && false", "true && false"),
        ("task.note == null", "task.note == null"),
        // Paths and (map) indexing, including chained indexes.
        (
            "task.meta[\"a\"][\"b\"] == \"c\"",
            "task.meta[\"a\"][\"b\"] == \"c\"",
        ),
        // Unary and word-form connectives normalize to symbol operators.
        ("not task.done", "!task.done"),
        ("!!task.done", "!!task.done"),
        (
            "task.a and task.b or task.c",
            "(task.a && task.b) || task.c",
        ),
        // Prefix `not` binds looser than comparisons.
        ("not task.state == \"open\"", "!(task.state == \"open\")"),
        // Boolean precedence: `&&` over `||`, unary over both.
        (
            "task.a || task.b && !task.c",
            "task.a || (task.b && !task.c)",
        ),
        // Arithmetic precedence: `* /` over `+ -`, both over comparisons.
        ("1 + 2 * 3 == 7", "(1 + (2 * 3)) == 7"),
        ("10 - 4 / 2 >= 8", "(10 - (4 / 2)) >= 8"),
        // Comparisons/membership are ONE flat left-associative level:
        // `a == b < c` groups as `(a == b) < c` (the spec sketch draws
        // ordering tighter than equality; the divergence is only
        // observable in chains, which the type checker rejects anyway —
        // this pin documents the implemented grouping).
        ("task.a == task.b < task.c", "(task.a == task.b) < task.c"),
        // Ordering and membership forms.
        ("task.n <= 5 && task.n > 0", "(task.n <= 5) && (task.n > 0)"),
        ("\"x\" in task.labels", "\"x\" in task.labels"),
        ("\"x\" not in task.labels", "\"x\" not in task.labels"),
        // Presence proof form vs collection form.
        ("exists task.owner", "exists(task.owner)"),
        (
            "exists(Task where done == false)",
            "exists(Task where done == false)",
        ),
        // count/empty over arrays, queries, and effect queries.
        ("count([1, 2]) == 2", "count([1, 2]) == 2"),
        (
            "empty(Task where done == false)",
            "empty(Task where done == false)",
        ),
        ("empty(task.labels)", "empty(task.labels)"),
        ("empty([])", "empty([])"),
        (
            "count(effect kind agent.tell where target == \"w\") == 0",
            "count(effect kind agent.tell where target == \"w\") == 0",
        ),
        (
            "exists(effect kind schema.coerce)",
            "exists(effect kind schema.coerce)",
        ),
        // Array and object literals.
        ("[\"a\", \"b\"]", "[\"a\", \"b\"]"),
        (
            "{title task.title, meta {phase \"kernel\"}}",
            "{title task.title, meta {phase \"kernel\"}}",
        ),
    ];

    for (source, expected) in cases {
        let expr = parse_expression(source).expect(source);
        assert_eq!(expr.to_snapshot(), expected, "for `{source}`");
    }
}

/// Invalid expression syntax fails deterministically with an actionable
/// message: dangling operators, unclosed delimiters, malformed queries,
/// and unsupported call syntax (tracker "invalid syntax diagnostics").
#[test]
fn invalid_expression_syntax_produces_deterministic_errors() {
    let cases = [
        // Dangling operators.
        ("task.a ==", "expected expression"),
        ("1 +", "expected expression"),
        ("task.a && || task.b", "expected expression"),
        ("task.a == == 1", "expected expression"),
        ("!", "expected expression"),
        // Unclosed delimiters.
        ("(task.a == 1", "expected `)`"),
        ("task.labels[\"k\"", "expected `]`"),
        ("[1, 2", "expected `,`"),
        ("{a 1", "expected object field name"),
        // Trailing garbage after a complete expression.
        ("task.a == 1)", "unexpected token"),
        ("in task.a", "unexpected token"),
        // Malformed queries and paths.
        ("count(Task where", "expected expression"),
        ("count(Task where )", "expected expression"),
        ("task..a", "expected field name after `.`"),
        ("task.a not b", "expected `in` after `not`"),
    ];

    for (source, expected) in cases {
        let message = parse_expression(source).expect_err(source);
        assert!(
            message.contains(expected),
            "`{source}` -> `{message}` (expected `{expected}`)"
        );
    }
}

/// Syntax errors inside real guards and assertions surface as compile
/// diagnostics naming the rule/assertion, not as panics or silent drops.
#[test]
fn guard_and_assertion_syntax_errors_surface_with_context() {
    let source = r#"
workflow BadExpressionSyntax

class Task {
  title string
}

assert count(Task) ==

rule dangling_guard
  when Task as task where task.title ==
=> {
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("invalid assertion expression: expected expression")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("rule `dangling_guard` has invalid guard expression: expected expression")));
}

/// `empty` static checks: arity, scalar rejection, and the optional rule —
/// `empty(Optional<T>)` is defined only when `empty(T)` is, so an optional
/// string is accepted while an optional int is rejected.
#[test]
fn validates_empty_call_arity_and_optional_arguments() {
    let source = r#"
workflow EmptyCallChecks

class Task {
  title string
  note string?
  age int?
  done bool
}

assert empty() == true
assert empty(["a"], ["b"]) == true
assert count(Task where empty(note) && empty(title)) == 0
assert count(Task where empty(age)) == 0
assert count(Task where empty(done)) == 0
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("calls `empty` with 0 arguments, expected 1")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("calls `empty` with 2 arguments, expected 1")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("calls `empty` with unsupported optional argument type `int?`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("calls `empty` with unsupported argument type `bool`")));
    // The accepted forms produce no `empty` diagnostics of their own.
    assert!(!compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("`string?`")));
    assert!(!compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("unsupported argument type `string`")));
}

/// The formatter never re-renders expression text: guards and assertions
/// keep the author's exact spelling (word-form connectives, redundant
/// parentheses), and formatting is idempotent over them. Rendered
/// parenthesization belongs to the IR snapshot (see
/// `parses_every_expression_form_with_pinned_precedence`), never to `fmt`.
#[test]
fn format_preserves_expression_source_text_verbatim() {
    let source = r#"workflow FormatExpressions

class Task {
  title string
  done bool
}

assert count(Task where (done == false) and not done) == 0

rule keep_spelling
  when Task as task where not task.done and (task.title == "a" or task.title == "b")
=> {
}
"#;

    let formatted = format_program(source);
    assert_eq!(formatted.diagnostics, Vec::new());
    let once = formatted.formatted.expect("formats");
    assert!(once.contains(
        "when Task as task where not task.done and (task.title == \"a\" or task.title == \"b\")"
    ));
    assert!(once.contains("assert count(Task where (done == false) and not done) == 0"));

    let twice = format_program(&once).formatted.expect("formats twice");
    assert_eq!(once, twice, "formatting is idempotent over expressions");
}

#[test]
fn validates_expected_schema_object_and_map_record_fields() {
    let source = r#"
workflow ObjectRecordFields

class Owner {
  name string
}

class Task {
  title string
  metadata map<string>
  owner Owner?
}

rule seed
  when started
=> {
    record Task {
    title "Implement object literals"
    metadata { phase "kernel" }
    owner { name "Ada" }
  }

  record Task {
    title "Implement multiline object literals"
    metadata {
      phase "kernel"
      owner "Ada"
    }
    owner {
      name "Ada"
    }
  }
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn rejects_invalid_expected_schema_object_and_map_record_fields() {
    let source = r#"
workflow BadObjectRecordFields

class Owner {
  name string
}

class Task {
  metadata map<string>
  owner Owner
}

rule seed
  when started
=> {
  record Task {
    metadata { phase 1 }
    owner { alias "Ada" }
  }
}

rule bad_guard
  when Task as task where { phase "kernel" } == task.metadata
=> {
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("field `Task.metadata` expects `string`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("class `Owner` has no field `alias`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("missing required object field `Owner.name`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("compares incompatible expression types")));
}

#[test]
fn rejects_invalid_expression_types() {
    let source = r#"
workflow BadExpressionTypes

class Task {
  title string
  labels map<string>
  priority int
  ready bool
}

rule non_bool_guard
  when Task as task where task.priority
=> {
}

rule bad_ordering
  when Task as task where task.title > "abc"
=> {
}

rule bad_membership
  when Task as task where task.title in task.priority
=> {
}

rule bad_equality
  when Task as task where task.ready == "yes"
=> {
}

rule bad_array
  when Task as task where task.title in ["abc", 1]
=> {
}

rule bad_map_key
  when Task as task where task.labels[1] == "urgent"
=> {
}

rule bad_map_membership
  when Task as task where 1 in task.labels
=> {
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("non-boolean guard expression")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("orders non-orderable expression values")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("uses membership against a non-array/non-map expression")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("compares incompatible expression types")));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("mixed-type array literal")));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("non-string key")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("map membership with a non-string key")));
}

#[test]
fn validates_duration_and_time_ordering_and_literals() {
    let source = r#"
workflow DurationTimeExpressions

class Window {
  elapsed duration
  limit duration
  opened_at time
  due_at time
}

assert exists(Window where elapsed < limit)
assert exists(Window where opened_at <= due_at)

rule seed
  when started
=> {
  record Window {
    elapsed "PT30.5M"
    limit "PT1.25H"
    opened_at "2026-05-29T10:00:00.250-04:00"
    due_at "2026-05-29T14:00:00.500Z"
  }
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn rejects_invalid_duration_and_time_literals() {
    let source = r#"
workflow BadDurationTimeExpressions

class Window {
  elapsed duration
  limit duration
  opened_at time
}

rule seed
  when started
=> {
  record Window {
    elapsed "thirty minutes"
    limit "P1M"
    opened_at "morning"
  }
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("field `Window.elapsed` has invalid duration literal")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("field `Window.limit` has invalid duration literal")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("field `Window.opened_at` has invalid time literal")));
}

#[test]
fn validates_assertion_expression_types_and_paths() {
    let source = r#"
workflow BadAssertions

class Task {
  provider "codex" | "claude"
  priority int
}

assert count(Task where provider == "bad") == 0
assert count(Task)
assert missing.root == "value"
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("assertion compares finite-domain value to unknown `bad`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("assertion has non-boolean assertion expression")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("assertion has unknown expression root `missing`")));
}

#[test]
fn validates_symmetric_finite_domain_literals_and_unknown_guard_roots() {
    let source = r#"
workflow SymmetricFiniteDomain

enum ReviewStatus {
  Accept
  Revise
}

class Task {
  status ReviewStatus
  provider "codex" | "claude"
}

rule symmetric_literal
  when Task as task where "bad" == task.provider
=> {
}

rule enum_variant_literal
  when Task as task where Missing == task.status
=> {
}

rule array_membership_literal
  when Task as task where task.provider in ["codex", "bad"]
=> {
}

rule implicit_query_head
  when Task as task where exists(Task where status == Missing)
=> {
}

rule unknown_root
  when Task as task where other.provider == "codex"
=> {
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("finite-domain value to unknown `bad`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("finite-domain value to unknown `Missing`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("unknown expression root `other`")));
}

#[test]
fn rejects_unsatisfiable_finite_domain_expression_relations() {
    let source = r#"
workflow UnsatisfiableFiniteDomains

class Task {
  provider "codex" | "claude"
  route "cache" | "coerce"
}

rule disjoint_equality
  when Task as task where task.provider == task.route
=> {
}

rule empty_membership
  when Task as task where task.provider in []
=> {
}

rule excluded_membership
  when Task as task where task.provider not in ["codex", "claude"]
=> {
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("statically unsatisfiable finite-domain equality")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("statically unsatisfiable finite-domain membership")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("statically unsatisfiable finite-domain exclusion")));
}

#[test]
fn accepts_map_index_expressions() {
    let source = r#"
workflow MapIndex

class Task {
  labels map<string>
}

rule route
  when Task as task where task.labels["priority"] == "high"
=> {
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("valid ir");
    let guard = ir.rules[0].whens[0].guard.as_ref().expect("guard");
    assert_eq!(
        guard.expr.to_snapshot(),
        "task.labels[\"priority\"] == \"high\""
    );
}

#[test]
fn lowers_deterministic_ir_snapshot() {
    let source = r#"
workflow Snapshot


class Work {
  title string
  files string[]
  state "open" | "done"
}

class Result {
  title string
  files string[]
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 2
  skills ["repo-user"]
}

rule start
  when Work as work
=>
{
  tell worker "{{ work.title }}"
}

rule finish
  when Result as result
=>
{
  record Work {
    title result.title
    files result.files
    state "done"
  }
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = match compiled.ir {
        Some(ir) => ir,
        None => panic!("expected lowered IR"),
    };

    let expected = "\
workflow Snapshot
schemas
  class Work
    title string
    files array<string>
    state union<literal<\"open\"> | literal<\"done\">>
  class Result
    title string
    files array<string>
agents
  agent worker harness=<fallback> provider=fixture profile=repo-writer capacity=2 skills=[repo-user] capabilities=[] tools=[]
rules
  rule start
    when Work as work
    reads
      schema:Work
    effects
      effect1 kind=agent.tell binding=- key=ef8ed2edd19578a222b6ad56ea1bffa8
    body_hash 96e148d2d421ee97960ef8f3edf61db9
  rule finish
    when Result as result
    reads
      schema:Result
    writes
      schema:Work
    body_hash 4a5ce925842b5b0bceb64bf33361d523
rule_dependencies
  finish --schema:Work--> start
";

    assert_eq!(ir.to_snapshot(), expected);
}

#[test]
fn an_unknown_completed_payload_claims_no_fields() {
    // The `Completed` payload of an effect whose result shape is not statically
    // known must claim NOTHING. It used to claim `{summary, effect_id,
    // run_id}` — the terminal ENVELOPE's fields, which the runtime never puts
    // in the payload — and the IR snapshot saying so is what made
    // `examples/scheduled-escalation.whip` read `decided.summary` where it
    // wanted `answer.summary`.
    //
    // Nothing enforces a payload's field set, so this is an accuracy property
    // rather than a refusal: the test is here because an IR that states
    // something untrue about the runtime misleads every reader of it, and
    // nothing else would notice it changing back.
    let compiled = compile_program(
        r#"
@service
workflow OpaquePayload

use std.agent
use std.ingress

agent worker { provider fixture }
signal go.now { x string }

output result R
class R { v string }

rule r
  when go.now as g
=> {
  tell worker as answer "do it"
  after answer completes {
    case answer {
      Completed as done => { complete result { v "ok" } }
      Failed as f => { complete result { v "no" } }
      TimedOut as t => { complete result { v "t" } }
      Cancelled as c => { complete result { v "c" } }
    }
  }
}
"#,
    );
    assert_eq!(compiled.diagnostics, Vec::new());
    let snapshot = compiled.ir.expect("lowered IR").to_snapshot();

    assert!(
        snapshot.contains("Completed payload=object<{}>"),
        "an unknown Completed payload must claim no fields: {snapshot}"
    );
    // The failure tags keep theirs, because `terminal_payload_for_tag` really
    // does lift `summary`/`effect_id`/`run_id` into those payloads. Only the
    // `Completed` side was fiction, and a fix that flattened all four would be
    // trading one wrong claim for three.
    assert!(
        snapshot.contains(
            "Failed payload=object<{reason string, summary string, effect_id string, run_id string}>"
        ),
        "{snapshot}"
    );
    assert!(
        snapshot
            .contains("TimedOut payload=object<{summary string, effect_id string, run_id string}>"),
        "{snapshot}"
    );
}

#[test]
fn example_ir_snapshots_are_stable() {
    let examples = [
        (
            include_str!("../../../../examples/minimal-noop.whip"),
            include_str!("../../../../examples/minimal-noop.ir"),
        ),
        (
            include_str!("../../../../examples/queue-worker-with-review.whip"),
            include_str!("../../../../examples/queue-worker-with-review.ir"),
        ),
        (
            include_str!("../../../../examples/circuit-breaker.whip"),
            include_str!("../../../../examples/circuit-breaker.ir"),
        ),
        (
            include_str!("../../../../examples/coerce-branch.whip"),
            include_str!("../../../../examples/coerce-branch.ir"),
        ),
        (
            include_str!("../../../../examples/terminal-output-union.whip"),
            include_str!("../../../../examples/terminal-output-union.ir"),
        ),
        (
            include_str!("../../../../examples/triage-chain.whip"),
            include_str!("../../../../examples/triage-chain.ir"),
        ),
        (
            include_str!("../../../../examples/incident-router.whip"),
            include_str!("../../../../examples/incident-router.ir"),
        ),
        (
            include_str!("../../../../examples/expression-kernel.whip"),
            include_str!("../../../../examples/expression-kernel.ir"),
        ),
        (
            include_str!("../../../../examples/multi-agent-bounded-concurrency.whip"),
            include_str!("../../../../examples/multi-agent-bounded-concurrency.ir"),
        ),
        // `openclaw-lite` now imports the external `memory` package, so it
        // only compiles clean with a `whip.lock`; this parser-level snapshot
        // has no package resolution. Its IR stability is covered by the
        // lock-aware `dev_openclaw_lite_observes_heartbeat_and_files_work`.
        (
            include_str!("../../../../examples/scheduled-escalation.whip"),
            include_str!("../../../../examples/scheduled-escalation.ir"),
        ),
        (
            include_str!("../../../../examples/event-bridge.whip"),
            include_str!("../../../../examples/event-bridge.ir"),
        ),
        (
            include_str!("../../../../examples/reusable-review-pattern.whip"),
            include_str!("../../../../examples/reusable-review-pattern.ir"),
        ),
        (
            include_str!("../../../../examples/reusable-action-chain.whip"),
            include_str!("../../../../examples/reusable-action-chain.ir"),
        ),
        (
            include_str!("../../../../examples/exec-json-ingest.whip"),
            include_str!("../../../../examples/exec-json-ingest.ir"),
        ),
        (
            include_str!("../../../../examples/deterministic-validation.whip"),
            include_str!("../../../../examples/deterministic-validation.ir"),
        ),
        (
            include_str!("../../../../examples/autoresearch-lite.whip"),
            include_str!("../../../../examples/autoresearch-lite.ir"),
        ),
        (
            include_str!("../../../../examples/gastown-lite.whip"),
            include_str!("../../../../examples/gastown-lite.ir"),
        ),
        (
            include_str!("../../../../examples/ralph.whip"),
            include_str!("../../../../examples/ralph.ir"),
        ),
    ];

    for (source, expected) in examples {
        let compiled = compile_program(source);
        assert_eq!(compiled.diagnostics, Vec::new());
        let ir = match compiled.ir {
            Some(ir) => ir,
            None => panic!("expected lowered IR"),
        };
        assert_eq!(ir.to_snapshot(), expected);
    }
}

#[test]
fn revision_examples_compile() {
    let examples = [
        (
            include_str!("../../../../examples/revision-ticket-v1.whip"),
            Some("RevisionTicket"),
        ),
        (
            include_str!("../../../../examples/revision-ticket-v2.whip"),
            Some("RevisionTicket"),
        ),
        (
            include_str!("../../../../examples/revision-repair-planner.whip"),
            Some("RevisionRepairPlanner"),
        ),
        (
            include_str!("../../../../examples/revision-running-cancel.whip"),
            Some("RevisionRunningCancel"),
        ),
        (
            include_str!("../../../../examples/revision-parent-child.whip"),
            Some("ParentRevisionExample"),
        ),
        (
            include_str!("../../../../examples/revision-validation-approval.whip"),
            Some("RevisionValidation"),
        ),
    ];

    for (source, root) in examples {
        let compiled = compile_program_with_root(source, root);
        assert_eq!(compiled.diagnostics, Vec::new());
        assert!(compiled.ir.is_some());
    }
}

#[test]
fn rejects_unknown_schema_references() {
    let source = include_str!("../../../../examples/invalid/unknown-schema.whip");
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert_eq!(compiled.diagnostics.len(), 2);
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message == "unknown schema reference `MissingStatus`"));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message == "unknown schema reference `MissingOutput`"));
}

#[test]
fn emit_of_undeclared_signal_is_flagged_statically() {
    // Q1: `emit signal <name>` must name a declared signal, caught at
    // `whip check` time (previously only at runtime effect-input building).
    let source = "\
workflow Emitter
signal trigger.x { peer string }
signal known.sig { note string }
rule relay
  when trigger.x as t
=> {
  emit signal known.sig to t.peer { note \"ok\" } as a
  emit signal unknown.sig to t.peer { note \"bad\" } as b
}
";
    let compiled = compile_program(source);
    let messages: Vec<&str> = compiled
        .diagnostics
        .iter()
        .map(|d| d.message.as_str())
        .collect();
    assert!(
        messages.contains(&"rule `relay` emits undeclared signal `unknown.sig`"),
        "expected the undeclared-emit diagnostic, got {messages:?}"
    );
    // The declared emit (`known.sig`) is not flagged.
    assert!(
        !messages
            .iter()
            .any(|m| m.contains("emits undeclared signal `known.sig`")),
        "a declared signal must not be flagged: {messages:?}"
    );
}

#[test]
fn source_emit_of_undeclared_signal_is_flagged_statically() {
    // The ingestion mirror of the reaction-side check: a `source` whose
    // `emit <signal>` names an undeclared signal is caught at `whip check`
    // time, so it cannot silently admit a fact no rule can react to.
    let source = "\
workflow SourceEmit
signal ingress.known { text string }
source file as feed {
  path \"/tmp/x.txt\"
  observe as obs
  emit ingress.unknown { text obs.line }
}
output result Done
class Done { ok string }
rule react
  when ingress.known as k
=> {
  complete result { ok \"ok\" }
}
";
    let compiled = compile_program(source);
    let messages: Vec<&str> = compiled
        .diagnostics
        .iter()
        .map(|d| d.message.as_str())
        .collect();
    assert!(
        messages.contains(&"source `feed` emits undeclared signal `ingress.unknown`"),
        "expected the undeclared source-emit diagnostic, got {messages:?}"
    );
    // A source emitting a declared signal must not be flagged.
    let ok_source = source.replace("ingress.unknown", "ingress.known");
    let ok_compiled = compile_program(&ok_source);
    assert!(
        !ok_compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("emits undeclared signal")),
        "a declared signal must not be flagged: {:?}",
        ok_compiled
            .diagnostics
            .iter()
            .map(|d| d.message.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn source_emit_of_unknown_observation_field_is_flagged_statically() {
    // A source emit maps the observation record by name; reading a field the
    // source kind's observation doesn't have (here a `file` source has only
    // line/line_index/path) is caught at `whip check`, not silently mapped
    // null at runtime.
    let source = "\
workflow BadObs
signal ingress.fed { text string }
source file as feed {
  path \"/tmp/x.txt\"
  observe as obs
  emit ingress.fed { text obs.nosuchfield }
}
output result Done
class Done { ok string }
rule react
  when ingress.fed as f
=> { complete result { ok \"ok\" } }
";
    let messages: Vec<String> = compile_program(source)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages.iter().any(|m| m.contains(
            "emit reads `obs.nosuchfield`, but a `file` source's observation has no field"
        )),
        "expected the unknown-observation-field diagnostic, got {messages:?}"
    );
    // A valid observation field (`line`) must not be flagged.
    let ok = source.replace("obs.nosuchfield", "obs.line");
    assert!(
        !compile_program(&ok)
            .diagnostics
            .iter()
            .any(|d| d.message.contains("observation has no field")),
        "a valid observation field must not be flagged"
    );
}

#[test]
fn renew_of_unacquired_lease_is_flagged_statically() {
    // `renew <binding>` must name a lease acquired in the same rule; a typo
    // (here `nonexistent`, no matching acquire) is caught at `whip check`
    // rather than renewing nothing at runtime.
    let source = "\
workflow RenewTypo
class Ticket { id string }
class Done { ok string }
lease slot { shared key Ticket slots 1 ttl 60s }
output result Done
table seed as Ticket [ { id \"t\" } ]
rule grab
  when Ticket as t
=> {
  acquire slot for t.id until ttl as held
  after held held {
    renew nonexistent until 300s as r
    complete result { ok \"ok\" }
  }
}
";
    let messages: Vec<String> = compile_program(source)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("renews unbound coordination binding `nonexistent`")),
        "expected the unbound-renew diagnostic, got {messages:?}"
    );
    // Renewing the actually-acquired lease (`held`) must not be flagged.
    let ok = source.replace("renew nonexistent", "renew held");
    assert!(
        !compile_program(&ok)
            .diagnostics
            .iter()
            .any(|d| d.message.contains("renews unbound coordination binding")),
        "renewing an acquired lease must not be flagged"
    );
}

/// T3: a `renew <binding>` naming a same-rule `claim ... as <binding>` CLAIM
/// binding is accepted at `whip check` (it lowers to `tracker.renew`), and
/// the parser emits the `tracker.renew` effect kind for it.
#[test]
fn renew_of_a_claim_binding_is_accepted_and_lowers_to_tracker_renew() {
    let source = "\
workflow RenewClaim
class Done { ok string }
tracker backlog { provider builtin }
output result Done
rule work
  when backlog has ready issue as issue
=> {
  claim issue ttl 1h as active

  after active succeeds {
    renew active as renewed
  }

  after renewed succeeds {
    complete result { ok \"ok\" }
  }
}
";
    let compiled = compile_program(source);
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("renews unbound coordination binding")),
        "renewing a claim binding must not be flagged: {:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("compiles");
    let work = ir
        .rules
        .iter()
        .find(|rule| rule.name == "work")
        .expect("work rule");
    assert!(
        work.metadata
            .effects
            .iter()
            .any(|effect| effect.kind == IrEffectKind::TrackerRenew),
        "a renew of a claim binding lowers to TrackerRenew: {:?}",
        work.metadata.effects
    );
    // And the coord `LeaseRenew` kind was NOT emitted for it.
    assert!(
        !work
            .metadata
            .effects
            .iter()
            .any(|effect| effect.kind == IrEffectKind::LeaseRenew),
        "no lease.renew for a claim-binding renew: {:?}",
        work.metadata.effects
    );
}

#[test]
fn release_of_each_bound_coordination_form_is_accepted() {
    // A `release <x>` legitimately names ONE OF THREE referents
    // (spec/coordination.md): (1) an `acquire ... as <x>` lease binding,
    // (2) a `claim <x> as ...` item, or (3) a `when <queue> has ready ... as
    // <x>` work-item binding. All three must pass `whip check`; the naive
    // acquire∪claim-binding model false-positives (2) and (3).
    let source = "\
workflow ReleaseForms
class Ticket { id string }
class Done { ok string }
lease slot { key Ticket slots 1 ttl 60s }
tracker backlog { provider builtin }
agent worker { provider fixture profile \"repo-writer\" capacity 1 }
output result Done
rule work
  when backlog has ready issue as issue
  when worker is available
=> {
  acquire slot for issue.id until ttl as held
  claim issue as active_claim
  after active_claim succeeds {
    release held
    release issue
    complete result { ok \"done\" }
  }
  after active_claim fails {
    release held
    complete result { ok \"gave-up\" }
  }
}
";
    let messages: Vec<String> = compile_program(source)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        !messages
            .iter()
            .any(|m| m.contains("releases unbound coordination item")),
        "no bound release form must be flagged, got {messages:?}"
    );
}

#[test]
fn release_of_unbound_coordination_item_is_flagged_statically() {
    // `release <x>` where `<x>` matches none of the three legitimate
    // referents (no acquire binding, no claim item, no when-has-ready
    // work-item binding) is a genuinely-unbound release: caught at
    // `whip check` rather than releasing nothing at runtime.
    let source = "\
workflow ReleaseTypo
class Done { ok string }
tracker backlog { provider builtin }
agent worker { provider fixture profile \"repo-writer\" capacity 1 }
output result Done
rule work
  when backlog has ready issue as issue
  when worker is available
=> {
  claim issue as active_claim
  after active_claim succeeds {
    release nonexistent
    complete result { ok \"done\" }
  }
  after active_claim fails {
    complete result { ok \"gave-up\" }
  }
}
";
    let messages: Vec<String> = compile_program(source)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("releases unbound coordination item `nonexistent`")),
        "expected the unbound-release diagnostic, got {messages:?}"
    );
    // Releasing the actually-bound work item (`issue`) must not be flagged.
    let ok = source.replace("release nonexistent", "release issue");
    assert!(
        !compile_program(&ok)
            .diagnostics
            .iter()
            .any(|d| d.message.contains("releases unbound coordination item")),
        "releasing a bound work item must not be flagged"
    );
}

#[test]
fn http_source_url_must_have_an_http_scheme() {
    // The runtime GETs the url, so a scheme-less url is caught at check time.
    let source = "\
workflow BadUrl
signal ingress.fed { text string }
source http as feed {
  url \"not-a-real-url\"
  observe as obs
  emit ingress.fed { text obs.item }
}
output result Done
class Done { ok string }
rule react
  when ingress.fed as f
=> { complete result { ok \"ok\" } }
";
    let messages: Vec<String> = compile_program(source)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("is not an absolute http(s) URL")),
        "expected the http url-scheme diagnostic, got {messages:?}"
    );
    // A well-formed https url must not be flagged.
    let ok = source.replace("not-a-real-url", "https://example.com/feed.json");
    assert!(
        !compile_program(&ok)
            .diagnostics
            .iter()
            .any(|d| d.message.contains("absolute http(s) URL")),
        "a well-formed url must not be flagged"
    );
}

/// I2a `watch` clause (spec/std-ingress.md): a `file` source in occurrence
/// mode parses, lowers `watch` into the IR, formats idempotently, and the
/// watch-mode observation schema (`path`/`content_hash`/`watch`) governs
/// the emit-field check.
#[test]
fn file_watch_source_parses_lowers_and_formats() {
    let source = "\
workflow WatchSource
signal drop.arrived { path string digest string }
source file as drops {
  watch \"./drops/*.json\"
  observe as obs
  emit drop.arrived {
    path obs.path
    digest obs.content_hash
  }
}
output result Done
class Done { ok string }
rule react
  when drop.arrived as f
=> { complete result { ok \"ok\" } }
";
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("watch source compiles");
    let decl = ir.sources.first().expect("source lowered");
    assert!(decl.is_file);
    assert_eq!(decl.watch.as_deref(), Some("./drops/*.json"));
    assert_eq!(decl.path, None);
    let formatted = format_program(source).formatted.expect("formats");
    assert!(
        formatted.contains("watch \"./drops/*.json\""),
        "{formatted}"
    );
    assert_eq!(
        format_program(&formatted).formatted.expect("reformats"),
        formatted,
        "fmt must be idempotent over the watch clause"
    );
    // The watch-mode observation record has no `line`: reading it is the
    // unknown-observation-field diagnostic.
    let bad = source.replace("digest obs.content_hash", "digest obs.line");
    let messages: Vec<String> = compile_program(&bad)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("observation has no field `line`")),
        "watch-mode emit must validate against the occurrence schema, got {messages:?}"
    );
}

/// I2a closed clause sets (spec/std-ingress.md "Static checks" #3): `watch`
/// is file-only; `path`/`watch` are exclusive; a file source must declare
/// one of them.
#[test]
fn file_source_clause_set_is_closed() {
    let watch_on_clock = "\
workflow BadWatch
signal tick.fired { at time }
source clock as ticker {
  every 5m
  missed skip
  watch \"./drops/*.json\"
  observe as tick
  emit tick.fired { at tick.scheduled_at }
}
output result Done
class Done { ok string }
rule react
  when tick.fired as f
=> { complete result { ok \"ok\" } }
";
    let messages: Vec<String> = compile_program(watch_on_clock)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("`watch` clause but its provider is `clock`")),
        "watch outside `file` must be rejected, got {messages:?}"
    );

    let both_modes = "\
workflow BothModes
signal ingress.fed { text string }
source file as feed {
  path \"./inbox.txt\"
  watch \"./drops/*.txt\"
  observe as obs
  emit ingress.fed { text obs.path }
}
output result Done
class Done { ok string }
rule react
  when ingress.fed as f
=> { complete result { ok \"ok\" } }
";
    let messages: Vec<String> = compile_program(both_modes)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("declares both `path` and `watch`")),
        "path+watch must be rejected as exclusive modes, got {messages:?}"
    );

    let neither = "\
workflow Neither
signal ingress.fed { text string }
source file as feed {
  observe as obs
  emit ingress.fed { text obs.line }
}
output result Done
class Done { ok string }
rule react
  when ingress.fed as f
=> { complete result { ok \"ok\" } }
";
    let messages: Vec<String> = compile_program(neither)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("requires a `path` or `watch` clause")),
        "a file source with neither mode must be rejected, got {messages:?}"
    );
}

/// I2a `dedup` clause (spec/std-ingress.md): parses and lowers to
/// `dedup_field` for http/file(line) sources; rejected where no provider
/// delivery identity applies (clock, watch mode) and when the path does
/// not name a known observation field off the observe binding.
#[test]
fn dedup_clause_parses_lowers_and_validates() {
    let source = "\
workflow DedupSource
signal ingress.ingested { text string }
source http as feed {
  url \"https://example.com/feed.json\"
  dedup obs.item
  observe as obs
  emit ingress.ingested { text obs.item }
}
output result Done
class Done { ok string }
rule react
  when ingress.ingested as f
=> { complete result { ok \"ok\" } }
";
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("dedup source compiles");
    let decl = ir.sources.first().expect("source lowered");
    assert!(decl.is_http);
    assert_eq!(decl.dedup_field.as_deref(), Some("item"));
    let formatted = format_program(source).formatted.expect("formats");
    assert!(formatted.contains("dedup obs.item"), "{formatted}");
    assert_eq!(
        format_program(&formatted).formatted.expect("reformats"),
        formatted,
        "fmt must be idempotent over the dedup clause"
    );

    // Unknown observation field: the admission key would be silently null.
    let bad_field = source.replace("dedup obs.item", "dedup obs.delivery_id");
    let messages: Vec<String> = compile_program(&bad_field)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("observation has no field `delivery_id`")),
        "an unknown dedup field must be rejected, got {messages:?}"
    );

    // Wrong binding root: dedup reads the observation, nothing else.
    let bad_root = source.replace("dedup obs.item", "dedup other.item");
    let messages: Vec<String> = compile_program(&bad_root)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("`dedup` must name one observation field")),
        "a dedup path off a foreign binding must be rejected, got {messages:?}"
    );

    // No provider delivery identity on a clock source.
    let on_clock = "\
workflow DedupClock
signal tick.fired { at time }
source clock as ticker {
  every 5m
  missed skip
  dedup tick.occurrence_id
  observe as tick
  emit tick.fired { at tick.scheduled_at }
}
output result Done
class Done { ok string }
rule react
  when tick.fired as f
=> { complete result { ok \"ok\" } }
";
    let messages: Vec<String> = compile_program(on_clock)
        .diagnostics
        .iter()
        .map(|d| d.message.clone())
        .collect();
    assert!(
        messages
            .iter()
            .any(|m| m.contains("declares a `dedup` clause but its provider is `clock`")),
        "dedup on a clock source must be rejected, got {messages:?}"
    );
}

#[test]
fn enum_variants_are_one_per_line() {
    // Pasted prose / a forgotten `#` would otherwise become variants that
    // pollute the domain (and reach coerce output schemas).
    let garbage = compile_program(
            "workflow T\noutput result D\nclass D { a string }\nenum E {\n  A\n  utterly unknown line\n  B\n}\nrule r\n  when started\n=> {\n  complete result { a \"x\" }\n}\n",
        );
    assert!(garbage.diagnostics.iter().any(|d| d
        .message
        .contains("on the same line as the previous variant")));
    // Payload-carrying variants (sum types) are untouched.
    let payload = compile_program(
            "workflow T\noutput result D\nclass D { a string }\nenum E {\n  Approved {\n    score float\n  }\n  Rejected {\n    reason string\n  }\n}\nrule r\n  when started\n=> {\n  complete result { a \"x\" }\n}\n",
        );
    assert!(
        !payload
            .diagnostics
            .iter()
            .any(|d| d.message.contains("same line")),
        "{:?}",
        payload.diagnostics
    );
}

#[test]
fn unknown_std_package_import_is_a_check_error() {
    // std resolution is a built-in registry: a typo'd name can never
    // resolve, so it must not silently import nothing.
    let typo = compile_program(
            "use std.coercon\nworkflow T\noutput result D\nclass D { a string }\nrule r\n  when started\n=> {\n  complete result { a \"x\" }\n}\n",
        );
    assert!(typo
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unknown standard package `std.coercon`")));
    // Every real std package name passes.
    for id in STD_PACKAGE_IDS {
        let ok = compile_program(&format!(
                "use {id}\nworkflow T\noutput result D\nclass D {{ a string }}\nrule r\n  when started\n=> {{\n  complete result {{ a \"x\" }}\n}}\n"
            ));
        assert!(
            !ok.diagnostics
                .iter()
                .any(|d| d.message.contains("unknown standard package")),
            "{id}: {:?}",
            ok.diagnostics
        );
    }
    // Non-std package names stay lock-resolved, not registry-checked.
    let nonstd = compile_program(
            "use notes\nworkflow T\noutput result D\nclass D { a string }\nrule r\n  when started\n=> {\n  complete result { a \"x\" }\n}\n",
        );
    assert!(!nonstd
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unknown standard package")));
}

#[test]
fn blockless_coerce_desugars_to_the_prompt_clause() {
    let block = compile_program(
            "use std.coercion\nworkflow T\noutput result D\nclass D { a string }\nclass V { a string }\ncoerce f(x string) -> V {\n  prompt \"\"\"markdown\n  Judge {{ x }}. {{ ctx.output_format }}\n  \"\"\"\n}\nrule r\n  when started\n=> {\n  coerce f(\"t\") as v\n  after v succeeds as o {\n    complete result { a o.a }\n  }\n}\n",
        );
    let blockless = compile_program(
            "use std.coercion\nworkflow T\noutput result D\nclass D { a string }\nclass V { a string }\ncoerce f(x string) -> V \"\"\"markdown\nJudge {{ x }}. {{ ctx.output_format }}\n\"\"\"\nrule r\n  when started\n=> {\n  coerce f(\"t\") as v\n  after v succeeds as o {\n    complete result { a o.a }\n  }\n}\n",
        );
    let block_ir = block.ir.expect("block form compiles");
    let blockless_ir = blockless.ir.expect("blockless form compiles");
    // Same declaration, same clause: the sugar prefixes `prompt ` onto the
    // raw string, so the body is the block form's sole clause.
    assert!(blockless_ir.coerces[0].body.starts_with("prompt \"\"\""));
    assert_eq!(block_ir.coerces[0].name, blockless_ir.coerces[0].name);
}

#[test]
fn coerce_body_is_a_validated_clause_list() {
    let source = |body: &str| {
        format!(
                "use std.coercion\nworkflow T\noutput result D\nclass D {{ a string }}\nclass V {{ a string }}\ncoerce f(x string) -> V {{\n{body}\n}}\nrule r\n  when started\n=> {{\n  coerce f(\"t\") as v\n  after v succeeds as o {{\n    complete result {{ a o.a }}\n  }}\n}}\n"
            )
    };
    // A typo'd `promt` — previously a SILENT no-prompt coercion — errors.
    let typo = compile_program(&source("  promt \"Judge {{ x }}\""));
    assert!(typo
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unknown coerce field `promt`")));
    // Unknown fields error.
    let junk = compile_program(&source("  prompt \"Judge {{ x }}\"\n  mystery field"));
    assert!(junk
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unknown coerce field `mystery`")));
    // The legal clauses pass: prompt (multi-line, annotated) + provider,
    // with comments and blank lines interleaved.
    let legal = compile_program(&source(
            "  # choose the fixture\n  provider fixture\n\n  prompt \"\"\"markdown\n  Judge {{ x }}.\n  {{ ctx.output_format }}\n  \"\"\"",
        ));
    assert!(
        !legal
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown coerce field")),
        "{:?}",
        legal.diagnostics
    );
    // A malformed provider clause errors.
    let malformed = compile_program(&source("  provider one two\n  prompt \"Judge {{ x }}\""));
    assert!(malformed
        .diagnostics
        .iter()
        .any(|d| d.message.contains("malformed `provider` clause")));
}

#[test]
fn rejects_invalid_agent_declarations() {
    let source = include_str!("../../../../examples/invalid/bad-agent.whip");
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert_eq!(compiled.diagnostics.len(), 3);
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("capacity must be greater than zero")));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("more than once")));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("unknown agent field")));
    // A missing profile is no longer a diagnostic: it defaults to the
    // least-authority `no-repo` (agent-declaration defaults, 2026-07-21).
    assert!(!compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("missing a profile")));
}

#[test]
fn rejects_invalid_effect_dependencies() {
    let source = include_str!("../../../../examples/invalid/bad-effect-graph.whip");
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("unknown effect binding")));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("unsupported `after`")));
}

#[test]
fn accepts_equality_guards_in_when_clauses() {
    let source = r#"
workflow GuardGuess

class WorkItem {
  state "ready" | "blocked"
}

rule branch
  when WorkItem as item where item.state == "ready"
=> {
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("valid ir");
    let when = ir
        .rules
        .iter()
        .flat_map(|rule| &rule.whens)
        .find(|when| when.source == "WorkItem as item where item.state == \"ready\"")
        .expect("guarded when");
    assert_eq!(when.pattern, "WorkItem as item");
    assert_eq!(
        when.guard.as_ref().map(|guard| guard.expr.to_snapshot()),
        Some("item.state == \"ready\"".to_owned())
    );
}

#[test]
fn lowers_assertions_to_parsed_expression_ir() {
    let source = r#"
workflow AssertionGuess

class Result {
  status "done"
}

assert count(Result where status == "done") == 1
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("valid ir");
    let assertion = ir.assertions.first().expect("assertion");
    assert_eq!(
        assertion.expr.source,
        "count(Result where status == \"done\") == 1"
    );
    assert_eq!(
        assertion.expr.expr.to_snapshot(),
        "count(Result where status == \"done\") == 1"
    );
    assert_eq!(
        assertion
            .projection_reads
            .iter()
            .map(IrProjectionRead::to_snapshot)
            .collect::<Vec<_>>(),
        vec!["fact:Result where status == \"done\""]
    );
}

#[test]
fn lowers_guard_projection_reads_to_rule_metadata() {
    let source = r#"
workflow GuardProjection

class Task {
  status "ready"
}

class Result {
  status "done"
}

rule gated
  when Task as task where exists(Result where status == "done")
=> {
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("valid ir");
    let rule = ir.rules.first().expect("rule");
    assert_eq!(
        rule.metadata
            .projection_reads
            .iter()
            .map(IrProjectionRead::to_snapshot)
            .collect::<Vec<_>>(),
        vec!["fact:Result where status == \"done\""]
    );
}

fn read_codec_program(format: &str) -> String {
    format!(
        r#"
workflow ReadBody

output result Result

class Result {{
  status string
}}

file store project_files {{
  root "./data"
}}

rule pick
  when started
=> {{
  read {format} from project_files at "note.md" as fileResult
  after fileResult succeeds as result {{
    complete result {{
      status "ok"
    }}
  }}
}}
"#
    )
}

#[test]
fn read_accepts_text_and_markdown_body_codecs() {
    for format in ["text", "markdown"] {
        let compiled = compile_program(&read_codec_program(format));
        assert_eq!(
            compiled.diagnostics,
            Vec::new(),
            "`read {format}` compiles clean"
        );
        assert!(compiled.ir.is_some(), "`read {format}` produces IR");
    }
}

#[test]
fn read_rejects_structured_and_binary_codecs() {
    // Structured codecs are the `import` surface; `bytes` is a deferred read
    // codec. `read` decodes only body formats in v0.
    for format in ["json", "jsonl", "csv", "bytes"] {
        let compiled = compile_program(&read_codec_program(format));
        assert!(
            compiled
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("not supported")),
            "`read {format}` is rejected with a diagnostic; got {:?}",
            compiled.diagnostics
        );
    }
}

fn write_program(format: &str, mode_clause: &str) -> String {
    format!(
        r#"
workflow WriteBody

output result Result

class Result {{
  status string
}}

file store out_files {{
  root "./data"
  allow write ["**"]
}}

rule pick
  when started
=> {{
  write {format} to out_files at "report.md" {{
    body "hello"
    {mode_clause}
  }} as written
  after written succeeds as result {{
    complete result {{
      status "ok"
    }}
  }}
}}
"#
    )
}

#[test]
fn write_accepts_text_and_markdown_with_explicit_mode() {
    for format in ["text", "markdown"] {
        let compiled = compile_program(&write_program(format, "mode create"));
        assert_eq!(
            compiled.diagnostics,
            Vec::new(),
            "`write {format}` with an explicit mode compiles clean"
        );
        assert!(compiled.ir.is_some(), "`write {format}` produces IR");
    }
}

#[test]
fn write_rejects_structured_codecs() {
    for format in ["json", "csv", "bytes"] {
        let compiled = compile_program(&write_program(format, "mode create"));
        assert!(
            compiled
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("not supported")),
            "`write {format}` is rejected; got {:?}",
            compiled.diagnostics
        );
    }
}

#[test]
fn write_requires_an_explicit_mode() {
    // "No silent overwrite": omitting the mode is a check error.
    let compiled = compile_program(&write_program("text", ""));
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("explicit `mode`")),
        "`write` without a mode is rejected; got {:?}",
        compiled.diagnostics
    );
}

#[test]
fn write_rejects_unknown_mode() {
    let compiled = compile_program(&write_program("text", "mode clobber"));
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("unknown write mode")),
        "an unknown write mode is rejected; got {:?}",
        compiled.diagnostics
    );
}

fn import_program(format: &str) -> String {
    format!(
        r#"
workflow ImportRows

output result Result

class Result {{
  status string
}}

class IssueRow {{
  title string
  priority string
}}

file store data_files {{
  root "./data"
}}

rule pick
  when started
=> {{
  import {format} IssueRow from data_files at "issues.in" as imported
  after imported succeeds as r {{
    complete result {{
      status "ok"
    }}
  }}
}}
"#
    )
}

#[test]
fn import_accepts_structured_codecs_and_lowers_to_file_import() {
    for format in ["jsonl", "json", "csv"] {
        let compiled = compile_program(&import_program(format));
        assert_eq!(
            compiled.diagnostics,
            Vec::new(),
            "`import {format}` compiles clean"
        );
        let ir = compiled.ir.expect("import produces IR");
        let rule = ir.rules.first().expect("rule");
        assert!(
            rule.metadata
                .effects
                .iter()
                .any(|effect| effect.kind == IrEffectKind::FileImport),
            "`import {format}` lowers to a file.import effect"
        );
    }
}

#[test]
fn import_rejects_unsupported_codecs() {
    // `import` decodes structured row codecs only; body/binary formats are
    // not import surfaces.
    for format in ["xml", "text", "markdown", "bytes"] {
        let compiled = compile_program(&import_program(format));
        assert!(
            compiled
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("not supported")),
            "`import {format}` is rejected; got {:?}",
            compiled.diagnostics
        );
    }
}

#[test]
fn class_field_key_annotation_lowers_and_rejects_duplicates() {
    let single = compile_program(
        r#"
workflow Keyed

class Row {
  id string @key
  title string
}
"#,
    );
    assert_eq!(
        single.diagnostics,
        Vec::new(),
        "single `@key` compiles clean"
    );
    let ir = single.ir.expect("ir");
    let class = ir
        .schemas
        .iter()
        .find_map(|schema| match schema {
            IrSchema::Class(class) if class.name == "Row" => Some(class),
            _ => None,
        })
        .expect("Row class");
    let key_fields = class
        .fields
        .iter()
        .filter(|field| field.is_key)
        .map(|field| field.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(key_fields, vec!["id"], "the `@key` field is recorded");

    let dual = compile_program(
        r#"
workflow Keyed

class Row {
  a string @key
  b string @key
}
"#,
    );
    assert!(
        dual.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("more than one `@key`")),
        "two `@key` fields are rejected; got {:?}",
        dual.diagnostics
    );
}

#[test]
fn single_line_terminal_block_validates_its_fields() {
    // Regression: `complete <name> { <field> }` on one line was reported as
    // missing the field, because the terminal-block extractor only captured
    // subsequent lines (a single-line block has brace-delta 0). Both the
    // single-line and multi-line forms must validate identically.
    for body in [
        "  complete result { status \"ok\" }",
        "  complete result {\n    status \"ok\"\n  }",
    ] {
        let source = format!(
            r#"
workflow S

output result Result

class Result {{
  status string
}}

rule go
  when started
=> {{
{body}
}}
"#
        );
        let compiled = compile_program(&source);
        assert!(
            !compiled
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("missing required field")),
            "terminal block validates its field; got {:?}",
            compiled.diagnostics
        );
    }
}

#[test]
fn action_declaration_parses_and_is_inert_until_expansion() {
    // DR-0023 slice 1: an `action` template parses (typed params + a block
    // body) and lowers away cleanly (inert until call-site expansion in
    // slice 2), so a program declaring an unused action compiles with no
    // diagnostics.
    let compiled = compile_program(
        r#"
workflow A

output result Result

class Result {
  status string
}

class Task {
  name string
}

action do_it(task Task, label string) {
  record Result {
    status label
  }
}

rule go
  when started
=> {
  complete result {
    status "ok"
  }
}
"#,
    );
    assert_eq!(
        compiled.diagnostics,
        Vec::new(),
        "an unused action declaration compiles clean"
    );
    let ir = compiled.ir.expect("program with an action lowers");
    // The action is a template consumed before lowering — it is not a runtime
    // construct, so it leaves no rule/schema behind beyond the workflow's own.
    assert!(
        ir.rules.iter().any(|rule| rule.name == "go"),
        "the ordinary rule still lowers alongside the action template"
    );
}

#[test]
fn accepts_typed_case_branches_in_rule_bodies() {
    let source = r#"
workflow CaseGuess

enum ReviewStatus {
  Accept
  Revise
  Blocked
}

class Review {
  status ReviewStatus
  assignee string?
}

class Routed {
  status ReviewStatus
}

rule route
  when Review as review
=> {
  case review.status {
    Accept => {
      record Routed {
        status Accept
      }
    }
    Revise => {
      record Routed {
        status Revise
      }
    }
    Blocked => {
      record Routed {
        status Blocked
      }
    }
  }

  case review.assignee {
    Some owner => {
      record Routed {
        status Accept
      }
    }
    None => {
      record Routed {
        status Blocked
      }
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn accepts_terminal_output_case_branches_inside_completes_after() {
    let source = r#"
workflow TerminalCaseGuess

class WorkItem {
  title string
}

class MessageClassification {
  summary string
}

class Routed {
  branch string
  detail string
}

coerce classifyMessage(title string) -> MessageClassification {
  prompt "Classify"
}

rule classify
  when WorkItem as item
=> {
  coerce classifyMessage(item.title) as classification

  after classification completes {
    case classification {
      Completed as result => {
        record Routed {
          branch "completed"
          detail result.summary
        }
      }
      Failed as failure => {
        record Routed {
          branch "failed"
          detail failure.reason
        }
      }
      TimedOut as timeout => {
        record Routed {
          branch "timed_out"
          detail timeout.summary
        }
      }
      Cancelled as cancel => {
        record Routed {
          branch "cancelled"
          detail cancel.summary
        }
      }
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn accepts_terminal_output_case_as_binding_form() {
    // `Completed as result` is accepted alongside the space form `Completed result`
    // and binds/narrows identically (Stage 1b surface unification).
    let source = r#"
workflow T

class WorkItem { title string }
class MessageClassification { summary string }
class Routed {
  branch string
  detail string
}

coerce classifyMessage(title string) -> MessageClassification {
  prompt "Classify"
}

rule classify
  when WorkItem as item
=> {
  coerce classifyMessage(item.title) as classification

  after classification completes {
    case classification {
      Completed as result => {
        record Routed { branch "completed" detail result.summary }
      }
      Failed as failure => {
        record Routed { branch "failed" detail failure.reason }
      }
      TimedOut as timeout => {
        record Routed { branch "timed_out" detail timeout.summary }
      }
      Cancelled as cancel => {
        record Routed { branch "cancelled" detail cancel.summary }
      }
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn accepts_after_times_out_branch_and_types_payload_alias() {
    let source = r#"
workflow TimedOutBranch

class WorkItem {
  title string
}

class MessageClassification {
  summary string
}

class Routed {
  branch string
  detail string
}

coerce classifyMessage(title string) -> MessageClassification {
  prompt "Classify"
}

rule classify
  when WorkItem as item
=> {
  coerce classifyMessage(item.title) as classification

  after classification times out as t {
    record Routed {
      branch "timed_out"
      detail t.summary
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn accepts_after_cancelled_branch_and_types_payload_alias() {
    let source = r#"
workflow CancelledBranch

class WorkItem {
  title string
}

class MessageClassification {
  summary string
}

class Routed {
  branch string
  detail string
}

coerce classifyMessage(title string) -> MessageClassification {
  prompt "Classify"
}

rule classify
  when WorkItem as item
=> {
  coerce classifyMessage(item.title) as classification

  after classification cancelled as c {
    record Routed {
      branch "cancelled"
      detail c.summary
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn rejects_invalid_after_predicate_during_compilation() {
    let source = r#"
workflow BadPredicate

class WorkItem {
  title string
}

class MessageClassification {
  summary string
}

class Routed {
  branch string
}

coerce classifyMessage(title string) -> MessageClassification {
  prompt "Classify"
}

rule classify
  when WorkItem as item
=> {
  coerce classifyMessage(item.title) as classification

  after classification explodes {
    record Routed {
      branch "boom"
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.diagnostics.iter().any(|d| d
        .message
        .contains("unsupported `after` predicate `explodes`")));
}

#[test]
fn lowers_terminal_output_case_branches_to_typed_ir() {
    let source = include_str!("../../../../examples/terminal-output-union.whip");
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("expected lowered IR");
    let rule = ir
        .rules
        .iter()
        .find(|rule| rule.name == "classify_work")
        .expect("rule");

    let terminal_output = rule
        .metadata
        .terminal_outputs
        .iter()
        .find(|output| output.binding == "classification")
        .expect("terminal output");
    assert_eq!(terminal_output.alternatives.len(), 4);
    assert_eq!(
        terminal_output.alternatives[0].payload_type,
        IrType::Ref("Classification".to_owned())
    );
    assert_eq!(
        rule.metadata
            .terminal_branches
            .iter()
            .map(|branch| {
                (
                    branch.tag.as_deref().unwrap_or("_"),
                    branch.binding.as_deref().unwrap_or("-"),
                )
            })
            .collect::<Vec<_>>(),
        vec![
            ("Completed", "result"),
            ("Failed", "failure"),
            ("TimedOut", "timeout"),
            ("Cancelled", "cancel"),
        ]
    );
}

#[test]
fn rejects_terminal_payload_fields_outside_refined_tag_schema() {
    let source = r#"
workflow BadTerminalPayload

class WorkItem {
  title string
}

class Classification {
  summary string
}

class TerminalRoute {
  detail string
}

coerce classify(title string) -> Classification {
  prompt "Classify"
}

rule classify_work
  when WorkItem as item
=> {
  coerce classify(item.title) as classification

  after classification completes {
    case classification {
      Completed as result => {
        record TerminalRoute {
          detail result.reason
        }
      }
      Failed as failure => {
        record TerminalRoute {
          detail failure.reason
        }
      }
      TimedOut as timeout => {
        record TerminalRoute {
          detail timeout.summary
        }
      }
      Cancelled as cancel => {
        record TerminalRoute {
          detail cancel.summary
        }
      }
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("invalid field path `result.reason`")));
}

#[test]
fn rejects_invalid_terminal_output_case_branches() {
    let source = r#"
workflow BadTerminalCaseGuess

class WorkItem {
  title string
}

class MessageClassification {
  summary string
}

coerce classifyMessage(title string) -> MessageClassification {
  prompt "Classify"
}

rule classify
  when WorkItem as item
=> {
  coerce classifyMessage(item.title) as classification

  after classification completes {
    case classification {
      Success as result => {
      }
      Completed as result => {
      }
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("terminal-output case pattern cannot be `Success`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("non-exhaustive terminal-output case; missing Failed, TimedOut, Cancelled")));
}

/// Source for terminal-output case tests: a coerce whose `Completed` payload
/// is `MessageClassification`, matched in an `after ... completes` case. The
/// `{cases}` placeholder is filled per test.
fn terminal_case_program(cases: &str) -> String {
    format!(
        r#"
workflow TerminalCaseMatrix

class WorkItem {{
  title string
}}

class MessageClassification {{
  summary string
}}

class Routed {{
  branch string
}}

coerce classifyMessage(title string) -> MessageClassification {{
  prompt "Classify"
}}

rule classify
  when WorkItem as item
=> {{
  coerce classifyMessage(item.title) as classification

  after classification completes {{
    case classification {{
{cases}
    }}
  }}
}}
"#
    )
}

#[test]
fn accepts_guarded_terminal_case_branch_referencing_refined_payload() {
    // Regression: a `where` guard on a tagged terminal branch must be able to
    // read the tag-refined payload binding (`result.summary`). It was wrongly
    // rejected as an unknown root because `validate_case_blocks` could not
    // bind the terminal payload into the guard scope.
    let source = terminal_case_program(
            "      Completed as result where result.summary == \"ok\" => { record Routed { branch \"ok\" } }\n      _ => { record Routed { branch \"other\" } }",
        );
    let compiled = compile_program(&source);
    assert_eq!(
        compiled.diagnostics,
        Vec::new(),
        "{:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some());
}

#[test]
fn rejects_terminal_case_guard_referencing_unknown_payload_field() {
    let source = terminal_case_program(
            "      Completed as result where result.nonexistent == \"ok\" => { record Routed { branch \"ok\" } }\n      _ => { record Routed { branch \"other\" } }",
        );
    let compiled = compile_program(&source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("schema `MessageClassification` has no field `nonexistent`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_non_boolean_terminal_case_guard() {
    let source = terminal_case_program(
            "      Completed as result where result.summary => { record Routed { branch \"ok\" } }\n      _ => { record Routed { branch \"other\" } }",
        );
    let compiled = compile_program(&source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("non-boolean case guard expression")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_duplicate_terminal_output_case_tag() {
    let source = terminal_case_program(
            "      Completed as result => { record Routed { branch \"a\" } }\n      Completed as other => { record Routed { branch \"b\" } }\n      Failed as failure => { record Routed { branch \"f\" } }\n      TimedOut as timeout => { record Routed { branch \"t\" } }\n      Cancelled as cancel => { record Routed { branch \"c\" } }",
        );
    let compiled = compile_program(&source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("duplicate unguarded terminal-output case pattern `Completed`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_terminal_output_case_branch_without_payload_binding() {
    let source = terminal_case_program(
            "      Completed => { record Routed { branch \"a\" } }\n      Failed as failure => { record Routed { branch \"f\" } }\n      TimedOut as timeout => { record Routed { branch \"t\" } }\n      Cancelled as cancel => { record Routed { branch \"c\" } }",
        );
    let compiled = compile_program(&source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("malformed terminal-output case pattern `Completed`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_invalid_case_branch_patterns() {
    let source = r#"
workflow BadCaseGuess

enum ReviewStatus {
  Accept
  Revise
}

class Review {
  status ReviewStatus
  assignee string
}

rule route
  when Review as review
=> {
  case review.status {
    Missing => {
    }
  }

  case review.assignee {
    Some owner => {
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    let missing = compiled
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("enum `ReviewStatus` has no variant `Missing`")
        })
        .expect("missing variant diagnostic");
    assert!(source[missing.span.start..missing.span.end].contains("Mis"));
    let some = compiled
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic
                .message
                .contains("uses `Some` for a non-optional case")
        })
        .expect("some diagnostic");
    assert!(source[some.span.start..some.span.end].contains("Some"));
}

#[test]
fn diagnoses_non_exhaustive_and_duplicate_case_branches() {
    let source = r#"
workflow CaseCoverageGuess

enum ReviewStatus {
  Accept
  Revise
  Blocked
}

class Review {
  status ReviewStatus
  provider "codex" | "claude"
  owner string?
}

rule route
  when Review as review
=> {
  case review.status {
    Accept => {
    }
    Accept => {
    }
    Revise => {
    }
  }

  case review.provider {
    "codex" => {
    }
  }

  case review.owner {
    Some owner => {
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("duplicate unguarded case pattern `Accept`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("non-exhaustive case; missing Blocked")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("non-exhaustive case; missing claude")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("non-exhaustive case; missing None")));
}

#[test]
fn accepts_fallback_and_guarded_duplicate_case_branches() {
    let source = r#"
workflow CaseFallbackGuess

enum ReviewStatus {
  Accept
  Revise
  Blocked
}

class Review {
  status ReviewStatus
  owner string?
}

rule route
  when Review as review
=> {
  case review.status {
    Accept where review.owner != null => {
    }
    Accept where review.owner == null => {
    }
    _ => {
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn rejects_unreachable_case_branch_after_wildcard() {
    // A branch placed after an unguarded `_` can never match (case-family.maude
    // inv c, redundant-postwild).
    let source = r#"
workflow CaseUnreachableGuess

enum ReviewStatus {
  Accept
  Revise
  Blocked
}

class Review {
  status ReviewStatus
}

rule route
  when Review as review
=> {
  case review.status {
    Accept => {
    }
    _ => {
    }
    Revise => {
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("unreachable case branch after the `_` wildcard")),
        "expected unreachable-after-wildcard diagnostic: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn family_b_presence_condition_validates_discriminant() {
    let program = |fields: &str| {
        format!(
            r#"
workflow B
input e Event
output result Done
class Done {{ ok bool }}
class Event {{
{fields}
}}
rule r
  when Event as e
=> {{
  complete result {{ ok true }}
}}
"#
        )
    };
    // Valid: a literal-union discriminant with an in-range `when` literal.
    let ok = compile_program(&program(
        "  kind \"deploy\" | \"rollback\"\n  region string when kind is \"deploy\"",
    ));
    assert_eq!(ok.diagnostics, Vec::new());
    assert!(ok.ir.is_some());
    // Unknown discriminant.
    let bad1 = compile_program(&program(
        "  kind \"deploy\" | \"rollback\"\n  region string when missing is \"deploy\"",
    ));
    assert!(bad1
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unknown discriminant `missing`")));
    // Literal not in the discriminant union.
    let bad2 = compile_program(&program(
        "  kind \"deploy\" | \"rollback\"\n  region string when kind is \"ship\"",
    ));
    assert!(bad2
        .diagnostics
        .iter()
        .any(|d| d.message.contains("not a value of `kind`")));
    // Discriminant is not a string-literal union.
    let bad3 = compile_program(&program(
        "  kind string\n  region string when kind is \"deploy\"",
    ));
    assert!(bad3
        .diagnostics
        .iter()
        .any(|d| d.message.contains("not a string-literal discriminant")));
}

#[test]
fn case_arm_effect_records_its_selector() {
    // An effect inside a `case <scrutinee> { <pattern> => … }` arm records the
    // selector `(scrutinee, pattern)` so the IFC checker can apply
    // NMIF-on-the-selector to a crossing (DR §7.4).
    let source = r#"
workflow S

input item WorkItem
output result R
class WorkItem { kind "a" | "b" }
class R { ok bool }
class V { ok bool }

coerce f(t string) -> V { prompt "x" }

rule r
  when WorkItem as item
=> {
  case item.kind {
    "a" => {
      coerce f("hi") as v
      after v succeeds {
        complete result { ok v.ok }
      }
    }
    "b" => {
      complete result { ok false }
    }
  }
}
"#;
    let ir = compile_program(source).ir.expect("compiles");
    let rule = ir.rules.iter().find(|r| r.name == "r").expect("rule r");
    let coerce = rule
        .metadata
        .effects
        .iter()
        .find(|e| e.binding.as_deref() == Some("v"))
        .expect("coerce effect v");
    let (scrutinee, pattern) = coerce
        .selected_by
        .as_ref()
        .expect("coerce in a case arm records its selector");
    assert_eq!(scrutinee, "item.kind");
    assert_eq!(pattern, "\"a\"");
    // An effect outside any case (the `complete` is in an arm, but there are no
    // top-level effects here) — sanity: a fresh top-level coerce has no selector.
    // (Covered by every other example whose effects are top-level: selected_by None.)
}

#[test]
fn family_b_read_narrowing_restricts_conditioned_reads() {
    let program = |body: &str| {
        format!(
            r#"
workflow B
input e Event
output result Done
class Done {{ region string }}
class Event {{
  kind "deploy" | "rollback"
  region string when kind is "deploy"
}}
rule r
  when Event as e
=> {{
{body}
}}
"#
        )
    };
    // Outside any case arm: a conditioned read is rejected.
    let outside = compile_program(&program("  complete result { region e.region }"));
    assert!(
        outside
            .diagnostics
            .iter()
            .any(|d| d.message.contains("conditional field `e.region`")),
        "{:?}",
        outside.diagnostics
    );
    // Inside the matching `deploy` arm: allowed.
    let matching = compile_program(&program(
            "  case e.kind {\n    \"deploy\" => { complete result { region e.region } }\n    \"rollback\" => { complete result { region \"none\" } }\n  }",
        ));
    assert_eq!(matching.diagnostics, Vec::new());
    assert!(matching.ir.is_some());
    // Inside the wrong (`rollback`) arm: rejected (region is a deploy-only field).
    let wrong = compile_program(&program(
            "  case e.kind {\n    \"deploy\" => { complete result { region \"x\" } }\n    \"rollback\" => { complete result { region e.region } }\n  }",
        ));
    assert!(
        wrong
            .diagnostics
            .iter()
            .any(|d| d.message.contains("conditional field `e.region`")),
        "{:?}",
        wrong.diagnostics
    );
}

#[test]
fn family_b_read_narrowing_covers_effect_operands() {
    // An effect operand carries the field's value out of the rule just as a
    // terminal payload does, so a presence-conditioned read narrows there too.
    // One case per operand SHAPE: free text (interpolations only), expression,
    // and field block.
    let program = |decls: &str, body: &str| {
        format!(
            r#"
workflow B
input e Event
output result Done
class Done {{ region string }}
class Event {{
  kind "deploy" | "rollback"
  region string when kind is "deploy"
}}
{decls}
rule r
  when Event as e
=> {{
{body}
  complete result {{ region "ok" }}
}}
"#
        )
    };
    let agent = r#"
agent worker {
  provider owned
  profile "repo-writer"
  capacity 1
}
"#;
    let coerce = r#"
coerce classify(text string) -> Done { prompt "x" }
"#;
    let ledger = r#"
class Row { region string }
ledger audit {
  entry Row
  partition by region
  retain 30d
}
"#;
    let lease = r#"
lease deploys {
  key string
  slots 1
  ttl 30m
}
"#;
    let rejects = |compiled: &CompileOutput, what: &str| {
        assert!(
            compiled
                .diagnostics
                .iter()
                .any(|d| d.message.contains("conditional field `e.region`")),
            "{what}: {:?}",
            compiled.diagnostics
        );
    };
    // FREE TEXT — a prompt reads only through its `{{ … }}` interpolations.
    rejects(
        &compile_program(&program(
            agent,
            "  tell worker \"ship to {{ e.region }}\" as t",
        )),
        "tell prompt",
    );
    // …and prose is not source: a bare `e.region` outside the braces is English,
    // and narrowing it would make the check unusable on ordinary prompts.
    let prose = compile_program(&program(
        agent,
        "  tell worker \"describe e.region for the operator\" as t",
    ));
    assert_eq!(prose.diagnostics, Vec::new());
    assert!(prose.ir.is_some());
    // …the same rule for an `exec` command line.
    rejects(
        &compile_program(&program("", "  exec \"deploy {{ e.region }}\" as x")),
        "exec command",
    );
    // EXPRESSION — a coerce argument and a coordination key.
    rejects(
        &compile_program(&program(coerce, "  coerce classify(e.region) as c")),
        "coerce argument",
    );
    rejects(
        &compile_program(&program(lease, "  acquire deploys for e.region as slot")),
        "lease key",
    );
    // FIELD BLOCK — a ledger row narrows through the shared field walk.
    rejects(
        &compile_program(&program(
            ledger,
            "  append Row {\n    region e.region\n  } to audit as row",
        )),
        "ledger row",
    );
    // Inside the matching arm every one of these operands is allowed.
    let matching = compile_program(&program(
            coerce,
            "  case e.kind {\n    \"deploy\" => {\n      coerce classify(e.region) as c\n      exec \"deploy {{ e.region }}\" as x\n    }\n    \"rollback\" => { }\n  }",
        ));
    assert_eq!(matching.diagnostics, Vec::new());
    assert!(matching.ir.is_some());
}

#[test]
fn family_b_read_narrowing_covers_from_copies() {
    // A `from <binding>` projection COPIES the source's same-named fields, so a
    // presence-conditioned one is read there just as surely as in a written
    // `<binding>.<field>` expression — whether the copy is spelled as a bare
    // shorthand field or left implicit (the block only overrides).
    let program = |body: &str| {
        format!(
            r#"
workflow B
input e Event
output result Done
class Done {{ region string }}
class Copy {{
  kind string
  region string
}}
class Event {{
  kind "deploy" | "rollback"
  region string when kind is "deploy"
}}
rule r
  when Event as e
=> {{
{body}
  complete result {{ region "ok" }}
}}
"#
        )
    };
    // `record <Class> from <binding>` — the shorthand copy is a read.
    let shorthand = compile_program(&program("  record Copy from e {\n    region\n  }"));
    assert!(
        shorthand
            .diagnostics
            .iter()
            .any(|d| d.message.contains("conditional field `e.region`")),
        "{:?}",
        shorthand.diagnostics
    );
    // The same copy, unspelled: naming only `kind` still copies `region`.
    let implicit = compile_program(&program("  record Copy from e {\n    kind \"x\"\n  }"));
    assert!(
        implicit
            .diagnostics
            .iter()
            .any(|d| d.message.contains("conditional field `e.region`")),
        "{:?}",
        implicit.diagnostics
    );
    // Overriding the field explicitly copies nothing, so it reads nothing.
    let overridden = compile_program(&program(
        "  record Copy from e {\n    kind \"x\"\n    region \"none\"\n  }",
    ));
    assert_eq!(overridden.diagnostics, Vec::new());
    assert!(overridden.ir.is_some());
    // Inside the matching `deploy` arm both copies are allowed.
    let matching = compile_program(&program(
            "  case e.kind {\n    \"deploy\" => { record Copy from e {\n    region\n  } }\n    \"rollback\" => { record Copy { kind \"r\" region \"none\" } }\n  }",
        ));
    assert_eq!(matching.diagnostics, Vec::new());
    assert!(matching.ir.is_some());
    // Inside the wrong (`rollback`) arm the copy is rejected.
    let wrong = compile_program(&program(
            "  case e.kind {\n    \"deploy\" => { record Copy { kind \"d\" region \"x\" } }\n    \"rollback\" => { record Copy from e {\n    region\n  } }\n  }",
        ));
    assert!(
        wrong
            .diagnostics
            .iter()
            .any(|d| d.message.contains("conditional field `e.region`")),
        "{:?}",
        wrong.diagnostics
    );
    // `complete <T> from <binding>`: the output-contract projection copies too.
    let terminal = compile_program(
        r#"
workflow B
input e Event
output result Done
class Done { region string }
class Event {
  kind "deploy" | "rollback"
  region string when kind is "deploy"
}
rule r
  when Event as e
=> {
  complete result from e {
    region
  }
}
"#,
    );
    assert!(
        terminal
            .diagnostics
            .iter()
            .any(|d| d.message.contains("conditional field `e.region`")),
        "{:?}",
        terminal.diagnostics
    );
    // `emit signal … from <binding>`: the S6 projection is the third copy
    // position, and its block-less form copies every declared field.
    let signal = |body: &str| {
        format!(
            r#"
use std.ingress

@service
workflow EmitFrom

signal deploy.finished {{
  kind "deploy" | "rollback"
  peer string
  region string when kind is "deploy"
}}

signal deploy.acknowledged {{
  peer string
  region string
}}

rule relay
  when deploy.finished as deployed
=> {{
{body}
}}
"#
        )
    };
    let signal_implicit = compile_program(&signal(
        "  emit signal deploy.acknowledged to deployed.peer from deployed as sent",
    ));
    assert!(
        signal_implicit
            .diagnostics
            .iter()
            .any(|d| d.message.contains("conditional field `deployed.region`")),
        "{:?}",
        signal_implicit.diagnostics
    );
    let signal_overridden = compile_program(&signal(
            "  emit signal deploy.acknowledged to deployed.peer from deployed {\n    region \"none\"\n  } as sent",
        ));
    assert_eq!(signal_overridden.diagnostics, Vec::new());
    assert!(signal_overridden.ir.is_some());
}

#[test]
fn rejects_conflicting_reused_effect_binding() {
    // Reusing an effect binding for two effects with DIFFERENT result types makes
    // `after <binding> …` ambiguous (§5.5). Same-type reuse is harmless and allowed.
    let source = r#"
workflow D

output result R
class R { x string }
class WorkItem { title string }
class A { a string }
class B { b string }

coerce fa(t string) -> A { prompt "x" }
coerce fb(t string) -> B { prompt "x" }

rule r
  when WorkItem as item
=> {
  coerce fa(item.title) as v
  coerce fb(item.title) as v
  complete result { x "done" }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("reuses effect binding `v`")),
        "{:?}",
        compiled.diagnostics
    );
}

/// `pattern` and `apply` are the compile-time reuse surface: an `apply`
/// expands into ordinary declarations before the type check, so a mistake here
/// produces declarations the author never wrote. A mutation sweep found none
/// of these refusals exercised.
///
/// Two further guards in this area — `pattern ... is not allowed inside this
/// declaration scope` and `pattern application ... was not expanded` — are
/// deliberately absent. They sit after the expansion pass in `lower_program`
/// and fire only if expansion left an item behind; a failed expansion removes
/// the item, so no source program reaches them. They are internal invariants
/// rather than refusals, which is why the sweep could not tell them apart from
/// the five below.
#[test]
fn pattern_and_apply_refusals_fire() {
    let cases: &[(&str, &str)] = &[
        (
            "pattern `Twice` is declared more than once",
            r#"
workflow P
output result R
class R { ok bool }

pattern Twice<A> {
  rule x
    when started
  => { complete result { ok true } }
}

pattern Twice<A> {
  rule y
    when started
  => { complete result { ok true } }
}

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        (
            "pattern `Missing` was not found",
            r#"
workflow P
output result R
class R { ok bool }

apply Missing<R> as Thing { }

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        (
            "pattern `Two` expects 2 type arguments but got 1",
            r#"
workflow P
output result R
class R { ok bool }

pattern Two<A, B> {
  rule x
    when started
  => { complete result { ok true } }
}

apply Two<R> as Thing { }

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        (
            "pattern application `Thing` passes argument `reviewer` more than once",
            r#"
workflow P
output result R
class R { ok bool }

pattern One<A> {
  rule x
    when started
  => { complete result { ok true } }
}

apply One<R> as Thing {
  reviewer codex
  reviewer claude
}

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        (
            "pattern application `Thing` has malformed argument `!!!`",
            r#"
workflow P
output result R
class R { ok bool }

pattern One<A> {
  rule x
    when started
  => { complete result { ok true } }
}

apply One<R> as Thing {
  !!!
}

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
    ];

    for (expected, source) in cases {
        let compiled = compile_program(source);
        assert!(
            compiled.diagnostics.iter().any(|d| d.message == *expected),
            "expected `{expected}`, got {:?}",
            compiled
                .diagnostics
                .iter()
                .map(|d| d.message.as_str())
                .collect::<Vec<_>>()
        );
    }
}

/// The declaration surface — `source`, `signal`, `agent`, `lease`,
/// `counter`, `test`, and `AgentRef` — is where a workflow names the world
/// outside itself. A refusal here separates a typo from a workflow that
/// observes nothing, contends for a slot nobody holds, or routes to an
/// agent that does not exist. A mutation sweep found none of these
/// exercised, and one of them had a wrapped line's indentation sitting
/// The rule body is where a workflow says what it DOES, so these refusals
/// are the ones an author meets most: an unknown terminal, an agent that
/// does not exist, a `case` arm over a value that cannot be matched, an
/// `after` predicate that observes the wrong outcome. A mutation sweep
/// found none of them exercised, and a second sweep across the whole
/// workspace confirmed it — a parser-suite-only verdict called nine more
/// unexercised that CLI and kernel tests do reach, so the cheap answer is
/// not the answer.
///
/// Three neighbours are deliberately absent, and were not merely skipped.
/// `has malformed tell target`, `has malformed field assignment in
/// \`record ...\``, and `has invalid expression for field` each sit behind a
/// line-shape helper whose failure condition the parser rejects earlier, so
/// no fixture reached them. That is a weaker claim than the unreachable
/// `pattern` guards: these may yet be reachable by a shape not tried here,
/// which is why they are recorded rather than asserted impossible.
#[test]
fn rule_body_refusals_fire() {
    let cases: &[(&str, &str)] = &[
            ("rule `r` completes unknown workflow terminal `missing`", "workflow W\noutput result R\nclass R { ok bool }\nrule r\n  when started\n=> { complete missing { ok true } }\n"),
            // Same message, a DIFFERENT refusal: the scalar terminal form
            // (`complete <name> <value>`, no block) is checked on its own path
            // from the block form below, so covering one leaves the other dead.
            // The bite test found exactly that -- this table asserted the text
            // and the scalar site stayed unexercised.
            ("rule `r` completes unknown workflow terminal `missing`",
             "workflow W\noutput result bool\nrule r\n  when started\n=> { complete missing true }\n"),
            ("rule `r` has malformed `complete` action", "workflow W\noutput result R\nclass R { ok bool }\nrule r\n  when started\n=> { complete result extra words { ok true } }\n"),
            ("rule `r` has unknown binding `nope` in `complete result` value", "workflow W\noutput result bool\nclass T { title string }\nrule r\n  when T as t\n=> { complete result nope.flag }\n"),
            ("rule `r` has unknown readiness pattern `42 as x`", "workflow W\noutput result R\nclass R { ok bool }\nrule r\n  when 42 as x\n=> { complete result { ok true } }\n"),
            ("rule `r` has `after out reaches \"half\"` for `out`, which is not a workflow-invoke binding in this rule", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t\n=> {\n  coerce classify(t.title) as out\n  after out reaches \"half\" { complete result { ok true } }\n}\n"),
            ("rule `r` observes acquire `s` with `succeeds`, which also matches a Contended outcome (the acquire op completes either way)", "use std.coord\n\nworkflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nlease slot { key T slots 1 ttl 10m }\nrule r\n  when T as t\n=> {\n  acquire slot for t.id as s\n  after s succeeds { complete result { ok true } }\n}\n"),
            ("rule `r` observes counter consume `c` with `succeeds`, which also matches an Over outcome (the consume op completes either way)", "use std.coord\n\nworkflow W\noutput result R\nclass R { ok bool }\nclass T { name string }\ncounter budget { key T cap 3 reset daily }\nrule r\n  when T as t\n=> {\n  consume budget for t.name amount 1 as c\n  after c succeeds { complete result { ok true } }\n}\n"),
            ("rule `r` has unsupported `after` dependency predicate", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t\n=> {\n  coerce classify(t.title) as out\n  after out explodes { complete result { ok true } }\n}\n"),
            ("rule `r` records unknown class `Missing`", "workflow W\noutput result R\nclass R { ok bool }\nrule r\n  when started\n=> {\n  record Missing { ok true }\n  complete result { ok true }\n}\n"),
            ("rule `r` has malformed coerce call", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t\n=> {\n  coerce notacall as out\n  after out completes { complete result { ok true } }\n}\n"),
            ("rule `r` has malformed workflow invocation", "workflow W\noutput result R\nclass R { ok bool }\nrule r\n  when started\n=> {\n  invoke as child\n  after child succeeds { complete result { ok true } }\n}\n"),
            ("rule `r` uses a string literal as a tell target", "workflow W\noutput result R\nclass R { ok bool }\nrule r\n  when started\n=> { tell \"someone\" \"do a thing\" }\n"),
            ("rule `r` tells unknown agent `ghost`", "workflow W\noutput result R\nclass R { ok bool }\nrule r\n  when started\n=> { tell ghost \"do a thing\" }\n"),
            ("rule `r` checks availability for non-AgentRef `t.title`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t\n  when t.title is available\n=> { complete result { ok true } }\n"),
            ("rule `r` checks unknown agent `ghost`", "workflow W\noutput result R\nclass R { ok bool }\nrule r\n  when started\n  when ghost is available\n=> { complete result { ok true } }\n"),
            ("rule `r` has case scrutinee `\"lit\"` that is not a typed path", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t\n=> {\n  case \"lit\" {\n    _ => { complete result { ok true } }\n  }\n}\n"),
            ("rule `r` uses `None` for a non-optional case", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t\n=> {\n  case t.title {\n    None => { complete result { ok true } }\n    _ => { complete result { ok false } }\n  }\n}\n"),
            ("rule `r` has unsupported case pattern `u.other`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { speed \"fast\" | \"slow\" }\nclass U { other string }\nrule r\n  when T as t\n  when U as u\n=> {\n  case t.speed {\n    u.other => { complete result { ok true } }\n    _ => { complete result { ok false } }\n  }\n}\n"),
            ("rule `r` has unsupported AgentRef case pattern `x.y`", "use std.agent\n\nworkflow W\noutput result R\nclass R { ok bool }\nagent a { provider fixture profile \"repo-writer\" capacity 1 }\nclass T { owner AgentRef<a> }\nrule r\n  when T as t\n=> {\n  case t.owner {\n    x.y => { complete result { ok true } }\n    _ => { complete result { ok false } }\n  }\n}\n"),
            ("rule `r` cannot pattern-match this scrutinee type", "workflow W\noutput result R\nclass R { ok bool }\nclass T { count int }\nrule r\n  when T as t\n=> {\n  case t.count {\n    1 => { complete result { ok true } }\n    _ => { complete result { ok false } }\n  }\n}\n"),
            ("rule `r` case pattern must be one of its literal variants", "workflow W\noutput result R\nclass R { ok bool }\nclass T { speed \"fast\" | \"slow\" }\nrule r\n  when T as t\n=> {\n  case t.speed {\n    42 => { complete result { ok true } }\n    _ => { complete result { ok false } }\n  }\n}\n"),
            ("rule `r` case pattern cannot be `medium`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { speed \"fast\" | \"slow\" }\nrule r\n  when T as t\n=> {\n  case t.speed {\n    \"medium\" => { complete result { ok true } }\n    _ => { complete result { ok false } }\n  }\n}\n"),
            ("rule `r` has non-agent case pattern", "use std.agent\n\nworkflow W\noutput result R\nclass R { ok bool }\nagent a { provider fixture profile \"repo-writer\" capacity 1 }\nclass T { owner AgentRef<a> }\nrule r\n  when T as t\n=> {\n  case t.owner {\n    42 => { complete result { ok true } }\n    _ => { complete result { ok false } }\n  }\n}\n"),
            ("rule `r` redacts `nope`, which has no known schema", "workflow W\noutput result R\nclass R { ok bool }\nrule r\n  when started\n=> {\n  redact nope keep [ok] as clean\n  complete result { ok true }\n}\n"),
            ("rule `r` appends to undeclared ledger `nope`", "workflow W\noutput result R\nclass R { ok bool }\nclass Entry { area string }\nrule r\n  when started\n=> {\n  append Entry { area \"a\" } to nope as e\n  after e succeeds { complete result { ok true } }\n}\n"),
            ("rule `r` appends unknown entry class `Missing`", "use std.coord\n\nworkflow W\noutput result R\nclass R { ok bool }\nclass Entry { area string }\nledger log { entry Entry partition by area retain 30d }\nrule r\n  when started\n=> {\n  append Missing { area \"a\" } to log as e\n  after e succeeds { complete result { ok true } }\n}\n"),
            ("rule `r` consumes undeclared counter `nope`", "use std.coord\n\nworkflow W\noutput result R\nfailure error R\nclass R { ok bool }\nclass T { name string }\nrule r\n  when T as t\n=> {\n  consume nope for t.name amount 1 as c\n  after c ok { complete result { ok true } }\n  after c over { fail error { ok false } }\n}\n"),
            ("rule `r` has invalid `timer until` operand `t`: `t` is a `T` record, not a `time` value", "workflow W\noutput result R\nclass R { ok bool }\nclass T { due time }\nrule r\n  when T as t\n=> {\n  timer until t as d\n  after d succeeds { complete result { ok true } }\n}\n"),
        ];

    // Report EVERY mismatch, not just the first. A table this size fails
    // one case at a time otherwise, and each rerun costs a full rebuild.
    let mut missing = Vec::new();
    for (expected, source) in cases {
        let compiled = compile_program(source);
        if !compiled.diagnostics.iter().any(|d| d.message == *expected) {
            missing.push(format!(
                "expected `{expected}`\n     got {:?}",
                compiled
                    .diagnostics
                    .iter()
                    .map(|d| d.message.as_str())
                    .collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {} rule-body refusals did not fire:\n  {}",
        missing.len(),
        cases.len(),
        missing.join("\n  ")
    );
}

/// inside its message text, which is what an unasserted message looks like.
#[test]
fn declaration_refusals_fire() {
    const SOURCE_PRELUDE: &str = r#"use std.ingress

@service
workflow S

signal ingress.fed {
  text string
}

class FedLine {
  text string
}

rule record_line
  when ingress.fed as f
=> {
  record FedLine {
    text f.text
  }
}
"#;

    let cases: &[(&str, String)] = &[
            (
                "lease `slot` keys on undeclared type `Missing`",
                r#"use std.coord

workflow L
output result R

class R { ok bool }

lease slot {
  key Missing
  slots 1
  ttl 10m
}

rule r
  when started
=> { complete result { ok true } }
"#
                .to_owned(),
            ),
            (
                "counter `budget` keys on undeclared type `Missing`",
                r#"use std.coord

workflow C
output result R

class R { ok bool }

counter budget {
  key Missing
  cap 3
  reset daily
}

rule r
  when started
=> { complete result { ok true } }
"#
                .to_owned(),
            ),
            (
                "signal `ingress.fed` is declared more than once",
                format!(
                    "{SOURCE_PRELUDE}
signal ingress.fed {{
  text string
}}
"
                ),
            ),
            (
                "signal `ingress.dup` declares field `text` more than once",
                format!(
                    "{SOURCE_PRELUDE}
signal ingress.dup {{
  text string
  text string
}}
"
                ),
            ),
            (
                "source `feed` is declared more than once",
                format!(
                    "{SOURCE_PRELUDE}
source file as feed {{
  path \"./inbox.txt\"
  observe as obs
  emit ingress.fed {{
    text obs.line
  }}
}}

source file as feed {{
  path \"./other.txt\"
  observe as obs
  emit ingress.fed {{
    text obs.line
  }}
}}
"
                ),
            ),
            (
                "source `feed` declares a `path` clause but its provider is `http`, not `file`",
                format!(
                    "{SOURCE_PRELUDE}
source http as feed {{
  url \"http://127.0.0.1:8080/feed.json\"
  path \"./inbox.txt\"
  observe as obs
  emit ingress.fed {{
    text obs.item
  }}
}}
"
                ),
            ),
            (
                "source `feed` declares a `url` clause but its provider is `file`, not `http`",
                format!(
                    "{SOURCE_PRELUDE}
source file as feed {{
  path \"./inbox.txt\"
  url \"http://127.0.0.1:8080/feed.json\"
  observe as obs
  emit ingress.fed {{
    text obs.line
  }}
}}
"
                ),
            ),
            (
                "source `feed` emits `from other`, but the only binding in scope is the observe binding `obs`",
                format!(
                    "{SOURCE_PRELUDE}
source file as feed {{
  path \"./inbox.txt\"
  observe as obs
  emit ingress.fed from other {{
    text obs.line
  }}
}}
"
                ),
            ),
            (
                "source `feed` emit reads unknown binding `other`",
                format!(
                    "{SOURCE_PRELUDE}
source file as feed {{
  path \"./inbox.txt\"
  observe as obs
  emit ingress.fed {{
    text other.line
  }}
}}
"
                ),
            ),
            (
                "agent `reviewer` is declared more than once",
                r#"use std.agent

workflow A
output result R

class R { ok bool }

agent reviewer {
  provider fixture
  profile "repo-writer"
  capacity 1
}

agent reviewer {
  provider fixture
  profile "repo-reader"
  capacity 1
}

rule r
  when started
=> { complete result { ok true } }
"#
                .to_owned(),
            ),
            (
                "agent `reviewer` declares compaction more than once",
                r#"use std.agent

workflow A
output result R

class R { ok bool }

agent reviewer {
  provider fixture
  profile "repo-writer"
  capacity 1
  compaction summarize
  compaction none
}

rule r
  when started
=> { complete result { ok true } }
"#
                .to_owned(),
            ),
            (
                "agent `reviewer` declares thread more than once",
                r#"use std.agent

workflow A
output result R

class R { ok bool }

agent reviewer {
  provider fixture
  profile "repo-writer"
  capacity 1
  thread continue
  thread fresh
}

rule r
  when started
=> { complete result { ok true } }
"#
                .to_owned(),
            ),
            (
                "AgentRef lists agent `reviewer` more than once",
                r#"use std.agent

workflow A
output result R

class R { ok bool }

class Ticket {
  owner AgentRef<reviewer | reviewer>
}

agent reviewer {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule r
  when started
=> { complete result { ok true } }
"#
                .to_owned(),
            ),
            (
                "AgentRef has no agent `nobody`",
                r#"use std.agent

workflow A
output result R

class R { ok bool }

class Ticket {
  owner AgentRef<reviewer>
}

agent reviewer {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule r
  when Ticket as t
=> {
  case t.owner {
    nobody => { complete result { ok true } }
    _ => { complete result { ok false } }
  }
}
"#
                .to_owned(),
            ),
            (
                "test `a run` is declared more than once",
                r#"workflow T
output result R

class R { ok bool }

rule r
  when started
=> { complete result { ok true } }

test "a run" {
  workflow T
  run until idle
  expect workflow completed
}

test "a run" {
  workflow T
  run until idle
  expect workflow completed
}
"#
                .to_owned(),
            ),
            (
                "test `a run` has no `expect` clause",
                r#"workflow T
output result R

class R { ok bool }

rule r
  when started
=> { complete result { ok true } }

test "a run" {
  workflow T
  run until idle
}
"#
                .to_owned(),
            ),
        ];

    for (expected, source) in cases {
        let compiled = compile_program(source);
        assert!(
            compiled.diagnostics.iter().any(|d| d.message == *expected),
            "expected `{expected}`, got {:?}",
            compiled
                .diagnostics
                .iter()
                .map(|d| d.message.as_str())
                .collect::<Vec<_>>()
        );
    }
}

/// The expression type checker's operand rules: whether `a + b` is
/// arithmetic on numbers, whether `x in y` compares compatible types,
/// whether `!e` applies to a boolean, whether a map is indexed by a string.
/// A mutation sweep found every one of them unexercised, confirmed against
/// the whole workspace. These are type-system enforcement, not artifact
/// plumbing — a rule guard is the condition deciding whether a workflow
/// acts at all.
///
/// One neighbour is deliberately absent and is PROVABLY unreachable, not
/// merely unreached: `calls unsupported expression function` sits on the
/// `_` arm of a match over a call's name, but the expression parser only
/// ever constructs a call for `count`, `exists`, or `empty` (the guard at
/// the `Ident` arm of `parse_primary`). Every other name fails to tokenize
/// first, so no source program reaches that arm.
///
/// One finding is not covered here because it is a defect rather than a
/// gap: `indexes a map with a non-string key` is emitted from TWO sites,
/// one validating and one inferring, and both fire on the same expression —
/// the author is told twice. The case below asserts the message appears; it
/// deliberately does not assert how many times, because pinning 2 would
/// enshrine the duplication. Neither site can be bite-tested alone while
/// The record-construction type checks: what may be assigned to a field of
/// a map, class, enum, literal-union, or AgentRef type. A mutation sweep
/// found these unexercised, confirmed workspace-wide.
///
/// Every one applies only INSIDE an object or array literal.
/// `validate_expected_assignment` returns early unless the value starts
/// with `{` or `[`, so a scalar assigned to the same field is handled by a
/// different, already-covered check. Four fixtures of mine produced no
/// diagnostic at all before I found that gate, which is worth recording:
/// the obvious fixture for these rules tests a different rule entirely.
#[test]
fn record_field_type_refusals_fire() {
    let cases: &[(&str, &str)] = &[
            ("field `E.m` expects a map literal", "workflow W\noutput result R\nclass R { ok bool }\nclass E { m map<string> }\nrule r\n  when started\n=> {\n  record E { m [\"a\", \"b\"] }\n  complete result { ok true }\n}\n"),
            ("field `E.m` expects a map literal: expected object field name", "workflow W\noutput result R\nclass R { ok bool }\nclass E { m map<string> }\nrule r\n  when started\n=> {\n  record E { m { 5 } }\n  complete result { ok true }\n}\n"),
            ("field `E.i` repeats object field `a`", "workflow W\noutput result R\nclass R { ok bool }\nclass Inner { a string }\nclass E { i Inner }\nrule r\n  when started\n=> {\n  record E { i { a \"1\"  a \"2\" } }\n  complete result { ok true }\n}\n"),
            ("field `Inner.n` receives incompatible expression type", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nclass Inner { n int }\nclass E { i Inner }\nrule r\n  when T as t\n=> {\n  record E { i { n t.title } }\n  complete result { ok true }\n}\n"),
            // NESTED, not top level. The same message is emitted from two
            // sites -- the literal-assignment path and the expression path --
            // and existing tests already cover the literal one, so a top-level
            // fixture pins a refusal that was never the gap.
            ("field `Inner.s` expects literal string `fixed`", "workflow W\noutput result R\nclass R { ok bool }\nclass Inner { s \"fixed\" }\nclass E { i Inner }\nrule r\n  when started\n=> {\n  record E { i { s \"other\" } }\n  complete result { ok true }\n}\n"),
            // A NON-string literal. `expects an AgentRef value` has two
            // variants: one naming the offending string, which existing tests
            // cover, and this bare one for a literal that is not a string at
            // all. Covering the first leaves the second dead.
            ("field `Inner.who` expects an AgentRef value", "use std.agent\nworkflow W\noutput result R\nclass R { ok bool }\nagent a { provider fixture  profile \"repo-writer\"  capacity 1 }\nclass Inner { who AgentRef<a> }\nclass E { i Inner }\nrule r\n  when started\n=> {\n  record E { i { who 5 } }\n  complete result { ok true }\n}\n"),
            ("field `Inner.k` expects enum `Kind`", "workflow W\noutput result R\nclass R { ok bool }\nenum Kind {\n  Alpha\n  Beta\n}\nclass Inner { k Kind }\nclass E { i Inner }\nrule r\n  when started\n=> {\n  record E { i { k \"nope\" } }\n  complete result { ok true }\n}\n"),
            ("rule `r` has invalid expression for field `E.i`: expected expression in `{ n t.count + }`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { count int }\nclass Inner { n int }\nclass E { i Inner }\nrule r\n  when T as t\n=> {\n  record E { i { n t.count + } }\n  complete result { ok true }\n}\n"),
        ];

    let mut missing = Vec::new();
    for (expected, source) in cases {
        let compiled = compile_program(source);
        if !compiled.diagnostics.iter().any(|d| d.message == *expected) {
            missing.push(format!(
                "expected `{expected}`\n     got {:?}",
                compiled
                    .diagnostics
                    .iter()
                    .map(|d| d.message.as_str())
                    .collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {} record-field refusals did not fire:\n  {}",
        missing.len(),
        cases.len(),
        missing.join("\n  ")
    );
}

/// The accept half: the same nested shapes, well typed. Without it a
/// checker that refused every object literal would satisfy the table above.
#[test]
fn well_typed_record_fields_are_admitted() {
    let source = "use std.agent\nworkflow W\noutput result R\nclass R { ok bool }\nagent a { provider fixture  profile \"repo-writer\"  capacity 1 }\nenum Kind {\n  Alpha\n  Beta\n}\nclass Inner { n int  who AgentRef<a>  k Kind  u \"a\" | \"b\" }\nclass E { i Inner  m map<string>  s \"fixed\" }\nclass T { count int }\nrule r\n  when T as t\n=> {\n  record E {\n    i { n t.count  who a  k Alpha  u \"a\" }\n    m { key \"value\" }\n    s \"fixed\"\n  }\n  complete result { ok true }\n}\n";
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "a well-typed nested record must be admitted, got {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|d| d.message.as_str())
            .collect::<Vec<_>>()
    );
}

/// the other survives, which is itself the evidence they are redundant.
#[test]
fn expression_type_refusals_fire() {
    let cases: &[(&str, &str)] = &[
            ("rule `r` uses arithmetic with a non-numeric operand", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string  count int }\nrule r\n  when T as t where t.title + 1 > 2\n=> { complete result { ok true } }\n"),
            ("rule `r` uses boolean operator with non-boolean operand", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where t.title and true\n=> { complete result { ok true } }\n"),
            ("rule `r` applies `!` to a non-boolean expression", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where !t.title\n=> { complete result { ok true } }\n"),
            ("rule `r` uses membership with incompatible item type", "workflow W\noutput result R\nclass R { ok bool }\nclass T { count int  tags string[] }\nrule r\n  when T as t where t.count in t.tags\n=> { complete result { ok true } }\n"),
            ("rule `r` indexes a non-map expression", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where t.title[\"k\"] == \"x\"\n=> { complete result { ok true } }\n"),
            ("rule `r` indexes a map with a non-string key", "workflow W\noutput result R\nclass R { ok bool }\nclass T { meta map<string> }\nrule r\n  when T as t where t.meta[1] == \"x\"\n=> { complete result { ok true } }\n"),
            ("rule `r` calls `count` with 0 arguments, expected 1", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where count() > 0\n=> { complete result { ok true } }\n"),
            ("rule `r` calls `count` with unsupported argument type `string`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where count(t.title) > 0\n=> { complete result { ok true } }\n"),
            ("rule `r` calls `exists` with 0 arguments, expected 1", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where exists()\n=> { complete result { ok true } }\n"),
            ("rule `r` calls `exists` with unsupported argument type `string`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where exists(t.title)\n=> { complete result { ok true } }\n"),
            ("rule `r` queries unknown fact schema `Missing`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where count(Missing) > 0\n=> { complete result { ok true } }\n"),
            ("rule `r` fact query `T` has unknown field `nofield`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where count(T where nofield == \"x\") > 0\n=> { complete result { ok true } }\n"),
            ("rule `r` has unsafe optional path `t.owner.name`: `owner` must be proven present before accessing `name`", "workflow W\noutput result R\nclass R { ok bool }\nclass Owner { name string }\nclass T { owner Owner? }\nrule r\n  when T as t where t.owner.name == \"x\"\n=> { complete result { ok true } }\n"),
            // The SAME rule in the other scope. `unsafe optional path` and
            // `invalid expression path` are each emitted from two mirrored
            // sites — one for a binding-rooted path in a rule guard, one for a
            // bare path inside a fact query — and covering one leaves the other
            // dead. The bite test found exactly that: this table pinned the
            // message and one of the two sites stayed unexercised.
            ("assertion has unsafe optional path `owner.name`: `owner` must be proven present before accessing `name`", "workflow W\noutput result R\nclass R { ok bool }\nclass Owner { name string }\nclass T { owner Owner? }\nassert count(T where owner.name == \"x\") <= 1\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("rule `r` has invalid expression path `t.nofield`: schema `T` has no field `nofield`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where t.nofield == \"x\"\n=> { complete result { ok true } }\n"),
            ("assertion has invalid expression path `title.nested`: field `title` is not a schema value", "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nassert count(T where title.nested == \"x\") <= 1\nrule r\n  when started\n=> { complete result { ok true } }\n"),
        ];

    let mut missing = Vec::new();
    for (expected, source) in cases {
        let compiled = compile_program(source);
        if !compiled.diagnostics.iter().any(|d| d.message == *expected) {
            missing.push(format!(
                "expected `{expected}`\n     got {:?}",
                compiled
                    .diagnostics
                    .iter()
                    .map(|d| d.message.as_str())
                    .collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {} expression refusals did not fire:\n  {}",
        missing.len(),
        cases.len(),
        missing.join("\n  ")
    );
}

/// The accept half. Every rule above rejects a SHAPE, and a checker that
/// rejected the shape's legitimate twin would satisfy the table while
/// refusing correct programs — so each accepted form here is the nearest
/// legal neighbour of a rejection above.
#[test]
fn well_typed_expressions_are_admitted() {
    let accepted: &[&str] = &[
            // arithmetic on numbers, membership in a matching array,
            // a boolean operand for `and`/`!`, a string map key
            "workflow W\noutput result R\nclass R { ok bool }\nclass T { count int  tags string[]  flag bool  meta map<string> }\nrule r\n  when T as t where t.count + 1 > 2 and !t.flag and \"a\" in t.tags and t.meta[\"k\"] == \"v\"\n=> { complete result { ok true } }\n",
            // `count` and `exists` over a declared fact schema
            "workflow W\noutput result R\nclass R { ok bool }\nclass T { title string }\nrule r\n  when T as t where count(T where title == \"x\") > 0 and exists(T)\n=> { complete result { ok true } }\n",
            // an optional read PROVEN present first: the same path the unsafe
            // case rejects, made safe by the proof rather than by weakening the
            // rule.
            "workflow W\noutput result R\nclass R { ok bool }\nclass Owner { name string }\nclass T { owner Owner? }\nrule r\n  when T as t where exists t.owner and t.owner.name == \"x\"\n=> { complete result { ok true } }\n",
        ];

    let mut rejected = Vec::new();
    for source in accepted {
        let compiled = compile_program(source);
        if !compiled.diagnostics.is_empty() {
            rejected.push(format!(
                "{:?}",
                compiled
                    .diagnostics
                    .iter()
                    .map(|d| d.message.as_str())
                    .collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        rejected.is_empty(),
        "{} well-typed program(s) were refused:\n  {}",
        rejected.len(),
        rejected.join("\n  ")
    );
}

/// through a shape I had not tried.
#[test]
fn declaration_reference_refusals_fire() {
    let cases: &[(&str, &str)] = &[
            ("tracker `t` uses unavailable provider `nonexistent`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\ntracker t {\n  provider nonexistent\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("a test scenario binds at most one `workflow`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nrule r\n  when started\n=> { complete result { ok true } }\ntest \"t\" {\n  workflow W\n  workflow W\n  run until idle\n  expect workflow completed\n}\n"),
            ("`recall` names unknown memory pool `nonexistent`", "use std.memory\nworkflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nclass Note { note string }\nrule m\n  when Note as note\n=> {\n  recall nonexistent for note as ctx\n  complete result { ok true }\n}\n"),
            ("multiple implicit workflow headers are not supported", "class T { id string }\nclass R { ok bool }\n\nworkflow A\noutput result R\n\nworkflow B\noutput result R\n\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("stream `s` must declare its members", "use std.vcs\nworkflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nstream s {\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("duplicate stream `s`", "use std.vcs\nuse std.agent\nworkflow W\noutput result R\nclass R { ok bool }\nagent a { provider fixture  profile \"repo-writer\"  capacity 1 }\nstream s {\n  members [a]\n}\nstream s {\n  members [a]\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("workflow invocation `Child` repeats input `task`", "class T { id string }\nclass R { ok bool }\n\nworkflow Child {\n  input task T\n  output result R\n\n  rule c\n    when T as t\n  => { complete result { ok true } }\n}\n\nworkflow W {\n  output result R\n\n  rule r\n    when started\n  => {\n    invoke Child { task { id \"a\" }  task { id \"b\" } } as ch\n    after ch succeeds { complete result { ok true } }\n  }\n}\n"),
        ];

    let mut missing = Vec::new();
    for (expected, source) in cases {
        let compiled = compile_program(source);
        if !compiled.diagnostics.iter().any(|d| d.message == *expected) {
            missing.push(format!(
                "expected `{expected}`\n     got {:?}",
                compiled
                    .diagnostics
                    .iter()
                    .map(|d| d.message.as_str())
                    .collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {} reference refusals did not fire:\n  {}",
        missing.len(),
        cases.len(),
        missing.join("\n  ")
    );
}

/// diagnostic list.
#[test]
fn declaration_completeness_refusals_fire() {
    let cases: &[(&str, &str)] = &[
            ("counter `c` must declare `key`, `cap`, and `reset`", "use std.coord\nworkflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\ncounter c {\n  key T\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("unknown reset period `fortnightly`", "use std.coord\nworkflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\ncounter c {\n  key T\n  cap 3\n  reset fortnightly\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("cap value must fit in u32", "use std.coord\nworkflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\ncounter c {\n  key T\n  cap 99999999999\n  reset daily\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("lease `l` must declare a `key` type and a `ttl` backstop", "use std.coord\nworkflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nlease l {\n  slots 1\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("invalid duration `10x`", "use std.coord\nworkflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nlease l {\n  key T\n  slots 1\n  ttl 10x\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("ledger `g` must declare `entry`, `partition by`, and `retain`", "use std.coord\nworkflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nclass E { area string }\nledger g {\n  entry E\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("file store `f` is missing a root", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nfile store f {\n  allow read [\"**\"]\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("signal name `Bad.Name` must be dotted lowercase", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nsignal Bad.Name {\n  x string\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("source `feed` must declare `observe as <binding>`", "use std.ingress\n@service\nworkflow W\nsignal s.fed {\n  t string\n}\nclass C { t string }\nsource file as feed {\n  path \"./in.txt\"\n  emit s.fed {\n    t \"x\"\n  }\n}\nrule r\n  when s.fed as f\n=> {\n  record C { t f.t }\n}\n"),
            ("source `feed` must declare `emit <signal> { ... }`", "use std.ingress\n@service\nworkflow W\nsignal s.fed {\n  t string\n}\nclass C { t string }\nsource file as feed {\n  path \"./in.txt\"\n  observe as obs\n}\nrule r\n  when s.fed as f\n=> {\n  record C { t f.t }\n}\n"),
            ("source `feed` uses clock-only clauses but its provider is `file`, not `clock`", "use std.ingress\n@service\nworkflow W\nsignal s.fed {\n  t string\n}\nclass C { t string }\nsource file as feed {\n  path \"./in.txt\"\n  every 5m\n  observe as obs\n  emit s.fed {\n    t obs.line\n  }\n}\nrule r\n  when s.fed as f\n=> {\n  record C { t f.t }\n}\n"),
            ("gauge `g` declares no judge", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\ngauge g {\n  expect P(ok) at least 0.9\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("gauge declares more than one judge", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\ngauge g {\n  judge via exec \"a\"\n  judge via exec \"b\"\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("unknown gauge clause", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\ngauge g {\n  judge via exec \"a\"\n  sparkle yes\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("unknown judge form", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\ngauge g {\n  judge via telepathy\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("unknown campaign clause", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\ngauge g {\n  judge via exec \"a\"\n}\ncampaign c {\n  sparkle g\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("tag is missing a name", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\n@\nclass Z { a string }\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("tag `@bad!tag` contains unsupported characters", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\n@bad!tag\nclass Z { a string }\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("unknown field tag `@weird`", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nclass Z {\n  a string @weird\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("class `Z` declares field `a` more than once", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nclass Z {\n  a string\n  a int\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("table `seed` has no rows", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\ntable seed as T [\n]\nrule r\n  when started\n=> { complete result { ok true } }\n"),
            ("coerce `f` declares parameter `a` more than once", "workflow W\noutput result R\nclass R { ok bool }\nclass T { id string }\nclass Out { v string }\ncoerce f(a string, a string) -> Out {\n  prompt \"x\"\n}\nrule r\n  when started\n=> { complete result { ok true } }\n"),
        ];

    let mut missing = Vec::new();
    for (expected, source) in cases {
        let compiled = compile_program(source);
        if !compiled.diagnostics.iter().any(|d| d.message == *expected) {
            missing.push(format!(
                "expected `{expected}`\n     got {:?}",
                compiled
                    .diagnostics
                    .iter()
                    .map(|d| d.message.as_str())
                    .collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "{} of {} declaration refusals did not fire:\n  {}",
        missing.len(),
        cases.len(),
        missing.join("\n  ")
    );
}

/// A value token where a field NAME was expected used to be dropped in
/// silence, and the recorded fact then took the SHORTHAND's value instead
/// of the literal the author wrote. Compiling clean and storing a different
/// value than the source states is the failure this project exists to
/// prevent, so the stray token is now a refusal.
#[test]
fn a_value_with_no_field_name_is_refused() {
    let source = "workflow W\noutput result R\nclass R { ok bool }\nclass Src { title string }\nclass Out { title string }\n\nrule r\n  when Src as s\n=> {\n  record Out {\n    title\n    \"hello\"\n  }\n  complete result { ok true }\n}\n";
    let compiled = compile_program(source);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message
                == "rule `r` has a value with no field name in `record Out`: `\"hello\"`"),
        "the stray literal must be refused, got {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|d| d.message.as_str())
            .collect::<Vec<_>>()
    );
}

/// The accept half, and the reason this is a stray-token rule rather than a
/// ban on shorthand: a line-delimited bare name IS a field, and a `from`
/// block of them must stay legal.
#[test]
fn line_delimited_shorthand_fields_are_still_admitted() {
    let source = "workflow W\noutput result R\nclass R { ok bool }\nclass Src { title string  note string }\nclass Out { title string  note string }\n\nrule r\n  when Src as s\n=> {\n  record Out from s {\n    title\n    note\n  }\n  complete result { ok true }\n}\n";
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "a from-block of shorthand fields must be admitted, got {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|d| d.message.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn rejects_transitive_workflow_invocation_cycle() {
    // A invokes B invokes A — a runtime invoke cycle with no compile-time
    // convergence proof (RESOLVED 2026-07-01). Rejected before root selection.
    let source = r#"
workflow A {
  input task TA
  output result RA
  class TA { id string }
  class RA { id string }
  rule go
    when TA as t
  => {
    invoke B { task { id t.id } } as b
    after b succeeds as r { complete result { id r.id } }
  }
}

workflow B {
  input task TB
  output result RB
  class TB { id string }
  class RB { id string }
  rule go
    when TB as t
  => {
    invoke A { task { id t.id } } as a
    after a succeeds as r { complete result { id r.id } }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("A"));
    assert!(compiled.ir.is_none());
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("graph.unbounded_workflow_invocation_recursion")
            && d.message.contains("A -> B -> A")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn accepts_acyclic_workflow_invocation_chain() {
    // A invokes B invokes C — a finite chain, never flagged (bite: the cycle
    // detector must not over-reject non-recursive nesting).
    let source = r#"
workflow A {
  input task TA
  output result RA
  class TA { id string }
  class RA { id string }
  rule go
    when TA as t
  => {
    invoke B { task { id t.id } } as b
    after b succeeds as r { complete result { id r.id } }
  }
}

workflow B {
  input task TB
  output result RB
  class TB { id string }
  class RB { id string }
  rule go
    when TB as t
  => {
    invoke C { task { id t.id } } as c
    after c succeeds as r { complete result { id r.id } }
  }
}

workflow C {
  input task TC
  output result RC
  class TC { id string }
  class RC { id string }
  rule go
    when TC as t
  => {
    complete result { id t.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("A"));
    assert!(
        !compiled.diagnostics.iter().any(|d| d
            .message
            .contains("graph.unbounded_workflow_invocation_recursion")),
        "acyclic chain wrongly flagged: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_invoking_private_sibling_workflow() {
    let source = r#"
class Job { id string }
class Report { id string }

@private
workflow Child {
  input task Job
  output result Report
  rule work
    when Job as t
  => {
    complete result { id t.id }
  }
}

workflow Parent {
  input task Job
  output result Report
  rule go
    when Job as t
  => {
    invoke Child { task t } as child
    after child succeeds as r { complete result { id r.id } }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("private workflow `Child`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn accepts_private_workflow_as_selected_root() {
    let source = r#"
class Job { id string }
class Report { id string }

@private
workflow Child {
  input task Job
  output result Report
  rule work
    when Job as t
  => {
    complete result { id t.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Child"));
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("private root compiles: {:?}", compiled.diagnostics));
    assert!(ir.source_tags.iter().any(|tag| {
        tag.name == "private" && tag.target_kind == "workflow" && tag.target == "Child"
    }));
}

#[test]
fn typed_invoke_result_checks_field_access_against_child_output() {
    // The child's output is a shared top-level class `Report`. The parent's
    // `after child succeeds as r` binds r to Report, so `r.missing` (not a
    // field of Report) is rejected — invoke results are no longer opaque.
    let source = r#"
class Report { id string }
class Job { id string }

workflow Parent {
  input task Job
  output result Report
  rule go
    when Job as t
  => {
    invoke Child { task { id t.id } } as child
    after child succeeds as r {
      complete result { id r.missing }
    }
  }
}

workflow Child {
  input task Job
  output result Report
  rule work
    when Job as t
  => {
    complete result { id t.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(
        compiled.ir.is_none(),
        "unknown field on invoke result must not compile"
    );
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("r.missing") || d.message.contains("missing")),
        "typed invoke result did not reject r.missing: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn typed_invoke_result_accepts_a_valid_child_output_field() {
    // Bite: a field that IS on the child's output contract resolves and the
    // program compiles.
    let source = r#"
class Report { id string }
class Job { id string }

workflow Parent {
  input task Job
  output result Report
  rule go
    when Job as t
  => {
    invoke Child { task { id t.id } } as child
    after child succeeds as r {
      complete result { id r.id }
    }
  }
}

workflow Child {
  input task Job
  output result Report
  rule work
    when Job as t
  => {
    complete result { id t.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(
        compiled.diagnostics.is_empty(),
        "valid invoke-result field access wrongly rejected: {:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some());
}

#[test]
fn typed_invoke_failure_checks_field_access_against_child_failure() {
    // The child's failure is a shared top-level class `ChildError`. The
    // parent's `after child fails as f` binds f to ChildError, so
    // `f.nonexistent` (not a field of ChildError) is rejected — the failure
    // binding is the child's declared failure shape, not the opaque base.
    let source = r#"
class Report { id string }
class Job { id string }
class ChildError { reason string }
class ParentError { detail string }

workflow Parent {
  input task Job
  output result Report
  failure err ParentError
  rule go
    when Job as t
  => {
    invoke Child { task { id t.id } } as child
    after child succeeds as r {
      complete result { id r.id }
    }
    after child fails as f {
      fail err { detail f.nonexistent }
    }
  }
}

workflow Child {
  input task Job
  output result Report
  failure err ChildError
  rule work
    when Job as t
  => {
    fail err { reason t.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(
        compiled.ir.is_none(),
        "unknown field on invoke failure must not compile"
    );
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("f.nonexistent") || d.message.contains("nonexistent")),
        "typed invoke failure did not reject f.nonexistent: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn typed_invoke_failure_accepts_a_valid_child_failure_field() {
    // Bite: a field that IS on the child's shared failure contract resolves
    // and the program compiles — the `fails` binding is no longer the opaque
    // `TerminalFailed` base when the child declares a shared failure class.
    let source = r#"
class Report { id string }
class Job { id string }
class ChildError { reason string }
class ParentError { detail string }

workflow Parent {
  input task Job
  output result Report
  failure err ParentError
  rule go
    when Job as t
  => {
    invoke Child { task { id t.id } } as child
    after child succeeds as r {
      complete result { id r.id }
    }
    after child fails as f {
      fail err { detail f.reason }
    }
  }
}

workflow Child {
  input task Job
  output result Report
  failure err ChildError
  rule work
    when Job as t
  => {
    fail err { reason t.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(
        compiled.diagnostics.is_empty(),
        "valid invoke-failure field access wrongly rejected: {:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some());
}

/// A child that declares its contract classes WORKFLOW-LOCALLY — the ordinary,
/// encapsulated spelling — used to make every parent-side read unchecked. The
/// class is not in the parent's index, so the field-path checks bailed and said
/// nothing, in all three observation positions: result, failure, and milestone.
///
/// The class still never becomes nameable in the parent; only reads off that
/// binding resolve, and they resolve in the child's own index.
#[test]
fn child_local_contract_classes_are_checked_in_the_child_scope() {
    let program = |parent_reads: &str| {
        format!(
            r#"
class Job {{ id string }}

workflow Parent {{
  input task Job
  output result ParentReport
  failure err ParentError
  class ParentReport {{ id string }}
  class ParentError {{ detail string }}
  class Seen {{ note string }}
  rule go
    when Job as t
  => {{
    invoke Child {{ task {{ id t.id }} }} as child
{parent_reads}
  }}
}}

workflow Child {{
  input task Job
  output result ChildReport
  failure err ChildError
  class ChildReport {{ summary string }}
  class ChildError {{ reason string }}
  class ChildProgress {{ detail string }}
  rule work
    when Job as t
  => {{
    emit milestone "started" of ChildProgress {{
      detail t.id
    }}
    complete result {{ summary t.id }}
  }}
}}
"#
        )
    };
    let bad_paths = |reads: &str| {
        compile_program_with_root(&program(reads), Some("Parent"))
            .diagnostics
            .into_iter()
            .filter(|d| d.message.contains("invalid field path"))
            .map(|d| d.message)
            .collect::<Vec<_>>()
    };

    // The child's OUTPUT class is workflow-local.
    let result_read = "    after child succeeds as r {\n      complete result { id r.nope }\n    }";
    assert_eq!(bad_paths(result_read).len(), 1, "{result_read}");

    // The child's FAILURE class is workflow-local.
    let failure_read = "    after child fails as f {\n      fail err { detail f.nope }\n    }";
    assert_eq!(bad_paths(failure_read).len(), 1, "{failure_read}");

    // The child's MILESTONE payload class is workflow-local. This read sits in a
    // `record` block, walked by a different pass than the terminal positions
    // above — both needed the child scope.
    let milestone_read =
        "    after child reaches \"started\" as m {\n      record Seen { note m.nope }\n    }";
    assert_eq!(bad_paths(milestone_read).len(), 1, "{milestone_read}");

    // The valid reads of all three still compile.
    let valid = "    after child succeeds as r {\n      complete result { id r.summary }\n    }\n\
                         after child fails as f {\n      fail err { detail f.reason }\n    }\n\
                         after child reaches \"started\" as m {\n      record Seen { note m.detail }\n    }";
    let compiled = compile_program_with_root(&program(valid), Some("Parent"));
    assert!(compiled.ir.is_some(), "{:?}", compiled.diagnostics);
    assert_eq!(bad_paths(valid), Vec::<String>::new());
}

/// The child's private class must not become NAMEABLE in the parent just
/// because the parent can read fields off a binding typed by it. Structural
/// access across the boundary, not an import.
#[test]
fn child_local_class_is_not_nameable_in_the_parent() {
    let source = r#"
class Job { id string }

workflow Parent {
  input task Job
  output result ParentReport
  class ParentReport { id string }
  class Holder { got ChildReport }
  rule go
    when Job as t
  => {
    complete result { id t.id }
  }
}

workflow Child {
  input task Job
  output result ChildReport
  class ChildReport { summary string }
  rule work
    when Job as t
  => {
    complete result { summary t.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(
        compiled.ir.is_none(),
        "parent must not declare a field of the child's private class: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn whole_program_validation_catches_a_broken_sibling_under_any_root() {
    // Two workflows; `Good` is well-formed, `Broken` references an undeclared
    // schema in its own scope. Compiling with `--root Good` must still catch
    // `Broken`'s error — the pre-pass validates EVERY workflow, not just the
    // selected root (RESOLVED 2026-07-01). Before this, a broken sibling was
    // silently discarded by root selection and never validated.
    let source = r#"
workflow Good {
  input task TG
  output result RG
  class TG { id string }
  class RG { id string }
  rule go
    when TG as t
  => {
    complete result { id t.id }
  }
}

workflow Broken {
  input task TB
  output result RB
  class TB { id string }
  class RB { id string }
  rule go
    when Nonexistent as t
  => {
    complete result { id t.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Good"));
    assert!(
        compiled.ir.is_none(),
        "a program with a broken sibling must not compile"
    );
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("Nonexistent")),
        "the broken sibling's error was not surfaced: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn cross_workflow_reference_to_sibling_local_is_annotated() {
    // `Consumer` references class `Secret`, which is declared *inside* sibling
    // workflow `Owner` (private to it). The reference is an error (isolation),
    // and it carries a related note pointing at Owner's declaration so the
    // author knows the name exists but is out of scope.
    let source = r#"
workflow Owner {
  input task TO
  output result RO
  class TO { id string }
  class RO { id string }
  class Secret { id string }
  rule go
    when TO as t
  => {
    complete result { id t.id }
  }
}

workflow Consumer {
  input task TC
  output result RC
  class TC { id string }
  class RC { id string }
  rule go
    when Secret as s
  => {
    complete result { id s.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Consumer"));
    assert!(
        compiled.ir.is_none(),
        "sibling-local reference must not compile"
    );
    let leak = compiled
        .diagnostics
        .iter()
        .find(|d| d.message.contains("`Secret`"))
        .expect("an unknown-name diagnostic for Secret");
    assert!(
        leak.related
            .iter()
            .any(|r| r.message.contains("workflow `Owner`")
                && r.message.contains("private to that workflow")),
        "missing sibling-local leak note: {:?}",
        leak.related
    );
}

#[test]
fn shared_top_level_name_is_not_annotated_as_a_leak() {
    // Bite: a class declared at the TOP LEVEL is global — both workflows may
    // reference it, and no leak note is attached. (Also confirms the program
    // compiles: the shared global resolves in each workflow.)
    let source = r#"
class Shared { id string }

workflow Alpha {
  input task Shared
  output result RA
  class RA { id string }
  rule go
    when Shared as s
  => {
    complete result { id s.id }
  }
}

workflow Beta {
  input task Shared
  output result RB
  class RB { id string }
  rule go
    when Shared as s
  => {
    complete result { id s.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Alpha"));
    assert!(
        compiled.diagnostics.is_empty(),
        "shared top-level global wrongly rejected: {:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some());
}

#[test]
fn whole_program_validation_accepts_all_well_formed_workflows() {
    // Bite: when every workflow is well-formed, the pre-pass adds no spurious
    // diagnostics and the selected root still compiles to IR.
    let source = r#"
workflow Alpha {
  input task TA
  output result RA
  class TA { id string }
  class RA { id string }
  rule go
    when TA as t
  => {
    complete result { id t.id }
  }
}

workflow Beta {
  input task TB
  output result RB
  class TB { id string }
  class RB { id string }
  rule go
    when TB as t
  => {
    complete result { id t.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Alpha"));
    assert!(
        compiled.diagnostics.is_empty(),
        "well-formed multi-workflow program emitted diagnostics: {:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some(), "selected root failed to compile");
}

#[test]
fn compact_workflow_signature_desugars_to_keyword_contracts() {
    // `Name(in: T) -> Out ! Fail` must produce exactly the contracts the
    // keyword form produces, with output named `result` and failure `error`.
    let compact = r#"
workflow Triage(ticket: Ticket) -> Resolution ! TriageFailed

class Ticket { id string }
class Resolution { id string }
class TriageFailed { reason string }

rule go
  when Ticket as t
=> {
  complete result { id t.id }
}
"#;
    let keyword = r#"
workflow Triage

input ticket Ticket
output result Resolution
failure error TriageFailed

class Ticket { id string }
class Resolution { id string }
class TriageFailed { reason string }

rule go
  when Ticket as t
=> {
  complete result { id t.id }
}
"#;
    let compact_ir = compile_program_with_root(compact, None);
    let keyword_ir = compile_program_with_root(keyword, None);
    assert!(
        compact_ir.diagnostics.is_empty(),
        "compact form did not compile: {:?}",
        compact_ir.diagnostics
    );
    assert!(
        keyword_ir.diagnostics.is_empty(),
        "keyword form did not compile: {:?}",
        keyword_ir.diagnostics
    );
    // Compare the semantic triple (kind, name, type) — spans naturally differ
    // between the two source layouts.
    let project = |ir: &IrProgram| {
        ir.workflow_contracts
            .iter()
            .map(|c| {
                (
                    format!("{:?}", c.kind),
                    c.name.clone(),
                    format!("{:?}", c.ty),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        project(&compact_ir.ir.expect("compact ir")),
        project(&keyword_ir.ir.expect("keyword ir")),
        "compact signature did not desugar to the same contracts"
    );
}

#[test]
fn compact_signature_supports_multiple_inputs_and_optional_failure() {
    // Multiple comma-separated inputs; failure clause omitted.
    let source = r#"
workflow Merge(left: LeftIn, right: RightIn) -> Merged

class LeftIn { id string }
class RightIn { id string }
class Merged { id string }

rule go
  when {
    LeftIn as l
    RightIn as r
  }
=> {
  complete result { id l.id }
}
"#;
    let compiled = compile_program_with_root(source, None);
    assert!(
        compiled.diagnostics.is_empty(),
        "multi-input compact form did not compile: {:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("ir");
    let inputs = ir
        .workflow_contracts
        .iter()
        .filter(|c| matches!(c.kind, IrWorkflowContractKind::Input))
        .count();
    let failures = ir
        .workflow_contracts
        .iter()
        .filter(|c| matches!(c.kind, IrWorkflowContractKind::Failure))
        .count();
    assert_eq!(inputs, 2, "expected two inputs");
    assert_eq!(
        failures, 0,
        "omitted failure clause must add no failure contract"
    );
}

#[test]
fn rejects_headerless_program_with_no_workflow() {
    // The implicit compatibility root is removed (RESOLVED 2026-07-01): a
    // source with no explicit `workflow` (only shared types/patterns) is a
    // library fragment, not a runnable program, and is rejected.
    let source = r#"
class SharedTicket {
  id string
}

pattern TagReviewed<Input> {
  rule tag
    when Input as item
  => {
    record SharedTicket { id item.id }
  }
}
"#;
    let compiled = compile_program_with_root(source, None);
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("program declares no `workflow`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn accepts_single_workflow_header_program() {
    // Bite: the headerless reject must not fire on a program that declares a
    // workflow via the header form (the common single-workflow shape).
    let source = r#"
workflow OnlyOne

input item Job
output result Done

class Job { id string }
class Done { id string }

rule go
  when Job as j
=> {
  complete result { id j.id }
}
"#;
    let compiled = compile_program_with_root(source, None);
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("program declares no `workflow`")),
        "header-form program wrongly rejected as headerless: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_recording_observer_only_terminal_schema() {
    // §5.4: the terminal family is `origin = observer` — the kernel projects
    // it, user rules may only eliminate it. A rule that `record`s a terminal
    // schema forges an outcome the kernel never produced, so it is rejected.
    for schema in ["TerminalFailed", "TerminalTimedOut", "TerminalCancelled"] {
        let source = format!(
            r#"
workflow Forge

input item Job
output result Done

class Job {{ id string }}
class Done {{ id string }}

rule sneak
  when Job as q
=> {{
  record {schema} {{ reason "x" summary "y" }}
  complete result {{ id q.id }}
}}
"#
        );
        let compiled = compile_program(&source);
        assert!(
            compiled
                .diagnostics
                .iter()
                .any(|d| d.message.contains(&format!(
                    "cannot record kernel-owned terminal schema `{schema}`"
                ))),
            "expected rejection for {schema}, got {:?}",
            compiled.diagnostics
        );
    }
}

#[test]
fn allows_recording_user_writable_builtin_schema() {
    // Regression guard for the fix above: `WorkItem` is a builtin schema ref
    // but user-writable (work-tracking state), so recording it must NOT be
    // rejected as observer-only.
    let source = r#"
workflow WriteWork

input item Job
output result Done

class Job { id string }
class Done { id string }

rule track
  when Job as q
=> {
  record WorkItem { title "t" status "reviewed" }
  complete result { id q.id }
}
"#;
    let compiled = compile_program(source);
    assert!(
        !compiled.diagnostics.iter().any(|d| d
            .message
            .contains("cannot record kernel-owned terminal schema")),
        "WorkItem must remain user-writable, got {:?}",
        compiled.diagnostics
    );
}

#[test]
fn exhaustive_bool_case_compiles() {
    // `case` over a `bool` field is valid when both `true` and `false` are
    // covered (the finite two-value domain).
    let source = r#"
workflow BoolCaseOk

output result Done

class Done {
  note string
}

class Flag {
  ready bool
}

rule route
  when Flag as f
=> {
  case f.ready {
    true => {
      complete result {
        note "t"
      }
    }
    false => {
      complete result {
        note "f"
      }
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(
        compiled.diagnostics,
        Vec::new(),
        "{:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some());
}

#[test]
fn bool_case_rejects_non_exhaustive_and_non_bool_patterns() {
    let source = r#"
workflow BoolCaseBad

class Flag {
  ready bool
}

rule route
  when Flag as f
=> {
  case f.ready {
    true => {
    }
  }

  case f.ready {
    maybe => {
    }
    false => {
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("non-exhaustive case; missing false")),
        "expected non-exhaustive diagnostic: {:?}",
        compiled.diagnostics
    );
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("case pattern `maybe` that is not a `bool` value")),
        "expected non-bool pattern diagnostic: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn exec_schema_result_resolves_typed_fields_for_case() {
    // `exec "..." -> Schema as v` registers its result type, so an
    // `after v succeeds as r` branch can `case` / field-access `r`'s fields —
    // the same after-binding type flow a named `coerce -> Schema` already
    // gets. Before the fix this produced "case scrutinee `r.kind` ... not a
    // typed path".
    let source = r#"
@service
workflow ExecTyped

class Pick { kind "a" | "b" }
class R { choice string }

output result R

signal go.now {
  x string
}

rule j
  when go.now as g
=> {
  exec "echo hi" -> Pick as v

  after v succeeds as r {
    case r.kind {
      "a" => {
        complete result {
          choice "a"
        }
      }
      "b" => {
        complete result {
          choice "b"
        }
      }
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not a typed path")),
        "exec -> Schema result fields should resolve: {:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some(), "{:?}", compiled.diagnostics);
}

#[test]
fn exec_with_requires_typed_record_binding() {
    // spec/std-script.md "Static checks" item 4: `exec <name> with <binding>`
    // serializes the binding to the script's stdin as a typed record, so the
    // binding must be a typed record binding — unknown or untyped-fact
    // bindings are check errors.
    let source = |with_line: &str, when_line: &str| {
        format!(
            r#"
@service
workflow ExecWith

class Request {{ text string }}
class Report {{ message string }}

output result Report

rule go
  when {when_line}
=> {{
  exec echo_report with {with_line} -> Report as report

  after report succeeds as out {{
    complete result {{
      message out.message
    }}
  }}
}}
"#
        )
    };

    // Positive: a class-typed `when` binding is a typed record binding.
    let compiled = compile_program(&source("request", "Request as request"));
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("typed record binding")),
        "typed record binding must pass: {:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some(), "{:?}", compiled.diagnostics);

    // Negative: an unknown binding.
    let compiled = compile_program(&source("missing", "Request as request"));
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("uses unknown binding `missing` in `exec echo_report with missing`")),
        "unknown binding must be rejected: {:?}",
        compiled.diagnostics
    );

    // Negative: an untyped runtime fact binding carries no record shape.
    let compiled = compile_program(&source("g", "fact foo.bar as g"));
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("passes untyped fact binding `g` to `exec echo_report with`")),
        "untyped fact binding must be rejected: {:?}",
        compiled.diagnostics
    );

    // Positive: a typed result binding (`exec -> Schema as r`) is a typed
    // record binding for a downstream `with`.
    let chained = r#"
@service
workflow ExecWithChained

class Request { text string }
class Report { message string }

output result Report

rule go
  when Request as request
=> {
  exec fetch_request with request -> Request as fetched

  after fetched succeeds as staged {
    exec echo_report with staged -> Report as report

    after report succeeds as out {
      complete result {
        message out.message
      }
    }
  }
}
"#;
    let compiled = compile_program(chained);
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("typed record binding")),
        "typed exec-result binding must pass: {:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some(), "{:?}", compiled.diagnostics);
}

#[test]
fn redact_projection_keeps_only_kept_fields() {
    // `redact c keep [id, status] as safe` synthesizes a projected class
    // holding only the kept fields, so `safe.id` resolves but `safe.ssn`
    // (dropped) is an unknown field — the type-system half of redaction
    // soundness (a dropped field cannot be reached through the projection).
    let kept = r#"
@service
workflow RedactKept

class Customer { id string  ssn string  status string }
class Result { tag string }
output result Result

signal go.now { x string }

coerce read_customer(x string) -> Customer { prompt "x" }

rule r
  when go.now as g
=> {
  coerce read_customer(g.x) as c
  after c succeeds as cust {
    redact cust keep [id, status] as safe
    complete result {
      tag safe.id
    }
  }
}
"#;
    let compiled = compile_program(kept);
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown field") || d.message.contains("not a typed")),
        "kept field `safe.id` should resolve: {:?}",
        compiled.diagnostics
    );

    assert!(
        compiled.ir.is_some(),
        "kept program should compile: {compiled:?}"
    );

    let dropped = kept.replace("tag safe.id", "tag safe.ssn");
    let compiled = compile_program(&dropped);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("safe.ssn") || d.message.contains("`ssn`")),
        "dropped field `safe.ssn` should be rejected: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn redact_unknown_kept_field_is_rejected() {
    let source = r#"
@service
workflow RedactBadKeep

class Customer { id string  status string }
class Result { tag string }
output result Result

signal go.now { x string }

coerce read_customer(x string) -> Customer { prompt "x" }

rule r
  when go.now as g
=> {
  coerce read_customer(g.x) as c
  after c succeeds as cust {
    redact cust keep [id, nonexistent] as safe
    complete result {
      tag safe.id
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("keeping unknown field `nonexistent`")),
        "expected unknown-kept-field rejection: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn inline_decide_result_resolves_typed_fields_for_case() {
    // `decide -> { fixed bool } as v` synthesizes a hygienic anonymous result
    // class, so `after v succeeds as r` can `case` / field-access `r`'s
    // fields — the same after-binding type flow a named `coerce -> Schema`
    // gets. Before this, an inline decide result had no type, so `r.fixed`
    // was "not a typed path" and `case r.fixed { true/false }` could not bind.
    let source = r#"
@service
workflow InlineDecideTyped

class R { choice string }
output result R

signal go.now {
  x string
}

rule j
  when go.now as g
=> {
  decide "is it fixed?" -> { fixed bool } as v

  after v succeeds as r {
    case r.fixed {
      true => {
        complete result {
          choice "a"
        }
      }
      false => {
        complete result {
          choice "b"
        }
      }
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not a typed path")),
        "inline decide result fields should resolve: {:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("compiles");
    // The synthesized hygienic class is visible in the IR (so the runtime
    // fixture can generate the anonymous shape).
    assert!(
        ir.schemas.iter().any(|schema| matches!(
            schema,
            IrSchema::Class(class) if class.name == "decide.j.v"
        )),
        "expected synthesized inline-decide class `decide.j.v` in IR schemas"
    );
}

#[test]
fn rejects_malformed_multiline_prompt_content_type_on_rule_prompt() {
    let source = r#"
workflow PromptAnnotationGuess

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule ask
  when started
=> {
  tell worker as turn """markdown extra
  do work
  """
}
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("malformed multiline prompt content type `markdown extra`")
            && diagnostic
                .suggestion
                .as_deref()
                .is_some_and(|suggestion| suggestion.contains("put prompt text on the next line"))
    }));
}

#[test]
fn rejects_malformed_multiline_prompt_content_type_on_coerce_prompt() {
    let source = r#"
workflow CoerceAnnotationGuess

class Review {
  status "ok"
}

coerce review() -> Review {
  prompt """text/markdown extra
  classify the review
  """
}

rule run
  when started
=> {
  coerce review() as result
}
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains(
            "coerce `review` has malformed multiline prompt content type `text/markdown extra`"
        )));
}

#[test]
fn rejects_pasted_top_level_gherkin_with_targeted_diagnostic() {
    let source = r#"
Feature: provider language routing

Scenario: fixture provider reviews every language task
  Given a queued language task
  When the provider turn completes
  Then the language result is reviewed
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .message
            .contains("Gherkin keyword `Feature` is not WhippleScript workflow syntax")
            && diagnostic.suggestion.as_deref().is_some_and(|suggestion| {
                suggestion.contains("use `workflow`, `table`, `rule")
                    && suggestion.contains("instead of free-text Given/When/Then steps")
            })
    }));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("Gherkin keyword `Given` is not WhippleScript workflow syntax")));
}

#[test]
fn rejects_pasted_gherkin_inside_workflow_body_with_targeted_diagnostic() {
    let source = r#"
workflow PastedGherkin {
  Scenario: fixture provider reviews every language task
  Given a queued language task
  When the provider turn completes
  Then the language result is reviewed
}
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("Gherkin keyword `Scenario` is not WhippleScript workflow syntax")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("Gherkin keyword `Then` is not WhippleScript workflow syntax")));
}

#[test]
fn rejects_pasted_gherkin_background_outline_examples_and_continuations() {
    let source = r#"
Feature: provider language routing

Rule: provider execution remains explicit

Background:
  Given a seeded provider table
  And all provider profiles are available

Scenario Outline: provider reviews language task
  When <provider> completes <language>
  But the review is missing
  Then the fixture fails

Examples:
  | provider | language |
  | codex    | French   |
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    for keyword in ["Rule", "Background", "And", "Scenario", "But", "Examples"] {
        assert!(
            compiled
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains(&format!(
                    "Gherkin keyword `{keyword}` is not WhippleScript workflow syntax"
                ))),
            "missing diagnostic for {keyword}: {:?}",
            compiled
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn explains_multiline_string_binding_position() {
    let source = r#"
workflow BindingGuess

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule branch
  when started
=> {
  tell worker """
  do work
  """ as turn

  after turn succeeds {
    tell worker "review" as review
  }
}
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("places effect binding `turn` after a multiline string delimiter")
        && diagnostic
            .suggestion
            .as_deref()
            .is_some_and(|suggestion| suggestion.contains("move `as turn` onto the effect line"))));
}

#[test]
fn invalid_fixtures_have_actionable_diagnostics() {
    let fixtures = [
        (
            "bad-agent",
            include_str!("../../../../examples/invalid/bad-agent.whip"),
        ),
        (
            "bad-record",
            include_str!("../../../../examples/invalid/bad-record.whip"),
        ),
        (
            "bad-terminal-payload",
            include_str!("../../../../examples/invalid/bad-terminal-payload.whip"),
        ),
        (
            "recursive-workflow-invocation",
            include_str!("../../../../examples/invalid/recursive-workflow-invocation.whip"),
        ),
        (
            "bad-effect-graph",
            include_str!("../../../../examples/invalid/bad-effect-graph.whip"),
        ),
        (
            "bad-effect-payload",
            include_str!("../../../../examples/invalid/bad-effect-payload.whip"),
        ),
        (
            "bad-expression-functions",
            include_str!("../../../../examples/invalid/bad-expression-functions.whip"),
        ),
        (
            "bad-finite-domain",
            include_str!("../../../../examples/invalid/bad-finite-domain.whip"),
        ),
        (
            "broken",
            include_str!("../../../../examples/invalid/broken.whip"),
        ),
        (
            "effect-output-scope",
            include_str!("../../../../examples/invalid/effect-output-scope.whip"),
        ),
        (
            "effectful-self-loop",
            include_str!("../../../../examples/invalid/effectful-self-loop.whip"),
        ),
        (
            "recursive-pattern",
            include_str!("../../../../examples/invalid/recursive-pattern.whip"),
        ),
        (
            "evidence-fact-match",
            include_str!("../../../../examples/invalid/evidence-fact-match.whip"),
        ),
        (
            "unknown-schema",
            include_str!("../../../../examples/invalid/unknown-schema.whip"),
        ),
        (
            "headerless-library",
            include_str!("../../../../examples/invalid/headerless-library.whip"),
        ),
    ];

    for (name, source) in fixtures {
        let compiled = compile_program(source);
        assert!(compiled.ir.is_none(), "{name} unexpectedly compiled");
        assert!(
            !compiled.diagnostics.is_empty(),
            "{name} did not emit diagnostics"
        );
        assert!(
            compiled
                .diagnostics
                .iter()
                .all(|diagnostic| diagnostic.suggestion.is_some()),
            "{name} emitted a diagnostic without a suggestion: {:?}",
            compiled.diagnostics
        );
    }
}

/// Seven refusals that a mutation sweep found nothing exercised: disabling
/// each one left the whole workspace suite green, so the compiler advertised
/// a rule no test proved it applies. They are grouped because they share that
/// provenance, not because they share a subject.
///
/// Each case asserts the message, not merely that compilation failed — a
/// program can fail for a reason other than the one under test, and that is
/// how an unexercised refusal hides.
#[test]
fn refusals_found_unexercised_by_mutation_sweep() {
    let cases: &[(&str, &str)] = &[
        (
            "agent `worker` declares capability `edit` more than once",
            r#"
workflow T
output result R
class R { ok bool }

agent worker {
  provider fixture
  profile "code"
  capacity 1
  capabilities ["edit", "edit"]
}

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        (
            "agent `worker` declares provider more than once",
            r#"
workflow T
output result R
class R { ok bool }

agent worker {
  provider fixture
  provider fixture
  profile "code"
  capacity 1
}

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        (
            "agent `worker` declares both `using` harness and direct provider `fixture`",
            r#"
workflow T
output result R
class R { ok bool }

harness coder: claude

agent worker using coder {
  provider fixture
  profile "code"
  capacity 1
}

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        (
            "enum `S` declares variant `A` more than once",
            r#"
workflow T
output result R
class R { ok bool }

enum S {
  A
  A
}

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        (
            "table `seed` targets unknown class `NoSuch`",
            r#"
workflow T
output result R
class R { ok bool }

table seed as NoSuch [ { x "1" } ]

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        (
            "ledger `l` records undeclared entry type `NoSuch`",
            r#"
workflow T
output result R
class R { ok bool }

ledger l { entry NoSuch partition by area retain 90d }

rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        (
            "rule `r` binds reserved keyword `record`",
            r#"
workflow T
output result R
class R { ok bool }
class Task { id string }

table seed as Task [ { id "1" } ]

rule r
  when Task as record
=> { complete result { ok true } }
"#,
        ),
    ];

    for (expected, source) in cases {
        let compiled = compile_program(source);
        assert!(
            compiled.diagnostics.iter().any(|d| d.message == *expected),
            "expected `{expected}`, got {:?}",
            compiled
                .diagnostics
                .iter()
                .map(|d| d.message.as_str())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn rejects_dangling_root_in_record_value() {
    // A record value referencing a binding that does not exist (a typo or an
    // unbound name) is a dangling reference that previously compiled silently.
    let source = r#"
@service
workflow DanglingRoot

class Ticket { id string }
class Note { text string }

table seed as Ticket [ { id "1" } ]

rule r
  when Ticket as ticket
=> {
  record Note {
    text tikcet.id
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown binding `tikcet`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_dangling_root_in_single_line_record() {
    // Single-line records (`record X { f y }`) were skipped by the line-based
    // extractor (brace_delta 0) and so were never field-validated; they are
    // now covered.
    let source = r#"
@service
workflow DanglingSingleLine

class Ticket { id string }
class Note { text string }

table seed as Ticket [ { id "1" } ]

rule r
  when Ticket as ticket
=> {
  record Note { text tikcet.id }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown binding `tikcet`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_dangling_root_in_coerce_argument() {
    // Coerce arguments are another value position where a typo'd/unbound root
    // was previously accepted leniently by the type-checker.
    let source = r#"
@service
workflow DanglingCoerceArg

class Ticket { id string  title string }
class Review { summary string }

coerce classify(title string) -> Review { prompt "c" }

agent reviewer { provider fixture  profile "r"  capacity 1 }

table seed as Ticket [ { id "1"  title "t" } ]

rule r
  when Ticket as ticket
  when reviewer is available
=> {
  coerce classify(tikcet.title) as rev
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown binding `tikcet`")
                && d.message.contains("coerce `classify`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_dangling_root_in_counter_consume_operand() {
    // Non-field effect operands (lease/counter `for <key>`, `emit ... to
    // <target>`) are also checked via `check_operand_root`.
    let source = r#"
@service
workflow CounterOperandDangling

class CallFailed { service string }
class Service { id string }

counter failure_budget { key Service cap 3 reset daily }

table seed as CallFailed [ { service "x" } ]

rule strike
  when CallFailed as f
=> {
  consume failure_budget for fff.service amount 1 as strike
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown binding `fff`") && d.message.contains("consume")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_dangling_root_in_queue_file_payload() {
    // Body-AST effect payloads (`file issue into`, `emit`, ledger `append`)
    // are validated via `validate_effect_field_roots`, not the line-based
    // validators; their field values were previously unchecked for roots.
    let source = r#"
@service
workflow QueueFieldDangling

class Ticket { id string }

tracker backlog { provider builtin }

table seed as Ticket [ { id "1" } ]

rule r
  when Ticket as ticket
=> {
  file issue into backlog {
    title tikcet.id
    body "x"
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown binding `tikcet`")
                && d.message.contains("file into")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_dangling_root_in_invoke_input() {
    // Invoke payload inputs are another value position the type-checker
    // accepted leniently for unknown roots.
    let source = r#"
workflow Parent {
  input task Task
  output result Out

  class Task { id string }
  class Out { x string }

  rule r
    when Task as task
  => {
    invoke Child { item tikcet.id } as c
    after c succeeds as cr {
      done task
      complete result { x cr.summary }
    }
  }
}

workflow Child {
  input item string
  output result ChildOut
  class ChildOut { y string }
  rule c
    when item as i
  => {
    complete result { y "done" }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown binding `tikcet`")
                && d.message.contains("invoke Child")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_dangling_root_in_tell_target() {
    // A dynamic tell target with a typo'd/unbound root was silently accepted
    // (the type lookup returned None and bailed).
    let source = r#"
@service
workflow DanglingTellTarget

class Ticket { id string  provider AgentRef<reviewer> }

agent reviewer { provider fixture  profile "r"  capacity 1 }

table seed as Ticket [ { id "1"  provider reviewer } ]

rule r
  when Ticket as ticket
=> {
  tell tikcet.provider as turn "go"
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown binding `tikcet`")
                && d.message.contains("tell target")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn accepts_effect_binding_root_in_record_value() {
    // The AST-collected root set must include `tell`/`after` results (which
    // the typed `binding_types` map omits), so reading an effect-result field
    // in a record value compiles. This is the case a naive binding_types-only
    // check wrongly rejected.
    let source = r#"
@service
workflow EffectRoot

class Ticket { id string }
class Note { text string }

agent reviewer { provider fixture  profile "r"  capacity 1 }

table seed as Ticket [ { id "1" } ]

rule r
  when Ticket as ticket
  when reviewer is available
=> {
  tell reviewer as turn "review"
  after turn succeeds {
    record Note {
      text turn.summary
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(
        compiled.diagnostics,
        Vec::new(),
        "{:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some());
}

#[test]
fn rejects_invalid_record_fields_paths_and_literals() {
    let source = include_str!("../../../../examples/invalid/bad-record.whip");
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert_eq!(compiled.diagnostics.len(), 5);
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("request.missing")));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("no variant `Maybe`")));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("expects `float`")));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("cannot be `scripted`")));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("no field `extra`")));
}

#[test]
fn rejects_effect_output_outside_after_scope() {
    let source = include_str!("../../../../examples/invalid/effect-output-scope.whip");
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert_eq!(compiled.diagnostics.len(), 1);
    assert!(compiled.diagnostics[0]
        .message
        .contains("outside a matching `after claim ...` block"));
}

/// DR-0043 Decision 5: a `during`/`until` region compiles; the canonical
/// IR body is the condition-HOLDS splice (no region syntax left), and the
/// metadata carries the removed/lapsed variants and the region effects
/// with their level-1 scopes.
#[test]
fn region_compiles_and_ir_carries_variants() {
    let source = r#"
workflow Deploy

output result Done
failure error Halted

class Incident {
  sev string
}

class Done {
  note string
}

class Halted {
  reason string
}

rule ship
  when started
=> {
  until exists(Incident where sev == "sev1") {
    then plan <- timer 1s
    then approved <- timer 1s
    complete result {
      note "shipped"
    }
  } on lapse as got {
    fail error {
      reason "halted"
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "region must compile: {:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("ir");
    let rule = &ir.rules[0];
    assert!(
        !rule.body.contains("until exists") && !rule.body.contains("on lapse"),
        "canonical body is the HOLDS splice: {}",
        rule.body
    );
    let region = rule.metadata.region.as_ref().expect("region metadata");
    assert!(region.until);
    assert_eq!(region.condition, "exists(Incident where sev == \"sev1\")");
    assert_eq!(region.lapse_binding.as_deref(), Some("got"));
    assert!(
        region.body_lapsed.contains("fail error"),
        "lapsed variant carries the arm: {}",
        region.body_lapsed
    );
    assert!(
        !region.body_removed.contains("timer") && !region.body_removed.contains("fail error"),
        "removed variant drops region AND arm: {}",
        region.body_removed
    );
    let bindings: Vec<&str> = region
        .effects
        .iter()
        .map(|effect| effect.binding.as_str())
        .collect();
    assert!(
        bindings.contains(&"__then_plan") && bindings.contains(&"__then_approved"),
        "region effects recorded: {bindings:?}"
    );
}

/// DR-0043 Decision 7 obligation 2: the lapse arm is typed.
///
/// The arm is spliced out of the canonical (HOLDS) rule body, so before this
/// nothing validated it — a bad path was a runtime nothing rather than a
/// compile-time diagnostic. Each of the DR's four rules is checked here, and
/// the step names are the AUTHOR's (`then plan <-` is `got.plan`, not
/// `got.__then_plan`), matching what the kernel pins into the view.
#[test]
fn lapse_arm_progress_view_is_typed() {
    let program = |arm: &str| {
        format!(
            r#"
workflow Deploy
input task Task
output result Done
failure error Halted
class Task {{ id string }}
class Incident {{ sev string }}
class Done {{ note string }}
class Halted {{ reason string }}
class Review {{ verdict string }}

coerce judge(t string) -> Review {{ prompt "judge {{{{ t }}}}" }}

rule ship
  when Task as task
=> {{
  until exists(Incident where sev == "sev1") {{
    then plan <- coerce judge(task.id)
    complete result {{ note "shipped" }}
  }} on lapse as got {{
    fail error {{ reason {arm} }}
  }}
}}
"#
        )
    };
    let bad_path = |arm: &str| {
        compile_program(&program(arm))
            .diagnostics
            .into_iter()
            .find(|d| d.message.contains("invalid field path"))
            .map(|d| d.message)
    };

    // Accepted: a step, a step's status, and a field of a step's own payload.
    for arm in ["got.plan.verdict", "got.steps.plan"] {
        let compiled = compile_program(&program(arm));
        assert!(compiled.ir.is_some(), "{:?}", compiled.diagnostics);
        assert_eq!(bad_path(arm), None, "`{arm}` must resolve");
    }

    // A field that is neither a step nor `steps`.
    assert!(bad_path("got.bogus").is_some_and(|m| m.contains("has no field `bogus`")));
    // A step name that does not exist.
    assert!(bad_path("got.steps.nostep").is_some_and(|m| m.contains("has no field `nostep`")),);
    // A path *through* a status: a status is a string, not a schema.
    assert!(bad_path("got.steps.plan.deeper").is_some_and(|m| m.contains("is not a schema value")),);
    // A deeper path under a step resolves against that step's OWN schema.
    assert!(bad_path("got.plan.bogus").is_some_and(|m| m.contains("`Review` has no field")));
}

/// The same splice hid ordinary bindings too: nothing in the arm was field
/// checked, so `task.bogus` — a plain input binding — compiled clean. That is
/// the wider half of the same gap and is covered by the same walk.
#[test]
fn lapse_arm_validates_ambient_binding_field_paths() {
    let source = r#"
workflow Deploy
input task Task
output result Done
failure error Halted
class Task { id string }
class Incident { sev string }
class Done { note string }
class Halted { reason string }

rule ship
  when Task as task
=> {
  until exists(Incident where sev == "sev1") {
    then plan <- timer 1s
    complete result { note "shipped" }
  } on lapse as got {
    fail error { reason task.bogus }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("invalid field path `task.bogus`")),
        "{:?}",
        compiled.diagnostics
    );
}

/// The splice hid the arm from Family B read-narrowing too: an `on lapse` arm
/// is an egress position like any other, so a presence-conditioned field read
/// there must be inside a matching `case` arm. The region may itself sit inside
/// one, and the arm keeps that arm's allowances — checking it against the rule
/// top would reject a legal read.
#[test]
fn lapse_arm_narrows_conditioned_reads() {
    let program = |arm_body: &str, wrap: bool| {
        let region = format!(
            r#"  until exists(Incident where sev == "sev1") {{
    then plan <- timer 1s
    complete result {{ note "shipped" }}
  }} on lapse as got {{
{arm_body}
  }}"#
        );
        let body = if wrap {
            format!(
                "  case e.kind {{\n    \"deploy\" => {{\n{region}\n    }}\n    \
                     \"rollback\" => {{ complete result {{ note \"rolled back\" }} }}\n  }}"
            )
        } else {
            region
        };
        format!(
            r#"
workflow Deploy
input e Event
output result Done
failure error Halted
class Done {{ note string }}
class Halted {{ reason string }}
class Incident {{ sev string }}
class Event {{
  kind "deploy" | "rollback"
  region string when kind is "deploy"
}}

rule ship
  when Event as e
=> {{
{body}
}}
"#
        )
    };
    let narrowed = |source: &str| {
        compile_program(source)
            .diagnostics
            .into_iter()
            .any(|d| d.message.contains("reads conditional field `e.region`"))
    };

    // Outside any arm: the read leaves the instance through the terminal.
    assert!(narrowed(&program(
        "    fail error { reason e.region }",
        false
    )));
    // Effect operands in the arm are egress reads too (the position #93 closed
    // for the canonical body, which never reached the arm).
    assert!(narrowed(&program(
        "    exec \"deploy {{ e.region }}\" as ran\n    fail error { reason \"lapsed\" }",
        false
    )));
    // Inside the matching `deploy` arm the same read is legal, and the region's
    // enclosing arm is the context the lapse arm inherits.
    let inside = compile_program(&program("        fail error { reason e.region }", true));
    assert!(inside.ir.is_some(), "{:?}", inside.diagnostics);
    assert!(!narrowed(&program(
        "        fail error { reason e.region }",
        true
    )));
}

/// v1 limit: one region per rule; the second draws a spanned error.
#[test]
fn two_regions_in_one_rule_rejected() {
    let source = r#"
workflow Two

output result Done

class Done {
  note string
}

class Flag {
  on string
}

rule go
  when started
=> {
  during empty(Flag) {
    timer 1s as a

    after a completes {
      record Flag {
        on "x"
      }
    }
  } on lapse {
    complete result {
      note "one"
    }
  }

  during empty(Flag) {
    timer 1s as b

    after b completes {
      complete result {
        note "two"
      }
    }
  } on lapse {
    complete result {
      note "three"
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("more than one `during`/`until` region")),
        "second region rejected: {:?}",
        compiled.diagnostics
    );
}

/// The lapse arm may not reference bindings the region introduces — they
/// may not exist when the arm runs; the progress view is the window.
#[test]
fn lapse_arm_referencing_region_binding_rejected() {
    let source = r#"
workflow Scope

output result Done
failure error Halted

class Incident {
  sev string
}

class Done {
  note string
}

class Halted {
  reason string
}

rule go
  when started
=> {
  until exists(Incident where sev == "sev1") {
    then plan <- timer 1s
    complete result {
      note plan.status
    }
  } on lapse {
    fail error {
      reason plan.status
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("references `plan`, a binding the")),
        "arm scope violation rejected: {:?}",
        compiled.diagnostics
    );
}

/// Full-line `#` comments are legal in rule bodies (ruling 2026-07-21):
/// at statement positions, inside `after` arms, between `then` lines
/// (blanked BEFORE then-expansion, so a comment containing braces cannot
/// corrupt the wrap-depth accounting), while a `#` inside a `"""` prompt
/// stays content -- the markdown heading survives to the effect prompt.
#[test]
fn full_line_comments_in_rule_bodies_compile_and_prompts_keep_hashes() {
    let source = r#"
use std.script

workflow Commented

output result Done

class Done {
  note string
}

agent helper

rule go
  when started
=> {
  # request the probe command
  exec "true" as probe

  after probe succeeds {
    # a comment with braces { and quotes " should be inert
    then turn <- tell helper """markdown
    # This heading is prompt CONTENT, not a comment.
    Summarize.
    """
    # comment between then chain and terminal
    complete result {
      note turn.summary
    }
  }

  after probe fails {
    # losing is fine
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.is_empty(),
        "comments must not produce diagnostics: {:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("compiles");
    let rule = &ir.rules[0];
    assert!(
        !rule.body.contains("# request"),
        "compile-path body text is comment-blanked: {}",
        rule.body
    );
    assert!(
        rule.body.contains("# This heading is prompt CONTENT"),
        "prompt interiors are untouched by blanking: {}",
        rule.body
    );
}

/// A `#` after code on the same line is still an error -- trailing
/// comments are top-level-only.
#[test]
fn trailing_comment_in_rule_body_still_rejected() {
    let source = r#"
workflow Trailing

output result Done

class Done {
  note string
}

rule go
  when started
=> {
  complete result {
    note "x"
  } # not allowed here
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unexpected character `#`")),
        "trailing comment must still be rejected: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_effectful_self_trigger_loop() {
    let source = include_str!("../../../../examples/invalid/effectful-self-loop.whip");
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert_eq!(compiled.diagnostics.len(), 1);
    assert!(compiled.diagnostics[0]
        .message
        .contains("preserves trigger fact `schema:WorkItem`"));
}

#[test]
fn rejects_non_file_operation_on_a_file_store_grant() {
    // A grant on a declared file store may only use file operations; a non-file op
    // (e.g. `recall`) is rejected. A non-file-store resource is left alone.
    let program = |op: &str, resource: &str, store: &str| {
        format!(
            r#"
@service
workflow FileGrant

output result R
class R {{ ok bool }}
class Ticket {{ id string  status "open" }}

agent coder {{ provider fixture  profile "repo-writer"  capacity 1 }}

file store {store} {{ root "./data"  allow read ["docs/**"] }}

table seed as Ticket [ {{ id "T1"  status "open" }} ]

rule work
  when Ticket as ticket where ticket.status == "open"
  when coder is available
=> {{
  tell coder as turn
    with access to {resource} {{
      {op}
    }}
  "go"

  after turn succeeds as outcome {{
    complete result {{ ok true }}
  }}
}}
"#
        )
    };

    // `recall` on a declared file store is not a file operation.
    let bad = compile_program(&program(
        "recall for ticket",
        "project_files",
        "project_files",
    ));
    assert!(
        bad.diagnostics
            .iter()
            .any(|d| d.message.contains("not a file operation")),
        "{:?}",
        bad.diagnostics
    );
    // The same `recall` on a non-file-store resource is left alone (could be a
    // package resource) — no false positive.
    let ok = compile_program(&program(
        "recall for ticket",
        "project_memory",
        "project_files",
    ));
    assert!(
        !ok.diagnostics
            .iter()
            .any(|d| d.message.contains("not a file operation")),
        "{:?}",
        ok.diagnostics
    );
}

#[test]
fn parses_memory_pool_declaration_and_snapshots_it() {
    // MEM-1: a `memory pool` declaration lowers to a metadata-only pool with
    // its optional `context limit`, and the .ir snapshot renders it.
    let source = r#"
workflow PoolDecl

memory pool project_memory {
  context limit 8
}
"#;
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("compiles");
    assert_eq!(ir.memory_pools.len(), 1);
    assert_eq!(ir.memory_pools[0].name, "project_memory");
    assert_eq!(ir.memory_pools[0].context_limit, Some(8));
    let snapshot = ir.to_snapshot();
    assert!(snapshot.contains("memory_pools"), "{snapshot}");
    assert!(
        snapshot.contains("memory pool project_memory"),
        "{snapshot}"
    );
    assert!(snapshot.contains("context limit 8"), "{snapshot}");

    // `context limit` is optional — an absent clause lowers to `None` and
    // omits the snapshot line (no ripple), mirroring file-store globs.
    let bare = compile_program("workflow Bare\n\nmemory pool p {\n}\n")
        .ir
        .expect("bare pool compiles");
    assert_eq!(bare.memory_pools[0].context_limit, None);
    assert!(!bare.to_snapshot().contains("context limit"));
}

#[test]
fn rejects_unknown_and_provider_memory_pool_clauses() {
    // Unknown clauses are rejected (file-store precedent). Since the
    // declaration-family migration (M2), `provider` is no longer a bespoke
    // "pools have no provider" clause but a generic unknown field — v1 pools
    // are provider-less, so it is simply not in the grammar.
    let unknown = compile_program("workflow U\n\nmemory pool p {\n  retention 5\n}\n");
    assert!(
        unknown
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown memory pool field `retention`")),
        "{:?}",
        unknown.diagnostics
    );
    let provider = compile_program("workflow P\n\nmemory pool p {\n  provider local\n}\n");
    assert!(
        provider
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unknown memory pool field `provider`")),
        "{:?}",
        provider.diagnostics
    );
}

#[test]
fn rejects_non_memory_operation_on_a_memory_pool_grant() {
    // MEM-1 static check 2 (mirrors the file-store grant precedent): a grant on
    // a declared memory pool may only use memory operations; a non-memory op
    // (e.g. a file `read`) is rejected. A grant on a non-pool resource is left
    // alone (zero-false-positive) — this closes the memory-grant-validation
    // deferral, now that `ir.memory_pools` gives a declared-pool list.
    let program = |op: &str, resource: &str, pool: &str| {
        format!(
            r#"
@service
workflow MemoryGrant

output result R
class R {{ ok bool }}
class Ticket {{ id string  status "open" }}

agent coder {{ provider fixture  profile "repo-writer"  capacity 1 }}

memory pool {pool} {{ context limit 8 }}

table seed as Ticket [ {{ id "T1"  status "open" }} ]

rule work
  when Ticket as ticket where ticket.status == "open"
  when coder is available
=> {{
  tell coder as turn
    with access to {resource} {{
      {op}
    }}
  "go"

  after turn succeeds as outcome {{
    complete result {{ ok true }}
  }}
}}
"#
        )
    };

    // A file `read` on a declared memory pool is not a memory operation.
    let bad = compile_program(&program(
        r#"read ["docs/**"]"#,
        "project_memory",
        "project_memory",
    ));
    assert!(
        bad.diagnostics
            .iter()
            .any(|d| d.message.contains("not a memory operation")),
        "{:?}",
        bad.diagnostics
    );

    // A memory operation (`recall`/`learn`) on the declared pool is accepted.
    let ok_recall = compile_program(&program(
        "recall for ticket\n      learn for ticket",
        "project_memory",
        "project_memory",
    ));
    assert!(
        !ok_recall
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not a memory operation")),
        "{:?}",
        ok_recall.diagnostics
    );

    // The same file `read` on a non-pool resource is left alone (no false
    // positive) — it could be a file store or a package-provided resource.
    let ok_other = compile_program(&program(
        r#"read ["docs/**"]"#,
        "project_files",
        "project_memory",
    ));
    assert!(
        !ok_other
            .diagnostics
            .iter()
            .any(|d| d.message.contains("not a memory operation")),
        "{:?}",
        ok_other.diagnostics
    );
}

#[test]
fn rejects_malformed_turn_access_grants() {
    // An empty grant block and a duplicate resource on one `tell` are both
    // structurally malformed.
    let program = |grant_block: &str| {
        format!(
            r#"
@service
workflow GrantCheck

output result R
class R {{ ok bool }}
class Ticket {{ id string  status "open" }}

agent coder {{ provider fixture  profile "repo-writer"  capacity 1 }}

table seed as Ticket [ {{ id "T1"  status "open" }} ]

rule work
  when Ticket as ticket where ticket.status == "open"
  when coder is available
=> {{
  tell coder as turn
{grant_block}
  "Work it."

  after turn succeeds as outcome {{
    complete result {{ ok true }}
  }}
}}
"#
        )
    };

    let empty = compile_program(&program("    with access to project_memory {\n    }\n"));
    assert!(
        empty
            .diagnostics
            .iter()
            .any(|d| d.message.contains("grants no operations")),
        "{:?}",
        empty.diagnostics
    );

    let duplicate = compile_program(&program(
            "    with access to project_memory {\n      recall for ticket\n    }\n    with access to project_memory {\n      learn for ticket\n    }\n",
        ));
    assert!(
        duplicate
            .diagnostics
            .iter()
            .any(|d| d.message.contains("more than once")),
        "{:?}",
        duplicate.diagnostics
    );
}

/// MEM-5 static check 4: a memory grant on a tell whose harness is a
/// native adapter warns (the grant is inert there); the same grant on
/// an owned harness stays quiet.
#[test]
fn warns_inert_memory_grant_on_a_native_adapter_tell() {
    let program = |harness_kind: &str| {
        format!(
            r#"
@service
workflow InertGrant

output result R
class R {{ ok bool }}
class Ticket {{ id string  status "open" }}

memory pool project_memory {{
  context limit 4
}}

harness h: {harness_kind}
agent coder using h {{ profile "repo-writer"  capacity 1 }}

table seed as Ticket [ {{ id "T1"  status "open" }} ]

rule work
  when Ticket as ticket where ticket.status == "open"
  when coder is available
=> {{
  tell coder as turn
    with access to project_memory {{
      recall for ticket
    }}
  "Work it."

  after turn succeeds as outcome {{
    complete result {{ ok true }}
  }}
}}
"#
        )
    };
    let native = compile_program(&program("codex"));
    assert!(
        native.diagnostics.is_empty(),
        "the grant itself is legal: {:?}",
        native.diagnostics
    );
    assert!(
        native
            .warnings
            .iter()
            .any(|warning| warning.message.contains("inert")),
        "a codex-harness tell warns: {:?}",
        native.warnings
    );
    let owned = compile_program(&program("owned"));
    assert!(
        owned
            .warnings
            .iter()
            .all(|warning| !warning.message.contains("inert")),
        "an owned-harness tell does not warn: {:?}",
        owned.warnings
    );
}

#[test]
fn counter_timezone_clause_parses_and_default_utc_warns() {
    // std.coord slice 3: `timezone "<IANA zone>"` anchors the counter's
    // reset-period boundary; omitting it is legal but draws the
    // default-UTC warning.
    let program = |timezone_clause: &str| {
        format!(
            r#"
@service
workflow CounterTz

class CallFailed {{ service string }}
class Service {{ id string }}
output result CallFailed
failure trouble CallFailed

counter failure_budget {{ key Service cap 3 reset daily {timezone_clause} }}

rule strike
  when CallFailed as f
=> {{
  consume failure_budget for f.service amount 1 as strike
  after strike ok {{
    complete result {{ service f.service }}
  }}
  after strike over {{
    fail trouble {{ service f.service }}
  }}
}}
"#
        )
    };
    let anchored = compile_program(&program(r#"timezone "America/New_York""#));
    assert!(
        anchored.diagnostics.is_empty(),
        "timezone clause parses: {:?}",
        anchored.diagnostics
    );
    let ir = anchored.ir.expect("anchored program compiles");
    assert_eq!(ir.counters[0].timezone.as_deref(), Some("America/New_York"));
    assert!(
        anchored
            .warnings
            .iter()
            .all(|warning| !warning.message.contains("timezone")),
        "an anchored counter does not warn: {:?}",
        anchored.warnings
    );

    let unanchored = compile_program(&program(""));
    assert!(
        unanchored.diagnostics.is_empty(),
        "omitting timezone stays legal: {:?}",
        unanchored.diagnostics
    );
    let ir = unanchored.ir.expect("unanchored program compiles");
    assert_eq!(ir.counters[0].timezone, None);
    assert!(
        unanchored
            .warnings
            .iter()
            .any(|warning| warning.message.contains("anchors to UTC")),
        "an unanchored counter draws the default-UTC warning: {:?}",
        unanchored.warnings
    );
}

#[test]
fn then_sugar_desugars_to_nested_after_and_composes_in_after_blocks() {
    // R2: `then <binding> <- <effect>` is pure parser sugar for
    // `after <handle> succeeds as <binding> { … }` with a synthetic
    // `__then_*` handle; it composes inside after blocks; and the reserved
    // namespace is rejected in author text.
    let source = r#"
use std.script

workflow ThenSugar

output result Done

class Done {
  note string
}

class Trigger {
  id string
}

table seed as Trigger [
  { id "t" }
]

rule pipeline
  when Trigger as t
=> {
  exec "true" as pre

  after pre succeeds {
    then a <- exec "one"
    then b <- exec "two"
    complete result {
      note b.stdout
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("compiles");
    let body = &ir
        .rules
        .iter()
        .find(|rule| rule.name == "pipeline")
        .expect("rule")
        .body;
    assert!(
        body.contains("exec \"one\" as __then_a"),
        "the chained effect binds the synthetic handle:\n{body}"
    );
    assert!(
        body.contains("after __then_a succeeds as a {"),
        "the continuation nests under the success predicate:\n{body}"
    );
    assert!(
        body.contains("after __then_b succeeds as b {"),
        "chained thens nest:\n{body}"
    );
    assert!(!body.contains("then a <-"), "no sugar survives:\n{body}");

    let reserved = compile_program(
        r#"
use std.script

workflow Reserved

output result Done

class Done {
  note string
}

rule r
  when started
=> {
  exec "true" as __then_x

  after __then_x succeeds {
    complete result { note "no" }
  }
}
"#,
    );
    assert!(
        reserved
            .diagnostics
            .iter()
            .any(|d| d.message.contains("reserved `__then_` binding namespace")),
        "{:?}",
        reserved.diagnostics
    );
}

#[test]
fn warns_on_unhandled_effect_failure_and_stays_quiet_when_observed() {
    // Auto-fail R1a: an effect handled only via `after … succeeds` draws the
    // prominent unhandled-failure warning; a `fails` or `completes` observer
    // silences it.
    let program = |handler: &str| {
        format!(
            r#"
use std.script

workflow AutoFailWarn

output result Done
failure error Broken

class Done {{ note string }}
class Broken {{ reason string }}
class Trigger {{ id string }}

table seed as Trigger [
  {{ id "t" }}
]

rule r
  when Trigger as t
=> {{
  exec "true" as x

  after x succeeds {{
    complete result {{ note "ok" }}
  }}
{handler}}}
"#
        )
    };
    let unhandled = compile_program(&program(""));
    assert!(
        unhandled.diagnostics.is_empty(),
        "{:?}",
        unhandled.diagnostics
    );
    assert!(
        unhandled
            .warnings
            .iter()
            .any(|warning| warning.message.contains("`x`'s failure is unhandled")),
        "succeeds-only handling draws the R1a warning: {:?}",
        unhandled.warnings
    );

    for observer in [
        "\n  after x fails {\n    fail error { reason \"broken\" }\n  }\n",
        "\n  after x completes {\n    complete result { note \"any\" }\n  }\n",
        "\n  after x times out {\n    fail error { reason \"slow\" }\n  }\n",
    ] {
        let observed = compile_program(&program(observer));
        assert!(
            observed.diagnostics.is_empty(),
            "{:?}",
            observed.diagnostics
        );
        assert!(
            observed
                .warnings
                .iter()
                .all(|warning| !warning.message.contains("failure is unhandled")),
            "an observer silences the warning ({observer:?}): {:?}",
            observed.warnings
        );
    }
}

#[test]
fn unhandled_failure_warning_exempts_services_timers_and_coordination() {
    // Auto-fail R1a exemptions: `@service` workflows record diagnostics
    // instead of auto-failing (so the warning's framing would be wrong),
    // timers cannot fail, and coordination outcome observers
    // (`held`/`contended`/`ok`/`over`) count as observers at check time.
    let service = compile_program(
        r#"
use std.script

@service
workflow ServiceQuiet

class Trigger { id string }
class Seen { note string }

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  exec "true" as x

  after x succeeds {
    record Seen { note "ok" }
  }
}
"#,
    );
    assert!(service.diagnostics.is_empty(), "{:?}", service.diagnostics);
    assert!(
        service
            .warnings
            .iter()
            .all(|warning| !warning.message.contains("failure is unhandled")),
        "@service is exempt: {:?}",
        service.warnings
    );

    let timer = compile_program(
        r#"
workflow TimerQuiet

output result Done

class Done { note string }
class Trigger { id string }

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  timer 5m as pause

  after pause completes {
    complete result { note "ok" }
  }
}
"#,
    );
    assert!(timer.diagnostics.is_empty(), "{:?}", timer.diagnostics);
    assert!(
        timer
            .warnings
            .iter()
            .all(|warning| !warning.message.contains("failure is unhandled")),
        "timers are exempt: {:?}",
        timer.warnings
    );

    let coordination = compile_program(
        r#"
workflow CoordQuiet

output result Done
failure error Broken

class Done { note string }
class Broken { reason string }
class Trigger { id string }

lease build_slot { key Trigger ttl 10m }

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  acquire build_slot for t.id as slot

  after slot held {
    complete result { note "ok" }
  }

  after slot contended {
    fail error { reason "busy" }
  }
}
"#,
    );
    assert!(
        coordination.diagnostics.is_empty(),
        "{:?}",
        coordination.diagnostics
    );
    assert!(
        coordination
            .warnings
            .iter()
            .all(|warning| !warning.message.contains("failure is unhandled")),
        "coordination outcome observers count at check time: {:?}",
        coordination.warnings
    );
}

#[test]
fn lowers_turn_access_grants_onto_the_agent_tell_effect() {
    // `with access to <resource> { … }` on a tell lowers to `access_grants` on the
    // agent.tell IR effect (Proposal A authority-narrowing metadata).
    let source = r#"
@service
workflow GrantDemo

output result R
class R { ok bool }
class Ticket { id string  status "open" }

agent coder { provider fixture  profile "repo-writer"  capacity 1 }

table seed as Ticket [ { id "T1"  status "open" } ]

rule work
  when Ticket as ticket where ticket.status == "open"
  when coder is available
=> {
  tell coder as turn
    with access to project_memory {
      recall for ticket
      learn for ticket
    }
    with access to project_files {
      read ["docs/**"]
    }
  "Work it."

  after turn succeeds as outcome {
    complete result { ok true }
  }
}
"#;
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("compiles");
    let tell = ir
        .rules
        .iter()
        .flat_map(|rule| rule.metadata.effects.iter())
        .find(|effect| effect.kind == IrEffectKind::AgentTell)
        .expect("agent.tell effect");
    assert_eq!(tell.access_grants.len(), 2);
    let memory = &tell.access_grants[0];
    assert_eq!(memory.resource, "project_memory");
    assert_eq!(memory.operations.len(), 2);
    assert_eq!(memory.operations[0].operation, "recall");
    assert_eq!(memory.operations[0].target.as_deref(), Some("ticket"));
    let files = &tell.access_grants[1];
    assert_eq!(files.resource, "project_files");
    assert_eq!(files.operations[0].operation, "read");
    assert_eq!(files.operations[0].globs, vec!["docs/**".to_owned()]);
}

#[test]
fn lowers_start_access_grants_onto_the_workflow_invoke_effect() {
    // `with access to <resource> { … }` on an invoke lowers to the same
    // `access_grants` metadata, ready for the start-grant attenuation seam.
    let source = r#"
workflow Parent {
  class Task { id string }

  rule dispatch
    when Task as task
  => {
    invoke Child { task task }
      with access to project_files {
        read ["docs/**"]
      }
      as child
  }
}

workflow Child {
  input task Task
  class Task { id string }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    let ir = compiled.ir.unwrap_or_else(|| {
        panic!(
            "source should compile, diagnostics: {:?}",
            compiled
                .diagnostics
                .iter()
                .map(|d| &d.message)
                .collect::<Vec<_>>()
        )
    });
    let invoke = ir
        .rules
        .iter()
        .flat_map(|rule| rule.metadata.effects.iter())
        .find(|effect| effect.kind == IrEffectKind::WorkflowInvoke)
        .expect("workflow.invoke effect");
    assert_eq!(invoke.binding.as_deref(), Some("child"));
    assert_eq!(invoke.access_grants.len(), 1);
    let files = &invoke.access_grants[0];
    assert_eq!(files.resource, "project_files");
    assert_eq!(files.operations[0].operation, "read");
    assert_eq!(files.operations[0].globs, vec!["docs/**".to_owned()]);
}

#[test]
fn lowers_resource_less_start_access_grant_shorthand_onto_the_workflow_invoke_effect() {
    // `with access to { <resource> { ... } ... }` is syntax sugar for multiple
    // resource-specific start grants.
    let source = r#"
workflow Parent {
  class Task { id string }

  rule dispatch
    when Task as task
  => {
    invoke Child { task task }
      with access to {
        project_memory {
          recall for task
        }
        project_files {
          read ["docs/**"]
        }
      }
      as child
  }
}

workflow Child {
  input task Task
  class Task { id string }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    let ir = compiled.ir.unwrap_or_else(|| {
        panic!(
            "source should compile, diagnostics: {:?}",
            compiled
                .diagnostics
                .iter()
                .map(|d| &d.message)
                .collect::<Vec<_>>()
        )
    });
    let invoke = ir
        .rules
        .iter()
        .flat_map(|rule| rule.metadata.effects.iter())
        .find(|effect| effect.kind == IrEffectKind::WorkflowInvoke)
        .expect("workflow.invoke effect");
    assert_eq!(invoke.binding.as_deref(), Some("child"));
    assert_eq!(invoke.access_grants.len(), 2);
    let memory = &invoke.access_grants[0];
    assert_eq!(memory.resource, "project_memory");
    assert_eq!(memory.operations[0].operation, "recall");
    assert_eq!(memory.operations[0].target.as_deref(), Some("task"));
    let files = &invoke.access_grants[1];
    assert_eq!(files.resource, "project_files");
    assert_eq!(files.operations[0].operation, "read");
    assert_eq!(files.operations[0].globs, vec!["docs/**".to_owned()]);
}

#[test]
fn rejects_rule_matching_evidence_only_turn_fact() {
    // In-turn observations (streamed/tool_requested/artifact_captured) are
    // evidence, never rule-matchable (spec/agent-harness.md); a `when` on them is
    // an error. The lifecycle facts (completed/failed/…) stay matchable.
    for evidence in [
        "agent.turn.streamed",
        "agent.turn.tool_requested",
        "agent.turn.artifact_captured",
    ] {
        let source = format!(
                "workflow EvidenceMatch\n\noutput result R\nclass R {{ ok bool }}\n\nrule react\n  when fact {evidence} as ev\n=> {{\n  complete result {{ ok true }}\n}}\n"
            );
        let compiled = compile_program(&source);
        assert!(compiled.ir.is_none(), "{evidence} should be rejected");
        assert!(
            compiled
                .diagnostics
                .iter()
                .any(|d| d.message.contains("evidence-only fact") && d.message.contains(evidence)),
            "{evidence}: {:?}",
            compiled.diagnostics
        );
    }
    // A matchable lifecycle fact does NOT get the evidence error (it may fail a
    // different check, e.g. needing a producer, but not this one).
    let matchable = "workflow M\n\noutput result R\nclass R {{ ok bool }}\n\nrule react\n  when fact agent.turn.completed as ev\n=> {{\n  complete result {{ ok true }}\n}}\n".replace("{{", "{").replace("}}", "}");
    let compiled = compile_program(&matchable);
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("evidence-only fact")),
        "completed must not be flagged as evidence-only: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_self_recursive_pattern_application() {
    // A pattern whose body applies itself is unbounded recursion: it can never
    // elaborate into a finite first-order program (graph.unbounded_pattern_recursion).
    let source = include_str!("../../../../examples/invalid/recursive-pattern.whip");
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    // Exactly the precise recursion diagnostic — the generic "nested apply not
    // supported yet" message must be suppressed for the recursive case.
    assert_eq!(compiled.diagnostics.len(), 1, "{:?}", compiled.diagnostics);
    let diagnostic = &compiled.diagnostics[0];
    assert!(
        diagnostic
            .message
            .contains("graph.unbounded_pattern_recursion"),
        "{}",
        diagnostic.message
    );
    assert!(
        diagnostic.message.contains("expansion cycle Loop -> Loop"),
        "the diagnostic names the cycle: {}",
        diagnostic.message
    );
}

#[test]
fn rejects_mutually_recursive_pattern_application() {
    // A cycle that spans two patterns is rejected once, naming the full cycle.
    let source = r#"
workflow MutualRecursion

class Item {
  id string
}

pattern Ping<T> {
  apply Pong<T> as a {
  }
}

pattern Pong<T> {
  apply Ping<T> as b {
  }
}

apply Ping<Item> as top {
}
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    let recursion: Vec<&Diagnostic> = compiled
        .diagnostics
        .iter()
        .filter(|d| d.message.contains("graph.unbounded_pattern_recursion"))
        .collect();
    // One cycle, reported once (members covered are not re-reported).
    assert_eq!(recursion.len(), 1, "{:?}", compiled.diagnostics);
    assert!(
        recursion[0].message.contains("Ping -> Pong -> Ping"),
        "names the full cycle: {}",
        recursion[0].message
    );
}

#[test]
fn allows_non_recursive_nested_apply_without_recursion_error() {
    // A nested apply that does NOT form a cycle is a separate v0 limitation
    // (the generic "not supported yet" message), NOT a recursion error.
    let source = r#"
workflow NonRecursive

class Item {
  id string
}

pattern Inner<T> {
}

pattern Outer<T> {
  apply Inner<T> as x {
  }
}

apply Outer<Item> as top {
}
"#;
    let compiled = compile_program(source);

    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("graph.unbounded_pattern_recursion")),
        "non-recursive nesting must not be flagged as recursion: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn rejects_unknown_or_wrong_arity_coerce_calls() {
    let source = r#"
workflow BadCoerce

class Review {
  reason string
}

coerce review(summary string) -> Review {
  prompt "review"
}

rule bad
  when started
=> {
  coerce missing("x") as one
  coerce review("x", "y") as two
}
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert_eq!(compiled.diagnostics.len(), 2);
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("unknown coerce function `missing`")));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("with 2 argument(s), expected 1")));
}

#[test]
fn rejects_bad_effect_payload_argument_types() {
    let source = r#"
workflow BadEffectPayloads

class Owner {
  name string
}

class Payload {
  title string
  owner Owner
  metadata map<string>
  tags string[]
}

class Task {
  title string
  owner string
}

class Review {
  accepted bool
}

coerce reviewPayload(payload Payload, metadata map<string>, score int) -> Review {
  prompt "review"
}

rule bad_coerce
  when Task as task where { owner "Ada" } == task.owner
=> {
  coerce reviewPayload(
    {
      title task.title
      owner { handle task.owner }
      metadata { phase 3 }
      tags ["object", 7]
      extra "bad"
    },
    { phase task.owner, count 3 },
    "high"
  ) as review
}
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    let messages = compiled
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect::<Vec<_>>();
    assert!(messages
        .iter()
        .any(|message| message.contains("object literal without an expected object")));
    assert!(messages
        .iter()
        .any(|message| message.contains("class `Owner` has no field `handle`")));
    assert!(messages
        .iter()
        .any(|message| message.contains("missing required object field `Owner.name`")));
    assert!(messages
        .iter()
        .any(|message| message.contains("class `Payload` has no field `extra`")));
    assert!(messages.iter().any(
        |message| message.contains("field `coerce `reviewPayload`.metadata` expects `string`")
    ));
    assert!(messages
        .iter()
        .any(|message| { message.contains("field `coerce `reviewPayload`.score` expects `int`") }));
}

#[test]
fn lowers_fact_consumption_metadata() {
    let source = r#"
workflow ConsumeTask

class Task {
  status "queued"
}

rule finish
  when Task as task
=> {
  done task
}
"#;
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("program compiles");

    assert_eq!(ir.rules[0].metadata.fact_consumes, vec!["schema:Task"]);
    assert!(ir.to_snapshot().contains("consumes\n      schema:Task"));
}

#[test]
fn rejects_unknown_fact_consumption_binding() {
    let source = r#"
workflow BadConsume

class Task {
  status "queued"
}

rule finish
  when Task as task
=> {
  done missing
}
"#;
    let compiled = compile_program(source);

    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("consumes unknown fact binding `missing`")));
}

#[test]
fn rejects_then_sequencing() {
    let source = r#"
workflow NoThen

class Task {
  topic string
  status "queued"
}

class Result {
  topic string
  turn AgentTurn
  status "done"
}

agent codex {
  provider codex
  profile "repo-writer"
  capacity 1
}

assert count(Task where status == "queued") == 0
assert count(Result where status == "done") == 1

rule finish
  when Task as task where task.status == "queued"
  when codex is available
=> {
  tell codex as turn "write"
  then done task -> record Result from task {
    topic
    turn turn
    status "done"
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("unsupported `then` sequencing")));
}

#[test]
fn rejects_after_arrow_sequencing() {
    let source = r#"
workflow NoAfterArrow

agent codex {
  provider codex
  profile "repo-writer"
  capacity 1
}

rule finish
  when started
  when codex is available
=> {
  tell codex as turn "write"

  after turn succeeds => {
    record Done {
      status "done"
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(compiled.ir.is_none());
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("unsupported `after ... =>` sequencing")));
}

#[test]
fn formats_top_level_syntax_scaffold() {
    let source = r#"workflow Messy
class Status {
kind "open"|"done"
}
rule start
when started
=> {tell worker "hi"}
"#;

    let formatted = format_program(source);
    assert_eq!(formatted.diagnostics, Vec::new());
    let expected = concat!(
        "workflow Messy\n",
        "\n",
        "class Status {\n",
        "  kind \"open\" | \"done\"\n",
        "}\n",
        "\n",
        "rule start\n",
        "  when started\n",
        "=> {\n",
        "  tell worker \"hi\"\n",
        "}\n",
    );

    assert_eq!(formatted.formatted.as_deref(), Some(expected));
}

#[test]
fn formats_content_typed_multiline_prompts() {
    let source = r#"workflow PromptFormat
class Review {
status "ok"
}
coerce review() -> Review {
prompt """markdown
classify
"""
}
agent worker {
  provider fixture
profile "repo-writer"
capacity 1
}
rule start
when started
=> {tell worker as turn """markdown
write
"""
tell worker """application/json
{"question":"approve?"}
"""}
"#;

    let formatted = format_program(source);
    assert_eq!(formatted.diagnostics, Vec::new());
    let expected = concat!(
        "workflow PromptFormat\n",
        "\n",
        "class Review {\n",
        "  status \"ok\"\n",
        "}\n",
        "\n",
        "coerce review() -> Review {\n",
        "  prompt \"\"\"markdown\n",
        "  classify\n",
        "  \"\"\"\n",
        "}\n",
        "\n",
        "agent worker {\n",
        "  provider fixture\n",
        "  profile \"repo-writer\"\n",
        "  capacity 1\n",
        "}\n",
        "\n",
        "rule start\n",
        "  when started\n",
        "=> {\n",
        "  tell worker as turn \"\"\"markdown\n",
        "  write\n",
        "  \"\"\"\n",
        "  tell worker \"\"\"application/json\n",
        "  {\"question\":\"approve?\"}\n",
        "  \"\"\"\n",
        "}\n",
    );

    assert_eq!(formatted.formatted.as_deref(), Some(expected));
}

#[test]
fn formats_harness_declarations_and_agent_bindings() {
    let source = r#"workflow HarnessFormat
harness coder: codex
agent implementer using coder {
profile "repo-writer"
capacity 1
}
"#;

    let formatted = format_program(source);
    assert_eq!(formatted.diagnostics, Vec::new());
    let expected = concat!(
        "workflow HarnessFormat\n",
        "\n",
        "harness coder: codex\n",
        "\n",
        "agent implementer using coder {\n",
        "  profile \"repo-writer\"\n",
        "  capacity 1\n",
        "}\n",
    );

    assert_eq!(formatted.formatted.as_deref(), Some(expected));
}

#[test]
fn formats_explicit_workflow_blocks() {
    let source = r#"class Shared {
id string
}
workflow One {
input item Shared
rule start
when Shared as item
=> {complete result {id item.id}}
}
"#;

    let formatted = format_program(source);
    assert_eq!(formatted.diagnostics, Vec::new());
    let expected = concat!(
        "class Shared {\n",
        "  id string\n",
        "}\n",
        "\n",
        "workflow One {\n",
        "  input item Shared\n",
        "\n",
        "  rule start\n",
        "    when Shared as item\n",
        "  => {\n",
        "    complete result {id item.id}\n",
        "  }\n",
        "}\n",
    );

    assert_eq!(formatted.formatted.as_deref(), Some(expected));
}

#[test]
fn formats_invoke_start_access_grants() {
    let source = r#"workflow Parent {
file store project_files { root "./data" allow read ["docs/**"] allow write ["reports/**"] }
class Task { id string }
rule dispatch
when Task as task
=> {
invoke Child {
task task
}
with access to project_files {
read ["docs/**"]
write ["reports/**"]
}
as child
}
}

workflow Child {
input task Task
class Task { id string }
}
"#;

    let formatted = format_program(source);
    assert_eq!(formatted.diagnostics, Vec::new());
    let expected = concat!(
        "workflow Parent {\n",
        "  file store project_files {\n",
        "    root \"./data\"\n",
        "    allow read [\"docs/**\"]\n",
        "    allow write [\"reports/**\"]\n",
        "  }\n",
        "\n",
        "  class Task {\n",
        "    id string\n",
        "  }\n",
        "\n",
        "  rule dispatch\n",
        "    when Task as task\n",
        "  => {\n",
        "    invoke Child {\n",
        "      task task\n",
        "    }\n",
        "    with access to project_files {\n",
        "      read [\"docs/**\"]\n",
        "      write [\"reports/**\"]\n",
        "    }\n",
        "    as child\n",
        "  }\n",
        "}\n",
        "\n",
        "workflow Child {\n",
        "  input task Task\n",
        "\n",
        "  class Task {\n",
        "    id string\n",
        "  }\n",
        "}\n",
    );

    assert_eq!(formatted.formatted.as_deref(), Some(expected));
}

#[test]
fn formats_patterns_and_apply_syntax() {
    let source = r#"pattern Review<Input>{
rule dispatch
when Input as item
=> {}
}
workflow Root {
apply Review<Task> as taskReview {}
}
"#;

    let formatted = format_program(source);
    assert_eq!(formatted.diagnostics, Vec::new());
    let expected = concat!(
        "pattern Review<Input> {\n",
        "  rule dispatch\n",
        "    when Input as item\n",
        "  => {\n",
        "  }\n",
        "}\n",
        "\n",
        "workflow Root {\n",
        "  apply Review<Task> as taskReview {\n",
        "  }\n",
        "}\n",
    );

    assert_eq!(formatted.formatted.as_deref(), Some(expected));
}

#[test]
fn lexer_captures_comments_without_affecting_tokens() {
    let source = "# top comment\nworkflow Demo\n\nclass Task {\n  title string  // trailing\n}\n";
    let comments = lex_comments(source);
    assert_eq!(comments.len(), 2);
    assert_eq!(comments[0].marker, CommentMarker::Hash);
    assert_eq!(comments[0].text, "top comment");
    assert_eq!(comments[1].marker, CommentMarker::Slash);
    assert_eq!(comments[1].text, "trailing");
    // Spans point back at the original source slice (marker through line end).
    let first = &comments[0];
    assert_eq!(&source[first.span.start..first.span.end], "# top comment");
    // Comments stay out of the parse: the program still compiles cleanly.
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
}

#[test]
fn test_block_parses_given_run_and_expect_clauses() {
    let source = r#"
@service
workflow Demo

test "ci triage" {
  given signal github.workflow_failed {
    run_id "run_123"
  }
  stub agent triager succeeds
  run until idle
  expect issue count where external_id == "run_123" is 1
  expect rule triage_failed_run fired
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    assert_eq!(ir.tests.len(), 1);
    let test = &ir.tests[0];
    assert_eq!(test.name, "ci triage");
    assert_eq!(test.clauses.len(), 5);

    match &test.clauses[0] {
        TestClause::Given(GivenClause::Signal { name, fields, .. }) => {
            assert_eq!(name, "github.workflow_failed");
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].name.name, "run_id");
            assert_eq!(fields[0].value, "\"run_123\"");
        }
        other => panic!("expected given signal, got {other:?}"),
    }
    match &test.clauses[1] {
        TestClause::Stub(stub) => {
            assert_eq!(stub.surface, vec!["agent".to_owned(), "triager".to_owned()]);
            assert_eq!(stub.outcome, "succeeds");
        }
        other => panic!("expected stub, got {other:?}"),
    }
    assert!(matches!(
        &test.clauses[2],
        TestClause::Run(RunClause {
            kind: RunKind::UntilIdle,
            ..
        })
    ));
    match &test.clauses[3] {
        TestClause::Expect(ExpectClause {
            target: ExpectTarget::Projection(query),
            ..
        }) => {
            assert_eq!(query.noun, "issue");
            match &query.kind {
                ProjQueryKind::Count { predicate, count } => {
                    assert_eq!(predicate, "external_id == \"run_123\"");
                    assert_eq!(*count, 1);
                }
                other => panic!("expected count query, got {other:?}"),
            }
        }
        other => panic!("expected expect projection, got {other:?}"),
    }
    match &test.clauses[4] {
        TestClause::Expect(ExpectClause {
            target: ExpectTarget::Rule { name, status },
            ..
        }) => {
            assert_eq!(name.name, "triage_failed_run");
            assert_eq!(*status, RuleStatus::Fired);
        }
        other => panic!("expected expect rule, got {other:?}"),
    }
}

#[test]
fn test_block_rejects_a_malformed_predicate() {
    let source = r#"
@service
workflow Demo

test "bad predicate" {
  run until idle
  expect issue count where == == is 1
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("predicate on `issue`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn source_clock_block_lowers_to_clock_source() {
    let source = r#"
workflow ClockSource

signal triage.tick {
  scheduled_at time
  observed_at time
  occurrence_id string
  missed_count int
}

source clock as daily_triage {
  every weekday at 09:00
  timezone "America/New_York"
  missed coalesce

  observe as tick
  emit triage.tick {
    scheduled_at tick.scheduled_at
    observed_at tick.observed_at
    occurrence_id tick.occurrence_id
    missed_count tick.missed_count
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    assert_eq!(ir.sources.len(), 1);
    let decl = &ir.sources[0];
    assert_eq!(decl.name, "daily_triage");
    assert_eq!(decl.provider, "clock");
    assert!(decl.is_clock);
    assert_eq!(decl.observe_binding, "tick");
    assert_eq!(decl.emit_signal, "triage.tick");
    assert_eq!(decl.emit_fields.len(), 4);
    assert_eq!(decl.timezone.as_deref(), Some("America/New_York"));
    assert_eq!(decl.missed, Some(MissedPolicy::Coalesce));
    match &decl.recurrence {
        Some(Recurrence::EveryCalendar { pattern, time, .. }) => {
            assert_eq!(*pattern, CalendarPattern::Weekday);
            assert_eq!(time.hour, 9);
            assert_eq!(time.minute, 0);
        }
        other => panic!("expected calendar recurrence, got {other:?}"),
    }
    // T1 (spec/std-time.md): declaring a clock source registers the
    // std.time standard library, exactly as a channel declaration
    // registers std.messaging.
    let registry = ir.contract_registry();
    assert!(
        registry
            .libraries
            .iter()
            .any(|library| library.id == "std.time" && library.standard),
        "clock source registers std.time: {:?}",
        registry.libraries
    );
}

#[test]
fn gauge_and_campaign_declarations_parse_and_lower() {
    let source = r##"
@service
workflow Improve

output result R
class R { v string }
signal go.now { x string }

coerce DueDateJudge(v string) -> R {
  prompt """markdown
  Judge {{ v }}.

  {{ ctx.output_format }}
  """
}

gauge extract_quality on j.result {
  judge via coerce DueDateJudge
  expect P(due_date_correct) at least 0.9
}

gauge tail_latency {
  judge via exec "./latency_check.py"
  expect p90 at most 800
}

gauge fulfillment_cost {
  judge via exec "./cost_model.py"
  inputs extract_quality, std.spend
}

campaign release_tuning {
  ascend extract_quality
  reach std.latency at most 800ms
  guard tail_latency within 2 percent
  sacrifice fulfillment_cost
  proposer redacted
}

rule j
  when go.now as g
=> {
  complete result {
    v "ok"
  }
}
"##;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    assert_eq!(ir.gauges.len(), 3);
    let extract = &ir.gauges[0];
    assert_eq!(extract.name, "extract_quality");
    assert_eq!(extract.site.as_deref(), Some("j.result"));
    assert_eq!(extract.judge_kind, "coerce");
    assert_eq!(extract.judge_target, "DueDateJudge");
    let bar = extract.expect.as_ref().expect("bar declared");
    assert_eq!(
        (
            bar.form.as_str(),
            bar.subject.as_str(),
            bar.op.as_str(),
            bar.threshold.as_str()
        ),
        ("chance", "due_date_correct", ">=", "0.9")
    );
    let tail = &ir.gauges[1];
    let tail_bar = tail.expect.as_ref().expect("stat bar declared");
    assert_eq!(
        (
            tail_bar.form.as_str(),
            tail_bar.subject.as_str(),
            tail_bar.op.as_str()
        ),
        ("stat", "p90", "<=")
    );
    let derived = &ir.gauges[2];
    assert_eq!(derived.judge_kind, "exec");
    assert_eq!(derived.inputs, vec!["extract_quality", "std.spend"]);
    assert_eq!(ir.campaigns.len(), 1);
    let campaign = &ir.campaigns[0];
    assert_eq!(campaign.ascend, vec!["extract_quality"]);
    assert_eq!(campaign.reach.len(), 1);
    assert_eq!(campaign.reach[0].gauge, "std.latency");
    assert_eq!(campaign.reach[0].op, "<=");
    assert_eq!(campaign.reach[0].threshold, "800");
    assert_eq!(campaign.reach[0].unit.as_deref(), Some("ms"));
    assert_eq!(campaign.guard[0].gauge, "tail_latency");
    assert_eq!(campaign.guard[0].band_percent, "2");
    assert_eq!(campaign.sacrifice, vec!["fulfillment_cost"]);
    assert!(campaign.proposer_redacted);
    let snapshot = ir.to_snapshot();
    assert!(snapshot.contains("gauge extract_quality judge=coerce:DueDateJudge site=j.result expect=chance:due_date_correct>=0.9"));
    assert!(snapshot.contains(
            "campaign release_tuning ascend=extract_quality reach=std.latency<=800ms guard=tail_latency:within:2% sacrifice=fulfillment_cost proposer=redacted"
        ));
}

#[test]
fn mark_declaration_parses_lowers_and_validates() {
    let source = r##"
@service
workflow Improve

output result R
class R { v string }
signal go.now { x string }

mark "triaged" after j

rule j
  when go.now as g
=> {
  complete result {
    v "ok"
  }
}
"##;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    assert_eq!(ir.marks.len(), 1);
    assert_eq!(ir.marks[0].name, "triaged");
    assert_eq!(ir.marks[0].site, "j");
    assert!(ir.to_snapshot().contains("mark \"triaged\" after j"));
    // An unknown site is a diagnostic.
    let unknown = compile_program(&source.replace(
        "mark \"triaged\" after j",
        "mark \"nowhere\" after missing_rule",
    ));
    assert!(unknown.diagnostics.iter().any(|d| d
        .message
        .contains("mark `nowhere` rides unknown site `missing_rule`")));
    // Duplicate names are rejected.
    let dup = compile_program(&source.replace(
        "mark \"triaged\" after j",
        "mark \"triaged\" after j\nmark \"triaged\" after j",
    ));
    assert!(dup.diagnostics.iter().any(|d| d
        .message
        .contains("mark `triaged` is declared more than once")));
    // Formatting is idempotent.
    let formatted = format_program(source).formatted.expect("formats");
    assert!(formatted.contains("mark \"triaged\" after j"));
    assert_eq!(
        format_program(&formatted).formatted.expect("reformats"),
        formatted
    );
}

#[test]
fn coerce_judge_explicit_arguments_parse_lower_and_validate() {
    let program = |judge_line: &str| {
        format!(
            r##"
@service
workflow Improve

output result R
class R {{ v string }}
class Ticket {{ title string }}
signal go.now {{ x string }}

coerce Assess(title string, priority string) -> R {{
  prompt """markdown
  Judge {{{{ title }}}} at {{{{ priority }}}}.

  {{{{ ctx.output_format }}}}
  """
}}

gauge quality {{
  {judge_line}
}}

rule j
  when go.now as g
=> {{
  complete result {{
    v "ok"
  }}
}}
"##
        )
    };
    // Explicit paths parse, lower in order, and roundtrip through fmt.
    let source = program("judge via coerce Assess(input.ticket.title, facts.Assessment.priority)");
    let compiled = compile_program(&source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("compiles");
    assert_eq!(
        ir.gauges[0].judge_args,
        vec!["input.ticket.title", "facts.Assessment.priority"]
    );
    let formatted = format_program(&source).formatted.expect("formats");
    assert!(
        formatted
            .contains("judge via coerce Assess(input.ticket.title, facts.Assessment.priority)"),
        "fmt keeps the binding: {formatted}"
    );
    // Arity is checked: a drifted signature is a check error, never a
    // silently rebound judge.
    let compiled = compile_program(&program("judge via coerce Assess(input.ticket.title)"));
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("passes 1 argument")),
        "{:?}",
        compiled.diagnostics
    );
    // Paths must be record paths.
    let compiled = compile_program(&program(
        "judge via coerce Assess(whatever.title, facts.Assessment.priority)",
    ));
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("not a record path")),
        "{:?}",
        compiled.diagnostics
    );
    // The reserved `(record)` form needs a single-parameter coerce.
    let compiled = compile_program(&program("judge via coerce Assess(record)"));
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("single-parameter")),
        "{:?}",
        compiled.diagnostics
    );
    // Bare (no arguments) still parses — declared, honestly unscoreable.
    let compiled = compile_program(&program("judge via coerce Assess"));
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.expect("compiles").gauges[0]
        .judge_args
        .is_empty());
}

#[test]
fn gauge_and_campaign_cross_reference_validation() {
    let source = r##"
@service
workflow Improve

output result R
class R { v string }
signal go.now { x string }

gauge broken_judge {
  judge via coerce MissingJudge
}

gauge broken_inputs {
  judge via prompt "score this"
  inputs nowhere
}

campaign confused {
  ascend broken_judge
  sacrifice broken_judge
}

campaign unknown_ref {
  ascend nowhere_else
}

rule j
  when go.now as g
=> {
  complete result {
    v "ok"
  }
}
"##;
    let compiled = compile_program(source);
    let messages: Vec<String> = compiled
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.clone())
        .collect();
    assert!(messages
        .iter()
        .any(|m| m.contains("judges via undeclared coerce `MissingJudge`")));
    assert!(messages
        .iter()
        .any(|m| m.contains("derived gauge `broken_inputs` must judge via exec")));
    assert!(messages
        .iter()
        .any(|m| m.contains("unknown gauge `nowhere`")));
    assert!(messages
        .iter()
        .any(|m| m.contains("unknown gauge `nowhere_else`")));
    assert!(messages
        .iter()
        .any(|m| m.contains("names gauge `broken_judge` as both ascend and sacrifice")));
}

#[test]
fn campaign_naming_nothing_is_rejected_at_parse() {
    let source = r##"
@service
workflow Improve

output result R
class R { v string }
signal go.now { x string }

campaign nothing_named {
  guard std.spend within 5 percent
}

rule j
  when go.now as g
=> {
  complete result {
    v "ok"
  }
}
"##;
    let compiled = compile_program(source);
    assert!(compiled.diagnostics.iter().any(|d| d
        .message
        .contains("campaign `nothing_named` names nothing to improve")));
}

#[test]
fn gauge_bar_operator_gets_word_form_diagnostic() {
    let source = r##"
@service
workflow Improve

output result R
class R { v string }
signal go.now { x string }

gauge extract_quality {
  judge via exec "./judge.py"
  expect P(ok) >= 0.9
}

rule j
  when go.now as g
=> {
  complete result {
    v "ok"
  }
}
"##;
    let compiled = compile_program(source);
    assert!(compiled.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .suggestion
            .as_deref()
            .is_some_and(|s| s.contains("write `at least`"))
    }));
}

#[test]
fn formats_gauge_and_campaign_declarations() {
    let source = "workflow Improve\n\n\ngauge extract_quality on j.result {\n  judge via exec \"./judge.py\"\n  expect P(ok) at least 0.9\n}\n\ncampaign release_tuning {\n  ascend extract_quality\n  reach std.latency at most 800ms\n  guard std.tokens within 2 percent\n  sacrifice std.spend\n  proposer redacted\n}\n";
    let formatted = format_program(source);
    assert_eq!(formatted.diagnostics, Vec::new());
    let once = formatted.formatted.expect("formats");
    assert!(once.contains("gauge extract_quality on j.result {"));
    assert!(once.contains("  judge via exec \"./judge.py\""));
    assert!(once.contains("  expect P(ok) at least 0.9"));
    assert!(once.contains("campaign release_tuning {"));
    assert!(once.contains("  reach std.latency at most 800ms"));
    assert!(once.contains("  guard std.tokens within 2 percent"));
    assert!(once.contains("  proposer redacted"));
    let twice = format_program(&once).formatted.expect("reformats");
    assert_eq!(once, twice, "gauge/campaign formatting is idempotent");
}

#[test]
fn channel_declaration_parses_and_lowers() {
    let source = r##"
@service
workflow ChannelDecl

use std.messaging

channel release_room {
  provider fixture
  workspace ops
  destination "#release"
}

output result R
class R { v string }
signal go.now { x string }

rule j
  when go.now as g
=> {
  complete result {
    v "ok"
  }
}
"##;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    assert_eq!(ir.channels.len(), 1);
    let channel = &ir.channels[0];
    assert_eq!(channel.name, "release_room");
    assert_eq!(channel.provider, "fixture");
    assert_eq!(channel.workspace.as_deref(), Some("ops"));
    assert_eq!(channel.destination.as_deref(), Some("#release"));
    // The channel construct auto-registers std.messaging in the contract
    // registry (like leases -> std.coord), and `use std.messaging` parses as
    // a dotted package name.
    let registry = ir.contract_registry();
    assert!(registry
        .libraries
        .iter()
        .any(|library| library.id == "std.messaging"));
    // The generic `Message` envelope is a built-in referenceable schema.
    assert!(SchemaIndex::with_builtins().class_exists("Message"));
    // The `send` construct's typed receipt (the messaging.send contract's
    // output schema) is a built-in class so `send … as r` binds a typed r.
    assert!(SchemaIndex::with_builtins().class_exists("MessageSendReceipt"));
}

#[test]
fn single_line_multi_field_terminal_payload_collects_every_field() {
    // R5 papercut: `complete result { first "a" second "b" }` on ONE line
    // must satisfy the required-field check for both fields (token-level
    // splitting, not line-based).
    let source = r#"
workflow OneLine

output result Done

class Done {
  first string
  second string
}

rule r
  when started
=> {
  complete result { first "a" second "b" }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn file_store_is_read_only_by_default() {
    // S4: a store with no `allow write` policy rejects writes at check
    // time; reads need no clause; `allow write` permits and bounds writes.
    let program = |allow: &str| {
        format!(
            r#"
use std.files

workflow Posture

output result Done

class Done {{
  note string
}}

file store docs {{
  root "./docs"
{allow}}}

rule r
  when started
=> {{
  write text to docs at "out.txt" {{
    body "x"
    mode create
  }} as out

  after out completes {{
    complete result {{ note "done" }}
  }}
}}
"#
        )
    };
    let denied = compile_program(&program(""));
    assert!(
        denied
            .diagnostics
            .iter()
            .any(|d| d.message.contains("permits no writes")),
        "{:?}",
        denied.diagnostics
    );
    let allowed = compile_program(&program("  allow write [\"**\"]\n"));
    assert_eq!(allowed.diagnostics, Vec::new());

    // Reads against a bare store stay clean.
    let read_only = compile_program(
        r#"
use std.files

workflow ReadOnly

output result Done

class Done {
  note string
}

file store docs {
  root "./docs"
}

rule r
  when started
=> {
  read text from docs at "in.txt" as doc

  after doc completes {
    complete result { note "done" }
  }
}
"#,
    );
    assert_eq!(read_only.diagnostics, Vec::new());
}

#[test]
fn tracker_bare_defaults_provider_to_builtin() {
    // S1 (surface-defaults batch): `tracker <name>` bare — no block —
    // defaults the provider to `builtin`.
    let source = r#"
@service
workflow TrackerBare

tracker backlog

class Item { id string }
signal go.now { x string }
rule j
  when go.now as g
=> {
  file issue into backlog {
    title g.x
  }
}
"#;
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("compiles");
    assert_eq!(ir.trackers.len(), 1);
    assert_eq!(ir.trackers[0].provider, "builtin");
}

/// std.vcs `stream` declaration (DR-0052 grammar pass): bare-ident
/// member lists parse via the DR-0011 list-identifier amendment;
/// staleness is an ordinary duration clause; members must name
/// declared agents; membership is single-valued; `on stream` on a
/// tell must name a declared stream; fmt canonicalizes the block.
#[test]
fn stream_declaration_parses_validates_and_formats() {
    let source = r#"
@service
workflow Streams

agent worker {
  profile "repo-writer"
}

agent reviewer {
  profile "repo-reader"
}

stream triage {
  members [worker, reviewer]
  staleness 2h
}

signal go.now { x string }
rule j
  when go.now as g
=> {
  tell worker as turn on stream triage """markdown
  Work {{ g.x }}.
  """
}
"#;
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("compiles");
    assert_eq!(ir.streams.len(), 1);
    assert_eq!(ir.streams[0].name, "triage");
    assert_eq!(ir.streams[0].members, vec!["worker", "reviewer"]);
    assert_eq!(ir.streams[0].staleness_seconds, Some(7200));
    let tell = ir
        .rules
        .iter()
        .flat_map(|rule| &rule.metadata.effects)
        .find(|effect| effect.kind == IrEffectKind::AgentTell)
        .expect("tell effect");
    assert_eq!(tell.on_stream.as_deref(), Some("triage"));

    // Undeclared member refused.
    let bad_member = source.replace("members [worker, reviewer]", "members [ghost]");
    let compiled = compile_program(&bad_member);
    assert!(compiled.ir.is_none());
    assert!(compiled
        .diagnostics
        .iter()
        .any(|d| d.message.contains("not a declared agent")));

    // Double membership refused (single-valued, topology stays a tree).
    let double = source.replace(
        "signal go.now { x string }",
        "stream hotfix {\n  members [worker]\n}\n\nsignal go.now { x string }",
    );
    let compiled = compile_program(&double);
    assert!(compiled.ir.is_none());
    assert!(compiled
        .diagnostics
        .iter()
        .any(|d| d.message.contains("already a member of stream")));

    // `on stream` must name a declared stream.
    let bad_target = source.replace("on stream triage", "on stream nowhere");
    let compiled = compile_program(&bad_target);
    assert!(compiled.ir.is_none());
    assert!(compiled
        .diagnostics
        .iter()
        .any(|d| d.message.contains("undeclared stream")));
}

/// std.vcs `promote <stream> as p` (DR-0052 grammar pass slice 3):
/// parses via the effect_operation table, lowers to a vcs.promote
/// capability call, refuses `succeeds` (the acquire posture), and
/// requires both outcome arms.
#[test]
fn promote_parses_refuses_succeeds_and_requires_both_arms() {
    let base = r#"
@service
workflow Promote
use std.vcs
use std.ingress

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

stream triage {
  members [worker]
}

class Note { body string }
signal go.now { x string }
rule hop
  when go.now as g
=> {
  promote triage as p
  after p promoted {
    record Note { body "landed" }
  }
  after p conflicted {
    record Note { body "blocked" }
  }
}
"#;
    let compiled = compile_program(base);
    let ir = compiled.ir.expect("compiles");
    let promote = ir
        .rules
        .iter()
        .flat_map(|rule| &rule.metadata.effects)
        .find(|effect| effect.kind == IrEffectKind::CapabilityCall)
        .expect("promote lowers to a capability call");
    assert_eq!(promote.binding.as_deref(), Some("p"));

    // `succeeds` on a promote binding is refused (a workflow must not
    // proceed "as if promoted" on a conflicted boundary).
    let succeeds = base.replace(
        "after p promoted {\n    record Note { body \"landed\" }\n  }",
        "after p succeeds {\n    record Note { body \"landed\" }\n  }",
    );
    let compiled = compile_program(&succeeds);
    assert!(compiled
        .diagnostics
        .iter()
        .any(|d| d.message.contains("also matches a Conflicted outcome")));

    // Outcome handling is exhaustive: a missing `conflicted` arm is a
    // program with no policy at the boundary.
    let missing = base.replace(
        "  after p conflicted {\n    record Note { body \"blocked\" }\n  }\n",
        "",
    );
    let compiled = compile_program(&missing);
    assert!(compiled.diagnostics.iter().any(|d| d
        .message
        .contains("does not handle the `conflicted` outcome")));
}

/// std.vcs selective verbs (DR-0052 R4): `undo`/`transport` parse,
/// enforce the acquire posture (succeeds refused, exhaustive arms),
/// statically validate literal selections against the one selection
/// grammar, and bound transport targets to the nameable tiers.
#[test]
fn selective_verbs_parse_enforce_and_validate_statically() {
    let base = r#"
@service
workflow Selective
use std.vcs
use std.ingress

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

stream triage {
  members [worker]
}

class Note { body string }
signal go.now { x string }
rule tidy
  when go.now as g
=> {
  undo "by(instance:i-1) & path(scratch/**)" as u
  after u applied {
    record Note { body "clean" }
  }
  after u stranded {
    record Note { body "kept" }
  }
  transport "path(src/**)" onto triage as t
  after t applied {
    record Note { body "moved" }
  }
  after t conflicted {
    record Note { body "blocked" }
  }
}
"#;
    let compiled = compile_program(base);
    let ir = compiled.ir.expect("compiles");
    let calls: Vec<_> = ir
        .rules
        .iter()
        .flat_map(|rule| &rule.metadata.effects)
        .filter(|effect| effect.kind == IrEffectKind::CapabilityCall)
        .collect();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].binding.as_deref(), Some("u"));
    assert_eq!(calls[1].transport_onto.as_deref(), Some("triage"));

    // A malformed literal selection is a check error.
    let bad_selection = base.replace(
        r#"undo "by(instance:i-1) & path(scratch/**)" as u"#,
        r#"undo "nonsense((" as u"#,
    );
    let compiled = compile_program(&bad_selection);
    assert!(compiled
        .diagnostics
        .iter()
        .any(|d| d.message.contains("selection does not parse")));

    // Transport targets are the nameable tiers only.
    let bad_target = base.replace("onto triage as t", "onto ghost as t");
    let compiled = compile_program(&bad_target);
    assert!(compiled.diagnostics.iter().any(|d| d
        .message
        .contains("neither `mainline` nor a declared stream")));

    // `succeeds` on a selective binding is refused.
    let succeeds = base.replace(
        "after u applied {\n    record Note { body \"clean\" }\n  }",
        "after u succeeds {\n    record Note { body \"clean\" }\n  }",
    );
    let compiled = compile_program(&succeeds);
    assert!(compiled
        .diagnostics
        .iter()
        .any(|d| d.message.contains("also matches a Stranded outcome")));

    // Outcome handling is exhaustive.
    let missing = base.replace(
        "  after t conflicted {\n    record Note { body \"blocked\" }\n  }\n",
        "",
    );
    let compiled = compile_program(&missing);
    assert!(compiled.diagnostics.iter().any(|d| d
        .message
        .contains("does not handle the `conflicted` outcome of transport")));
}

/// DR-0052 R3: the vcs repair grant parses on invoke with a bound
/// arming fact; an unknown op and an unbound binding are refused.
#[test]
fn vcs_repair_grant_validates() {
    let base = r#"
workflow Main {
  use std.vcs

  rule unstick
    when reconcile stalled as r
  => {
    invoke RepairFlow { note "repair" } as fix
      with access to vcs {
        repair for r
      }
  }
}

workflow RepairFlow {
  input note string
  output result Fixed
  class Fixed { note string }

  rule fix
    when started
  => {
    complete result { note "done" }
  }
}
"#;
    let compiled = compile_program_with_root(base, Some("Main"));
    assert!(
        compiled.ir.is_some(),
        "expected compile, got {:?}",
        compiled.diagnostics
    );

    let unbound = base.replace("repair for r", "repair for ghost");
    let compiled = compile_program_with_root(&unbound, Some("Main"));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|d| d.message.contains("names no binding of this rule")));

    let bad_op = base.replace("repair for r", "undo for r");
    let compiled = compile_program_with_root(&bad_op, Some("Main"));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|d| d.message.contains("unknown `vcs` grant operation")));
}

#[test]
fn emit_signal_from_projects_bounded_fields() {
    // S6: `emit signal <name> to <target> from <binding>` parses (block
    // optional; an override block allows shorthand), mirroring
    // `record … from`.
    let source = r#"
use std.ingress

@service
workflow EmitFrom

signal deploy.finished {
  service string
  peer string
}

signal deploy.acknowledged {
  service string
}

rule relay
  when deploy.finished as deployed
=> {
  emit signal deploy.acknowledged to deployed.peer from deployed as sent
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn inline_contract_payload_synthesizes_anonymous_class() {
    // S7: `output result { message string }` synthesizes the hygienic
    // `output.result` class (the `decide` precedent); the terminal payload
    // validates against it.
    let source = r#"
workflow Inline

output result {
  message string
}

failure error {
  reason string
}

rule r
  when started
=> {
  complete result {
    message "hello"
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("compiles");
    assert!(ir.schemas.iter().any(|schema| matches!(
        schema,
        IrSchema::Class(class) if class.name == "output.result"
    )));
    assert!(ir.schemas.iter().any(|schema| matches!(
        schema,
        IrSchema::Class(class) if class.name == "failure.error"
    )));

    // A bad payload field is still a check error against the synthesized class.
    let bad = compile_program(
        r#"
workflow InlineBad

output result {
  message string
}

rule r
  when started
=> {
  complete result {
    wrong "hello"
  }
}
"#,
    );
    assert!(
        !bad.diagnostics.is_empty(),
        "unknown field on the synthesized class must be rejected"
    );
}

#[test]
fn channel_defaults_provider_to_local() {
    // S2 (surface-defaults batch): a channel without a `provider` clause —
    // block or bare — defaults to `local`.
    let source = r#"
use std.messaging
use std.ingress

@service
workflow ChannelDefault

channel orphan {
  workspace ops
}

channel bare

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("compiles");
    assert!(
        ir.channels
            .iter()
            .all(|channel| channel.provider == "local"),
        "{:?}",
        ir.channels
    );
    assert_eq!(ir.channels.len(), 2);
}

#[test]
fn credential_declaration_lowers_with_normalized_kind() {
    // DR-0053 §5: `credential <name> { kind <kind> }` — a bare handle,
    // channel-style. Kinds are underscore-spelled identifiers in source
    // and normalize to the protocol's kebab-case in IR.
    let source = r#"
@service
workflow Creds

credential stripe_api { kind bearer }
credential release_signing { kind ed25519 }
credential s3_key { kind aws_sigv4 }

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("compiles");
    assert_eq!(ir.credentials.len(), 3);
    assert_eq!(ir.credentials[0].name, "stripe_api");
    assert_eq!(ir.credentials[0].kind, "bearer");
    assert_eq!(ir.credentials[2].kind, "aws-sigv4");
    let snapshot = ir.to_snapshot();
    assert!(snapshot.contains("credential stripe_api kind=bearer"));
    assert!(snapshot.contains("credential s3_key kind=aws-sigv4"));
    assert!(
        ir.contract_registry()
            .libraries
            .iter()
            .any(|library| library.id == "std.custody"),
        "declaring a credential registers std.custody"
    );
}

#[test]
fn credential_requires_a_known_kind() {
    let compiled = compile_program(
        r#"
@service
workflow CredsBadKind

credential mystery { kind quantum }

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#,
    );
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("unknown kind `quantum`")),
        "{:?}",
        compiled.diagnostics
    );

    let missing = compile_program(
        r#"
@service
workflow CredsNoKind

credential bare_handle

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#,
    );
    assert!(
        missing
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("must declare its kind")),
        "{:?}",
        missing.diagnostics
    );
}

#[test]
fn duplicate_credential_is_rejected() {
    let compiled = compile_program(
        r#"
@service
workflow DupCred

credential stripe_api { kind bearer }
credential stripe_api { kind raw }

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#,
    );
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("declared more than once")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn secret_fields_admit_no_literal() {
    // The no-eliminator property's source-level face: a `secret`-typed
    // field can never be filled from a literal (DR-0053 §5 — material is
    // never a value in source).
    let compiled = compile_program(
        r#"
@service
workflow SecretLiteral

class Config {
  token secret
}

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> {
  record Config { token "sk_live_oops" }
  complete result { v "ok" }
}
"#,
    );
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("secrets have no literal form")),
        "{:?}",
        compiled.diagnostics
    );
}

fn mint_program(parent: &str, presents: &str, extra: &str) -> CompileOutput {
    compile_program(&format!(
        r#"
@service
workflow MintScopedToken

use std.custody
use std.ingress

credential stripe_api {{ kind bearer }}
{extra}

signal charge.disputed {{ note string }}

output result R
class R {{ v string }}
rule scoped
  when charge.disputed as charge
=> {{
  mint credential from {parent} {{
    at POST "https://connect.stripe.com/oauth/token"
    header "Authorization" basic {presents}
    body "grant_type=client_credentials&scope=charges:write"
    token at "access_token"
    public ["expires_in"]
  }} as token

  after token succeeds {{
    complete result {{ v "minted" }}
  }}
}}
"#
    ))
}

#[test]
fn a_mint_carries_its_exchange_and_declares_no_scope() {
    // DR-0053 §5 as amended. The exchange is the author's; the vendor scope is
    // a body field because that is what it is, and there is no `scope` clause
    // beside it that could say something different.
    let compiled = mint_program("stripe_api", "stripe_api", "");
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("compiles");
    let node = ir
        .rules
        .iter()
        .flat_map(|rule| rule.metadata.effects.iter())
        .find(|effect| effect.kind == IrEffectKind::MintCredential)
        .expect("the mint lowers to an effect node");
    let mint = node.mint_credential.as_ref().expect("payload");
    assert_eq!(mint.parent, "stripe_api");
    assert_eq!(mint.token_path, "access_token");
    assert_eq!(mint.public_paths, vec!["expires_in".to_owned()]);
    // The parent is a MARKED SLOT, so the exchange presents it without any
    // expression ever yielding material.
    assert_eq!(mint.exchange.slot_count(), 1);
}

#[test]
fn a_mint_must_present_the_credential_it_mints_from() {
    // The confusion worth refusing: the child inherits `{parent}`'s ceiling by
    // name, so an exchange spending a DIFFERENT credential would produce a
    // child bounded by an authority it was never derived from.
    let compiled = mint_program(
        "stripe_api",
        "other_key",
        "credential other_key { kind basic }",
    );
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("but the exchange presents `other_key`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn a_mint_from_an_undeclared_credential_is_refused() {
    let compiled = mint_program("ghost", "ghost", "");
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("mints from undeclared credential `ghost`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn a_mint_exchange_must_say_where_the_token_is() {
    // Defaulting to a conventional name would guess one vendor's spelling on
    // every vendor's behalf, and a wrong guess is a mint that silently finds
    // nothing.
    let compiled = compile_program(
        r#"
@service
workflow MintNoPath

use std.custody

credential stripe_api { kind bearer }

output result R
class R { v string }
signal go.now { x string }
rule scoped
  when go.now as g
=> {
  mint credential from stripe_api {
    at POST "https://issuer/token"
    header "Authorization" basic stripe_api
  } as token

  after token succeeds { complete result { v "ok" } }
}
"#,
    );
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("must say where the token is")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn a_secret_carries_its_credential_kind() {
    // DR-0053 §15. The kind-conditioned checks are name-keyed, and every one
    // of the four things a secret is allowed to do — bind, pass, store in a
    // field, sit in an effect position — leaves no name to resolve. The
    // discriminant is what a stored secret still carries.
    let compiled = compile_program(
        r#"
@service
workflow SecretKind

class Config {
  signing secret<ed25519>
  webhook secret<hmac_sha256>
  anything secret
}

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> {
  complete result { v "ok" }
}
"#,
    );
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.expect("program compiles");
    let snapshot = ir.to_snapshot();
    // The discriminant survives lowering into the IR, which is the point: a
    // bare `secret` in the snapshot would mean the type carried nothing.
    assert!(snapshot.contains("secret<ed25519>"), "{snapshot}");
    assert!(snapshot.contains("secret<hmac_sha256>"), "{snapshot}");
}

#[test]
fn an_unknown_secret_kind_is_refused_rather_than_widened() {
    // Silently widening `secret<ed2551>` to bare `secret` would give the
    // author a narrowing they asked for and did not get — the over-promise
    // DR-0053 §14 keeps two grant classes apart to avoid.
    let compiled = compile_program(
        r#"
@service
workflow BadSecretKind

class Config {
  signing secret<ed2551>
}

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> {
  complete result { v "ok" }
}
"#,
    );
    let diagnostic = compiled
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("unknown credential kind"))
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
    // The suggestion is derived from the protocol's closed set, so a kind
    // added there appears here without anyone remembering to add it.
    let suggestion = diagnostic.suggestion.as_deref().unwrap_or_default();
    for spelling in ["bearer", "hmac_sha256", "jwt_rs256"] {
        assert!(suggestion.contains(spelling), "{suggestion}");
    }
}

#[test]
fn a_parameterised_secret_field_still_admits_no_literal() {
    // The no-eliminator property does not weaken when the type narrows, and
    // the diagnostic names the type as written rather than bare `secret`.
    let compiled = compile_program(
        r#"
@service
workflow ParameterisedSecretLiteral

class Config {
  signing secret<ed25519>
}

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> {
  record Config { signing "sk_live_oops" }
  complete result { v "ok" }
}
"#,
    );
    let diagnostic = compiled
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("secrets have no literal form"))
        .unwrap_or_else(|| panic!("{:?}", compiled.diagnostics));
    assert!(
        diagnostic.message.contains("secret<ed25519>"),
        "{}",
        diagnostic.message
    );
}

#[test]
fn obtain_credential_escalates_for_a_declared_credential_only() {
    // DR-0053 §11. The escalation is FOR a specific authority, so a typo'd
    // handle would file a governance item asking a human for a credential no
    // rule can ever use — the escalation would look answered and change
    // nothing.
    let good = compile_program(
        r#"
@service
workflow Escalate

use std.custody

tracker ops { provider builtin }
credential deploy_key { kind ed25519 }

output result R
class R { v string }
rule seed
  when started
=> {
  obtain credential deploy_key into ops {
    title "not granted"
    body "please grant"
  } as escalation
}
"#,
    );
    assert!(good.diagnostics.is_empty(), "{:?}", good.diagnostics);

    let bad = compile_program(
        r#"
@service
workflow Escalate

use std.custody

tracker ops { provider builtin }
credential deploy_key { kind ed25519 }

output result R
class R { v string }
rule seed
  when started
=> {
  obtain credential deply_key into ops {
    title "not granted"
    body "please grant"
  } as escalation
}
"#,
    );
    assert!(
        bad.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("undeclared credential `deply_key`")),
        "{:?}",
        bad.diagnostics
    );
}

#[test]
fn duplicate_channel_is_rejected() {
    let source = r#"
@service
workflow DupChannel

channel room {
  provider fixture
}
channel room {
  provider discord
}

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#;
    let compiled = compile_program(source);
    let dup = compiled
        .diagnostics
        .iter()
        .find(|d| d.message.contains("declared more than once"))
        .expect("expected duplicate-channel diagnostic");
    // The diagnostic carries related-information pointing at the first
    // declaration (spec/error-handling.md "Spans And Labels").
    assert_eq!(dup.related.len(), 1, "expected one related-info entry");
    assert_eq!(dup.related[0].message, "first declared here");
    assert!(dup.related[0].span.start < dup.span.start);
}

#[test]
fn when_message_from_binds_message_and_validates_channel() {
    // `when message from <channel> as msg` binds the built-in `Message`
    // envelope and the channel must be declared (spec/messaging.md).
    let ok = compile_program(
        r#"
@service
workflow Inbound

channel release_room {
  provider fixture
}

output result Decision
class Decision { note string }

rule react
  when message from release_room as msg
=> {
  complete result { note msg.text }
}
"#,
    );
    assert!(
        ok.diagnostics.is_empty(),
        "expected clean compile, got {:?}",
        ok.diagnostics
    );
    // `msg.text` resolving against the Message schema proves the binding typed.

    let bad = compile_program(
        r#"
@service
workflow Inbound

channel release_room {
  provider fixture
}

output result Decision
class Decision { note string }

rule react
  when message from typo_room as msg
=> {
  complete result { note msg.text }
}
"#,
    );
    assert!(
        bad.diagnostics.iter().any(|d| d
            .message
            .contains("`when message from typo_room` names an unknown channel")),
        "expected unknown-channel diagnostic, got {:?}",
        bad.diagnostics
    );
}

#[test]
fn unknown_channel_provider_is_a_check_error() {
    // spec/std-messaging.md "Static checks": a channel `provider`
    // identifier must resolve to a v1 provider capability report; a
    // free-form name (`slack` shipped in old demos) is a check error.
    let compiled = compile_program(
        r##"
@service
workflow UnknownProvider

channel ops_room {
  provider slack
  destination "#ops"
}

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"##,
    );
    let unknown = compiled
        .diagnostics
        .iter()
        .find(|d| {
            d.message
                .contains("channel `ops_room` names unknown messaging provider `slack`")
        })
        .expect("expected unknown-provider diagnostic");
    assert!(
        unknown
            .suggestion
            .as_deref()
            .is_some_and(|s| s.contains("fixture") && s.contains("desktop")),
        "suggestion lists the v1 providers: {:?}",
        unknown.suggestion
    );
}

#[test]
fn desktop_channel_is_outbound_only_at_check_time() {
    // The v1 acceptance test (spec/std-messaging.md "Static checks"):
    // send/receive-capable providers are DISTINGUISHABLE. `send via` a
    // desktop channel passes; `when message from` the same channel is a
    // check error conditioned on the provider's capability report.
    let send_ok = compile_program(
        r#"
@service
workflow DesktopSend

use std.messaging

channel alerts {
  provider desktop
}

output result R
class R { v string }
signal go.now { x string }

rule j
  when go.now as g
=> {
  send via alerts {
    text "ping"
  } as sent

  after sent succeeds {
    complete result { v "ok" }
  }
}
"#,
    );
    assert!(
        send_ok.diagnostics.is_empty(),
        "outbound send over desktop passes: {:?}",
        send_ok.diagnostics
    );

    let inbound_bad = compile_program(
        r#"
@service
workflow DesktopInbound

channel alerts {
  provider desktop
}

output result R
class R { v string }

rule react
  when message from alerts as msg
=> { complete result { v msg.text } }
"#,
    );
    assert!(
            inbound_bad.diagnostics.iter().any(|d| d.message.contains(
                "`when message from alerts` observes a channel whose provider `desktop` is outbound-only"
            )),
            "expected outbound-only diagnostic, got {:?}",
            inbound_bad.diagnostics
        );

    // A bidirectional provider (`local`) admits both directions.
    let bidirectional = compile_program(
        r#"
@service
workflow LocalInbound

channel alerts {
  provider local
}

output result R
class R { v string }

rule react
  when message from alerts as msg
=> { complete result { v msg.text } }
"#,
    );
    assert!(
        bidirectional.diagnostics.is_empty(),
        "bidirectional provider admits inbound observation: {:?}",
        bidirectional.diagnostics
    );
}

#[test]
fn channel_provider_reports_cover_the_v1_matrix() {
    // Report data is load-bearing for the conditioned checks: pin the v1
    // provider set, direction axis, and short-name/provider-id resolution.
    let shorts: Vec<&str> = CHANNEL_PROVIDER_REPORTS
        .iter()
        .map(|r| r.short_name)
        .collect();
    assert_eq!(shorts, ["fixture", "local", "desktop", "stdio"]);
    for report in CHANNEL_PROVIDER_REPORTS {
        assert!(
            matches!(
                report.direction,
                "outbound_only" | "inbound_only" | "bidirectional"
            ),
            "direction vocabulary: {}",
            report.direction
        );
        assert!(
            matches!(report.identity, "anonymous" | "claimed_actor"),
            "identity ladder is v1-narrowed (no verified_actor): {}",
            report.identity
        );
        assert_eq!(report.delivery_receipts, &["accepted", "failed"]);
        assert_eq!(
            channel_provider_report(report.short_name),
            Some(report),
            "short name resolves"
        );
        assert_eq!(
            channel_provider_report(report.provider_id),
            Some(report),
            "provider id resolves"
        );
    }
    assert_eq!(channel_provider_report("slack"), None);
    assert_eq!(
        channel_provider_report("desktop").map(|r| r.direction),
        Some("outbound_only")
    );
}

#[test]
fn duplicate_schema_diagnostic_points_at_first_declaration() {
    let source = r#"
@service
workflow DupSchema

class Thing { v string }
class Thing { w string }

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#;
    let compiled = compile_program(source);
    let dup = compiled
        .diagnostics
        .iter()
        .find(|d| {
            d.message
                .contains("schema `Thing` is declared more than once")
        })
        .expect("expected duplicate-schema diagnostic");
    assert_eq!(dup.related.len(), 1);
    assert_eq!(dup.related[0].message, "first declared here");
    assert!(dup.related[0].span.start < dup.span.start);
}

#[test]
fn interval_clock_source_parses_duration() {
    let source = r#"
workflow Interval

signal tick.beat {
  at_time time
}

source clock as heartbeat {
  every 5m
  missed skip

  observe as tick
  emit tick.beat {
    at_time tick.scheduled_at
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    match &ir.sources[0].recurrence {
        Some(Recurrence::EveryDuration { seconds, .. }) => assert_eq!(*seconds, 300),
        other => panic!("expected duration recurrence, got {other:?}"),
    }
    assert_eq!(ir.sources[0].missed, Some(MissedPolicy::Skip));
}

#[test]
fn fails_binding_types_to_effecterror_base() {
    // DR-0032: `after <effect> fails as f` types `f` to the EffectError base
    // (TerminalFailed: reason, summary, effect_id, run_id, kind). The base
    // fields read cleanly.
    let source = r#"
workflow W {
  input task T
  output result R
  failure error E
  class T { x string }
  class R { y string }
  class E { reason string detail string }

  rule go when T as task => {
    exec "true" as e
    after e fails as f {
      fail error { reason f.reason detail f.kind }
    }
    after e succeeds {
      complete result { y task.x }
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("invalid field path")),
        "base fields should type-check: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn fails_binding_rejects_non_base_field() {
    // The teeth of DR-0032 typing: a field outside the binding's per-kind
    // failure schema is a check error. An exec binding narrows to
    // TerminalFailedExec (exit_code is legal), but stderr is NOT exposed
    // (Decision 4 — redaction), and a coerce binding may not read exec's
    // extras (extras are reachable only under the matching kind).
    let exec_source = r#"
workflow W {
  input task T
  output result R
  failure error E
  class T { x string }
  class R { y string }
  class E { reason string }

  rule go when T as task => {
    exec "true" as e
    after e fails as f {
      fail error { reason f.stderr }
    }
    after e succeeds {
      complete result { y task.x }
    }
  }
}
"#;
    let compiled = compile_program(exec_source);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("invalid field path `f.stderr`")),
        "{:?}",
        compiled.diagnostics
    );

    let cross_kind = r#"
workflow W {
  input task T
  output result R
  failure error E
  class T { x string }
  class R { y string }
  class E { reason string }
  class V { note string }

  coerce judge(x string) -> V {
    prompt "Classify {{ x }}"
  }

  rule go when T as task => {
    coerce judge(task.x) as c
    after c fails as f {
      fail error { reason f.exit_code }
    }
    after c succeeds {
      complete result { y task.x }
    }
  }
}
"#;
    let compiled = compile_program(cross_kind);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("invalid field path `f.exit_code`")
                && d.message.contains("TerminalFailedCoerce")),
        "a coerce binding must not read exec extras: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn fails_binding_narrows_to_per_kind_failure_extras() {
    // DR-0032 P3 (DQ-2 static narrowing): the v1 per-kind extras are legal
    // exactly when the binding's effect kind matches — exec `exit_code`,
    // coerce `error_class` (+ optional `http_status`), tell `error_class`.
    let source = r#"
workflow W {
  input task T
  output result R
  failure error E
  class T { x string }
  class R { y string }
  class E { reason string code int klass string }
  class V { note string }

  agent worker {
    provider fixture
    profile "repo-reader"
    capacity 1
  }

  coerce judge(x string) -> V {
    prompt "Classify {{ x }}"
  }

  rule go when T as task => {
    exec "true" as e
    coerce judge(task.x) as c
    tell worker as turn "go"

    after e fails as fe {
      fail error { reason fe.reason code fe.exit_code klass "x" }
    }
    after c fails as fc {
      fail error { reason fc.reason code 0 klass fc.error_class }
    }
    after turn fails as ft {
      fail error { reason ft.reason code 0 klass ft.error_class }
    }
    after e succeeds {
      complete result { y task.x }
    }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("invalid field path")),
        "per-kind extras must type-check under the matching kind: {:?}",
        compiled.diagnostics
    );
}

#[test]
fn milestone_reaches_rejects_undeclared_milestone() {
    // Family C terminal-only observation invariant: a parent cannot observe a
    // milestone the invoked child never declares.
    let source = r#"
workflow Parent {
  input task Task
  class Task { title string }
  class Saw { note string }

  rule dispatch when Task as task => {
    invoke Child { task { title task.title } } as child
    after child reaches "never_declared" as m {
      record Saw { note m.note }
    }
  }
}

workflow Child {
  input task Task
  output result R
  class Task { title string }
  class R { title string }
  class P { note string }

  rule go when Task as task => {
    emit milestone "actually_declared" of P { note task.title }
    complete result { title task.title }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("reaches milestone `never_declared` that workflow `Child` does not declare")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn emit_milestone_rejects_unknown_payload_class() {
    let source = r#"
workflow Child {
  input task Task
  output result R
  class Task { title string }
  class R { title string }

  rule go when Task as task => {
    emit milestone "m1" of Nonexistent { note task.title }
    complete result { title task.title }
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("emits milestone `m1` with unknown payload class `Nonexistent`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn milestone_reaches_accepts_declared_milestone() {
    // The positive control: a declared milestone is accepted (no
    // reject-undeclared / unknown-class diagnostics).
    let source = r#"
workflow Parent {
  input task Task
  class Task { title string }
  class Saw { note string }

  rule dispatch when Task as task => {
    invoke Child { task { title task.title } } as child
    after child reaches "halfway" as m {
      record Saw { note m.note }
    }
  }
}

workflow Child {
  input task Task
  output result R
  class Task { title string }
  class R { title string }
  class P { note string }

  rule go when Task as task => {
    emit milestone "halfway" of P { note task.title }
    complete result { title task.title }
  }
}
"#;
    let compiled = compile_program_with_root(source, Some("Parent"));
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("reaches milestone")
                || d.message.contains("unknown payload class")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn recurring_clock_source_requires_missed() {
    let source = r#"
workflow NeedsMissed

signal triage.tick {
  scheduled_at time
}

source clock as daily {
  every weekday at 09:00
  timezone "UTC"

  observe as tick
  emit triage.tick {
    scheduled_at tick.scheduled_at
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("must declare a `missed` policy")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn calendar_clock_source_requires_timezone() {
    let source = r#"
workflow NeedsTimezone

signal triage.tick {
  scheduled_at time
}

source clock as daily {
  every weekday at 09:00
  missed skip

  observe as tick
  emit triage.tick {
    scheduled_at tick.scheduled_at
  }
}
"#;
    let compiled = compile_program(source);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("should declare a `timezone`")),
        "{:?}",
        compiled.diagnostics
    );
}

#[test]
fn generic_source_block_lowers_to_signal_source() {
    let source = r#"
workflow Ingress

signal deploy.finished {
  service string
}

source webhook as deploys {
  observe as obs
  emit deploy.finished {
    service obs.service
  }
}
"#;
    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("program compiles");
    assert_eq!(ir.sources.len(), 1);
    let decl = &ir.sources[0];
    assert!(!decl.is_clock);
    assert_eq!(decl.provider, "webhook");
    assert!(decl.recurrence.is_none());
    assert_eq!(decl.emit_signal, "deploy.finished");
}

#[test]
fn complete_field_reads_are_collected_per_field() {
    // The per-field flow-signature metadata (DR-0030 X2 v2) keeps each result
    // field's referenced roots SEPARATE (where `egress_payload_reads` joins them):
    // `id` references only `a`, `note` references only `b`.
    let source = r#"
@tool
workflow Producer {
  input request Req
  output result R
  class Req { id string }
  class A { x string }
  class B { y string }
  class R { id string  note string }

  rule combine
    when A as a
    when B as b
  => {
    complete result {
      id a.x
      note b.y
    }
  }
}
"#;
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("program compiles");
    let rule = ir
        .rules
        .iter()
        .find(|r| r.name == "combine")
        .expect("combine rule");
    let per_field = rule
        .metadata
        .complete_field_reads
        .get("result")
        .expect("result has per-field reads");
    assert_eq!(
        per_field.get("id"),
        Some(&BTreeSet::from(["a".to_owned()])),
        "id references only a: {per_field:?}"
    );
    assert_eq!(
        per_field.get("note"),
        Some(&BTreeSet::from(["b".to_owned()])),
        "note references only b: {per_field:?}"
    );
}

#[test]
fn milestone_field_reads_are_collected_per_field() {
    // D3′: milestone payload fields get the same per-field root metadata as
    // `complete result`, so a parent can audit each milestone field separately.
    let source = r#"
workflow Child {
  input request Req
  output result R
  class Req { id string }
  class A { x string }
  class B { y string }
  class R { ok bool }
  class Progress { hot string  cold string }

  rule report
    when A as a
    when B as b
  => {
    emit milestone "halfway" of Progress {
      hot a.x
      cold b.y
    }
    complete result { ok true }
  }
}
"#;
    let compiled = compile_program(source);
    let ir = compiled.ir.expect("program compiles");
    let rule = ir
        .rules
        .iter()
        .find(|r| r.name == "report")
        .expect("report rule");
    let per_field = rule
        .metadata
        .milestone_field_reads
        .get("halfway")
        .expect("milestone has per-field reads");
    assert_eq!(
        per_field.get("hot"),
        Some(&BTreeSet::from(["a".to_owned()])),
        "hot references only a: {per_field:?}"
    );
    assert_eq!(
        per_field.get("cold"),
        Some(&BTreeSet::from(["b".to_owned()])),
        "cold references only b: {per_field:?}"
    );
}

const REQUEST_PROGRAM: &str = r#"@service
workflow RequestTest

output result R
class R { ok bool }
class Ticket { id string  status "open" }

credential stripe_api { kind bearer }

table seed as Ticket [ { id "T1"  status "open" } ]

rule pay
  when Ticket as ticket where ticket.status == "open"
=> {
  request POST "https://api.stripe.com/v1/refunds" {
    header "Authorization" bearer stripe_api
    header "Idempotency-Key" ticket.id
    body ticket.id
  } as refund

  after refund succeeds as reply {
    complete result { ok true }
  }
}
"#;

/// The construct lowers, and its binding is seeded from the AST — `as refund`
/// closes on the block line, where the line scanner cannot see it (the same
/// shape as `send via`).
#[test]
fn a_request_lowers_with_its_credential_slot_and_binding() {
    let compiled = compile_program(REQUEST_PROGRAM);
    let ir = compiled.ir.expect("request program compiles");
    let rule = ir.rules.iter().find(|r| r.name == "pay").expect("rule pay");
    let effect = rule
        .metadata
        .effects
        .iter()
        .find(|e| e.kind == IrEffectKind::HttpRequest)
        .expect("the request lowered to an effect");
    assert_eq!(effect.binding.as_deref(), Some("refund"));

    let request = effect.http_request.as_ref().expect("request payload");
    assert_eq!(request.method, "POST");
    assert_eq!(request.url, "https://api.stripe.com/v1/refunds");
    // One MARKED slot, not two: the idempotency header is an ordinary
    // expression. The count is what the custodian is told out of band, so it
    // has to mean the author's slots and nothing else.
    assert_eq!(request.slot_count(), 1);
    assert_eq!(request.credential_handles(), vec!["stripe_api"]);
}

/// A handle that was never declared reaches the custodian as an unknown
/// credential at egress; the checker refuses it at build time instead.
#[test]
fn a_request_naming_an_undeclared_credential_is_refused() {
    let compiled =
        compile_program(&REQUEST_PROGRAM.replace("bearer stripe_api", "bearer typo_api"));
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("presents undeclared credential `typo_api`")),
        "{:?}",
        compiled
            .diagnostics
            .iter()
            .map(|d| &d.message)
            .collect::<Vec<_>>()
    );
}

/// A request that presents nothing and signs nothing authenticates nothing.
/// Saying so at build time is cheaper than discovering it against a live
/// endpoint, and `signed with` alone still satisfies it.
#[test]
fn a_request_that_authenticates_nothing_is_refused_but_signing_alone_suffices() {
    let unauthenticated =
        REQUEST_PROGRAM.replace("    header \"Authorization\" bearer stripe_api\n", "");
    let compiled = compile_program(&unauthenticated);
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("authenticates nothing")),
        "{:?}",
        compiled
            .diagnostics
            .iter()
            .map(|d| &d.message)
            .collect::<Vec<_>>()
    );

    // Signing is authentication too, so the same body with `signed with` is
    // accepted -- the check must not demand a header slot specifically.
    let signed = unauthenticated.replace("  } as refund", "  } signed with stripe_api as refund");
    let compiled = compile_program(&signed);
    assert!(
        !compiled
            .diagnostics
            .iter()
            .any(|d| d.message.contains("authenticates nothing")),
        "{:?}",
        compiled
            .diagnostics
            .iter()
            .map(|d| &d.message)
            .collect::<Vec<_>>()
    );
}

/// One `CustodyOp::Request` carries one credential's material, so a request
/// naming two is not expressible at the custodian. The sentinel format supports
/// several handles; the operation does not, and the author should learn that
/// from the compiler rather than at egress.
#[test]
fn a_request_presenting_two_credentials_is_refused() {
    let two = REQUEST_PROGRAM
        .replace(
            "credential stripe_api { kind bearer }",
            "credential stripe_api { kind bearer }\ncredential other_api { kind bearer }",
        )
        .replace(
            "    header \"Idempotency-Key\" ticket.id",
            "    header \"X-Other\" bearer other_api",
        );
    let compiled = compile_program(&two);
    assert!(
        compiled.diagnostics.iter().any(|d| d
            .message
            .contains("presents 2 credentials in one `request`")),
        "{:?}",
        compiled
            .diagnostics
            .iter()
            .map(|d| &d.message)
            .collect::<Vec<_>>()
    );
}

// --- DR-0074 §10: `sealed<T>` -------------------------------------------------

#[test]
fn sealed_type_parses_and_carries_its_payload_type() {
    // A sealed field is declarable and its payload type is a schema reference
    // like any other, so `validate_type_refs` must see through the constructor.
    let source = r#"
workflow SealedFields

class PatientRecord {
  notes string
}

class Claim {
  id string
  body sealed<PatientRecord>
}

rule seed
  when started
=> {
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("sealed field compiles");
    let claim = ir
        .schemas
        .iter()
        .find_map(|schema| match schema {
            IrSchema::Class(class) if class.name == "Claim" => Some(class),
            _ => None,
        })
        .expect("Claim schema");
    let body = claim
        .fields
        .iter()
        .find(|field| field.name == "body")
        .expect("body field");
    // The payload type survives into the IR: this is the whole reason §10 puts
    // it in the type rather than leaving it to provenance.
    assert_eq!(
        format!("{:?}", body.ty),
        "Sealed(Ref(\"PatientRecord\"))",
        "sealed<T> must carry T into the IR"
    );
}

#[test]
fn sealed_payload_type_must_resolve() {
    // The constructor is transparent to schema-reference checking, so an
    // unknown payload type is caught rather than hidden by the wrapper.
    let source = r#"
workflow SealedUnknownPayload

class Claim {
  body sealed<NoSuchClass>
}

rule seed
  when started
=> {
}
"#;

    let compiled = compile_program(source);
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("unknown schema reference `NoSuchClass`")));
}

#[test]
fn sealed_field_rejects_a_literal_because_there_is_no_literal_form() {
    // DR-0074 §1: a sealed value arises only from `seal`. A literal in the slot
    // is refused with the route to fix rather than a downstream type mismatch.
    let source = r#"
workflow SealedLiteral

class PatientRecord {
  notes string
}

class Claim {
  body sealed<PatientRecord>
}

rule seed
  when started
=> {
  record Claim {
    body "not ciphertext"
  }
}
"#;

    let compiled = compile_program(source);
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("expects `sealed<PatientRecord>`, which has no literal form")
        }),
        "diagnostics were: {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

// --- DR-0074 §2: the type-narrowed grant class -------------------------------

fn sealed_grant_source(grant_ops: &str) -> String {
    format!(
        r#"
use std.agent
workflow SealedGrant

class PatientRecord {{
  notes string
}}

agent triage {{ provider fixture  profile "repo-writer"  capacity 1 }}

credential phi_key {{ kind raw }}

rule seed
  when started
=> {{
  tell triage
    with access to credential phi_key {{
      {grant_ops}
    }}
  "Triage the claim."
}}
"#
    )
}

fn kinded_grant_source(kind: &str, grant_ops: &str) -> String {
    format!(
        r#"
use std.agent
workflow KindedGrant

class PatientRecord {{
  notes string
}}

agent triage {{ provider fixture  profile "repo-writer"  capacity 1 }}

credential key {{ kind {kind} }}

rule seed
  when started
=> {{
  tell triage
    with access to credential key {{
      {grant_ops}
    }}
  "Triage the claim."
}}
"#
    )
}

#[test]
fn a_credential_kind_that_cannot_unwrap_is_refused_at_compile_time() {
    // `CredentialKind::supports` was enforced only by the custodian, so an
    // ed25519 key granted `unwrap` compiled clean and failed in production. An
    // ed25519 key cannot decrypt, and nothing about that depends on runtime
    // state, so the compiler is where it belongs — S4's argument, applied to
    // custody.
    let compiled = compile_program(&kinded_grant_source("ed25519", "unwrap for PatientRecord"));
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("whose kind `ed25519` cannot perform it")
        }),
        "diagnostics were: {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
    // The refusal names the kinds that CAN, which is what makes `kind raw`
    // discoverable rather than folklore held in the custodian's source.
    assert!(compiled.diagnostics.iter().any(|diagnostic| {
        diagnostic
            .suggestion
            .as_deref()
            .is_some_and(|s| s.contains("raw or hmac-sha256"))
    }));
}

#[test]
fn the_kinds_that_can_unwrap_still_compile() {
    // Both arms of `supports`, so the check is not simply refusing `unwrap`.
    for kind in ["raw", "hmac-sha256"] {
        let compiled = compile_program(&kinded_grant_source(kind, "unwrap for PatientRecord"));
        assert_eq!(compiled.diagnostics, Vec::new(), "kind {kind} must unwrap");
    }
}

#[test]
fn the_credential_kind_check_covers_every_operation_not_just_unwrap() {
    // Written because a check that happened to be right about `unwrap` and
    // wrong about everything else would pass the tests above.
    let signing = compile_program(&kinded_grant_source("bearer", "sign"));
    assert!(
        signing
            .diagnostics
            .iter()
            .any(|d| d.message.contains("cannot perform it")),
        "a bearer token does not sign: {:?}",
        signing
            .diagnostics
            .iter()
            .map(|d| &d.message)
            .collect::<Vec<_>>()
    );
    let requesting = compile_program(&kinded_grant_source("ed25519", "request [\"api/*\"]"));
    assert!(requesting
        .diagnostics
        .iter()
        .any(|d| d.message.contains("cannot perform it")));
    // ...and a kind that does support its operation is left alone.
    assert_eq!(
        compile_program(&kinded_grant_source("ed25519", "sign")).diagnostics,
        Vec::new()
    );
}

#[test]
fn type_narrowed_unwrap_grant_names_its_type() {
    let compiled = compile_program(&sealed_grant_source("unwrap for PatientRecord"));
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some());
}

#[test]
fn bare_unwrap_grant_fails_closed() {
    // Reading a bare `unwrap` as "every type" would preserve exactly the
    // over-grant DR-0074 exists to remove, so it is a check error.
    let compiled = compile_program(&sealed_grant_source("unwrap"));
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| {
            diagnostic.message.contains("names no type")
                && diagnostic.message.contains("credential `phi_key`")
        }),
        "diagnostics were: {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn unwrap_grant_refuses_a_glob_list() {
    // §14's original objection stands: there is no natural glob for `unwrap`,
    // and a clause that reads as narrowed while meaning nothing is the
    // over-promise the class system exists to avoid.
    let compiled = compile_program(&sealed_grant_source(
        "unwrap for PatientRecord [\"records/*\"]",
    ));
    assert!(compiled.diagnostics.iter().any(|diagnostic| diagnostic
        .message
        .contains("carries a glob list as well as a type")));
}

#[test]
fn non_narrowable_wrap_grant_refuses_narrowing() {
    // `wrap` stays non-narrowable deliberately: sealing into a type is the
    // author's own act on data it already holds.
    let compiled = compile_program(&sealed_grant_source("wrap for PatientRecord"));
    assert!(compiled
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("carries a narrowing clause")));
}

// --- The exec unwrap grant: a deterministic projection of a sealed value -----

fn exec_grant_source(grant: &str) -> String {
    format!(
        r#"
use std.custody
use std.script
@service
workflow ExecGrant

class PatientRecord {{
  notes string
  acuity string
}}

class Claim {{
  id string
  body sealed<PatientRecord>
}}

class Acuity {{
  acuity string
}}

credential phi_key {{ kind raw }}

@external
rule project
  when Claim as claim
=> {{
  exec project_acuity with claim -> Acuity
{grant}
    as a
  after a succeeds as r {{
    record Acuity {{ acuity r.acuity }}
  }}
}}
"#
    )
}

#[test]
fn exec_takes_an_unwrap_grant_in_modifier_position() {
    // The grammar question this construct posed: `exec <cap> with <binding>`
    // already spends `with` on the stdin binding, so a grant clause looked like
    // it needed a new spelling. It does not — the stdin `with` is consumed by
    // the target parse, and the grant sits in MODIFIER position alongside `as`,
    // `requires` and `timeout`, where every other construct puts it.
    let compiled = compile_program(&exec_grant_source(
        "    with access to credential phi_key {\n\
         \x20     unwrap for PatientRecord\n\
         \x20   }",
    ));
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("ir");
    let effect = ir
        .rules
        .iter()
        .flat_map(|rule| rule.metadata.effects.iter())
        .find(|effect| effect.kind == IrEffectKind::ExecCommand)
        .expect("exec effect");
    // The grant must reach the effect's DURABLE row: the worker opens on the
    // strength of what was authorized at commit, not of what it can reach at
    // execution.
    assert!(
        effect.access_grants.iter().any(|grant| {
            grant.resource == "credential phi_key"
                && grant.operations.iter().any(|op| {
                    op.operation == "unwrap" && op.target.as_deref() == Some("PatientRecord")
                })
        }),
        "grants were: {:?}",
        effect.access_grants
    );
}

#[test]
fn an_exec_without_the_grant_still_refuses_the_sealed_stdin() {
    // Without the grant the script receives ciphertext on stdin, which is the
    // same failure the check exists to prevent for a model prompt.
    let compiled = compile_program(&exec_grant_source(""));
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("would receive ciphertext")),
        "diagnostics were: {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_exec_grant_narrows_by_type_like_every_other() {
    let compiled = compile_program(&exec_grant_source(
        "    with access to credential phi_key {\n\
         \x20     unwrap for Acuity\n\
         \x20   }",
    ));
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("unwrap for PatientRecord")),
        "diagnostics were: {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

// --- Worker-side opening: a sealed input needs an unwrap grant ---------------

fn sealed_input_source(grant: &str) -> String {
    format!(
        r#"
use std.custody
use std.agent
@service
workflow SealedInput

class PatientRecord {{
  notes string
}}

class Claim {{
  id string
  body sealed<PatientRecord>
}}

agent Specialist {{ provider fixture  profile "repo-writer"  capacity 1 }}
credential phi_key {{ kind raw }}

@external
rule delegate
  when Claim as claim
=> {{
  tell Specialist
{grant}
    "Summarize this record: {{{{ claim.body }}}}" as summary
}}
"#
    )
}

fn nested_sealed_source(sent: &str, grant: &str) -> String {
    format!(
        r#"
use std.custody
use std.agent
@service
workflow NestedSealed

class PatientRecord {{
  notes string
}}

class Claim {{
  id string
  body sealed<PatientRecord>
}}

class Batch {{
  claims Claim[]
}}

agent Specialist {{ provider fixture  profile "repo-writer"  capacity 1 }}
credential phi_key {{ kind raw }}

@external
rule delegate
  when Claim as claim
=> {{
  tell Specialist
{grant}
    "Look at {{{{ {sent} }}}}" as summary
}}
"#
    )
}

fn nested_errors(sent: &str, grant: &str) -> Vec<String> {
    compile_program(&nested_sealed_source(sent, grant))
        .diagnostics
        .into_iter()
        .map(|diagnostic| diagnostic.message)
        .filter(|message| message.contains("would receive ciphertext"))
        .collect()
}

#[test]
fn a_sealed_field_reached_through_a_record_is_refused_too() {
    // The gap this closes. `dotted_paths` yields only paths with at least one
    // field, so a value passed WHOLE was invisible to the check — while the
    // runtime walker recurses into objects to find exactly that envelope. The
    // checker disagreed with the resolution it is supposed to be gating, and
    // the provider got ciphertext in a nested field.
    let errors = nested_errors("claim", "");
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(
        errors[0].contains("claim.body"),
        "names the field: {errors:?}"
    );
}

#[test]
fn naming_the_record_and_the_field_reports_the_sealed_value_once() {
    // Keyed by WHERE the sealed value is, not by how it was reached, so a
    // prompt mentioning both does not report the same field twice.
    let errors = nested_errors("claim }} and {{ claim.body", "");
    assert_eq!(errors.len(), 1, "{errors:?}");
}

#[test]
fn a_grant_admits_the_nested_sealed_field() {
    // The other half: worker-side opening recurses, so a granted turn may pass
    // the whole record and have its envelope opened in place.
    let errors = nested_errors(
        "claim",
        "    with access to credential phi_key {\n\
         \x20     unwrap for PatientRecord\n\
         \x20   }",
    );
    assert_eq!(errors, Vec::<String>::new());
}

#[test]
fn a_sealed_value_inside_a_collection_is_reached() {
    // A sealed value in an array still renders as ciphertext, and the runtime
    // walker descends into arrays, so the checker must too.
    let errors = nested_errors("batch", "");
    assert!(
        errors.is_empty(),
        "no `batch` binding in this rule: {errors:?}"
    );

    let source =
        nested_sealed_source("claim", "").replace("  when Claim as claim", "  when Batch as batch");
    let messages: Vec<String> = compile_program(&source.replace("{{ claim }}", "{{ batch }}"))
        .diagnostics
        .into_iter()
        .map(|diagnostic| diagnostic.message)
        .filter(|message| message.contains("would receive ciphertext"))
        .collect();
    assert!(
        messages
            .iter()
            .any(|message| message.contains("claims.body")),
        "reached through the array: {messages:?}"
    );
}

#[test]
fn a_sealed_value_reaching_a_provider_without_a_grant_is_refused() {
    // The trap: a sealed value interpolated into a prompt renders as its
    // ENVELOPE, so the provider receives base64 ciphertext and answers about
    // nothing. It compiles, it runs, and the failure looks like a plausible
    // model reply. There is no sentinel machinery for payloads the way DR-0053
    // §5 provides one for credentials.
    let compiled = compile_program(&sealed_input_source(""));
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("the provider would receive ciphertext")
        }),
        "diagnostics were: {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn an_unwrap_grant_on_the_turn_admits_the_sealed_input() {
    // The other statement an effect can be making: worker-side opening. The
    // effect's durable row already records `unwrap` narrowed to the type,
    // which is the authorization half — what is missing is the runtime
    // resolution, not the surface.
    let compiled = compile_program(&sealed_input_source(
        "    with access to credential phi_key {\n\
         \x20     unwrap for PatientRecord\n\
         \x20   }",
    ));
    assert_eq!(compiled.diagnostics, Vec::new());
}

#[test]
fn a_grant_for_another_type_does_not_admit_it() {
    // The narrowing has to bite here too, or the grant is possession-based
    // again: holding `unwrap for` anything would admit every sealed input.
    let compiled = compile_program(&sealed_input_source(
        "    with access to credential phi_key {\n\
             \x20     unwrap for Claim\n\
             \x20   }",
    ));
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("no `unwrap for PatientRecord` grant")
        }),
        "diagnostics were: {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

// --- DR-0074 §3: `open` and the confinement region ---------------------------

fn open_source(body: &str) -> String {
    format!(
        r#"
use std.custody
@service
workflow OpenRegion

class PatientRecord {{
  notes string
  severity int
}}

class BillingRecord {{
  amount int
}}

class Claim {{
  id string
  body sealed<PatientRecord>
}}

class Triaged {{
  id string
  note string
}}

credential phi_key {{ kind raw }}

@external
rule triage
  when Claim as claim
=> {{
{body}
}}
"#
    )
}

#[test]
fn open_is_an_effect_whose_after_block_binds_the_plaintext() {
    // DR-0074 §3: `open` is an effect because a rule commit does no I/O and
    // AEAD is nondeterministic, so the plaintext binds where every effect
    // output binds — inside `after`. That block IS the confinement region; no
    // new region construct exists, and `Region` is taken by DR-0043 anyway.
    let compiled = compile_program(&open_source(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20 }",
    ));
    assert_eq!(compiled.diagnostics, Vec::new());
    let ir = compiled.ir.expect("ir");
    let rule = ir.rules.first().expect("rule");
    assert!(
        rule.metadata
            .effects
            .iter()
            .any(|effect| effect.kind == IrEffectKind::CapabilityCall),
        "open lowers to a capability call"
    );
}

#[test]
fn the_plaintext_binding_carries_the_type_it_was_opened_into() {
    // The binding is typed by `into <Type>`, so a field on it resolves like any
    // other typed binding — and a field that does not exist is caught.
    // The assertion is about the TYPE, so it checks for the absence of a
    // field-path error rather than of every diagnostic: §4 independently
    // refuses the crossing, and that refusal is another test's subject.
    let good = compile_program(&open_source(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20   record Triaged { id claim.id  note patient.notes }\n\
         \x20 }",
    ));
    assert!(
        !good
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("invalid field path")),
        "`notes` is a real field of PatientRecord: {:?}",
        good.diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );

    let bad = compile_program(&open_source(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20   record Triaged { id claim.id  note patient.nosuchfield }\n\
         \x20 }",
    ));
    assert!(
        bad.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("schema `PatientRecord` has no field `nosuchfield`")
        }),
        "diagnostics were: {:?}",
        bad.diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn opening_into_the_wrong_type_is_refused() {
    // DR-0074 §3, obligation 3. A mismatch is not a cast: it asks the custodian
    // for a grant on one type while handing it another, so if a grant on the
    // named type existed it would open bytes under an authorisation that was
    // never about them.
    let compiled = compile_program(&open_source(
        "  open claim.body into BillingRecord with phi_key as opening\n\
         \x20 after opening succeeds as billing {\n\
         \x20 }",
    ));
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("but it is sealed as `sealed<PatientRecord>`")
        }),
        "diagnostics were: {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn opening_something_that_is_not_sealed_is_refused() {
    // `open claim.id` names a plain string. Left unchecked it would reach the
    // custodian as an envelope and fail there, at run time, in production.
    let compiled = compile_program(&open_source(
        "  open claim.id into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20 }",
    ));
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("which is not a sealed value")),
        "diagnostics were: {:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

// --- DR-0074 §4: the crossing rule -------------------------------------------

fn confinement_source(body: &str) -> String {
    format!(
        r#"
use std.custody
use std.agent
@service
workflow Confinement

class PatientRecord {{
  notes string
  kind "urgent" | "normal"
}}

class Claim {{
  id string
  body sealed<PatientRecord>
}}

class Triaged {{
  id string
  note string
}}

agent worker {{ provider fixture  profile "repo-writer"  capacity 1 }}
credential phi_key {{ kind raw }}

@external
rule triage
  when Claim as claim
=> {{
{body}
}}
"#
    )
}

fn confinement_errors(body: &str) -> Vec<String> {
    compile_program(&confinement_source(body))
        .diagnostics
        .into_iter()
        .map(|diagnostic| diagnostic.message)
        .collect()
}

#[test]
fn opened_plaintext_may_not_reach_a_fact() {
    // §4, the load-bearing rule. `facts.value_json` is durable, so this is the
    // crossing the whole record exists to refuse.
    let errors = confinement_errors(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20   record Triaged { id claim.id  note patient.notes }\n\
         \x20 }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("holds plaintext opened inside a")),
        "{errors:?}"
    );
}

#[test]
fn the_confinement_travels_through_derivation() {
    // §6: a value computed from in-region plaintext is itself in-region.
    // Without this the discipline is defeated by one interpolation, and §4
    // would protect only the value that entered the block.
    let errors = confinement_errors(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20   record Triaged { id claim.id  note \"seen: {{ patient.notes }}\" }\n\
         \x20 }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("holds plaintext opened inside a")),
        "{errors:?}"
    );
}

#[test]
fn opened_plaintext_may_not_reach_any_effect_input() {
    // §4: "Reaching anything outside whip means creating an effect, and every
    // effect records its input durably." There is no non-durable sink, so a
    // turn is a crossing exactly as a fact is.
    let errors = confinement_errors(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20   tell worker \"Summarize {{ patient.notes }}\"\n\
         \x20 }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("creates an effect, whose input is durable")),
        "{errors:?}"
    );
}

#[test]
fn in_region_plaintext_may_be_compared_freely() {
    // §4: within the interpreter it may be computed over freely — compared,
    // projected, iterated, interpolated. None of that writes anything down, so
    // a `case` over plaintext is not a crossing and a fact built from
    // non-confined values inside the arm is fine.
    let errors = confinement_errors(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20   case patient.kind {\n\
         \x20     \"urgent\" => {\n\
         \x20       record Triaged { id claim.id  note \"high\" }\n\
         \x20     }\n\
         \x20     _ => {}\n\
         \x20   }\n\
         \x20 }",
    );
    assert_eq!(errors, Vec::<String>::new());
}

#[test]
fn a_case_binding_over_plaintext_stays_confined() {
    // The arm's `as` binding is part of the plaintext, so recording IT is the
    // same crossing wearing a different name.
    let errors = confinement_errors(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20   case patient.kind {\n\
         \x20     \"urgent\" as k => {\n\
         \x20       record Triaged { id claim.id  note k }\n\
         \x20     }\n\
         \x20     _ => {}\n\
         \x20   }\n\
         \x20 }",
    );
    assert!(
        errors
            .iter()
            .any(|message| message.contains("holds plaintext opened inside a")),
        "{errors:?}"
    );
}

#[test]
fn outside_the_region_nothing_is_confined() {
    // Zero false positives: the rule applies to the region, not to the rule.
    let errors = confinement_errors(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20 }\n\
         \x20 record Triaged { id claim.id  note claim.id }",
    );
    assert_eq!(errors, Vec::<String>::new());
}

#[test]
fn the_refusal_offers_confine_as_a_resolution() {
    // The DR's *Consequences*: `confine` is a FOURTH resolution beside
    // `separate`, `cleared`, and `downgrade`, and the diagnostic is where an
    // author meets it.
    let compiled = compile_program(&confinement_source(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20   record Triaged { id claim.id  note patient.notes }\n\
         \x20 }",
    ));
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .suggestion
                .as_deref()
                .is_some_and(|text| text.contains("confine the work to the region"))
        }),
        "{:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.suggestion)
            .collect::<Vec<_>>()
    );
}

// --- DR-0074 §5: `declassify`, the region's pure exit ------------------------

fn declassify_source(body: &str) -> String {
    format!(
        r#"
use std.custody
@service
workflow Declassifying

class PatientRecord {{
  notes string
  severity int
}}

class Receipt {{
  severity int
}}

class Claim {{
  id string
  body sealed<PatientRecord>
}}

class Triaged {{
  id string
  severity int
}}

credential phi_key {{ kind raw }}

@external
rule triage
  when Claim as claim
=> {{
{body}
}}
"#
    )
}

const OPEN_AND_DECLASSIFY: &str = "  open claim.body into PatientRecord with phi_key as opening\n\
     \x20 after opening succeeds as patient {\n\
     \x20   declassify patient into Receipt as receipt\n\
     \x20   record Triaged { id claim.id  severity receipt.severity }\n\
     \x20 }";

#[test]
fn declassify_is_the_exit_that_lets_a_value_out_of_a_region() {
    // §5. Without a working exit a region satisfies §4 trivially and the whole
    // construct is vacuous, so this is the test that says the feature does
    // something. `declassify` is pure — no effect, no durable input row —
    // which is exactly why it can be the exit while `seal` (an effect) cannot
    // yet be.
    let compiled = compile_program(&declassify_source(OPEN_AND_DECLASSIFY));
    assert_eq!(compiled.diagnostics, Vec::new());
}

#[test]
fn a_declassified_value_is_no_longer_confined() {
    // The point of the crossing: `receipt` may be recorded, while `patient`
    // may not.
    let refused = compile_program(&declassify_source(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20   record Triaged { id claim.id  severity patient.severity }\n\
         \x20 }",
    ));
    assert!(
        refused.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("holds plaintext opened inside a")),
        "{:?}",
        refused
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_declassify_target_type_must_really_project_the_source() {
    // The target type is the BOUND on the release, so it has to be a real
    // projection rather than an assertion. A target naming a field the source
    // does not have is a release whose shape nothing checks — the decorative
    // mechanism the grant classes exist to avoid.
    let compiled = compile_program(&declassify_source(OPEN_AND_DECLASSIFY).replace(
        "severity int\n}\n\nclass Claim",
        "nosuchfield string\n}\n\nclass Claim",
    ));
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("a field `PatientRecord` does not have")),
        "{:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn the_declassified_binding_carries_the_target_type() {
    let compiled = compile_program(&declassify_source(
        "  open claim.body into PatientRecord with phi_key as opening\n\
         \x20 after opening succeeds as patient {\n\
         \x20   declassify patient into Receipt as receipt\n\
         \x20   record Triaged { id claim.id  severity receipt.bogus }\n\
         \x20 }",
    ));
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| {
            diagnostic
                .message
                .contains("schema `Receipt` has no field `bogus`")
        }),
        "{:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn declassify_joins_the_audited_crossing_set() {
    // §5 calls this the GRANTED, audited crossing. Wiring the binding into
    // `declassified_roots` is what makes it audited rather than merely
    // explicit: the existing DR-0027 machinery — `grant declassify`
    // consultation at the egress, the guarantee report's trusted surface,
    // NMIF-on-the-selector — all key on that set, so the exit inherits the
    // whole discipline instead of introducing a second one.
    let compiled = compile_program(&declassify_source(OPEN_AND_DECLASSIFY));
    let ir = compiled.ir.expect("ir");
    let rule = ir.rules.first().expect("rule");
    assert!(
        rule.metadata.declassified_roots.contains("receipt"),
        "declassified roots were: {:?}",
        rule.metadata.declassified_roots
    );
}

// --- DR-0074 §10: a sealed value is storable, at its own payload type -------

fn seal_storage_source(sealed: &str, field_type: &str) -> String {
    format!(
        r#"
use std.custody
@service
workflow SealStorage

class PatientRecord {{
  notes string
}}

class Claim {{
  id string
  rec PatientRecord
}}

class Stored {{
  id string
  body {field_type}
}}

credential phi_key {{ kind raw }}

@external
rule keep
  when Claim as claim
=> {{
  seal {sealed} with phi_key as sealing
  after sealing succeeds as envelope {{
    record Stored {{ id claim.id  body envelope }}
  }}
}}
"#
    )
}

#[test]
fn a_sealed_value_can_be_stored_in_a_sealed_field() {
    // Slice 1 shipped `seal` without ever storing its result, so this path was
    // never exercised: a bare binding in a field position parses as
    // `LiteralExpr::Ident`, and the no-literal-form refusal caught it. The
    // envelope had nowhere to go, which is the whole point of sealing.
    let compiled = compile_program(&seal_storage_source("claim.rec", "sealed<PatientRecord>"));
    assert_eq!(compiled.diagnostics, Vec::new());
}

#[test]
fn a_literal_in_a_sealed_field_is_still_refused() {
    // The exemption above is for BINDINGS. A literal still has no sealed form,
    // and that refusal is the one DR-0074 §1 asks for.
    let compiled = compile_program(
        &seal_storage_source("claim.rec", "sealed<PatientRecord>")
            .replace("body envelope }", "body \"ciphertext\" }"),
    );
    assert!(
        compiled
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("which has no literal form")),
        "{:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_sealed_value_may_not_be_stored_at_the_wrong_payload_type() {
    // The three-way agreement §2 depends on is only as good as its weakest
    // leg. `open` trusts the FIELD's declared type to choose the unwrap grant,
    // so a string stored in a `sealed<PatientRecord>` field would make it ask
    // for a grant on a type the bytes were never sealed as.
    let compiled = compile_program(&seal_storage_source("claim.id", "sealed<PatientRecord>"));
    assert!(
        compiled.diagnostics.iter().any(|diagnostic| diagnostic
            .message
            .contains("it was sealed as `sealed<string>`")),
        "{:?}",
        compiled
            .diagnostics
            .iter()
            .map(|diagnostic| &diagnostic.message)
            .collect::<Vec<_>>()
    );
}

// --- DR-0074 §12: `seal` as a std.custody construct instance -----------------

#[test]
fn seal_is_a_package_effect_with_an_after_binding() {
    // The whole point of §12: `seal` is a construct instance declared in the
    // std.custody manifest, not a core effect kind. It must parse, create an
    // effect, and have that effect's binding resolve in an `after` block —
    // which is where an earlier cut failed, because the text-based scanner
    // carried its own hardcoded verb list independent of the generated table.
    let source = r#"
use std.custody
workflow SealDemo
output result R
class R { ok bool }

class PatientRecord {
  notes string
}

credential phi_key { kind raw }

rule intake
  when started
=> {
  record PatientRecord { notes "confidential" }
}

rule seal_it
  when PatientRecord as patient
=> {
  seal patient with phi_key as sealing
  after sealing succeeds {
    complete result { ok true }
  }
  after sealing fails {
    complete result { ok false }
  }
}
"#;

    let compiled = compile_program(source);
    assert_eq!(compiled.diagnostics, Vec::new());
    assert!(compiled.ir.is_some(), "seal compiles end to end");
}

#[test]
fn seal_requires_its_credential_connective() {
    // The slot carries the `with` connective, so omitting it is a parse error
    // rather than a silently different effect.
    let source = r#"
use std.custody
workflow SealDemo
output result R
class R { ok bool }
class PatientRecord { notes string }
credential phi_key { kind raw }

rule seal_it
  when PatientRecord as patient
=> {
  seal patient phi_key as sealing
  after sealing succeeds {
    complete result { ok true }
  }
}
"#;

    let compiled = compile_program(source);
    assert!(
        !compiled.diagnostics.is_empty(),
        "a missing `with` must not parse as a valid seal"
    );
}
