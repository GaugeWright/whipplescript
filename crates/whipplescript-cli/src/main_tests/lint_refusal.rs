//! Extracted verbatim from `main.rs` (module path `lint_refusal_tests` is unchanged).

use super::{lint_agent_tool_grants, lint_workflow_liveness};
use whipplescript_parser::{compile_program, compile_program_with_root, IrProgram};

/// `whip lint` ships zero-false-positive analyses, which means every one of
/// these is meant to be a hard signal. A mutation sweep found that none of
/// them was exercised: deleting any single diagnostic left the whole workspace
/// suite green. A lint that never fires is not a strict lint, it is a broken
/// one, and nothing here could tell the difference.
fn ir_of(source: &str) -> IrProgram {
    let compiled = compile_program(source);
    assert!(
        compiled.ir.is_some(),
        "fixture must lower: {:?}",
        compiled.diagnostics
    );
    compiled.ir.expect("ir")
}

fn ir_rooted(source: &str, root: &str) -> IrProgram {
    let compiled = compile_program_with_root(source, Some(root));
    assert!(
        compiled.ir.is_some(),
        "fixture must lower: {:?}",
        compiled.diagnostics
    );
    compiled.ir.expect("ir")
}

fn asserts(ir: &IrProgram, expected: &str) {
    let found = lint_workflow_liveness(ir);
    assert!(
        found.iter().any(|d| d.message.contains(expected)),
        "expected `{expected}`, got {:?}",
        found.iter().map(|d| d.message.as_str()).collect::<Vec<_>>()
    );
}

fn is_clean(ir: &IrProgram) {
    let found = lint_workflow_liveness(ir);
    assert!(
        found.is_empty(),
        "a well-formed workflow must draw no liveness lint, got {:?}",
        found.iter().map(|d| d.message.as_str()).collect::<Vec<_>>()
    );
}

/// The accept case for every rejection below: without it, a lint that fired on
/// everything would satisfy the whole module.
const WELL_FORMED: &str = r#"
workflow Fine
output result R
class R { ok bool }
rule r
  when started
=> { complete result { ok true } }
"#;

#[test]
fn a_workflow_with_no_terminal_is_flagged() {
    asserts(
        &ir_of(
            r#"
workflow NoEnd
class Note { id string }
table seed as Note [ { id "1" } ]
rule r
  when Note as n
=> { record Note { id "2" } }
"#,
        ),
        "has no rule that reaches `complete` or `fail`",
    );
    is_clean(&ir_of(WELL_FORMED));
}

#[test]
fn a_tool_workflow_cannot_also_be_a_service() {
    asserts(
        &ir_of(
            r#"
@tool
@service
workflow Both
output result R
class R { ok bool }
rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        "is both `@tool` and `@service`",
    );
}

/// `@bounded` and `@service` answer the same question in opposite directions —
/// does this workflow settle — and the effect-cycle check reads both, so a
/// workflow carrying the pair is refused rather than silently resolved.
#[test]
fn a_bounded_workflow_cannot_also_be_a_service() {
    asserts(
        &ir_of(
            r#"
@bounded
@service
workflow BothWays
output result R
class R { ok bool }
rule r
  when started
=> { complete result { ok true } }
"#,
        ),
        "is both `@bounded` and `@service`",
    );
    is_clean(&ir_of(WELL_FORMED));
}

/// v1 `@tool` workflows must be leaves, must not be driven by an external
/// event, and must not await a message: each would make a tool's completion
/// depend on something its caller cannot see.
#[test]
fn a_tool_workflow_must_be_a_leaf() {
    asserts(
        &ir_rooted(
            r#"
class T { id string }
class R { ok bool }

@tool
workflow Leaf {
  input task T
  output result R
  rule r
    when T as t
  => {
    invoke Child { task { id t.id } } as c
    after c succeeds { complete result { ok true } }
    after c fails { complete result { ok true } }
  }
}

workflow Child {
  input task T
  output result R
  rule w
    when T as t
  => { complete result { ok true } }
}
"#,
            "Leaf",
        ),
        "invokes a sub-workflow; v1 `@tool` workflows must be leaves",
    );
}

#[test]
fn a_tool_workflow_rule_cannot_be_external() {
    asserts(
        &ir_of(
            r#"
@tool
workflow Ext
input task T
output result R
class T { id string }
class R { ok bool }
@external
rule r
  when T as t
=> { complete result { ok true } }
"#,
        ),
        "is `@external`; a `@tool` workflow",
    );
}

#[test]
fn a_tool_workflow_rule_cannot_await_a_message() {
    asserts(
        &ir_of(
            r##"
use std.messaging

@tool
workflow Msg
input task T
output result R
class T { id string }
class R { ok bool }
channel peer {
  provider local
  workspace ops
  destination "#peer"
}
rule r
  when message from peer as m
=> { complete result { ok true } }
"##,
        ),
        "awaits an inbound message",
    );
}

#[test]
fn a_rule_matching_a_fact_nothing_produces_is_flagged() {
    asserts(
        &ir_of(
            r#"
workflow Dead
output result R
class R { ok bool }
class Ghost { id string }
rule r
  when Ghost as g
=> { complete result { ok true } }
rule s
  when started
=> { complete result { ok true } }
"#,
        ),
        "can never fire: nothing produces `Ghost`",
    );
}

/// The same message has two producers: the ordinary `when <Class>` match and
/// the runtime `when fact <Class>` form. Covering one leaves the other
/// unexercised, which a message-level assertion alone would not reveal.
#[test]
fn a_rule_matching_a_runtime_fact_nothing_produces_is_flagged() {
    asserts(
        &ir_of(
            r#"
workflow DeadFact
output result R
class R { ok bool }
class Ghost { id string }
rule r
  when fact Ghost as g
=> { complete result { ok true } }
rule s
  when started
=> { complete result { ok true } }
"#,
        ),
        "can never fire: nothing produces `Ghost`",
    );
}

#[test]
fn a_rule_awaiting_a_turn_no_rule_creates_is_flagged() {
    asserts(
        &ir_of(
            r#"
workflow NoTurn
output result R
class R { ok bool }
agent worker {
  provider fixture
  profile "code"
  capacity 1
}
rule r
  when worker completed turn as t
=> { complete result { ok true } }
rule s
  when started
=> { complete result { ok true } }
"#,
        ),
        "can never fire: no rule creates an agent turn",
    );
}

/// A granted tool must be a `@tool` workflow that passes the convergence
/// check. Granting an agent a name that is not one hands it authority the
/// checker never resolved.
#[test]
fn an_agent_granted_a_non_tool_is_flagged() {
    // The grant resolver reads the program back off disk, so the fixture has
    // to be a real bundle: a granted name that resolves to an untagged
    // workflow is the only way to reach the `@tool` refusal rather than the
    // earlier "not a workflow in this program" one.
    let dir = std::env::temp_dir().join(format!(
        "whip-tool-grant-lint-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("grants.whip");
    let source = r#"
class R { ok bool }

workflow Grants {
  output result R
  agent worker {
    provider fixture
    profile "code"
    capacity 1
    tools [Helper]
  }
  rule r
    when started
  => { complete result { ok true } }
}

workflow Helper {
  output result R
  rule h
    when started
  => { complete result { ok true } }
}
"#;
    std::fs::write(&path, source).expect("write fixture");

    let ir = ir_rooted(source, "Grants");
    let found = lint_agent_tool_grants(&path, &ir, None);
    assert!(
        found.iter().any(|d| d
            .message
            .contains("is granted `Helper`: `Helper` is not tagged `@tool`")),
        "{:?}",
        found.iter().map(|d| d.message.as_str()).collect::<Vec<_>>()
    );

    // A name no workflow in the bundle carries is refused for that reason
    // instead: a distinct refusal, and it must not be mistaken for the one
    // above.
    let missing = ir_rooted(
        &source.replace("tools [Helper]", "tools [NoSuchTool]"),
        "Grants",
    );
    let found = lint_agent_tool_grants(&path, &missing, None);
    assert!(
        found.iter().any(|d| d
            .message
            .contains("is granted `NoSuchTool`: `NoSuchTool` is not a workflow in this program")),
        "{:?}",
        found.iter().map(|d| d.message.as_str()).collect::<Vec<_>>()
    );

    // A program granting nothing draws no grant lint.
    let clean = ir_of(WELL_FORMED);
    assert!(lint_agent_tool_grants(&path, &clean, None).is_empty());

    std::fs::remove_dir_all(&dir).ok();
}

const BUILTIN_TRIGGER_NAMES: [&str; 6] = [
    "AgentTurn",
    "WorkItem",
    "Evidence",
    "TerminalFailed",
    "TerminalTimedOut",
    "TerminalCancelled",
];

fn schema_trigger_source(
    _name: &str,
    pattern: &str,
    declarations: &str,
    producer: &str,
    external: bool,
) -> String {
    format!("workflow Probe\noutput result R\nclass R {{ ok bool }}\n{declarations}\n{producer}\nrule start when started => {{ complete result {{ ok true }} }}\n{}rule observe when {pattern} as item => {{ complete result {{ ok true }} }}\n", if external { "@external\n" } else { "" })
}

#[test]
fn builtin_schema_triggers_require_the_same_producers_as_explicit_facts() {
    for name in BUILTIN_TRIGGER_NAMES {
        for pattern in [name.to_owned(), format!("fact {name}")] {
            let source = schema_trigger_source(name, &pattern, "", "", false);
            asserts(
                &ir_of(&source),
                &format!("can never fire: nothing produces `{name}`"),
            );
        }
    }
}

#[test]
fn builtin_schema_triggers_keep_records_tables_inputs_and_external_admission() {
    for name in BUILTIN_TRIGGER_NAMES {
        let class = format!("class {name} {{ id string }}");
        let record = format!("rule seed when started => {{ record {name} {{ id \"one\" }} }}");
        is_clean(&ir_of(&schema_trigger_source(
            name, name, &class, &record, false,
        )));
        let table = format!("table seed as {name} [ {{ id \"one\" }} ]");
        is_clean(&ir_of(&schema_trigger_source(
            name, name, &class, &table, false,
        )));
        // Builtin Ref inputs do not declare a competing provider schema.
        let input = format!("input supplied {name}");
        for pattern in [name.to_owned(), format!("fact {name}")] {
            is_clean(&ir_of(&schema_trigger_source(
                name, &pattern, &input, "", false,
            )));
            is_clean(&ir_of(&schema_trigger_source(name, &pattern, "", "", true)));
        }
        // Preserve the existing reserved-name guard on the explicit spelling:
        // it is checked before liveness and is not weakened by this repair.
        let collision = compile_program(&schema_trigger_source(
            name,
            &format!("fact {name}"),
            &class,
            &record,
            false,
        ));
        assert!(collision.ir.is_none());
        assert!(collision
            .diagnostics
            .iter()
            .any(|d| d.code.as_str() == "construct.reserved_name"));
    }
    // Evidence has no observer-only record restriction; its actual builtin
    // producer remains valid without a user-declared same-name class.
    let record = "rule seed when started => { record Evidence { title \"proof\" path \"local\" summary \"observed\" } }";
    for pattern in ["Evidence", "fact Evidence"] {
        is_clean(&ir_of(&schema_trigger_source(
            "Evidence", pattern, "", record, false,
        )));
    }
}

#[test]
fn observer_declarations_do_not_produce_bare_schema_facts() {
    let tracker = schema_trigger_source("WorkItem", "WorkItem", "tracker review", "", false);
    asserts(
        &ir_of(&tracker),
        "can never fire: nothing produces `WorkItem`",
    );
    let agent = "agent worker { provider fixture profile \"code\" capacity 1 }";
    let tell = "rule seed when started => { tell worker as turn \"hello\" }";
    let turn = schema_trigger_source("AgentTurn", "AgentTurn", agent, tell, false);
    asserts(
        &ir_of(&turn),
        "can never fire: nothing produces `AgentTurn`",
    );
    is_clean(&ir_of(&schema_trigger_source(
        "WorkItem",
        "review has ready issue",
        "tracker review",
        "",
        false,
    )));
    is_clean(&ir_of(&schema_trigger_source(
        "AgentTurn",
        "worker completed turn",
        agent,
        tell,
        false,
    )));
}

/// WS-274: each builtin name, refused as an unproduced bare (or `fact`)
/// trigger, says what that name actually means as a trigger. The suggestion is
/// per name because the remedies differ: two have observer sugar, one is
/// recordable, and three are terminal case payloads.
#[test]
fn unproduced_builtin_schema_triggers_name_their_meaning() {
    let cases: [(&str, &[&str]); 6] = [
        (
            "AgentTurn",
            &["cannot be recorded", "completed turn as turn"],
        ),
        (
            "WorkItem",
            &["cannot be recorded", "has ready issue as issue"],
        ),
        ("Evidence", &["record it in another rule"]),
        (
            "TerminalFailed",
            &["terminal case payload", "after <effect> fails as x"],
        ),
        (
            "TerminalTimedOut",
            &["terminal case payload", "after <effect> times out as x"],
        ),
        (
            "TerminalCancelled",
            &["terminal case payload", "after <effect> cancels as x"],
        ),
    ];
    for (name, expected) in cases {
        for pattern in [name.to_owned(), format!("fact {name}")] {
            let ir = ir_of(&schema_trigger_source(name, &pattern, "", "", false));
            let found = lint_workflow_liveness(&ir);
            let refusal = found
                .iter()
                .find(|d| d.message.contains(&format!("nothing produces `{name}`")))
                .unwrap_or_else(|| panic!("`{pattern}` must be refused, got {found:?}"));
            assert_eq!(refusal.code.as_str(), "graph.rule_never_fires");
            let suggestion = &refusal.suggestion.as_ref().expect("suggestion").message;
            for fragment in expected {
                assert!(
                    suggestion.contains(fragment),
                    "`{pattern}` suggestion must contain `{fragment}`, got `{suggestion}`"
                );
            }
            assert!(
                suggestion.contains("workflow input") && suggestion.contains("@external"),
                "`{pattern}` suggestion must keep the input/@external remedy, got `{suggestion}`"
            );
        }
    }
    // A declared class keeps the generic remedy.
    let ir = ir_of(&schema_trigger_source(
        "Order",
        "Order",
        "class Order { id string }",
        "",
        false,
    ));
    let found = lint_workflow_liveness(&ir);
    let suggestion = &found[0].suggestion.as_ref().expect("suggestion").message;
    assert!(
        suggestion.starts_with("seed `Order` from a table"),
        "{suggestion}"
    );
}

/// WS-274: the terminal case payloads are observed through `after … fails`,
/// which the liveness check accepts without any recorded producer.
#[test]
fn terminal_payloads_are_observed_through_after_blocks() {
    let source = "workflow Probe\noutput result R\nclass R { ok bool }\nagent worker { provider fixture profile \"code\" capacity 1 }\nrule start when started => {\n  tell worker as turn \"hello\"\n  after turn fails as failure {\n    complete result { ok false }\n  }\n}\n";
    is_clean(&ir_of(source));
}
