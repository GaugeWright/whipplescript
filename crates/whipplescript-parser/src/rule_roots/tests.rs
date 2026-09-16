use super::*;
use crate::action_plan::resolved::resolve_rule_types;

fn program(source: &str) -> Program {
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    parsed.program
}

fn source(whens: &str, body: &str) -> String {
    format!(
        r#"workflow Roots
class Person {{ name string }}
class Ticket {{ title string  owner Person?  worker AgentRef<reader> }}
class Result {{ status string }}
agent reader {{ provider mock }}
tracker backlog {{ provider builtin }}
channel inbox {{ provider fixture }}
signal deploy.finished {{ ok bool }}
action label(t Ticket) -> string {{ return t.title }}
rule run {whens} => {{ {body} }}
"#
    )
}

#[test]
fn root_preserves_actual_triggers_and_matches_legacy_projection_reads() {
    let source = source(
        "when Ticket as ticket where exists(Result where status == \"done\") && exists(Result where status == \"done\")\nwhen backlog has ready issue as item\nwhen message from inbox as msg\nwhen deploy.finished as event",
        "",
    );
    let program = program(&source);
    let root = resolve_rule_root(&program, "run").unwrap();
    assert_eq!(root.name.name, "run");
    assert_eq!(root.kind, RuleKind::Rule);
    assert_eq!(
        root.binding_schemas,
        BTreeMap::from([
            ("ticket".into(), "Ticket".into()),
            ("item".into(), "WorkItem".into()),
            ("msg".into(), "Message".into()),
            ("event".into(), "deploy.finished".into()),
        ])
    );
    assert_eq!(
        root.fact_reads,
        [
            "pattern:backlog has ready issue as item",
            "pattern:deploy.finished as event",
            "pattern:message from inbox as msg",
            "schema:Ticket"
        ]
    );
    assert_eq!(root.resource_reads, ["channel:inbox", "tracker:backlog"]);
    assert_eq!(
        root.projection_reads
            .iter()
            .map(IrProjectionRead::to_snapshot)
            .collect::<Vec<_>>(),
        ["fact:Result where status == \"done\""]
    );
    let semantic = SemanticContext::from_program(&program, BTreeMap::new());
    let Item::Rule(rule) = program
        .items
        .iter()
        .find(|item| matches!(item, Item::Rule(_)))
        .unwrap()
    else {
        panic!()
    };
    let (body, errors) = body::parse_rule_body(&rule.body.text, rule.body.body_base());
    assert!(errors.is_empty());
    let mut errors = Vec::new();
    let legacy = analyze_rule(rule, &body, &semantic, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(root.projection_reads, legacy.projection_reads);
    assert_eq!(root.fact_reads, legacy.fact_reads);
    assert_eq!(root.resource_reads, legacy.resource_reads);
    assert_eq!(
        root.whens,
        rule.whens
            .iter()
            .cloned()
            .map(lower_when_clause)
            .collect::<Vec<_>>()
    );
    let guard = root.whens[0].guard.as_ref().unwrap();
    assert_eq!(
        &source[guard.span.start..guard.span.end],
        "exists(Result where status == \"done\") && exists(Result where status == \"done\")"
    );
    resolve_rule_types(&program, "run").unwrap();
}

#[test]
fn managed_roots_refuse_invalid_inputs_through_the_actual_type_entry_point() {
    for (when, code) in [
        ("when Missing as ticket", "type.unknown_schema"),
        ("when deploy.missing as event", "type.unknown_signal"),
        (
            "when something odd as value",
            "parse.unsupported_when_pattern",
        ),
        ("when Ticket as record", "construct.reserved_name"),
        (
            "when Ticket as ticket\nwhen Ticket as ticket",
            "construct.invalid_expansion",
        ),
        ("when missing is available", "type.unknown_agent"),
        (
            "when Ticket as ticket\nwhen ticket.missing is available",
            "type.unknown_field",
        ),
        ("when missing.worker is available", "type.unknown_binding"),
        (
            "when Ticket as ticket\nwhen ticket.title is available",
            "type.mismatch",
        ),
        ("when message from missing as msg", "type.unknown_channel"),
        (
            "when fact agent.turn.streamed as detail",
            "graph.unmatchable_fact",
        ),
    ] {
        let source = source(when, "timer 1s as wait");
        let program = program(&source);
        for result in [
            resolve_rule_root(&program, "run").map(|_| ()),
            resolve_rule_types(&program, "run").map(|_| ()),
        ] {
            let errors = result.expect_err(when);
            assert!(
                errors.iter().any(|d| d.code.as_str() == code),
                "{when}: {errors:?}"
            );
            assert!(
                errors
                    .iter()
                    .all(|d| d.span.start >= source.find("rule run").unwrap()),
                "{when}: {errors:?}"
            );
        }
    }
    for when in [
        "when Ticket as ticket",
        "when fact custom.event as event",
        "when reader is available",
        "when Ticket as ticket\nwhen ticket.worker is available",
    ] {
        resolve_rule_types(&program(&source(when, "timer 1s as wait")), "run").unwrap();
    }
    let outbound = source("when message from inbox as msg", "")
        .replace("provider fixture", "provider desktop");
    let errors = resolve_rule_root(&program(&outbound), "run").unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].code.as_str(), "provider.feature_unavailable");
}

#[test]
fn root_guards_have_trigger_scope_and_authored_diagnostics() {
    for (guard, code) in [
        ("42", "expr.non_boolean_condition"),
        ("ticket.title ==", "parse.invalid_expression"),
        ("ticket.missing == \"x\"", "type.unknown_field"),
        ("missing.title == \"x\"", "type.unknown_binding"),
        ("result.title == \"x\"", "type.unknown_binding"),
        ("exists(Missing)", "type.unknown_schema"),
    ] {
        let source = source(
            &format!("when Ticket as ticket where {guard}"),
            "label(ticket) as result",
        );
        let p = program(&source);
        let errors = resolve_rule_types(&p, "run").expect_err(guard);
        assert!(
            errors.iter().any(|d| d.code.as_str() == code),
            "{guard}: {errors:?}"
        );
        let start = source.find(guard).unwrap();
        assert!(
            errors
                .iter()
                .all(|d| d.span.start >= start && d.span.end <= start + guard.len()),
            "{guard}: {errors:?}"
        );
    }
    let source = source(
        "when Ticket as ticket where ticket.owner != null && ticket.owner.name == \"Ada\"",
        "label(ticket) as result",
    );
    resolve_rule_types(&program(&source), "run").unwrap();
}

#[test]
fn root_selection_and_input_collision_retain_related_locations() {
    let source = source("when Ticket as ticket\nwhen Ticket as ticket", "");
    let p = program(&source);
    let errors = resolve_rule_root(&p, "run").unwrap_err();
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(&source[errors[0].span.start..errors[0].span.end], "ticket");
    assert_eq!(errors[0].related.len(), 1);
    assert!(errors[0].related[0].span.start < errors[0].span.start);
    assert!(resolve_rule_root(&p, "absent").unwrap_err()[0]
        .message
        .contains("unknown rule `absent`"));
    let duplicate = format!(
        "{}\nrule run when started => {{}}",
        self::source("when started", "")
    );
    let errors = resolve_rule_root(&program(&duplicate), "run").unwrap_err();
    assert!(
        errors
            .iter()
            .any(|d| d.message.contains("declared more than once") && !d.related.is_empty()),
        "{errors:?}"
    );
}

#[test]
fn root_analysis_retains_view_identity_without_claiming_body_validation() {
    let text =
        source("when Ticket as ticket", "label(ticket) as result").replace("rule run", "view run");
    let root = resolve_rule_root(&program(&text), "run").unwrap();
    assert_eq!(root.kind, RuleKind::View);
    assert_eq!(root.name.name, "run");
    assert_eq!(root.projection_reads, []);
}
