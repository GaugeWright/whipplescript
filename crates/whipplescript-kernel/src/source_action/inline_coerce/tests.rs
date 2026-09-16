use super::*;
use crate::source_action::arguments::{
    Bindings, ObservationKind, QueryObservation, Slot, ValueSource,
};
use crate::source_action::{CauseId, Disposition, FailureKind};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

const SOURCE: &str = r#"
workflow PromptValues
output result Done
class Done { ok bool }
rule finish when started => { complete result { ok true } }
"#;

fn ir() -> IrProgram {
    whipplescript_parser::compile_program(SOURCE)
        .ir
        .expect("prompt fixture compiles")
}

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "finish".into(),
        identity: Some("ticket".into()),
        trigger_event: Some("admitted".into()),
    }
}

fn run(
    source: &str,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
    config: &str,
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    run_body(
        &body.statements[0],
        Some("finish"),
        &ir(),
        bindings,
        effects,
        events,
        config,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_body(
    body: &BodyStmt,
    root_rule: Option<&str>,
    ir: &IrProgram,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
    config: &str,
) -> Result<Leaf, String> {
    project_prompt(
        Statement {
            node: NodeId(0),
            root_rule,
            admitted: bindings,
            identity: "operation".into(),
            body,
            environment: &Environment::from([("name".into(), BindingId(0))]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir,
            frame: &frame(),
            effects,
            events,
            coercion_config_fingerprint: config,
            source_path: None,
        },
    )
}

fn run_decide(
    source: &str,
    ir: &IrProgram,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
    config: &str,
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    project_decide(
        Statement {
            node: NodeId(0),
            root_rule: Some("finish"),
            admitted: bindings,
            identity: "operation".into(),
            body: &body.statements[0],
            environment: &Environment::from([("name".into(), BindingId(0))]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir,
            frame: &frame(),
            effects,
            events,
            coercion_config_fingerprint: config,
            source_path: None,
        },
    )
}

fn parts(leaf: Leaf) -> (Box<OwnedLowering>, Option<Argument>, OwnedWork) {
    let Leaf::Ready {
        lowering,
        value,
        work: Some(work),
    } = leaf
    else {
        panic!("ready operation leaf")
    };
    (lowering, value, work)
}

fn effect(status: &str) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation".into(),
        kind: "schema.coerce".into(),
        target: Some("anthropic".into()),
        input_json: json!({
            "function_name":"prompt", "output_type":"string",
            "output_schema": {
                "type":"object", "properties":{"value":{"type":"string"}},
                "required":["value"], "additionalProperties":false
            },
            "provider":"anthropic", "prompt":"Hello",
            "prompt_template":"Hello", "action_arguments":[]
        })
        .to_string(),
        status: status.into(),
        created_by_rule: "finish".into(),
        program_version_id: Some("v".into()),
        revision_epoch: 0,
        profile: None,
        cancel_requested: false,
    }
}

fn event(kind: &str, sequence: i64, payload: Value) -> EventView {
    EventView {
        event_id: format!("event-{sequence}"),
        sequence,
        event_type: kind.into(),
        payload_json: payload.to_string(),
        source: "kernel".into(),
        occurred_at: "2026-09-12T00:00:00Z".into(),
    }
}

fn result_events(status: &str, value: Value) -> Vec<EventView> {
    vec![
        event(
            "effect.terminal",
            1,
            json!({"effect_id":"operation","run_id":"run","status":status}),
        ),
        event(
            match status {
                "completed" => "schema.coerce.succeeded",
                "timed_out" => "schema.coerce.timed_out",
                _ => "schema.coerce.failed",
            },
            2,
            json!({
                "effect_id":"operation", "run_id":"run", "status":status,
                "function_name":"prompt", "output_type":"string", "value":value
            }),
        ),
    ]
}

#[test]
fn managed_prompt_waits_then_captures_rendered_text_and_freshness_arguments() {
    let source = r#"prompt "Hello {{ name }}" using anthropic as answer"#;
    let Leaf::Waiting(wait) = run(source, &Bindings::new(), &[], &[], "cfg").unwrap() else {
        panic!("missing input must wait")
    };
    assert!(
        matches!(wait.state, State::Blocked { waiting, .. } if waiting == [BindingId(0)].into())
    );

    let bindings = Bindings::from([(
        BindingId(0),
        Slot::Ready(Argument {
            value: json!("Ada"),
            sources: [ValueSource::Fact {
                fact_id: "person".into(),
                admission_event: "admission".into(),
            }]
            .into(),
            subjects: Default::default(),
            validity: [QueryObservation {
                frontier: 7,
                kind: ObservationKind::Fact,
                head: "Ticket".into(),
                guard_json: None,
                members: Default::default(),
            }]
            .into(),
        }),
    )]);
    let (draft, value, work) = parts(run(source, &bindings, &[], &[], "cfg").unwrap());
    assert_eq!(work.state, WorkState::Pending);
    assert!(value.is_none());
    let operation = &draft.effects[0];
    assert_eq!(operation.kind, "schema.coerce");
    assert_eq!(operation.target.as_deref(), Some("anthropic"));
    assert_eq!(operation.required_capabilities_json, r#"["schema.coerce"]"#);
    let input: Value = serde_json::from_str(&operation.input_json).unwrap();
    assert_eq!(input["prompt"], "Hello Ada");
    assert_eq!(input["prompt_template"], "Hello {{ name }}");
    assert_eq!(input["action_arguments"][0]["validity"][0]["frontier"], 7);
    assert_eq!(
        input["action_arguments"][0]["sources"][0]["fact_id"],
        "person"
    );
    let (same, _, _) = parts(
        run(
            source,
            &Bindings::from([(BindingId(0), Slot::Ready(json!("Grace").into()))]),
            &[],
            &[],
            "cfg",
        )
        .unwrap(),
    );
    assert_eq!(operation.idempotency_key, same.effects[0].idempotency_key);
    let (changed, _, _) = parts(run(source, &bindings, &[], &[], "other-cfg").unwrap());
    assert_ne!(
        operation.idempotency_key,
        changed.effects[0].idempotency_key
    );

    let (defaulted, _, _) = parts(
        run(
            r#"prompt "Hello" as answer"#,
            &Bindings::new(),
            &[],
            &[],
            "cfg",
        )
        .unwrap(),
    );
    assert!(defaulted.effects[0].target.is_none());
    let defaulted_input: Value = serde_json::from_str(&defaulted.effects[0].input_json).unwrap();
    assert!(defaulted_input.get("provider").is_none());

    let mut rebound = effect("queued");
    rebound.target = None;
    assert!(run(
        r#"prompt "Hello" as answer"#,
        &Bindings::new(),
        &[rebound],
        &[],
        "cfg",
    )
    .is_err());
}

#[test]
fn managed_prompt_observes_one_string_result_and_preserves_failures() {
    let source = r#"prompt "Hello" using anthropic as answer"#;
    let events = result_events("completed", json!("world"));
    let (_, value, work) = parts(
        run(
            source,
            &Bindings::new(),
            &[effect("completed")],
            &events,
            "cfg",
        )
        .unwrap(),
    );
    assert_eq!(value.unwrap().value, json!("world"));
    assert_eq!(work.state, WorkState::Succeeded);

    for status in ["failed", "timed_out"] {
        let events = result_events(status, json!({"reason":"safe"}));
        let (_, value, work) =
            parts(run(source, &Bindings::new(), &[effect(status)], &events, "cfg").unwrap());
        assert!(value.is_none());
        assert_eq!(work.state, WorkState::Failed(Disposition::Propagate));
        assert_eq!(
            work.causes[&CauseId("operation".into())].cause.payload,
            json!({"reason":"safe"})
        );
    }
    let cancelled = vec![event(
        "effect.cancelled",
        3,
        json!({"effect_id":"operation"}),
    )];
    let (_, _, work) = parts(
        run(
            source,
            &Bindings::new(),
            &[effect("cancelled")],
            &cancelled,
            "cfg",
        )
        .unwrap(),
    );
    assert_eq!(
        work.causes[&CauseId("operation".into())].cause.kind,
        FailureKind::Cancelled
    );
}

#[test]
fn managed_prompt_refuses_wrong_dispatch_identity_and_non_string_success() {
    assert_eq!(
        run("return null", &Bindings::new(), &[], &[], "cfg").unwrap_err(),
        "inline coerce projector requires an effect statement"
    );
    assert_eq!(
        run("timer 1s as wait", &Bindings::new(), &[], &[], "cfg").unwrap_err(),
        "inline prompt projector requires an inline prompt statement"
    );
    for change in [
        "kind",
        "target",
        "rule",
        "version",
        "input",
        "function",
        "output",
        "template",
        "prompt",
        "arguments",
        "provider",
    ] {
        let mut row = effect("queued");
        match change {
            "kind" => row.kind = "timer.wait".into(),
            "target" => row.target = Some("other".into()),
            "rule" => row.created_by_rule = "other".into(),
            "version" => row.program_version_id = Some("other".into()),
            "input" => row.input_json = "{".into(),
            "function" | "output" | "template" | "prompt" | "arguments" | "provider" => {
                let mut input: Value = serde_json::from_str(&row.input_json).unwrap();
                match change {
                    "function" => input["function_name"] = "other".into(),
                    "output" => input["output_type"] = "json".into(),
                    "template" => input["prompt_template"] = "other".into(),
                    "prompt" => {
                        input.as_object_mut().unwrap().remove("prompt");
                    }
                    "arguments" => input["action_arguments"] = json!({}),
                    "provider" => input["provider"] = "other".into(),
                    _ => unreachable!(),
                }
                row.input_json = input.to_string();
            }
            _ => unreachable!(),
        }
        assert!(
            run(
                r#"prompt "Hello" using anthropic as answer"#,
                &Bindings::new(),
                &[row],
                &[],
                "cfg"
            )
            .is_err(),
            "{change}"
        );
    }
    let mut gained_content = effect("queued");
    let mut input: Value = serde_json::from_str(&gained_content.input_json).unwrap();
    input["prompt_content_type"] = "markdown".into();
    gained_content.input_json = input.to_string();
    assert_eq!(
        run(
            r#"prompt "Hello" using anthropic as answer"#,
            &Bindings::new(),
            &[gained_content],
            &[],
            "cfg",
        )
        .unwrap_err(),
        "recorded inline coerce gained a content type absent from source"
    );
    let events = result_events("completed", json!({"not":"text"}));
    assert!(run(
        r#"prompt "Hello" using anthropic as answer"#,
        &Bindings::new(),
        &[effect("completed")],
        &events,
        "cfg",
    )
    .is_err());

    let (parsed, errors) = whipplescript_parser::body::parse_action_body(
        r#"prompt "Hello" using anthropic as answer"#,
        0,
    );
    assert!(errors.is_empty());
    let body = &parsed.statements[0];
    let current_ir = ir();
    assert!(run_body(body, None, &current_ir, &Bindings::new(), &[], &[], "cfg",).is_err());
    let mut no_rule = current_ir.clone();
    no_rule.rules.clear();
    assert!(run_body(
        body,
        Some("finish"),
        &no_rule,
        &Bindings::new(),
        &[],
        &[],
        "cfg",
    )
    .is_err());
    let mut no_template = body.clone();
    let BodyStmt::Effect(statement_effect) = &mut no_template else {
        unreachable!()
    };
    statement_effect.prompt = None;
    assert!(run_body(
        &no_template,
        Some("finish"),
        &current_ir,
        &Bindings::new(),
        &[],
        &[],
        "cfg",
    )
    .is_err());
    let mut malformed = body.clone();
    let BodyStmt::Effect(statement_effect) = &mut malformed else {
        unreachable!()
    };
    statement_effect.prompt.as_mut().unwrap().text = "{{".into();
    assert!(run_body(
        &malformed,
        Some("finish"),
        &current_ir,
        &Bindings::new(),
        &[],
        &[],
        "cfg",
    )
    .is_err());
    let mut overflow = body.clone();
    let BodyStmt::Effect(statement_effect) = &mut overflow else {
        unreachable!()
    };
    statement_effect.timeout_seconds = Some(u64::MAX);
    assert!(run_body(
        &overflow,
        Some("finish"),
        &current_ir,
        &Bindings::new(),
        &[],
        &[],
        "cfg",
    )
    .is_err());

    let mut typed_content = body.clone();
    let BodyStmt::Effect(statement_effect) = &mut typed_content else {
        unreachable!()
    };
    statement_effect.prompt.as_mut().unwrap().content_type = Some("markdown".into());
    let mut row = effect("queued");
    let mut input: Value = serde_json::from_str(&row.input_json).unwrap();
    input["prompt_content_type"] = "plain".into();
    row.input_json = input.to_string();
    assert!(run_body(
        &typed_content,
        Some("finish"),
        &current_ir,
        &Bindings::new(),
        &[row],
        &[],
        "cfg",
    )
    .is_err());
}

fn decide_ir(source: &str) -> IrProgram {
    whipplescript_parser::compile_program(source)
        .ir
        .expect("decide fixture compiles")
}

fn decide_effect(ir: &IrProgram, status: &str) -> ProjectionEffect {
    let output = whipplescript_parser::inline_decide_output_type(
        &[
            ("safe".into(), "bool".into()),
            ("reason".into(), "string".into()),
        ],
        whipplescript_parser::SourceSpan { start: 0, end: 0 },
    );
    ProjectionEffect {
        effect_id: "operation".into(),
        kind: "schema.coerce".into(),
        target: None,
        input_json: json!({
            "function_name":"decide",
            "output_type":"{safe bool, reason string}",
            "output_schema": crate::coerce_native::output_schema_envelope(&output, &ir.schemas).0,
            "prompt":"Review Ada", "prompt_template":"Review {{ name }}",
            "action_arguments": [{}]
        })
        .to_string(),
        status: status.into(),
        created_by_rule: "finish".into(),
        program_version_id: Some("v".into()),
        revision_epoch: 0,
        profile: None,
        cancel_requested: false,
    }
}

fn decide_result_events(status: &str, value: Value) -> Vec<EventView> {
    vec![
        event(
            "effect.terminal",
            1,
            json!({"effect_id":"operation","run_id":"run","status":status}),
        ),
        event(
            match status {
                "completed" => "schema.coerce.succeeded",
                "timed_out" => "schema.coerce.timed_out",
                _ => "schema.coerce.failed",
            },
            2,
            json!({
                "effect_id":"operation", "run_id":"run", "status":status,
                "function_name":"decide", "output_type":"{safe bool, reason string}",
                "value":value
            }),
        ),
    ]
}

#[test]
fn managed_decide_carries_one_structural_output_through_actions_and_freshness() {
    const PROGRAM: &str = r#"
workflow Decision
output result Done
class Done { ok bool }
action judge(name string) -> bool {
  decide "Review {{ name }}" -> { safe bool, reason string } as verdict
  after verdict succeeds { return verdict.safe }
}
rule finish when started => { judge("Ada") as answer
complete result { ok answer } }
"#;
    let ir = decide_ir(PROGRAM);
    let source = r#"decide "Review {{ name }}" -> { safe bool, reason string } as verdict"#;
    let Leaf::Waiting(wait) = run_decide(source, &ir, &Bindings::new(), &[], &[], "cfg").unwrap()
    else {
        panic!("missing decision input must wait")
    };
    assert!(
        matches!(wait.state, State::Blocked { waiting, .. } if waiting == [BindingId(0)].into())
    );
    let bindings = Bindings::from([(
        BindingId(0),
        Slot::Ready(Argument {
            value: json!("Ada"),
            sources: [ValueSource::Fact {
                fact_id: "person".into(),
                admission_event: "admission".into(),
            }]
            .into(),
            subjects: Default::default(),
            validity: [QueryObservation {
                frontier: 11,
                kind: ObservationKind::Fact,
                head: "Person".into(),
                guard_json: None,
                members: Default::default(),
            }]
            .into(),
        }),
    )]);
    let (draft, value, work) = parts(run_decide(source, &ir, &bindings, &[], &[], "cfg").unwrap());
    assert!(value.is_none());
    assert_eq!(work.state, WorkState::Pending);
    let operation = &draft.effects[0];
    let input: Value = serde_json::from_str(&operation.input_json).unwrap();
    assert_eq!(input["function_name"], "decide");
    assert_eq!(input["prompt"], "Review Ada");
    assert_eq!(input["output_type"], "{safe bool, reason string}");
    assert_eq!(
        input["output_schema"]["properties"]["safe"]["type"],
        "boolean"
    );
    assert_eq!(input["action_arguments"][0]["validity"][0]["frontier"], 11);
    assert!(operation.target.is_none());
    let (same, _, _) = parts(
        run_decide(
            source,
            &ir,
            &Bindings::from([(BindingId(0), Slot::Ready(json!("Grace").into()))]),
            &[],
            &[],
            "cfg",
        )
        .unwrap(),
    );
    assert_eq!(operation.idempotency_key, same.effects[0].idempotency_key);
    let (changed_schema, _, _) = parts(
        run_decide(
            r#"decide "Review {{ name }}" -> { safe bool, score int } as verdict"#,
            &ir,
            &bindings,
            &[],
            &[],
            "cfg",
        )
        .unwrap(),
    );
    assert_ne!(
        operation.idempotency_key,
        changed_schema.effects[0].idempotency_key
    );
    let (changed_config, _, _) =
        parts(run_decide(source, &ir, &bindings, &[], &[], "other-cfg").unwrap());
    assert_ne!(
        operation.idempotency_key,
        changed_config.effects[0].idempotency_key
    );

    let (_, value, work) = parts(
        run_decide(
            source,
            &ir,
            &Bindings::new(),
            &[decide_effect(&ir, "completed")],
            &decide_result_events("completed", json!({"safe":true,"reason":"bounded"})),
            "cfg",
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Succeeded);
    assert_eq!(value.unwrap().value["safe"], true);
}

#[test]
fn managed_decide_refuses_a_rebound_or_malformed_inline_contract() {
    const PROGRAM: &str = r#"
workflow Decision
output result Done
class Done { ok bool }
rule finish when started => {
  decide "Review {{ name }}" -> { safe bool, reason string } as verdict
  after verdict succeeds { complete result { ok verdict.safe } }
}
"#;
    let ir = decide_ir(PROGRAM);
    let source = r#"decide "Review {{ name }}" -> { safe bool, reason string } as verdict"#;
    let bindings = Bindings::from([(BindingId(0), Slot::Ready(json!("Ada").into()))]);

    let (prompt_body, errors) = whipplescript_parser::body::parse_action_body(
        r#"prompt "Review {{ name }}" as verdict"#,
        0,
    );
    assert!(errors.is_empty());
    let wrong_dispatch = project_decide(
        Statement {
            node: NodeId(0),
            root_rule: Some("finish"),
            admitted: &bindings,
            identity: "operation".into(),
            body: &prompt_body.statements[0],
            environment: &Environment::from([("name".into(), BindingId(0))]),
            bindings: &bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir: &ir,
            frame: &frame(),
            effects: &[],
            events: &[],
            coercion_config_fingerprint: "cfg",
            source_path: None,
        },
    );
    assert_eq!(
        wrong_dispatch.unwrap_err(),
        "inline decide projector requires an inline decide statement"
    );

    for change in ["target", "function", "output", "schema", "template"] {
        let mut row = decide_effect(&ir, "queued");
        let mut input: Value = serde_json::from_str(&row.input_json).unwrap();
        match change {
            "target" => row.target = Some("other".into()),
            "function" => input["function_name"] = "prompt".into(),
            "output" => input["output_type"] = "string".into(),
            "schema" => input["output_schema"] = json!({"type":"object"}),
            "template" => input["prompt_template"] = "other".into(),
            _ => unreachable!(),
        }
        row.input_json = input.to_string();
        assert!(
            run_decide(source, &ir, &bindings, &[row], &[], "cfg").is_err(),
            "{change}"
        );
    }
    let bad_value = decide_result_events("completed", json!({"safe":"yes","reason":"bad"}));
    assert!(run_decide(
        source,
        &ir,
        &bindings,
        &[decide_effect(&ir, "completed")],
        &bad_value,
        "cfg",
    )
    .is_err());
}
