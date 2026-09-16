use super::*;
use crate::source_action::arguments::{Bindings, Slot, ValueSource};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

fn ir() -> IrProgram {
    whipplescript_parser::compile_program(
        r#"
workflow TellValues
output result Done
class Done { ok bool }
agent worker { provider mock profile "review" capabilities ["search"] }
file store fs { root "./workspace" allow read ["**/*.md"] }
rule finish when started => { complete result { ok true } }
"#,
    )
    .ir
    .expect("tell fixture compiles")
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
    ir: &IrProgram,
    source: &str,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    project(
        Statement {
            node: NodeId(0),
            root_rule: Some("finish"),
            admitted: bindings,
            identity: "operation".into(),
            body: &body.statements[0],
            environment: &Environment::from([
                ("target".into(), BindingId(0)),
                ("a".into(), BindingId(1)),
                ("b".into(), BindingId(2)),
            ]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir,
            frame: &frame(),
            effects,
            events,
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
        panic!("ready leaf");
    };
    (lowering, value, work)
}
fn effect(status: &str) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation".into(),
        kind: "agent.tell".into(),
        target: Some("worker".into()),
        input_json: json!({"agent":"worker","rule":"finish","prompt":"captured"}).to_string(),
        status: status.into(),
        created_by_rule: "finish".into(),
        program_version_id: Some("v".into()),
        revision_epoch: 0,
        profile: Some("review".into()),
        cancel_requested: false,
    }
}
fn terminal(status: &str, summary: Value) -> EventView {
    EventView { event_id: "terminal".into(), sequence: 3, event_type: "effect.terminal".into(),
        payload_json: json!({"effect_id":"operation","run_id":"run","status":status,"run_status":status,"summary":summary,"metadata":{"provider":"mock"}}).to_string(),
        source: "kernel".into(), occurred_at: "2026-09-10T00:00:00Z".into() }
}
fn observe(status: &str, events: &[EventView]) -> Result<Leaf, String> {
    run(
        &ir(),
        "tell target \"{{ a }}\" as answer",
        &Bindings::new(),
        &[effect(status)],
        events,
    )
}

#[test]
fn managed_tell_waits_for_actual_reads_and_keeps_prose_and_inserted_text_literal() {
    let mut bindings = Bindings::from([
        (BindingId(0), Slot::Ready(json!("worker").into())),
        (BindingId(1), Slot::Pending),
        (
            BindingId(2),
            Slot::Failed(BTreeSet::from([CauseId("original".into())])),
        ),
    ]);
    let source = "tell target \"{{ a }} / {{ b }}\" as answer";
    let Leaf::Waiting(wait) = run(&ir(), source, &bindings, &[], &[]).unwrap() else {
        panic!("wait");
    };
    assert!(
        matches!(wait.state, State::Blocked { waiting, causes } if waiting == BTreeSet::from([BindingId(1)]) && causes == BTreeSet::from([CauseId("original".into())]))
    );
    bindings.insert(
        BindingId(1),
        Slot::Ready(Argument {
            value: json!("{{ b.secret }}"),
            sources: BTreeSet::from([ValueSource::Operation {
                operation_id: "parent".into(),
            }]),
            subjects: Default::default(),
            validity: Default::default(),
        }),
    );
    let (draft, _, work) = parts(
        run(
            &ir(),
            "tell target \"a.secret is prose: {{ a }}\" as answer",
            &bindings,
            &[],
            &[],
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Pending);
    assert_eq!(draft.effects.len(), 1);
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    assert_eq!(input["prompt"], "a.secret is prose: {{ b.secret }}");
    assert_eq!(input["bindings"], json!({}));
    assert_eq!(input["action_arguments"].as_array().unwrap().len(), 2);
    assert_eq!(
        input["action_arguments"][1]["sources"][0]["operation_id"],
        "parent"
    );
    assert!(!draft.effects[0].input_json.contains("original"));
    assert_eq!(draft.effects[0].profile.as_deref(), Some("review"));
    bindings.insert(BindingId(0), Slot::Pending);
    assert!(matches!(
        run(&ir(), source, &bindings, &[], &[]).unwrap(),
        Leaf::Waiting(_)
    ));
}

#[test]
fn managed_tell_carries_grants_capabilities_skills_and_pinned_identity() {
    let source = "tell worker \"Review\" with access to fs { read [\"docs/**\"] } with skills [\"review\"] requires [\"search\"] timeout 5s as answer";
    let (draft, _, _) = parts(run(&ir(), source, &Bindings::new(), &[], &[]).unwrap());
    let effect = &draft.effects[0];
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["access_grants"][0]["resource"], "fs");
    assert_eq!(
        input["access_grants"][0]["operations"][0]["globs"],
        json!(["docs/**"])
    );
    assert_eq!(
        input["access_grants"][0]["store_policy"]["allow_read"],
        json!(["**/*.md"])
    );
    assert_eq!(input["turn_skills"], json!(["review"]));
    assert_eq!(
        serde_json::from_str::<Value>(&effect.required_capabilities_json).unwrap(),
        json!(["search"])
    );
    assert_eq!(effect.timeout_seconds, Some(5));
    assert_eq!(effect.correlation_id.as_deref(), Some("ticket"));
    assert!(effect.source_span_json.is_some());
    assert_eq!(
        parts(run(&ir(), source, &Bindings::new(), &[], &[]).unwrap())
            .0
            .effects[0],
        *effect
    );
}

#[test]
fn managed_tell_observes_terminal_summary_without_result_facts_or_operand_replay() {
    let event = terminal("completed", json!("actual answer"));
    let (draft, value, work) = parts(observe("completed", &[event]).unwrap());
    assert!(!draft.has_commit_work());
    assert_eq!(value.unwrap().value, json!("actual answer"));
    assert_eq!(work.state, WorkState::Succeeded);
    for status in ["queued", "running", "blocked_by_capacity", "uncertain"] {
        let (_, value, work) = parts(observe(status, &[]).unwrap());
        assert!(value.is_none());
        assert_eq!(
            work.state,
            if status == "uncertain" {
                WorkState::Uncertain
            } else {
                WorkState::Pending
            }
        );
    }
    let mut requested = effect("running");
    requested.cancel_requested = true;
    assert_eq!(
        parts(
            run(
                &ir(),
                "tell target \"{{ a }}\"",
                &Bindings::new(),
                &[requested],
                &[]
            )
            .unwrap()
        )
        .2
        .state,
        WorkState::CancellationRequested
    );
    for (status, kind) in [
        ("failed", FailureKind::Failed),
        ("timed_out", FailureKind::TimedOut),
        ("cancelled", FailureKind::Cancelled),
    ] {
        let event = terminal(status, json!("provider stopped"));
        let payload: Value = serde_json::from_str(&event.payload_json).unwrap();
        let (_, value, work) = parts(observe(status, &[event]).unwrap());
        assert!(value.is_none());
        assert_eq!(work.state, WorkState::Failed(Disposition::Propagate));
        assert_eq!(work.causes[&CauseId("operation".into())].cause.kind, kind);
        assert_eq!(
            work.causes[&CauseId("operation".into())].cause.payload,
            payload
        );
    }
}

#[test]
fn managed_tell_refuses_missing_or_conflicting_evidence_and_wrong_scope() {
    assert!(observe("mystery", &[]).is_err());
    assert!(observe("completed", &[]).is_err());
    assert!(observe("completed", &[terminal("failed", json!("wrong"))]).is_err());
    for summary in [Value::Null, json!(42), json!({"text":"not a string"})] {
        assert!(observe("completed", &[terminal("completed", summary)]).is_err());
    }
    for (field, value) in [("run_id", Value::Null), ("run_status", json!("running"))] {
        let mut event = terminal("completed", json!("answer"));
        let mut payload: Value = serde_json::from_str(&event.payload_json).unwrap();
        payload[field] = value;
        event.payload_json = payload.to_string();
        assert!(observe("completed", &[event]).is_err());
    }
    let mut uncertain = terminal("completed", json!("not yet"));
    let mut payload: Value = serde_json::from_str(&uncertain.payload_json).unwrap();
    payload["run_status"] = json!("uncertain");
    uncertain.payload_json = payload.to_string();
    assert_eq!(
        parts(observe("completed", &[uncertain]).unwrap()).2.state,
        WorkState::Uncertain
    );
    for field in ["kind", "rule", "version", "profile", "agent"] {
        let mut effect = effect("running");
        match field {
            "kind" => effect.kind = "timer".into(),
            "rule" => effect.created_by_rule = "other".into(),
            "version" => effect.program_version_id = Some("other".into()),
            "profile" => effect.profile = None,
            _ => effect.target = Some("missing".into()),
        }
        assert!(run(
            &ir(),
            "tell worker \"hello\"",
            &Bindings::new(),
            &[effect],
            &[]
        )
        .is_err());
    }
    let mut program = ir();
    program.rules.clear();
    assert!(run(
        &program,
        "tell worker \"hello\"",
        &Bindings::new(),
        &[],
        &[]
    )
    .is_err());
    assert!(run(&ir(), "tell unknown \"hello\"", &Bindings::new(), &[], &[]).is_err());
    for source in ["timer 1s as timer", "return 1"] {
        assert!(run(&ir(), source, &Bindings::new(), &[], &[]).is_err());
    }
}

#[test]
fn managed_tell_prompt_wire_refuses_unknown_segments_and_missing_arguments() {
    for parts in [
        json!([{"kind":"eval","source":"secret"}]),
        json!([{"kind":"value","argument":9}]),
        json!([{"kind":"text","text":"x","extra":1}]),
    ] {
        let mut input = json!({"managed_prompt":parts,"action_arguments":[]});
        assert!(materialize_prompt(&mut input).is_err());
    }
    assert!(
        materialize_prompt(&mut json!({"managed_prompt":[],"action_arguments":"bad"})).is_err()
    );
}
