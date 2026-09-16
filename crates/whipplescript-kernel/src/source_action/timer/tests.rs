use super::*;
use crate::source_action::arguments::{Bindings, Slot, ValueSource};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "rule".into(),
        identity: Some("ticket".into()),
        trigger_event: Some("trigger".into()),
    }
}
fn run(
    source: &str,
    inputs: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    project(
        Statement {
            root_rule: None,
            admitted: &Bindings::new(),
            node: NodeId(0),
            identity: "operation".into(),
            body: &body.statements[0],
            environment: &Environment::from([("delay".into(), BindingId(0))]),
            bindings: inputs,
            queries: None,
            outcomes: None,
        },
        &frame(),
        effects,
        events,
        None,
    )
}
fn input(value: Value) -> Bindings {
    Bindings::from([(
        BindingId(0),
        Slot::Ready(Argument {
            subjects: Default::default(),
            value,
            sources: BTreeSet::from([ValueSource::Fact {
                fact_id: "fact".into(),
                admission_event: "admitted".into(),
            }]),
            validity: Default::default(),
        }),
    )])
}
fn effect(status: &str) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation".into(),
        kind: "timer.wait".into(),
        target: None,
        input_json: "{}".into(),
        status: status.into(),
        created_by_rule: frame().rule,
        program_version_id: Some(frame().version),
        revision_epoch: 0,
        profile: None,
        cancel_requested: false,
    }
}
fn terminal(status: &str, sequence: i64) -> EventView {
    EventView {
        event_id: format!("event-{sequence}"),
        sequence,
        event_type: "effect.terminal".into(),
        payload_json:
            json!({"effect_id":"operation","status":status,"metadata":{"reason":"original cause"}})
                .to_string(),
        source: "kernel".into(),
        occurred_at: "2026-09-09T00:00:00Z".into(),
    }
}
fn ready(leaf: Leaf) -> (Box<OwnedLowering>, Option<Argument>, OwnedWork) {
    let Leaf::Ready {
        lowering,
        value,
        work: Some(work),
    } = leaf
    else {
        panic!("ready operation expected");
    };
    (lowering, value, work)
}

#[test]
fn action_timer_drafts_relative_and_absolute_operands_with_sources() {
    for (source, inputs, expected, seconds) in [
        ("timer 1m as t", Bindings::new(), json!("PT60S"), Some(60)),
        (
            "timer delay as t",
            input(json!("PT9S")),
            json!("PT9S"),
            Some(9),
        ),
        (
            "timer until delay as t",
            input(json!("2027-01-01T00:00:00Z")),
            json!("2027-01-01T00:00:00Z"),
            None,
        ),
        (
            "timer until \"2027-01-01T00:00:00Z\" as t",
            Bindings::new(),
            json!("2027-01-01T00:00:00Z"),
            None,
        ),
    ] {
        let (lowering, value, work) = ready(run(source, &inputs, &[], &[]).unwrap());
        assert_eq!(work.state, WorkState::Pending);
        assert_eq!(value, None);
        assert_eq!(lowering.effects.len(), 1);
        let draft = &lowering.effects[0];
        assert_eq!(draft.effect_id, "operation");
        assert_eq!(draft.idempotency_key, "operation");
        assert_eq!(draft.timeout_seconds, seconds);
        assert_eq!(draft.correlation_id, frame().identity);
        let payload: Value = serde_json::from_str(&draft.input_json).unwrap();
        assert_eq!(payload["rule"], frame().rule);
        assert_eq!(payload["action_argument"]["value"], expected);
        assert_eq!(
            payload["action_argument"]["sources"]
                .as_array()
                .unwrap()
                .len(),
            usize::from(!inputs.is_empty())
        );
        if let Some(seconds) = seconds {
            assert_eq!(payload["duration_seconds"], seconds);
        } else {
            assert_eq!(payload["deadline_at"], expected);
        }
        assert!(draft.source_span_json.as_ref().unwrap().contains("effect"));
    }
    let (mut body, errors) = whipplescript_parser::body::parse_action_body("timer 1s as t", 0);
    assert!(errors.is_empty());
    let BodyStmt::Effect(ref mut timer) = body.statements[0] else {
        unreachable!()
    };
    timer.requires = vec!["a".into(), "b".into(), "a".into()];
    let (lowering, _, _) = ready(
        project(
            Statement {
                root_rule: None,
                admitted: &Bindings::new(),
                node: NodeId(0),
                identity: "op".into(),
                body: &body.statements[0],
                environment: &Environment::new(),
                bindings: &Bindings::new(),
                queries: None,
                outcomes: None,
            },
            &frame(),
            &[],
            &[],
            None,
        )
        .unwrap(),
    );
    assert_eq!(
        lowering.effects[0].required_capabilities_json,
        r#"["a","b"]"#
    );
}

#[test]
fn action_timer_waits_for_inputs_and_refuses_absent_invalid_or_lossy_operands() {
    let pending = Bindings::from([(BindingId(0), Slot::Pending)]);
    let Leaf::Waiting(value) = run("timer delay as t", &pending, &[], &[]).unwrap() else {
        panic!("pending input cannot draft");
    };
    assert!(matches!(value.state, State::Blocked { .. }));
    assert_eq!(value.reads, BTreeSet::from([BindingId(0)]));
    let Leaf::Waiting(value) =
        run("timer delay.duration as t", &input(json!({})), &[], &[]).unwrap()
    else {
        panic!("absence cannot draft");
    };
    assert!(matches!(value.state, State::Invalid(_)));
    for operand in [
        Value::Null,
        json!(1),
        json!("PT0S"),
        json!("PT-1S"),
        json!("PT0.5S"),
        json!("PT9007199254740993.0S"),
        json!("PT01S"),
        json!("PT1M"),
        json!("PT9223372036854775808S"),
        json!("invalid"),
    ] {
        assert!(run("timer delay as t", &input(operand), &[], &[]).is_err());
    }
    let (draft, _, _) = ready(
        run(
            "timer delay as t",
            &input(json!("PT9223372036854775807S")),
            &[],
            &[],
        )
        .unwrap(),
    );
    assert_eq!(draft.effects[0].timeout_seconds, Some(i64::MAX));
    let (draft, _, _) = ready(
        run(
            "timer delay as t",
            &input(json!("PT9007199254740993S")),
            &[],
            &[],
        )
        .unwrap(),
    );
    assert_eq!(
        draft.effects[0].timeout_seconds,
        Some(9_007_199_254_740_993)
    );
    assert!(run(
        "timer until delay as t",
        &input(json!("tomorrow")),
        &[],
        &[]
    )
    .is_err());
    assert!(run("timer 1s timeout 2s as t", &Bindings::new(), &[], &[]).is_err());
    assert!(run("return null", &Bindings::new(), &[], &[]).is_err());
    assert!(run("prompt \"hello\" as p", &Bindings::new(), &[], &[]).is_err());
}

#[test]
fn action_timer_replay_uses_recorded_state_before_unavailable_operands() {
    for status in [
        "queued",
        "running",
        "blocked",
        "blocked_by_admission",
        "blocked_by_dependency",
        "blocked_by_capacity",
        "blocked_by_capability",
        "blocked_by_profile",
        "uncertain",
    ] {
        let (lowering, value, work) = ready(
            run(
                "timer delay as t",
                &Bindings::new(),
                &[effect(status)],
                &[terminal("failed", 1)],
            )
            .unwrap(),
        );
        assert!(!lowering.has_commit_work());
        assert_eq!(value, None);
        assert_eq!(
            work.state,
            if status == "uncertain" {
                WorkState::Uncertain
            } else {
                WorkState::Pending
            }
        );
        assert!(
            work.causes.is_empty(),
            "old failed attempt cannot settle a retry"
        );
    }
    let mut cancelling = effect("running");
    cancelling.cancel_requested = true;
    let (_, value, work) =
        ready(run("timer delay as t", &Bindings::new(), &[cancelling], &[]).unwrap());
    assert_eq!(work.state, WorkState::CancellationRequested);
    assert_eq!(value, None);
    let events = [terminal("failed", 1), terminal("completed", 2)];
    let (lowering, value, work) = ready(
        run(
            "timer delay as t",
            &Bindings::new(),
            &[effect("completed")],
            &events,
        )
        .unwrap(),
    );
    assert!(!lowering.has_commit_work());
    assert_eq!(value.unwrap().value, Value::Null);
    assert_eq!(work.state, WorkState::Succeeded);
    assert!(work.causes.is_empty());
}

#[test]
fn action_timer_failures_preserve_original_payload_and_evidence() {
    for (status, kind) in [
        ("failed", FailureKind::Failed),
        ("timed_out", FailureKind::TimedOut),
        ("cancelled", FailureKind::Cancelled),
    ] {
        let event = terminal(status, 2);
        let (_, value, work) = ready(
            run(
                "timer 1s as t",
                &Bindings::new(),
                &[effect(status)],
                std::slice::from_ref(&event),
            )
            .unwrap(),
        );
        assert_eq!(value, None);
        assert_eq!(work.state, WorkState::Failed(Disposition::Propagate));
        let cause = &work.causes[&CauseId("operation".into())];
        assert!(!cause.recovered);
        assert_eq!(cause.cause.kind, kind);
        assert_eq!(
            cause.cause.payload,
            serde_json::from_str::<Value>(&event.payload_json).unwrap()
        );
        assert_eq!(cause.cause.evidence, BTreeSet::from([event.event_id]));
    }
    let mut event = terminal("failed", 3);
    let mut payload: Value = serde_json::from_str(&event.payload_json).unwrap();
    payload["run_status"] = json!("uncertain");
    event.payload_json = payload.to_string();
    let (_, value, work) = ready(
        run(
            "timer 1s as t",
            &Bindings::new(),
            &[effect("failed")],
            &[event],
        )
        .unwrap(),
    );
    assert_eq!(value, None);
    assert_eq!(work.state, WorkState::Uncertain);
    assert_eq!(work.causes.len(), 1);
}

#[test]
fn action_timer_refuses_conflicting_rows_and_missing_or_unreadable_settlement() {
    for change in 0..4 {
        let mut wrong = effect("queued");
        match change {
            0 => wrong.kind = "other".into(),
            1 => wrong.created_by_rule = "other".into(),
            2 => wrong.program_version_id = None,
            _ => wrong.status = "future-status".into(),
        }
        assert!(run("timer 1s as t", &Bindings::new(), &[wrong], &[]).is_err());
    }
    assert!(run(
        "timer 1s as t",
        &Bindings::new(),
        &[effect("completed")],
        &[]
    )
    .is_err());
    let mut unrelated = terminal("completed", 1);
    unrelated.payload_json = json!({"effect_id":"other","status":"completed"}).to_string();
    assert!(run(
        "timer 1s as t",
        &Bindings::new(),
        &[effect("completed")],
        &[unrelated]
    )
    .is_err());
    assert!(run(
        "timer 1s as t",
        &Bindings::new(),
        &[effect("completed")],
        &[terminal("failed", 1)]
    )
    .is_err());
    let mut unreadable = terminal("completed", 1);
    unreadable.payload_json = "broken".into();
    assert!(run(
        "timer 1s as t",
        &Bindings::new(),
        &[effect("completed")],
        &[unreadable]
    )
    .is_err());
    let mut cancelled = terminal("cancelled", 1);
    cancelled.event_type = "effect.cancelled".into();
    cancelled.payload_json = json!({"effect_id":"operation"}).to_string();
    let (_, value, work) = ready(
        run(
            "timer 1s as t",
            &Bindings::new(),
            &[effect("cancelled")],
            &[cancelled],
        )
        .unwrap(),
    );
    assert_eq!(value, None);
    assert_eq!(work.state, WorkState::Failed(Disposition::Propagate));
}
