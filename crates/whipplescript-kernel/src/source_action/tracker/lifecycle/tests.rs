use super::*;
use crate::source_action::arguments::{Bindings, QueryObservation, Slot, ValueSource};
use whipplescript_parser::action_plan::{NodeId, NodeKind};

fn source(statement: &str) -> String {
    format!(
        r#"workflow TrackerLifecycle
tracker backlog
output answer Answer
class Answer {{ value string }}
rule run
  when backlog has ready issue as item
=> {{
  {statement}
  after operation succeeds {{ complete answer {{ value operation.id }} }}
}}"#
    )
}

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "run".into(),
        identity: Some("started".into()),
        trigger_event: Some("admitted".into()),
    }
}

fn item() -> Argument {
    Argument {
        value: json!({
            "queue":"backlog",
            "id":"WS-1",
            "title":"Fix login",
            "body":"Users see 500s",
            "status":"open",
            "labels":["bug"],
            "releases":0,
        }),
        sources: BTreeSet::from([ValueSource::Fact {
            fact_id: "item-fact".into(),
            admission_event: "item-admitted".into(),
        }]),
        subjects: Default::default(),
        validity: BTreeSet::from([QueryObservation {
            frontier: 4,
            kind: super::super::super::arguments::ObservationKind::Fact,
            head: "tracker.issue.ready".into(),
            guard_json: None,
            members: Default::default(),
        }]),
    }
}

fn run(
    statement_source: &str,
    item_slot: Slot,
    effects: &[ProjectionEffect],
    events: &[EventView],
    mutate: impl FnOnce(BodyStmt) -> BodyStmt,
) -> Result<Leaf, String> {
    run_with_root(
        statement_source,
        item_slot,
        effects,
        events,
        Some("run"),
        mutate,
    )
}

fn run_with_root(
    statement_source: &str,
    item_slot: Slot,
    effects: &[ProjectionEffect],
    events: &[EventView],
    root_rule: Option<&str>,
    mutate: impl FnOnce(BodyStmt) -> BodyStmt,
) -> Result<Leaf, String> {
    let source = source(statement_source);
    let compiled = whipplescript_parser::execution_semantics::compile_recorded_program_with_root(
        &source,
        None,
        whipplescript_parser::ExecutionSemantics::TypedActionsV1,
    );
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let ir = compiled.ir.unwrap();
    let typed = compiled
        .typed_actions
        .unwrap()
        .remove("run")
        .expect("typed root");
    let (node, body, environment) = typed
        .plan
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            let NodeKind::Statement(body) = &node.kind else {
                return None;
            };
            let BodyStmt::Effect(effect) = body.as_ref() else {
                return None;
            };
            matches!(
                effect.kind,
                BodyEffectKind::TrackerClaim { .. }
                    | BodyEffectKind::TrackerRelease { .. }
                    | BodyEffectKind::TrackerFinish { .. }
            )
            .then(|| {
                (
                    NodeId(index),
                    body.as_ref().clone(),
                    typed.plan.blocks[node.block.0].environment.clone(),
                )
            })
        })
        .expect("lifecycle operation");
    let item_binding = environment["item"];
    let bindings = Bindings::from([(item_binding, item_slot)]);
    let body = mutate(body);
    project(
        Statement {
            node,
            root_rule,
            admitted: &bindings,
            identity: "operation-id".into(),
            body: &body,
            environment: &environment,
            bindings: &bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir: &ir,
            typed: &typed,
            frame: &frame(),
            frontier: 7,
            effects,
            events,
            source_path: None,
        },
    )
}

fn ready(leaf: Leaf) -> (Box<OwnedLowering>, Option<Argument>, OwnedWork) {
    let Leaf::Ready {
        lowering,
        value,
        work: Some(work),
    } = leaf
    else {
        panic!("ready lifecycle leaf")
    };
    (lowering, value, work)
}

fn effect(kind: &str, status: &str, input: Value) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation-id".into(),
        kind: kind.into(),
        target: Some("backlog".into()),
        input_json: input.to_string(),
        status: status.into(),
        created_by_rule: "run".into(),
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
        occurred_at: "2026-09-13T00:00:00Z".into(),
    }
}

fn completed(kind: &str, value: Value) -> Vec<EventView> {
    vec![
        event(
            "effect.terminal",
            1,
            json!({"effect_id":"operation-id","run_id":"run","status":"completed"}),
        ),
        event(
            "fact.derived",
            2,
            json!({
                "name":format!("{kind}.completed"),
                "key":"operation-id",
                "value":{
                    "effect_id":"operation-id",
                    "run_id":"run",
                    "status":"completed",
                    "value":value,
                }
            }),
        ),
    ]
}

fn draft(statement: &str) -> (String, Value) {
    let (lowering, value, work) =
        ready(run(statement, Slot::Ready(item()), &[], &[], |body| body).unwrap());
    assert!(value.is_none());
    assert_eq!(work.state, WorkState::Pending);
    let [effect] = lowering.effects.as_slice() else {
        panic!("one lifecycle effect")
    };
    let input = serde_json::from_str(&effect.input_json).unwrap();
    (effect.kind.clone(), input)
}

#[test]
fn managed_tracker_lifecycle_captures_and_projects_each_typed_receipt() {
    let cases = [
        (
            "claim item ttl 5m as operation",
            "tracker.claim",
            json!({
                "queue":"backlog","id":"WS-1","title":"Fix login",
                "claimed_by":"instance","expires_at":null,
            }),
        ),
        (
            "release item as operation",
            "tracker.release",
            json!({"queue":"backlog","id":"WS-1","title":"Fix login","status":"open"}),
        ),
        (
            "finish item { summary item.body } as operation",
            "tracker.finish",
            json!({
                "queue":"backlog","id":"WS-1","title":"Fix login",
                "status":"closed","summary":"Users see 500s",
            }),
        ),
    ];
    for (statement, expected_kind, receipt) in cases {
        let (kind, input) = draft(statement);
        assert_eq!(kind, expected_kind);
        assert_eq!(input["resources"], json!(["backlog"]));
        assert_eq!(input["item_argument"]["sources"][0]["fact_id"], "item-fact");
        if expected_kind == "tracker.claim" {
            assert_eq!(input["ttl_seconds"], 300);
        }
        let events = completed(expected_kind, receipt.clone());
        let (_, value, work) = ready(
            run(
                statement,
                Slot::Pending,
                &[effect(expected_kind, "completed", input)],
                &events,
                |body| body,
            )
            .unwrap(),
        );
        assert_eq!(work.state, WorkState::Succeeded);
        assert_eq!(value.unwrap().value, receipt);
    }
}

#[test]
fn managed_tracker_lifecycle_waits_and_refuses_runtime_or_source_drift() {
    let Leaf::Waiting(wait) = run("claim item as operation", Slot::Pending, &[], &[], |body| {
        body
    })
    .unwrap() else {
        panic!("pending item must wait")
    };
    assert!(matches!(wait.state, State::Blocked { .. }));

    assert_eq!(
        run_with_root(
            "claim item as operation",
            Slot::Ready(item()),
            &[],
            &[],
            None,
            |body| body,
        )
        .unwrap_err(),
        "managed tracker operation requires its pinned root rule"
    );

    let incompatible = whipplescript_parser::action_plan::resources::ResolvedEffect {
        kind: whipplescript_parser::IrEffectKind::TimerWait,
        resources: BTreeSet::from(["backlog".into()]),
        controls: BTreeSet::new(),
    };
    assert_eq!(
        validate_checked_resources(
            &incompatible,
            Operation::Claim {
                ttl_seconds: None,
                endorsed: false,
            },
        )
        .unwrap_err(),
        "managed tracker operation has an incompatible resource contract"
    );

    assert!(run(
        "claim item as operation",
        Slot::Ready(item()),
        &[],
        &[],
        |body| {
            let span = match body {
                BodyStmt::Effect(effect) => effect.span,
                _ => unreachable!(),
            };
            BodyStmt::Terminal(whipplescript_parser::body::TerminalStmt {
                kind: whipplescript_parser::body::TerminalKind::Complete,
                name: "answer".into(),
                from: None,
                fields: Vec::new(),
                scalar: None,
                span,
            })
        },
    )
    .unwrap_err()
    .contains("effect statement"));

    let invalid = Argument {
        value: json!({"queue":"backlog","id":"WS-1"}),
        ..item()
    };
    assert!(run(
        "claim item as operation",
        Slot::Ready(invalid),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("string title"));

    let mut outside = item();
    outside.value["queue"] = json!("other");
    assert_eq!(
        run(
            "claim item as operation",
            Slot::Ready(outside),
            &[],
            &[],
            |body| body,
        )
        .unwrap_err(),
        "managed tracker address is outside its checked resource set"
    );

    assert!(run(
        "claim item as operation",
        Slot::Ready(item()),
        &[],
        &[],
        |mut body| {
            let BodyStmt::Effect(effect) = &mut body else {
                unreachable!()
            };
            effect.kind = BodyEffectKind::Timer {
                duration_seconds: 1,
                duration_source: "1s".into(),
                until: None,
            };
            body
        },
    )
    .unwrap_err()
    .contains("requires claim, release or finish"));

    let (_, input) = draft("claim item as operation");
    let mut wrong = effect("tracker.release", "queued", input.clone());
    wrong.target = Some("other".into());
    assert!(run(
        "claim item as operation",
        Slot::Pending,
        &[wrong],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("source operation"));
    let mut incomplete = input.clone();
    incomplete["item_argument"]["validity"] = Value::Null;
    assert!(run(
        "claim item as operation",
        Slot::Pending,
        &[effect("tracker.claim", "queued", incomplete)],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("incomplete freshness"));
    let mut outside = input.clone();
    outside["item"]["queue"] = json!("other");
    outside["item_argument"]["value"]["queue"] = json!("other");
    assert_eq!(
        run(
            "claim item as operation",
            Slot::Pending,
            &[effect("tracker.claim", "queued", outside)],
            &[],
            |body| body,
        )
        .unwrap_err(),
        "recorded tracker address is outside its checked resource set"
    );
    let mut drift = input;
    drift["provider"] = json!("other");
    assert!(run(
        "claim item as operation",
        Slot::Pending,
        &[effect("tracker.claim", "queued", drift)],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("source contract"));
}

#[test]
fn managed_tracker_lifecycle_refuses_malformed_finish_and_settlement() {
    assert_eq!(
        run(
            "finish item { summary item.body } as operation",
            Slot::Ready(item()),
            &[],
            &[],
            |mut body| {
                let BodyStmt::Effect(effect) = &mut body else {
                    unreachable!()
                };
                let BodyEffectKind::TrackerFinish { fields, .. } = &mut effect.kind else {
                    unreachable!()
                };
                fields[0].name = "other".into();
                body
            },
        )
        .unwrap_err(),
        "managed tracker finish has an unknown field"
    );

    assert_eq!(
        validate_payload(&json!({"other":"value"})).unwrap_err(),
        "managed tracker finish payload has an unknown field"
    );
    assert_eq!(
        validate_payload(&json!({"summary":42})).unwrap_err(),
        "managed tracker finish summary must be a string"
    );

    assert_eq!(
        run(
            "finish item { summary item.body } as operation",
            Slot::Ready(item()),
            &[],
            &[],
            |mut body| {
                let BodyStmt::Effect(effect) = &mut body else {
                    unreachable!()
                };
                let BodyEffectKind::TrackerFinish { fields, .. } = &mut effect.kind else {
                    unreachable!()
                };
                fields.push(fields[0].clone());
                body
            },
        )
        .unwrap_err(),
        "managed tracker finish has duplicate fields"
    );

    let (_, input) = draft("finish item { summary item.body } as operation");
    let mut incomplete_payload = input.clone();
    incomplete_payload["payload_argument"]["validity"] = Value::Null;
    assert_eq!(
        run(
            "finish item { summary item.body } as operation",
            Slot::Pending,
            &[effect("tracker.finish", "queued", incomplete_payload)],
            &[],
            |body| body,
        )
        .unwrap_err(),
        "recorded tracker finish has an incomplete payload argument"
    );
    let mut payload_drift = input.clone();
    payload_drift["payload_fields"] = json!([]);
    assert_eq!(
        run(
            "finish item { summary item.body } as operation",
            Slot::Pending,
            &[effect("tracker.finish", "queued", payload_drift)],
            &[],
            |body| body,
        )
        .unwrap_err(),
        "recorded tracker finish payload differs from its source contract"
    );
    assert!(run(
        "finish item { summary item.body } as operation",
        Slot::Pending,
        &[effect("tracker.finish", "mystery", input.clone())],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("unknown status"));
    assert!(run(
        "finish item { summary item.body } as operation",
        Slot::Pending,
        &[effect("tracker.finish", "completed", input.clone())],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("exactly one terminal"));
    let failed_terminal = vec![event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation-id","run_id":"run","status":"failed"}),
    )];
    assert_eq!(
        run(
            "finish item { summary item.body } as operation",
            Slot::Pending,
            &[effect("tracker.finish", "completed", input.clone())],
            &failed_terminal,
            |body| body,
        )
        .unwrap_err(),
        "tracker terminal evidence differs from its recorded status"
    );
    let terminal_only = vec![event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation-id","run_id":"run","status":"completed"}),
    )];
    assert_eq!(
        run(
            "finish item { summary item.body } as operation",
            Slot::Pending,
            &[effect("tracker.finish", "completed", input.clone())],
            &terminal_only,
            |body| body,
        )
        .unwrap_err(),
        "tracker terminal requires exactly one result for its run"
    );
    let mut out_of_order = completed(
        "tracker.finish",
        json!({
            "queue":"backlog","id":"WS-1","title":"Fix login",
            "status":"closed","summary":"Users see 500s",
        }),
    );
    out_of_order[1].sequence = 0;
    assert_eq!(
        run(
            "finish item { summary item.body } as operation",
            Slot::Pending,
            &[effect("tracker.finish", "completed", input.clone())],
            &out_of_order,
            |body| body,
        )
        .unwrap_err(),
        "tracker result differs from its terminal"
    );
    let events = completed(
        "tracker.finish",
        json!({
            "queue":"backlog","id":"WS-1","title":"Fix login",
            "status":"closed","summary":"different",
        }),
    );
    assert!(run(
        "finish item { summary item.body } as operation",
        Slot::Pending,
        &[effect("tracker.finish", "completed", input)],
        &events,
        |body| body,
    )
    .unwrap_err()
    .contains("violates its source contract"));
}
