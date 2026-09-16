use super::*;
use crate::source_action::arguments::{Bindings, QueryObservation, Slot, ValueSource};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

const SOURCE: &str = r#"
workflow Trackers
class Request { title string body string source string }
class Answer { value string }
tracker backlog
output result Answer
rule file when started => { complete result { value "done" } }
"#;

const FILE: &str = "file issue into backlog { title request.title body request.body labels [\"bug\"] metadata { source request.source } } as filed";

fn ir() -> IrProgram {
    let compiled = whipplescript_parser::compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    compiled.ir.expect("tracker fixture compiles")
}

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "file".into(),
        identity: Some("started".into()),
        trigger_event: Some("admitted".into()),
    }
}

fn bindings() -> Bindings {
    Bindings::from([(
        BindingId(0),
        Slot::Ready(Argument {
            value: json!({"title":"Fix login","body":"Users see 500s","source":"api"}),
            sources: BTreeSet::from([ValueSource::Fact {
                fact_id: "request-fact".into(),
                admission_event: "request-admitted".into(),
            }]),
            subjects: Default::default(),
            validity: BTreeSet::from([QueryObservation {
                frontier: 4,
                kind: super::super::arguments::ObservationKind::Fact,
                head: "Request".into(),
                guard_json: None,
                members: Default::default(),
            }]),
        }),
    )])
}

fn run(
    source: &str,
    root_rule: Option<&str>,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
    mutate: impl FnOnce(BodyStmt) -> BodyStmt,
) -> Result<Leaf, String> {
    run_with_ir(&ir(), source, root_rule, bindings, effects, events, mutate)
}

fn run_with_ir(
    ir: &IrProgram,
    source: &str,
    root_rule: Option<&str>,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
    mutate: impl FnOnce(BodyStmt) -> BodyStmt,
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    let statement = mutate(body.statements[0].clone());
    project(
        Statement {
            node: NodeId(0),
            root_rule,
            admitted: bindings,
            identity: "operation".into(),
            body: &statement,
            environment: &Environment::from([("request".into(), BindingId(0))]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir,
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
        panic!("ready tracker-file leaf")
    };
    (lowering, value, work)
}

fn effect(status: &str, input: Value) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation".into(),
        kind: "tracker.file".into(),
        target: Some("backlog".into()),
        input_json: input.to_string(),
        status: status.into(),
        created_by_rule: "file".into(),
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

fn result_event(name: &str, sequence: i64, value: Value) -> EventView {
    event(
        "fact.derived",
        sequence,
        json!({"name":name,"key":"operation","value":value}),
    )
}

fn receipt() -> Value {
    json!({"queue":"backlog","id":"WS-1","title":"Fix login"})
}

#[test]
fn managed_tracker_file_captures_one_checked_item_and_tracker_contract() {
    let Leaf::Waiting(wait) =
        run(FILE, Some("file"), &Bindings::new(), &[], &[], |body| body).unwrap()
    else {
        panic!("missing item input must wait")
    };
    assert!(matches!(wait.state, State::Blocked { .. }));

    let (lowering, value, work) = ready(run(
        "file issue into backlog { title request.title body request.body labels [\"bug\"] metadata { source request.source } } as filed timeout 5s requires [\"tracker\"]",
        Some("file"), &bindings(), &[], &[], |body| body,
    ).unwrap());
    assert!(value.is_none());
    assert_eq!(work.state, WorkState::Pending);
    let [effect] = lowering.effects.as_slice() else {
        panic!("one tracker-file effect")
    };
    assert_eq!(effect.kind, "tracker.file");
    assert_eq!(effect.target.as_deref(), Some("backlog"));
    assert_eq!(effect.timeout_seconds, Some(5));
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["provider"], "builtin");
    assert_eq!(input["item"]["title"], "Fix login");
    assert_eq!(input["item"]["labels"], json!(["bug"]));
    assert_eq!(input["item_argument"]["validity"][0]["frontier"], 4);
    assert_eq!(
        input["item_argument"]["sources"][0]["fact_id"],
        "request-fact"
    );
}

#[test]
fn managed_tracker_file_projects_its_stable_receipt() {
    let (draft, _, _) = ready(run(FILE, Some("file"), &bindings(), &[], &[], |body| body).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let (_, value, work) = ready(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[effect("completed", input)],
        &[
            event("effect.terminal", 1, json!({"effect_id":"operation","run_id":"run","status":"completed"})),
            result_event("tracker.file.completed", 2, json!({"effect_id":"operation","run_id":"run","status":"completed","value":receipt()})),
        ],
        |body| body,
    ).unwrap());
    assert_eq!(work.state, WorkState::Succeeded);
    assert_eq!(value.unwrap().value, receipt());
}

#[test]
fn managed_tracker_file_refuses_source_freshness_and_runtime_shape_drift() {
    assert!(run(
        "return request",
        Some("file"),
        &bindings(),
        &[],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("effect statement"));
    assert!(run(
        "prompt \"hi\" as answer",
        Some("file"),
        &bindings(),
        &[],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("file statement"));
    assert!(run(FILE, None, &bindings(), &[], &[], |body| body)
        .unwrap_err()
        .contains("pinned root rule"));
    assert!(run(
        &FILE.replace("backlog", "missing"),
        Some("file"),
        &bindings(),
        &[],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("declared tracker"));
    assert!(run(
        "file issue into backlog { body \"x\" } as filed",
        Some("file"),
        &bindings(),
        &[],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("no title"));
    assert!(run(
        "file issue into backlog { title \"x\" priority 1 } as filed",
        Some("file"),
        &bindings(),
        &[],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("unknown field"));
    assert!(run(
        "file issue into backlog { title \"x\" title \"y\" } as filed",
        Some("file"),
        &bindings(),
        &[],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("duplicate fields"));
    assert!(run(
        "file issue into backlog { title 7 } as filed",
        Some("file"),
        &bindings(),
        &[],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("title must be a string"));

    let (draft, _, _) = ready(run(FILE, Some("file"), &bindings(), &[], &[], |body| body).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let mut wrong_identity = effect("queued", input.clone());
    wrong_identity.kind = "tracker.claim".into();
    assert!(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[wrong_identity],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("source operation"));
    let mut incomplete = input.clone();
    incomplete["item_argument"]["validity"] = Value::Null;
    assert!(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[effect("queued", incomplete)],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("incomplete freshness"));
    let mut stale = input.clone();
    stale["item_argument"]["validity"][0]["frontier"] = json!(8);
    assert!(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[effect("queued", stale)],
        &[],
        |body| body
    )
    .is_err());
    for (field, invalid, expected) in [
        ("body", json!(7), "body must be a string"),
        ("labels", json!(["bug", 7]), "labels must be strings"),
        ("metadata", json!(7), "metadata must be an object"),
    ] {
        let mut malformed = input.clone();
        malformed["item"][field] = invalid.clone();
        malformed["item_argument"]["value"][field] = invalid;
        assert!(run(
            FILE,
            Some("file"),
            &Bindings::new(),
            &[effect("queued", malformed)],
            &[],
            |body| body
        )
        .unwrap_err()
        .contains(expected));
    }
    let mut drift = input;
    drift["provider"] = json!("other");
    assert!(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[effect("queued", drift)],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("source contract"));
}

#[test]
fn managed_tracker_file_refuses_malformed_settlement() {
    let (draft, _, _) = ready(run(FILE, Some("file"), &bindings(), &[], &[], |body| body).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    assert!(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[effect("mystery", input.clone())],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("unknown operation status"));
    assert!(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("exactly one terminal"));
    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    assert!(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[effect("failed", input.clone())],
        std::slice::from_ref(&terminal),
        |body| body
    )
    .unwrap_err()
    .contains("recorded status"));
    assert!(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        std::slice::from_ref(&terminal),
        |body| body
    )
    .unwrap_err()
    .contains("exactly one result"));
    let mismatched_status = result_event(
        "tracker.file.completed",
        2,
        json!({"effect_id":"operation","run_id":"run","status":"failed","value":receipt()}),
    );
    assert!(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        &[terminal.clone(), mismatched_status],
        |body| body
    )
    .unwrap_err()
    .contains("result differs from its terminal"));
    let wrong = result_event(
        "tracker.file.completed",
        2,
        json!({"effect_id":"operation","run_id":"run","status":"completed","value":{"queue":"other","id":"WS-1","title":"Fix login"}}),
    );
    assert!(run(
        FILE,
        Some("file"),
        &Bindings::new(),
        &[effect("completed", input)],
        &[terminal, wrong],
        |body| body
    )
    .unwrap_err()
    .contains("violates its source contract"));
}
