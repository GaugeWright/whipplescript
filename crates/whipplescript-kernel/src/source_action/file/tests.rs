use super::*;
use crate::source_action::arguments::{Bindings, QueryObservation, Slot, ValueSource};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

const SOURCE: &str = r#"
workflow Files
file store workspace { root "." allow read ["docs/**"] allow write ["out/**"] }
output result Answer
class Answer { text string }
class Ticket { owner string priority int }
rule finish when started => { complete result { text "done" } }
"#;

fn ir() -> IrProgram {
    let compiled = whipplescript_parser::compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    compiled.ir.expect("file fixture compiles")
}

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "finish".into(),
        identity: Some("started".into()),
        trigger_event: Some("admitted".into()),
    }
}

fn run(
    source: &str,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
) -> Result<Leaf, String> {
    run_with(source, Some("finish"), bindings, effects, events, |body| {
        body
    })
}

fn run_with(
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
    project_read(
        Statement {
            node: NodeId(0),
            root_rule,
            admitted: bindings,
            identity: "operation".into(),
            body: &statement,
            environment: &Environment::from([("path".into(), BindingId(0))]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir: &ir(),
            frame: &frame(),
            frontier: 7,
            effects,
            events,
            facts: &[],
            source_path: None,
        },
    )
}

fn run_write(
    source: &str,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
) -> Result<Leaf, String> {
    run_write_with(source, Some("finish"), bindings, effects, events, |body| {
        body
    })
}

fn run_write_with(
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
    project_write(
        Statement {
            node: NodeId(0),
            root_rule,
            admitted: bindings,
            identity: "operation".into(),
            body: &statement,
            environment: &Environment::from([
                ("path".into(), BindingId(0)),
                ("body".into(), BindingId(1)),
            ]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir: &ir(),
            frame: &frame(),
            frontier: 7,
            effects,
            events,
            facts: &[],
            source_path: None,
        },
    )
}

fn run_import(
    source: &str,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
) -> Result<Leaf, String> {
    run_import_with(source, Some("finish"), bindings, effects, events, |body| {
        body
    })
}

fn run_import_with(
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
    project_import(
        Statement {
            node: NodeId(0),
            root_rule,
            admitted: bindings,
            identity: "operation".into(),
            body: &statement,
            environment: &Environment::from([("path".into(), BindingId(0))]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir: &ir(),
            frame: &frame(),
            frontier: 7,
            effects,
            events,
            facts: &[],
            source_path: None,
        },
    )
}

fn run_export(
    source: &str,
    bindings: &Bindings,
    facts: &[ProjectionFact],
    effects: &[ProjectionEffect],
    events: &[EventView],
) -> Result<Leaf, String> {
    run_export_with(
        source,
        Some("finish"),
        bindings,
        facts,
        effects,
        events,
        |body| body,
    )
}

fn run_export_with(
    source: &str,
    root_rule: Option<&str>,
    bindings: &Bindings,
    facts: &[ProjectionFact],
    effects: &[ProjectionEffect],
    events: &[EventView],
    mutate: impl FnOnce(BodyStmt) -> BodyStmt,
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    let statement = mutate(body.statements[0].clone());
    project_export(
        Statement {
            node: NodeId(0),
            root_rule,
            admitted: bindings,
            identity: "operation".into(),
            body: &statement,
            environment: &Environment::from([("path".into(), BindingId(0))]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir: &ir(),
            frame: &frame(),
            frontier: 7,
            effects,
            events,
            facts,
            source_path: None,
        },
    )
}

fn path() -> Bindings {
    Bindings::from([(
        BindingId(0),
        Slot::Ready(Argument {
            value: json!("docs/guide.md"),
            sources: BTreeSet::from([ValueSource::Fact {
                fact_id: "path-fact".into(),
                admission_event: "admitted".into(),
            }]),
            subjects: Default::default(),
            validity: BTreeSet::from([QueryObservation {
                frontier: 4,
                kind: super::super::arguments::ObservationKind::Fact,
                head: "Path".into(),
                guard_json: None,
                members: Default::default(),
            }]),
        }),
    )])
}

fn write_inputs() -> Bindings {
    let mut bindings = path();
    bindings.insert(
        BindingId(1),
        Slot::Ready(Argument {
            value: json!("Guide"),
            sources: BTreeSet::from([ValueSource::Operation {
                operation_id: "render".into(),
            }]),
            subjects: Default::default(),
            validity: Default::default(),
        }),
    );
    if let Slot::Ready(path) = bindings.get_mut(&BindingId(0)).unwrap() {
        path.value = json!("out/guide.md");
    }
    bindings
}

fn export_inputs() -> Bindings {
    let mut bindings = path();
    if let Slot::Ready(path) = bindings.get_mut(&BindingId(0)).unwrap() {
        path.value = json!("out/tickets.jsonl");
    }
    bindings
}

fn import_inputs() -> Bindings {
    let mut bindings = path();
    if let Slot::Ready(path) = bindings.get_mut(&BindingId(0)).unwrap() {
        path.value = json!("docs/tickets.json");
    }
    bindings
}

fn ready(leaf: Leaf) -> (Box<OwnedLowering>, Option<Argument>, OwnedWork) {
    let Leaf::Ready {
        lowering,
        value,
        work: Some(work),
    } = leaf
    else {
        panic!("ready file leaf")
    };
    (lowering, value, work)
}

fn projection_effect(status: &str, input: Value) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation".into(),
        kind: "file.read".into(),
        target: Some("workspace".into()),
        input_json: input.to_string(),
        status: status.into(),
        created_by_rule: "finish".into(),
        program_version_id: Some("v".into()),
        revision_epoch: 0,
        profile: None,
        cancel_requested: false,
    }
}

fn write_effect(status: &str, input: Value) -> ProjectionEffect {
    ProjectionEffect {
        kind: "file.write".into(),
        ..projection_effect(status, input)
    }
}

fn export_effect(status: &str, input: Value) -> ProjectionEffect {
    ProjectionEffect {
        kind: "file.export".into(),
        ..projection_effect(status, input)
    }
}

fn import_effect(status: &str, input: Value) -> ProjectionEffect {
    ProjectionEffect {
        kind: "file.import".into(),
        ..projection_effect(status, input)
    }
}

fn export_fact(id: &str, key: &str, owner: &str, priority: i64) -> ProjectionFact {
    ProjectionFact {
        fact_id: id.into(),
        program_version_id: Some("v".into()),
        revision_epoch: 0,
        name: "Ticket".into(),
        key: key.into(),
        value_json: json!({"owner":owner,"priority":priority}).to_string(),
        provenance_class: "internal".into(),
        source_span_json: None,
        validity_json: None,
        source_event_id: format!("admitted-{id}"),
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
        json!({
            "fact_id": format!("fact-{name}"),
            "name": name,
            "key": "operation",
            "value": value,
            "schema_id": null,
            "provenance_class": "external",
            "correlation_id": null,
        }),
    )
}

fn success_value() -> Value {
    json!({
        "store":"workspace", "path":"docs/guide.md", "format":"text",
        "content":"Guide", "bytes":5, "content_hash":"hash"
    })
}

fn write_value() -> Value {
    json!({
        "store":"workspace", "path":"out/guide.md", "full_path":"./out/guide.md",
        "format":"markdown", "mode":"replace", "bytes":5, "content_hash":"hash",
        "receipt":{"schema_ref":"s","label_ref":"l","content_hash":"r"}
    })
}

fn export_value() -> Value {
    json!({
        "store":"workspace", "path":"out/tickets.jsonl", "format":"jsonl",
        "schema":"Ticket", "mode":"replace", "row_count":1, "content_hash":"hash"
    })
}

fn import_value() -> Value {
    json!({
        "store":"workspace", "path":"docs/tickets.json", "format":"json",
        "schema":"Ticket", "row_count":2, "admitted":2, "skipped":0
    })
}

#[test]
fn managed_file_read_waits_then_captures_a_fresh_typed_path() {
    let Leaf::Waiting(wait) = run(
        "read text from workspace at path as document",
        &Bindings::new(),
        &[],
        &[],
    )
    .unwrap() else {
        panic!("missing path must wait")
    };
    assert!(matches!(wait.state, State::Blocked { .. }));

    let (lowering, value, work) = ready(
        run(
            "read text from workspace at path as document timeout 5s requires [\"audit\"]",
            &path(),
            &[],
            &[],
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Pending);
    assert!(value.is_none());
    let [effect] = lowering.effects.as_slice() else {
        panic!("one file effect")
    };
    assert_eq!(effect.kind, "file.read");
    assert_eq!(effect.target.as_deref(), Some("workspace"));
    assert_eq!(effect.timeout_seconds, Some(5));
    assert_eq!(effect.required_capabilities_json, r#"["audit"]"#);
    let captured: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(captured["path"], "docs/guide.md");
    assert_eq!(captured["path_expr"], "path");
    assert_eq!(captured["root"], ".");
    assert_eq!(captured["allow"], json!(["docs/**"]));
    assert_eq!(
        captured["path_argument"]["sources"][0]["fact_id"],
        "path-fact"
    );
    assert_eq!(captured["path_argument"]["validity"][0]["frontier"], 4);
}

#[test]
fn managed_file_read_observes_only_its_exact_result_and_failure() {
    let source = "read text from workspace at path as document";
    let (draft, _, _) = ready(run(source, &path(), &[], &[]).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let completed = projection_effect("completed", input.clone());
    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    let result = result_event(
        "file.read.completed",
        2,
        json!({
            "effect_id":"operation", "run_id":"run", "status":"completed",
            "value": success_value()
        }),
    );
    let (_, value, work) = ready(
        run(
            source,
            &Bindings::new(),
            std::slice::from_ref(&completed),
            &[terminal.clone(), result],
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Succeeded);
    assert_eq!(value.unwrap().value, success_value());

    let failure = json!({
        "error_kind":"file_effect_failed", "message":"missing", "summary":"missing",
        "effect_id":"operation", "run_id":"run", "kind":"file.read"
    });
    let (_, value, work) = ready(
        run(
            source,
            &Bindings::new(),
            &[projection_effect("failed", input)],
            &[
                event(
                    "effect.terminal",
                    1,
                    json!({"effect_id":"operation","run_id":"run","status":"failed"}),
                ),
                result_event(
                    "file.read.failed",
                    2,
                    json!({
                        "effect_id":"operation", "run_id":"run", "status":"failed",
                        "value":failure
                    }),
                ),
            ],
        )
        .unwrap(),
    );
    assert!(value.is_none());
    assert_eq!(work.state, WorkState::Failed(Disposition::Propagate));
    assert_eq!(
        work.causes[&CauseId("operation".into())].cause.payload,
        failure
    );
}

#[test]
fn managed_file_read_refuses_tampered_source_and_replay_contracts() {
    let source = "read text from workspace at path as document";
    assert!(run_with(source, None, &path(), &[], &[], |body| body)
        .unwrap_err()
        .contains("pinned root rule"));
    assert!(run("return path", &path(), &[], &[])
        .unwrap_err()
        .contains("requires an effect statement"));
    assert!(run("prompt \"hi\" as answer", &path(), &[], &[])
        .unwrap_err()
        .contains("requires a read statement"));
    assert!(
        run_with(source, Some("finish"), &path(), &[], &[], |mut body| {
            if let BodyStmt::Effect(effect) = &mut body {
                let BodyEffectKind::FileRead { format, .. } = &mut effect.kind else {
                    unreachable!()
                };
                *format = "bytes".into();
            }
            body
        })
        .unwrap_err()
        .contains("unsupported format")
    );
    assert!(run(
        "read text from absent at path as document",
        &path(),
        &[],
        &[]
    )
    .unwrap_err()
    .contains("no declared store"));
    assert!(
        run_with(source, Some("finish"), &path(), &[], &[], |mut body| {
            if let BodyStmt::Effect(effect) = &mut body {
                effect.binding = None;
            }
            body
        })
        .unwrap_err()
        .contains("no result binding")
    );

    let (draft, _, _) = ready(run(source, &path(), &[], &[]).unwrap());
    let original: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let mut wrong_effect = projection_effect("queued", original.clone());
    wrong_effect.kind = "other".into();
    assert!(run(source, &Bindings::new(), &[wrong_effect], &[])
        .unwrap_err()
        .contains("source operation"));

    let mut incomplete = original.clone();
    incomplete["path_argument"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    assert!(run(
        source,
        &Bindings::new(),
        &[projection_effect("queued", incomplete)],
        &[],
    )
    .unwrap_err()
    .contains("incomplete freshness"));

    let mut changed = original;
    changed["allow"] = json!(["other/**"]);
    assert!(run(
        source,
        &Bindings::new(),
        &[projection_effect("queued", changed)],
        &[],
    )
    .unwrap_err()
    .contains("source contract"));
}

#[test]
fn managed_file_read_settlement_refusal_boundaries_are_observable() {
    let source = "read text from workspace at path as document";
    let (draft, _, _) = ready(run(source, &path(), &[], &[]).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let unknown = projection_effect("mystery", input.clone());
    assert!(run(source, &Bindings::new(), &[unknown], &[])
        .unwrap_err()
        .contains("unknown operation status"));

    let completed = projection_effect("completed", input.clone());
    assert!(run(
        source,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        &[],
    )
    .unwrap_err()
    .contains("exactly one terminal"));
    let wrong_terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"failed"}),
    );
    assert!(run(
        source,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        &[wrong_terminal],
    )
    .unwrap_err()
    .contains("recorded status"));

    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    assert!(run(
        source,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        std::slice::from_ref(&terminal),
    )
    .unwrap_err()
    .contains("exactly one result"));

    let wrong_result = result_event(
        "file.read.completed",
        1,
        json!({
            "effect_id":"operation", "run_id":"run", "status":"completed",
            "value": success_value()
        }),
    );
    assert!(run(
        source,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        &[terminal.clone(), wrong_result],
    )
    .unwrap_err()
    .contains("differs from its terminal"));

    let mut invalid = success_value();
    invalid["bytes"] = json!("five");
    let invalid = result_event(
        "file.read.completed",
        2,
        json!({
            "effect_id":"operation", "run_id":"run", "status":"completed",
            "value":invalid
        }),
    );
    assert!(run(
        source,
        &Bindings::new(),
        &[projection_effect("completed", input)],
        &[terminal, invalid],
    )
    .unwrap_err()
    .contains("violates its source contract"));
}

const WRITE: &str = "write markdown to workspace at path { body body mode replace } as written";

#[test]
fn managed_file_write_waits_then_captures_both_fresh_string_arguments() {
    let Leaf::Waiting(wait) = run_write(WRITE, &path(), &[], &[]).unwrap() else {
        panic!("missing body must wait")
    };
    assert!(matches!(wait.state, State::Blocked { .. }));

    let (lowering, value, work) = ready(
        run_write(
            "write markdown to workspace at path { body body mode replace } as written timeout 5s requires [\"audit\"]",
            &write_inputs(),
            &[],
            &[],
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Pending);
    assert!(value.is_none());
    let [effect] = lowering.effects.as_slice() else {
        panic!("one file write")
    };
    assert_eq!(effect.kind, "file.write");
    assert_eq!(effect.target.as_deref(), Some("workspace"));
    assert_eq!(effect.timeout_seconds, Some(5));
    assert_eq!(effect.required_capabilities_json, r#"["audit"]"#);
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["path"], "out/guide.md");
    assert_eq!(input["body"], "Guide");
    assert_eq!(input["path_expr"], "path");
    assert_eq!(input["body_expr"], "body");
    assert_eq!(input["allow"], json!(["out/**"]));
    assert_eq!(input["path_argument"]["sources"][0]["fact_id"], "path-fact");
    assert_eq!(
        input["body_argument"]["sources"][0]["operation_id"],
        "render"
    );
}

#[test]
fn managed_file_write_projects_stable_public_result_and_failure() {
    let (draft, _, _) = ready(run_write(WRITE, &write_inputs(), &[], &[]).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let completed = write_effect("completed", input.clone());
    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    let result = result_event(
        "file.write.completed",
        2,
        json!({
            "effect_id":"operation", "run_id":"run", "status":"completed",
            "value":write_value()
        }),
    );
    let (_, value, work) = ready(
        run_write(
            WRITE,
            &Bindings::new(),
            std::slice::from_ref(&completed),
            &[terminal, result],
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Succeeded);
    assert_eq!(
        value.unwrap().value,
        json!({
            "store":"workspace", "path":"out/guide.md", "format":"markdown",
            "mode":"replace", "bytes":5, "content_hash":"hash"
        })
    );

    let failure = json!({
        "error_kind":"file_effect_failed", "message":"denied", "summary":"denied",
        "effect_id":"operation", "run_id":"run", "kind":"file.write"
    });
    let (_, value, work) = ready(
        run_write(
            WRITE,
            &Bindings::new(),
            &[write_effect("failed", input)],
            &[
                event(
                    "effect.terminal",
                    1,
                    json!({"effect_id":"operation","run_id":"run","status":"failed"}),
                ),
                result_event(
                    "file.write.failed",
                    2,
                    json!({
                        "effect_id":"operation", "run_id":"run", "status":"failed",
                        "value":failure
                    }),
                ),
            ],
        )
        .unwrap(),
    );
    assert!(value.is_none());
    assert_eq!(work.state, WorkState::Failed(Disposition::Propagate));
    assert_eq!(
        work.causes[&CauseId("operation".into())].cause.payload,
        failure
    );
}

#[test]
fn managed_file_write_refuses_tampered_source_and_capture() {
    assert!(
        run_write_with(WRITE, None, &write_inputs(), &[], &[], |body| body)
            .unwrap_err()
            .contains("pinned root rule")
    );
    assert!(run_write("return path", &write_inputs(), &[], &[])
        .unwrap_err()
        .contains("requires an effect statement"));
    assert!(run_write(
        "read text from workspace at path as document",
        &write_inputs(),
        &[],
        &[]
    )
    .unwrap_err()
    .contains("requires a write statement"));
    assert!(run_write_with(
        WRITE,
        Some("finish"),
        &write_inputs(),
        &[],
        &[],
        |mut body| {
            if let BodyStmt::Effect(effect) = &mut body {
                let BodyEffectKind::FileWrite { mode, .. } = &mut effect.kind else {
                    unreachable!()
                };
                *mode = "mystery".into();
            }
            body
        }
    )
    .unwrap_err()
    .contains("unsupported format or mode"));
    assert!(run_write(
        "write text to absent at path { body body mode replace } as written",
        &write_inputs(),
        &[],
        &[]
    )
    .unwrap_err()
    .contains("no declared store"));
    assert!(run_write_with(
        WRITE,
        Some("finish"),
        &write_inputs(),
        &[],
        &[],
        |mut body| {
            if let BodyStmt::Effect(effect) = &mut body {
                effect.binding = None;
            }
            body
        }
    )
    .unwrap_err()
    .contains("no result binding"));

    let (draft, _, _) = ready(run_write(WRITE, &write_inputs(), &[], &[]).unwrap());
    let original: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let mut wrong = write_effect("queued", original.clone());
    wrong.target = Some("other".into());
    assert!(run_write(WRITE, &Bindings::new(), &[wrong], &[])
        .unwrap_err()
        .contains("source operation"));
    let mut incomplete = original.clone();
    incomplete["body_argument"]
        .as_object_mut()
        .unwrap()
        .remove("sources");
    assert!(run_write(
        WRITE,
        &Bindings::new(),
        &[write_effect("queued", incomplete)],
        &[]
    )
    .unwrap_err()
    .contains("incomplete freshness"));
    let mut changed = original;
    changed["mode"] = json!("append");
    assert!(run_write(
        WRITE,
        &Bindings::new(),
        &[write_effect("queued", changed)],
        &[]
    )
    .unwrap_err()
    .contains("source contract"));
}

#[test]
fn managed_file_write_settlement_refusals_are_observable() {
    let (draft, _, _) = ready(run_write(WRITE, &write_inputs(), &[], &[]).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    assert!(run_write(
        WRITE,
        &Bindings::new(),
        &[write_effect("mystery", input.clone())],
        &[]
    )
    .unwrap_err()
    .contains("unknown operation status"));
    let completed = write_effect("completed", input.clone());
    assert!(run_write(
        WRITE,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        &[]
    )
    .unwrap_err()
    .contains("exactly one terminal"));
    let wrong_terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"failed"}),
    );
    assert!(run_write(
        WRITE,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        &[wrong_terminal]
    )
    .unwrap_err()
    .contains("recorded status"));
    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    assert!(run_write(
        WRITE,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        std::slice::from_ref(&terminal)
    )
    .unwrap_err()
    .contains("exactly one result"));
    let early = result_event(
        "file.write.completed",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed","value":write_value()}),
    );
    assert!(run_write(
        WRITE,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        &[terminal.clone(), early]
    )
    .unwrap_err()
    .contains("differs from its terminal"));
    let mut wrong_source = write_value();
    wrong_source["mode"] = json!("append");
    let wrong_source = result_event(
        "file.write.completed",
        2,
        json!({"effect_id":"operation","run_id":"run","status":"completed","value":wrong_source}),
    );
    assert!(run_write(
        WRITE,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        &[terminal.clone(), wrong_source]
    )
    .unwrap_err()
    .contains("source contract"));
    let mut invalid = write_value();
    invalid["bytes"] = json!("five");
    let invalid = result_event(
        "file.write.completed",
        2,
        json!({"effect_id":"operation","run_id":"run","status":"completed","value":invalid}),
    );
    assert!(run_write(
        WRITE,
        &Bindings::new(),
        &[write_effect("completed", input)],
        &[terminal, invalid]
    )
    .unwrap_err()
    .contains("output type"));
}

const IMPORT: &str = "import json Ticket from workspace at path as loaded";

#[test]
fn managed_file_import_captures_a_fresh_typed_path_and_schema_contract() {
    let Leaf::Waiting(wait) = run_import(IMPORT, &Bindings::new(), &[], &[]).unwrap() else {
        panic!("missing path must wait")
    };
    assert!(matches!(wait.state, State::Blocked { .. }));

    let (lowering, value, work) = ready(
        run_import(
            "import json Ticket from workspace at path as loaded timeout 5s requires [\"audit\"]",
            &import_inputs(),
            &[],
            &[],
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Pending);
    assert!(value.is_none());
    let [effect] = lowering.effects.as_slice() else {
        panic!("one import effect")
    };
    assert_eq!(effect.kind, "file.import");
    assert_eq!(effect.target.as_deref(), Some("workspace"));
    assert_eq!(effect.timeout_seconds, Some(5));
    assert_eq!(effect.required_capabilities_json, r#"["audit"]"#);
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["path"], "docs/tickets.json");
    assert_eq!(input["path_expr"], "path");
    assert_eq!(input["schema"], "Ticket");
    assert_eq!(input["root"], ".");
    assert_eq!(input["allow"], json!(["docs/**"]));
    assert_eq!(input["required_fields"], json!(["owner", "priority"]));
    assert_eq!(input["natural_key_field"], "");
    assert_eq!(input["path_argument"]["sources"][0]["fact_id"], "path-fact");
    assert_eq!(input["path_argument"]["validity"][0]["frontier"], 4);
}

#[test]
fn managed_file_import_projects_its_admission_receipt_and_failure() {
    let (draft, _, _) = ready(run_import(IMPORT, &import_inputs(), &[], &[]).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    let result = result_event(
        "file.import.completed",
        2,
        json!({
            "effect_id":"operation", "run_id":"run", "status":"completed",
            "value":import_value()
        }),
    );
    let (_, value, work) = ready(
        run_import(
            IMPORT,
            &Bindings::new(),
            &[import_effect("completed", input.clone())],
            &[terminal, result],
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Succeeded);
    assert_eq!(value.unwrap().value, import_value());

    let failure = json!({
        "error_kind":"file_effect_failed", "message":"invalid row", "summary":"invalid row",
        "effect_id":"operation", "run_id":"run", "kind":"file.import"
    });
    let (_, value, work) = ready(
        run_import(
            IMPORT,
            &Bindings::new(),
            &[import_effect("failed", input)],
            &[
                event(
                    "effect.terminal",
                    1,
                    json!({"effect_id":"operation","run_id":"run","status":"failed"}),
                ),
                result_event(
                    "file.import.failed",
                    2,
                    json!({
                        "effect_id":"operation", "run_id":"run", "status":"failed",
                        "value":failure
                    }),
                ),
            ],
        )
        .unwrap(),
    );
    assert!(value.is_none());
    assert_eq!(work.state, WorkState::Failed(Disposition::Propagate));
    assert_eq!(
        work.causes[&CauseId("operation".into())].cause.payload,
        failure
    );
}

#[test]
fn managed_file_import_refuses_tampered_source_capture_and_settlement() {
    assert!(run_import("return path", &import_inputs(), &[], &[])
        .unwrap_err()
        .contains("requires an effect statement"));
    assert!(
        run_import("prompt \"hi\" as answer", &import_inputs(), &[], &[])
            .unwrap_err()
            .contains("requires an import statement")
    );
    assert!(
        run_import_with(IMPORT, None, &import_inputs(), &[], &[], |body| body)
            .unwrap_err()
            .contains("pinned root rule")
    );
    assert!(run_import(
        "import json Missing from workspace at path as loaded",
        &import_inputs(),
        &[],
        &[],
    )
    .unwrap_err()
    .contains("no declared row schema"));
    assert!(run_import(
        "import json Ticket from missing at path as loaded",
        &import_inputs(),
        &[],
        &[],
    )
    .unwrap_err()
    .contains("no declared store"));
    assert!(run_import_with(
        IMPORT,
        Some("finish"),
        &import_inputs(),
        &[],
        &[],
        |mut body| {
            let BodyStmt::Effect(effect) = &mut body else {
                unreachable!()
            };
            let BodyEffectKind::FileImport { format, .. } = &mut effect.kind else {
                unreachable!()
            };
            *format = "markdown".into();
            body
        },
    )
    .unwrap_err()
    .contains("unsupported format"));
    assert!(run_import_with(
        IMPORT,
        Some("finish"),
        &import_inputs(),
        &[],
        &[],
        |mut body| {
            let BodyStmt::Effect(effect) = &mut body else {
                unreachable!()
            };
            effect.binding = None;
            body
        },
    )
    .unwrap_err()
    .contains("no result binding"));
    let non_string = Bindings::from([(BindingId(0), Slot::Ready(json!(42).into()))]);
    assert!(run_import(IMPORT, &non_string, &[], &[])
        .unwrap_err()
        .contains("path must be a string"));
    assert!(run_import_with(
        IMPORT,
        Some("finish"),
        &import_inputs(),
        &[],
        &[],
        |mut body| {
            let BodyStmt::Effect(effect) = &mut body else {
                unreachable!()
            };
            effect.timeout_seconds = Some(u64::MAX);
            body
        },
    )
    .unwrap_err()
    .contains("timeout exceeds"));

    let (draft, _, _) = ready(run_import(IMPORT, &import_inputs(), &[], &[]).unwrap());
    let original: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let mut wrong_effect = import_effect("queued", original.clone());
    wrong_effect.kind = "file.read".into();
    assert!(run_import(IMPORT, &Bindings::new(), &[wrong_effect], &[])
        .unwrap_err()
        .contains("source operation"));
    let unreadable = ProjectionEffect {
        input_json: "{".into(),
        ..import_effect("queued", original.clone())
    };
    assert!(run_import(IMPORT, &Bindings::new(), &[unreadable], &[])
        .unwrap_err()
        .contains("unreadable recorded"));
    let mut incomplete = original.clone();
    incomplete["path_argument"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    assert!(run_import(
        IMPORT,
        &Bindings::new(),
        &[import_effect("queued", incomplete)],
        &[],
    )
    .unwrap_err()
    .contains("incomplete freshness"));
    let mut changed = original.clone();
    changed["schema"] = json!("Other");
    assert!(run_import(
        IMPORT,
        &Bindings::new(),
        &[import_effect("queued", changed)],
        &[],
    )
    .unwrap_err()
    .contains("source contract"));

    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    assert!(run_import(
        IMPORT,
        &Bindings::new(),
        &[import_effect("mystery", original.clone())],
        &[],
    )
    .unwrap_err()
    .contains("unknown operation status"));
    assert!(run_import(
        IMPORT,
        &Bindings::new(),
        &[import_effect("completed", original.clone())],
        &[],
    )
    .unwrap_err()
    .contains("exactly one terminal"));
    let wrong_terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"failed"}),
    );
    assert!(run_import(
        IMPORT,
        &Bindings::new(),
        &[import_effect("completed", original.clone())],
        &[wrong_terminal],
    )
    .unwrap_err()
    .contains("recorded status"));
    assert!(run_import(
        IMPORT,
        &Bindings::new(),
        &[import_effect("completed", original.clone())],
        std::slice::from_ref(&terminal),
    )
    .unwrap_err()
    .contains("exactly one result"));
    let early = result_event(
        "file.import.completed",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed","value":import_value()}),
    );
    assert!(run_import(
        IMPORT,
        &Bindings::new(),
        &[import_effect("completed", original.clone())],
        &[terminal.clone(), early],
    )
    .unwrap_err()
    .contains("differs from its terminal"));
    let mut wrong_source = import_value();
    wrong_source["schema"] = json!("Other");
    let wrong_source = result_event(
        "file.import.completed",
        2,
        json!({"effect_id":"operation","run_id":"run","status":"completed","value":wrong_source}),
    );
    assert!(run_import(
        IMPORT,
        &Bindings::new(),
        &[import_effect("completed", original.clone())],
        &[terminal.clone(), wrong_source],
    )
    .unwrap_err()
    .contains("source contract"));
    let mut invalid = import_value();
    invalid["row_count"] = json!("two");
    let invalid = result_event(
        "file.import.completed",
        2,
        json!({"effect_id":"operation","run_id":"run","status":"completed","value":invalid}),
    );
    assert!(run_import(
        IMPORT,
        &Bindings::new(),
        &[import_effect("completed", original)],
        &[terminal, invalid],
    )
    .unwrap_err()
    .contains("source contract"));
}

const EXPORT: &str =
    "export jsonl Ticket to workspace at path { where priority > 2 mode replace } as saved";

#[test]
fn managed_file_export_freezes_rows_and_membership_at_admission() {
    let Leaf::Waiting(wait) = run_export(EXPORT, &Bindings::new(), &[], &[], &[]).unwrap() else {
        panic!("missing path must wait")
    };
    assert!(matches!(wait.state, State::Blocked { .. }));

    let facts = [
        export_fact("low", "b", "bob", 1),
        export_fact("high", "a", "alice", 4),
    ];
    let (lowering, value, work) = ready(
        run_export(
            "export jsonl Ticket to workspace at path { where priority > 2 mode replace } as saved timeout 5s requires [\"audit\"]",
            &export_inputs(),
            &facts,
            &[],
            &[],
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Pending);
    assert!(value.is_none());
    let [effect] = lowering.effects.as_slice() else {
        panic!("one export effect")
    };
    assert_eq!(effect.kind, "file.export");
    assert_eq!(effect.timeout_seconds, Some(5));
    assert_eq!(effect.required_capabilities_json, r#"["audit"]"#);
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["path"], "out/tickets.jsonl");
    assert_eq!(input["path_expr"], "path");
    assert_eq!(input["predicate"], "priority > 2");
    assert_eq!(input["fields"], json!(["owner", "priority"]));
    assert_eq!(
        input["rows_argument"]["value"],
        json!([{"owner":"alice","priority":4}])
    );
    assert_eq!(input["rows_argument"]["validity"][0]["frontier"], 7);
    assert_eq!(
        input["rows_argument"]["validity"][0]["members"][0]["fact_id"],
        "high"
    );
}

#[test]
fn managed_file_export_projects_its_stable_receipt_and_failure() {
    let facts = [export_fact("high", "a", "alice", 4)];
    let (draft, _, _) = ready(run_export(EXPORT, &export_inputs(), &facts, &[], &[]).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let completed = export_effect("completed", input.clone());
    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    let result = result_event(
        "file.export.completed",
        2,
        json!({
            "effect_id":"operation", "run_id":"run", "status":"completed",
            "value":export_value()
        }),
    );
    let (_, value, work) = ready(
        run_export(
            EXPORT,
            &Bindings::new(),
            &[],
            &[completed],
            &[terminal, result],
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Succeeded);
    assert_eq!(value.unwrap().value, export_value());

    let failure = json!({
        "error_kind":"file_effect_failed", "message":"denied", "summary":"denied",
        "effect_id":"operation", "run_id":"run", "kind":"file.export"
    });
    let (_, value, work) = ready(
        run_export(
            EXPORT,
            &Bindings::new(),
            &[],
            &[export_effect("failed", input)],
            &[
                event(
                    "effect.terminal",
                    1,
                    json!({"effect_id":"operation","run_id":"run","status":"failed"}),
                ),
                result_event(
                    "file.export.failed",
                    2,
                    json!({
                        "effect_id":"operation", "run_id":"run", "status":"failed",
                        "value":failure
                    }),
                ),
            ],
        )
        .unwrap(),
    );
    assert!(value.is_none());
    assert_eq!(work.state, WorkState::Failed(Disposition::Propagate));
    assert_eq!(
        work.causes[&CauseId("operation".into())].cause.payload,
        failure
    );
}

#[test]
fn managed_file_export_refuses_tampered_capture_and_settlement() {
    let facts = [export_fact("high", "a", "alice", 4)];
    assert!(
        run_export("return path", &export_inputs(), &facts, &[], &[])
            .unwrap_err()
            .contains("requires an effect statement")
    );
    assert!(run_export(
        "prompt \"hi\" as answer",
        &export_inputs(),
        &facts,
        &[],
        &[],
    )
    .unwrap_err()
    .contains("requires an export statement"));
    assert!(
        run_export_with(EXPORT, None, &export_inputs(), &facts, &[], &[], |body| {
            body
        },)
        .unwrap_err()
        .contains("pinned root rule")
    );
    assert!(run_export(
        "export jsonl Missing to workspace at path { mode replace } as saved",
        &export_inputs(),
        &facts,
        &[],
        &[],
    )
    .unwrap_err()
    .contains("no declared row schema"));
    assert!(run_export_with(
        EXPORT,
        Some("finish"),
        &export_inputs(),
        &facts,
        &[],
        &[],
        |mut body| {
            if let BodyStmt::Effect(effect) = &mut body {
                let BodyEffectKind::FileExport { format, .. } = &mut effect.kind else {
                    unreachable!()
                };
                *format = "markdown".into();
            }
            body
        },
    )
    .unwrap_err()
    .contains("unsupported format or mode"));

    let mut no_identity = export_fact("", "a", "alice", 4);
    no_identity.source_event_id.clear();
    assert!(
        run_export(EXPORT, &export_inputs(), &[no_identity], &[], &[],)
            .unwrap_err()
            .contains("no durable identity")
    );
    let invalid_row = ProjectionFact {
        value_json: json!({"owner":"alice","priority":"high"}).to_string(),
        ..export_fact("invalid", "a", "alice", 4)
    };
    assert!(run_export(
        "export jsonl Ticket to workspace at path { mode replace } as saved",
        &export_inputs(),
        &[invalid_row],
        &[],
        &[],
    )
    .unwrap_err()
    .contains("member violates `Ticket`"));

    let (draft, _, _) = ready(run_export(EXPORT, &export_inputs(), &facts, &[], &[]).unwrap());
    let original: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let mut wrong_effect = export_effect("queued", original.clone());
    wrong_effect.kind = "file.write".into();
    assert!(
        run_export(EXPORT, &Bindings::new(), &[], &[wrong_effect], &[],)
            .unwrap_err()
            .contains("source operation")
    );
    let mut incomplete = original.clone();
    incomplete["rows_argument"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("queued", incomplete)],
        &[],
    )
    .unwrap_err()
    .contains("incomplete freshness"));
    let mut changed_observation = original.clone();
    changed_observation["rows_argument"]["validity"][0]["head"] = json!("Other");
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("queued", changed_observation)],
        &[],
    )
    .unwrap_err()
    .contains("exact collection observation"));
    let mut non_fact = original.clone();
    non_fact["rows_argument"]["value"] = json!([]);
    non_fact["rows_argument"]["sources"] = json!([{"kind":"operation","operation_id":"render"}]);
    non_fact["rows_argument"]["validity"][0]["members"] = json!([]);
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("queued", non_fact)],
        &[],
    )
    .unwrap_err()
    .contains("non-fact source"));
    let mut membership = original.clone();
    membership["rows_argument"]["sources"] = json!([]);
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("queued", membership)],
        &[],
    )
    .unwrap_err()
    .contains("captured membership"));
    let mut invalid_saved_row = original.clone();
    invalid_saved_row["rows_argument"]["value"][0]["priority"] = json!("high");
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("queued", invalid_saved_row)],
        &[],
    )
    .unwrap_err()
    .contains("rows violate their source schema"));
    let mut changed = original.clone();
    changed["predicate"] = json!("");
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("queued", changed)],
        &[],
    )
    .unwrap_err()
    .contains("source contract"));

    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("mystery", original.clone())],
        &[],
    )
    .unwrap_err()
    .contains("unknown operation status"));
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("completed", original.clone())],
        &[],
    )
    .unwrap_err()
    .contains("exactly one terminal"));
    let wrong_terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"failed"}),
    );
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("completed", original.clone())],
        &[wrong_terminal],
    )
    .unwrap_err()
    .contains("recorded status"));
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("completed", original.clone())],
        std::slice::from_ref(&terminal),
    )
    .unwrap_err()
    .contains("exactly one result"));
    let early = result_event(
        "file.export.completed",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed","value":export_value()}),
    );
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("completed", original.clone())],
        &[terminal.clone(), early],
    )
    .unwrap_err()
    .contains("differs from its terminal"));
    let mut wrong_source = export_value();
    wrong_source["mode"] = json!("append");
    let wrong_source = result_event(
        "file.export.completed",
        2,
        json!({"effect_id":"operation","run_id":"run","status":"completed","value":wrong_source}),
    );
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("completed", original.clone())],
        &[terminal.clone(), wrong_source],
    )
    .unwrap_err()
    .contains("source contract"));
    let mut bad = export_value();
    bad["row_count"] = json!("one");
    let result = result_event(
        "file.export.completed",
        2,
        json!({"effect_id":"operation","run_id":"run","status":"completed","value":bad}),
    );
    assert!(run_export(
        EXPORT,
        &Bindings::new(),
        &[],
        &[export_effect("completed", original)],
        &[terminal, result],
    )
    .unwrap_err()
    .contains("output type"));
}
