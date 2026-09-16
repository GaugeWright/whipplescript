use super::*;
use crate::source_action::journal::{context_with_captures, CallCapture};
use serde_json::json;
use whipplescript_parser::{parse_program, Ident, Item, SourceSpan};
use whipplescript_store::{EventView, FactView};

fn frame() -> Frame {
    Frame {
        version: "v1".into(),
        revision: "0".into(),
        rule: "root".into(),
        identity: None,
        trigger_event: Some("started".into()),
    }
}
fn context() -> String {
    r#"{ "identity":null, "trigger_event_id":"started", "bindings":[] }"#.into()
}
fn root() -> RootCapture {
    RootCapture {
        inputs: vec![RootInput {
            binding: 0,
            argument: Argument {
                subjects: [(
                    String::new(),
                    crate::source_action::arguments::FactSubject {
                        fact_id: "fact-original".into(),
                        admission_event: "admission-original".into(),
                    },
                )]
                .into(),
                value: json!({"title":"original"}),
                sources: BTreeSet::from([ValueSource::Fact {
                    fact_id: "fact-original".into(),
                    admission_event: "admission-original".into(),
                }]),
                validity: Default::default(),
            },
        }],
        frontier: 1,
    }
}
fn event(root: Option<&RootCapture>, calls: &[CallCapture], sequence: i64) -> EventView {
    let f = frame();
    let context = context_with_captures(&context(), &f, calls, sequence - 1).unwrap();
    let context = context_with_root(&context, &f, root, sequence - 1).unwrap();
    EventView {
        event_id: format!("event-{sequence}"),
        sequence,
        event_type: "rule.committed".into(),
        payload_json:
            json!({"rule":"root","context":serde_json::from_str::<Value>(&context).unwrap()})
                .to_string(),
        source: "test".into(),
        occurred_at: "test".into(),
    }
}
fn rule_plan() -> ActionPlan {
    let parsed =
        parse_program("workflow W\nclass Ticket { title string }\nrule root when Ticket as ticket => { timer 1s as wait }");
    assert!(parsed.diagnostics.is_empty());
    let rule = parsed
        .program
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .unwrap();
    whipplescript_parser::action_plan::expand_rule_syntax(
        &[],
        &rule,
        &[Ident {
            name: "ticket".into(),
            span: SourceSpan { start: 0, end: 0 },
        }],
    )
    .unwrap()
}
fn fact_context() -> RuleContext {
    RuleContext {
        trigger_event_id: frame().trigger_event,
        identity: None,
        bindings: vec![(
            "ticket".into(),
            FactView {
                fact_id: "fact-original".into(),
                program_version_id: Some("v1".into()),
                revision_epoch: 0,
                name: "Ticket".into(),
                key: "ticket".into(),
                value_json: r#"{"title":"original"}"#.into(),
                provenance_class: "external".into(),
                source_span_json: None,
                validity_json: None,
                source_event_id: "admission-original".into(),
            },
        )],
    }
}

#[test]
fn action_root_captures_all_inputs_and_replay_ignores_current_values() {
    let plan = rule_plan();
    let admitted = admitted_rule_inputs(&plan, &fact_context(), 1).unwrap();
    let (first, fresh) = prepare(&plan, &admitted, None, 1).unwrap();
    assert_eq!(first, admitted);
    assert_eq!(fresh, Some(root()));
    let changed = Bindings::from([(plan.root_inputs[0], Slot::Ready(json!("newer").into()))]);
    for inputs in [&changed, &Bindings::new()] {
        let (replayed, fresh) = prepare(&plan, inputs, Some(&root()), 4).unwrap();
        assert_eq!(replayed, first);
        assert!(fresh.is_none());
    }
    assert!(prepare(&plan, &Bindings::new(), None, 1).is_err());
    assert!(prepare(
        &plan,
        &Bindings::from([(plan.root_inputs[0], Slot::Pending)]),
        None,
        1
    )
    .is_err());
    let mut wrong = root();
    wrong.inputs[0].binding = u64::MAX;
    assert!(prepare(&plan, &admitted, Some(&wrong), 1).is_err());
}

#[test]
fn admitted_root_inherits_the_fact_admission_validity() {
    use crate::source_action::arguments::{ObservationKind, QueryObservation};

    let premise = QueryObservation {
        frontier: 1,
        kind: ObservationKind::Fact,
        head: "Evidence".into(),
        guard_json: None,
        members: Default::default(),
    };
    let mut context = fact_context();
    context.bindings[0].1.validity_json =
        Some(serde_json::to_string(&BTreeSet::from([premise.clone()])).unwrap());
    let admitted = admitted_rule_inputs(&rule_plan(), &context, 1).unwrap();
    let Slot::Ready(argument) = admitted.values().next().unwrap() else {
        panic!("admitted fact is ready")
    };
    assert_eq!(argument.validity, BTreeSet::from([premise]));
    assert!(
        admitted_rule_inputs(&rule_plan(), &context, 0).is_err(),
        "a root cannot inherit an observation beyond its admission frontier"
    );

    context.bindings[0].1.validity_json = Some("{}".into());
    assert!(
        admitted_rule_inputs(&rule_plan(), &context, 1).is_err(),
        "a malformed stored validity set cannot enter an action root"
    );
}

#[test]
fn pinned_rule_context_round_trip_preserves_fact_validity() {
    use crate::source_action::arguments::{ObservationKind, QueryObservation, Validity};

    let premise = QueryObservation {
        frontier: 1,
        kind: ObservationKind::Fact,
        head: "Evidence".into(),
        guard_json: None,
        members: Default::default(),
    };
    let mut context = fact_context();
    context.bindings[0].1.validity_json =
        Some(serde_json::to_string(&BTreeSet::from([premise.clone()])).unwrap());
    let record: Value =
        serde_json::from_str(&crate::rule_lowering::context_record_json(&context)).unwrap();
    let restored = crate::rule_lowering::context_from_record(&record).unwrap();
    let validity: Validity =
        serde_json::from_str(restored.bindings[0].1.validity_json.as_deref().unwrap()).unwrap();
    assert_eq!(validity, BTreeSet::from([premise]));

    let mut malformed = record;
    malformed["bindings"][0]["validity"] = serde_json::json!({});
    assert!(
        crate::rule_lowering::context_from_record(&malformed).is_none(),
        "a pinned context refuses a malformed validity set"
    );
}

#[test]
fn action_root_is_immutable_commit_work_with_legacy_bytes_preserved() {
    let original = root();
    let first = event(Some(&original), &[], 2);
    let call = CallCapture {
        call: 3,
        arguments: vec![original.inputs[0].argument.clone()],
        reads: BTreeSet::from([0]),
        frontier: 2,
    };
    let mut journal = Journal::default();
    journal.apply(&first).unwrap();
    journal
        .apply(&event(None, std::slice::from_ref(&call), 3))
        .unwrap();
    journal.apply(&first).unwrap();
    assert_eq!(journal.root(&frame()), Some(&original));
    assert_eq!(journal.calls(&frame()).unwrap()[&3], call);
    assert!(journal.check_root(&frame(), Some(&original), 9).is_ok());
    assert!(Journal::default()
        .check_root(&frame(), Some(&original), 9)
        .is_err());
    let empty = crate::lowering::OwnedLowering::default();
    let captured = crate::lowering::OwnedLowering {
        action_root: Some(original.clone()),
        ..Default::default()
    };
    assert!(captured.has_commit_work());
    assert_ne!(
        crate::rule_pass::lowering_idempotency_key(&captured),
        crate::rule_pass::lowering_idempotency_key(&empty)
    );
    assert_eq!(
        context_with_root(&context(), &frame(), None, 1).unwrap(),
        context()
    );
    for change in 0..5 {
        let mut changed = original.clone();
        match change {
            0 => changed.frontier = 2,
            1 => changed.inputs[0].argument.value = json!("new"),
            2 => {
                changed.inputs[0].argument.sources.clear();
                changed.inputs[0].argument.subjects.clear();
            }
            3 => changed.inputs[0].binding = 1,
            _ => changed.inputs[0].argument.subjects.clear(),
        }
        assert_ne!(identity(&original), identity(&changed));
        let before = journal.clone();
        assert!(journal.apply(&event(Some(&changed), &[], 3)).is_err());
        assert_eq!(journal, before);
        assert!(journal.check_root(&frame(), Some(&changed), 3).is_err());
    }
    let recorded = context_with_root(&context(), &frame(), Some(&original), 1).unwrap();
    assert!(context_with_root(&recorded, &frame(), Some(&original), 1).is_err());
    assert!(context_with_root("not json", &frame(), Some(&original), 1).is_err());
}

#[test]
fn action_root_rejects_unordered_slots_frontiers_and_incomplete_sources() {
    for frontier in [-1, 2] {
        let mut invalid = root();
        invalid.frontier = frontier;
        assert!(context_with_root(&context(), &frame(), Some(&invalid), 1).is_err());
    }
    for slots in [[0, 0], [1, 0]] {
        let mut invalid = root();
        invalid.inputs = slots
            .into_iter()
            .map(|binding| RootInput {
                binding,
                argument: Value::Null.into(),
            })
            .collect();
        assert!(context_with_root(&context(), &frame(), Some(&invalid), 1).is_err());
    }
    for source in [
        ValueSource::Fact {
            fact_id: "".into(),
            admission_event: "event".into(),
        },
        ValueSource::Fact {
            fact_id: "fact".into(),
            admission_event: "".into(),
        },
        ValueSource::Operation {
            operation_id: "".into(),
        },
    ] {
        let mut invalid = root();
        invalid.inputs[0].argument.sources = BTreeSet::from([source]);
        assert!(context_with_root(&context(), &frame(), Some(&invalid), 1).is_err());
    }
}

#[test]
fn action_root_refuses_malformed_envelopes_without_publishing_partial_deltas() {
    let call = CallCapture {
        call: 3,
        arguments: vec![],
        reads: BTreeSet::new(),
        frontier: 1,
    };
    let valid = event(Some(&root()), &[call], 2);
    for change in 0..9 {
        let mut event = valid.clone();
        let mut payload: Value = serde_json::from_str(&event.payload_json).unwrap();
        match change {
            0 => payload["context"][FIELD]["schema"] = json!("future"),
            1 => payload["context"][FIELD]["root"]["inputs"][0]["argument"]
                .as_object_mut()
                .unwrap()
                .remove("sources")
                .map(|_| ())
                .unwrap(),
            2 => payload["context"][FIELD]["root"]["inputs"][0]["argument"]
                .as_object_mut()
                .unwrap()
                .remove("value")
                .map(|_| ())
                .unwrap(),
            3 => payload["context"][FIELD]["frame"]
                .as_object_mut()
                .unwrap()
                .remove("identity")
                .map(|_| ())
                .unwrap(),
            4 => payload["context"][FIELD] = Value::Null,
            5 => payload["rule"] = json!("different"),
            6 => payload["context"]["action_captures"]["schema"] = json!("future"),
            7 => payload["context"]["action_captures"]["frame"]["version"] = json!("v2"),
            _ => payload["context"][FIELD]["root"]["extra"] = json!(true),
        }
        event.payload_json = payload.to_string();
        let mut journal = Journal::default();
        assert!(journal.apply(&event).is_err(), "mutation {change}");
        assert_eq!(
            journal,
            Journal::default(),
            "neither root nor calls may leak on mutation {change}"
        );
    }
}

#[test]
fn action_root_admission_preserves_real_fact_references_and_refuses_legacy_loss() {
    let plan = rule_plan();
    let context = fact_context();
    let admitted = admitted_rule_inputs(&plan, &context, 1).unwrap();
    assert_eq!(
        admitted[&plan.root_inputs[0]],
        Slot::Ready(root().inputs[0].argument.clone())
    );
    let legacy_json = crate::rule_lowering::context_record_json(&context);
    let restored =
        crate::rule_lowering::context_from_record(&serde_json::from_str(&legacy_json).unwrap())
            .unwrap();
    assert!(admitted_rule_inputs(&plan, &restored, 1).is_err());
    for change in 0..5 {
        let mut context = context.clone();
        match change {
            0 => context.bindings.clear(),
            1 => context.bindings.push(context.bindings[0].clone()),
            2 => context
                .bindings
                .push(("extra".into(), context.bindings[0].1.clone())),
            3 => context.bindings[0].1.value_json = "invalid".into(),
            _ => context.bindings[0].1.fact_id.clear(),
        }
        assert!(
            admitted_rule_inputs(&plan, &context, 1).is_err(),
            "mutation {change}"
        );
    }
    let mut invalid_plan = plan.clone();
    invalid_plan.root_rule = None;
    assert!(admitted_rule_inputs(&invalid_plan, &context, 1).is_err());
    let mut invalid_plan = plan;
    invalid_plan.bindings[0].name = None;
    assert!(admitted_rule_inputs(&invalid_plan, &context, 1).is_err());
}

#[test]
fn action_root_isolated_firings_and_root_only_rule_mismatch() {
    let original = frame();
    let mut frames = vec![original.clone()];
    for axis in 0..5 {
        let mut next = original.clone();
        match axis {
            0 => next.version = "v2".into(),
            1 => next.revision = "fork".into(),
            2 => next.rule = "other".into(),
            3 => next.identity = Some("other-ticket".into()),
            _ => next.trigger_event = Some("readmission".into()),
        }
        frames.push(next);
    }
    let mut journal = Journal::default();
    for (index, frame) in frames.iter().enumerate() {
        let mut captured = root();
        captured.inputs[0].argument.value = json!(index);
        let mut event = event(Some(&captured), &[], 2);
        let mut payload: Value = serde_json::from_str(&event.payload_json).unwrap();
        payload["rule"] = json!(frame.rule);
        payload["context"]["identity"] = json!(frame.identity);
        payload["context"]["trigger_event_id"] = json!(frame.trigger_event);
        payload["context"][FIELD]["frame"] = json!(frame);
        event.payload_json = payload.to_string();
        journal.apply(&event).unwrap();
    }
    for (index, frame) in frames.iter().enumerate() {
        assert_eq!(
            journal.root(frame).unwrap().inputs[0].argument.value,
            json!(index)
        );
    }
    let mut wrong = event(Some(&root()), &[], 2);
    let mut payload: Value = serde_json::from_str(&wrong.payload_json).unwrap();
    payload["rule"] = json!("different");
    wrong.payload_json = payload.to_string();
    assert!(Journal::default().apply(&wrong).is_err());
}

#[test]
fn action_fact_subject_root_schema_is_explicit_and_legacy_replay_cannot_upgrade() {
    let current = event(Some(&root()), &[], 2);
    let mut payload: Value = serde_json::from_str(&current.payload_json).unwrap();
    assert_eq!(
        payload["context"]["action_root"]["schema"],
        "whipplescript-action-root/v3"
    );
    let mut unsupported_payload = payload.clone();
    unsupported_payload["context"]["action_root"]["schema"] = json!("whipplescript-action-root/v4");
    let mut unsupported = current.clone();
    unsupported.payload_json = unsupported_payload.to_string();
    assert!(Journal::default()
        .apply(&unsupported)
        .unwrap_err()
        .0
        .contains("unsupported action root schema"));
    let mut legacy = payload.clone();
    legacy["context"]["action_root"]["schema"] = json!("whipplescript-action-root/v1");
    let mut legacy_event = current.clone();
    legacy_event.payload_json = legacy.to_string();
    assert!(Journal::default()
        .apply(&legacy_event)
        .unwrap_err()
        .0
        .contains("subject map"));
    legacy["context"]["action_root"]["root"]["inputs"][0]["argument"]
        .as_object_mut()
        .unwrap()
        .remove("subjects");
    legacy["context"]["action_root"]["root"]["inputs"][0]["argument"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    legacy_event.payload_json = legacy.to_string();
    let mut journal = Journal::default();
    journal.apply(&legacy_event).unwrap();
    let captured = journal.root(&frame()).unwrap();
    assert!(captured.inputs[0].argument.subjects.is_empty());
    let plan = rule_plan();
    let inputs = admitted_rule_inputs(&plan, &fact_context(), 1).unwrap();
    let (replayed, fresh) = prepare(&plan, &inputs, Some(captured), 4).unwrap();
    let Slot::Ready(value) = &replayed[&plan.root_inputs[0]] else {
        panic!("ready")
    };
    assert!(value.subjects.is_empty());
    assert!(fresh.is_none());
    let mut previous = payload.clone();
    previous["context"]["action_root"]["schema"] = json!("whipplescript-action-root/v2");
    previous["context"]["action_root"]["root"]["inputs"][0]["argument"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    let mut previous_event = current.clone();
    previous_event.payload_json = previous.to_string();
    Journal::default().apply(&previous_event).unwrap();
    payload["context"]["action_root"]["root"]["inputs"][0]["argument"]
        .as_object_mut()
        .unwrap()
        .remove("subjects");
    let mut missing = current.clone();
    missing.payload_json = payload.to_string();
    assert!(Journal::default()
        .apply(&missing)
        .unwrap_err()
        .0
        .contains("subject map"));
    let mut missing_validity = current;
    let mut payload: Value = serde_json::from_str(&missing_validity.payload_json).unwrap();
    payload["context"]["action_root"]["root"]["inputs"][0]["argument"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    missing_validity.payload_json = payload.to_string();
    assert!(Journal::default()
        .apply(&missing_validity)
        .unwrap_err()
        .0
        .contains("validity set"));
}
