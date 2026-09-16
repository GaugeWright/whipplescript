use super::*;
use serde_json::json;

fn frame() -> Frame {
    Frame {
        version: "v1".into(),
        revision: "0@main".into(),
        rule: "review".into(),
        identity: Some("ticket-1".into()),
        trigger_event: Some("admission-1".into()),
    }
}
fn capture(call: u64) -> CallCapture {
    CallCapture {
        call,
        arguments: vec![Value::Null.into(), json!({"title": "original"}).into()],
        reads: BTreeSet::new(),
        frontier: 1,
    }
}
fn context(frame: &Frame) -> String {
    json!({"identity": frame.identity, "trigger_event_id": frame.trigger_event, "bindings": []})
        .to_string()
}
fn event(frame: &Frame, calls: &[CallCapture], sequence: i64) -> EventView {
    let context = context_with_captures(&context(frame), frame, calls, sequence - 1)
        .expect("valid capture delta");
    EventView { event_id: format!("event-{sequence}"), sequence, event_type: "rule.committed".into(), payload_json: json!({"rule": frame.rule, "context": serde_json::from_str::<Value>(&context).expect("valid context JSON")}).to_string(), source: "test".into(), occurred_at: "test".into() }
}

#[test]
fn action_capture_folds_later_commits_and_exact_replays() {
    let f = frame();
    let first = event(&f, &[capture(1)], 2);
    let second = event(&f, &[capture(2)], 3);
    let mut journal = Journal::default();
    journal.apply(&first).unwrap();
    journal.apply(&second).unwrap();
    journal.apply(&first).unwrap();
    let calls = journal.calls(&f).unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[&1].arguments[0].value, Value::Null);
    assert_eq!(calls[&2], capture(2));
}

#[test]
fn action_capture_distinguishes_every_execution_axis() {
    let original = frame();
    let mut frames = vec![original.clone()];
    for axis in 0..5 {
        let mut changed = original.clone();
        match axis {
            0 => changed.version = "v2".into(),
            1 => changed.revision = "0@fork.r1".into(),
            2 => changed.rule = "other".into(),
            3 => changed.identity = Some("ticket-2".into()),
            _ => changed.trigger_event = Some("readmission".into()),
        }
        frames.push(changed);
    }
    let mut journal = Journal::default();
    for (index, f) in frames.iter().enumerate() {
        let mut c = capture(1);
        c.arguments.push(json!(index).into());
        journal.apply(&event(f, &[c], 2)).unwrap();
    }
    for (index, f) in frames.iter().enumerate() {
        assert_eq!(
            journal.calls(f).unwrap()[&1].arguments[2].value,
            json!(index)
        );
    }
}

#[test]
fn action_capture_refuses_reevaluation_atomically() {
    for change_frontier in [false, true] {
        let f = frame();
        let mut journal = Journal::default();
        journal.apply(&event(&f, &[capture(1)], 2)).unwrap();
        let before = journal.clone();
        let mut changed = capture(1);
        if change_frontier {
            changed.frontier = 2;
        } else {
            changed.arguments[1] = json!("reevaluated").into();
        }
        let error = journal
            .apply(&event(&f, &[capture(0), changed], 3))
            .unwrap_err();
        assert!(error.0.contains("captured differently"));
        assert_eq!(
            journal, before,
            "a failed delta cannot partly insert call 0"
        );
    }
}

#[test]
fn action_capture_provenance_and_read_dependencies_are_immutable_and_required() {
    use crate::source_action::arguments::ValueSource;
    let f = frame();
    let original = capture(1);
    let mut journal = Journal::default();
    journal
        .apply(&event(&f, std::slice::from_ref(&original), 2))
        .unwrap();
    for change_reads in [false, true] {
        let mut changed = original.clone();
        if change_reads {
            changed.reads.insert(9);
        } else {
            changed.arguments[0].sources.insert(ValueSource::Fact {
                fact_id: "fact".into(),
                admission_event: "event".into(),
            });
        }
        assert_ne!(
            capture_identity(std::slice::from_ref(&original)),
            capture_identity(std::slice::from_ref(&changed))
        );
        assert!(journal
            .apply(&event(&f, &[changed], 2))
            .unwrap_err()
            .0
            .contains("captured differently"));
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
        let mut invalid = original.clone();
        invalid.arguments[0].sources.insert(source);
        assert!(Journal::default()
            .check(&f, &[invalid], 1)
            .unwrap_err()
            .0
            .contains("incomplete source identity"));
    }
    for missing in ["reads", "sources", "value"] {
        let mut event = event(&f, std::slice::from_ref(&original), 2);
        let mut payload: Value = serde_json::from_str(&event.payload_json).unwrap();
        let target = if missing == "reads" {
            &mut payload["context"][FIELD]["calls"][0]
        } else {
            &mut payload["context"][FIELD]["calls"][0]["arguments"][0]
        };
        target.as_object_mut().unwrap().remove(missing);
        event.payload_json = payload.to_string();
        assert!(
            Journal::default().apply(&event).is_err(),
            "missing {missing}"
        );
    }
}

#[test]
fn action_capture_old_absence_is_not_a_malformed_present_record() {
    let f = frame();
    let old = event(&f, &[], 2);
    let mut journal = Journal::default();
    journal.apply(&old).unwrap();
    assert!(journal.calls(&f).is_none());
    for raw in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"schema": "future"}),
    ] {
        let mut e = old.clone();
        let mut payload: Value = serde_json::from_str(&e.payload_json).unwrap();
        payload["context"][FIELD] = raw;
        e.payload_json = payload.to_string();
        assert!(journal.apply(&e).unwrap_err().0.contains("malformed"));
    }
    let mut future = event(&f, &[capture(1)], 2);
    let mut payload: Value = serde_json::from_str(&future.payload_json).unwrap();
    payload["context"][FIELD]["schema"] = json!("v99");
    future.payload_json = payload.to_string();
    assert!(journal
        .apply(&future)
        .unwrap_err()
        .0
        .contains("unsupported"));
    assert_eq!(journal, Journal::default());
}

#[test]
fn action_capture_checks_commit_owner_and_required_nullable_fields() {
    for (pointer, replacement, message) in [
        (
            "/context/bindings",
            json!({}),
            "valid pinned trigger context",
        ),
        ("/rule", json!("wrong-rule"), "rule differs"),
        ("/context/identity", Value::Null, "firing differs"),
        (
            "/context/trigger_event_id",
            json!("other"),
            "firing differs",
        ),
        (
            "/context/action_captures/frame/version",
            json!(""),
            "needs a version",
        ),
        (
            "/context/action_captures/frame/revision",
            json!(""),
            "needs a version",
        ),
        (
            "/context/action_captures/frame/rule",
            json!(""),
            "needs a version",
        ),
    ] {
        let mut e = event(&frame(), &[capture(1)], 2);
        let mut payload: Value = serde_json::from_str(&e.payload_json).unwrap();
        *payload.pointer_mut(pointer).unwrap() = replacement;
        e.payload_json = payload.to_string();
        assert!(Journal::default()
            .apply(&e)
            .unwrap_err()
            .0
            .contains(message));
    }
    for field in ["identity", "trigger_event"] {
        let mut f = frame();
        f.identity = None;
        f.trigger_event = None;
        let mut e = event(&f, &[capture(1)], 2);
        let mut payload: Value = serde_json::from_str(&e.payload_json).unwrap();
        payload["context"][FIELD]["frame"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        e.payload_json = payload.to_string();
        assert!(Journal::default()
            .apply(&e)
            .unwrap_err()
            .0
            .contains("malformed"));
    }
}

#[test]
fn action_capture_checks_frontier_duplicate_calls_and_corrupt_json() {
    assert!(Journal::default()
        .check(&frame(), &[capture(1)], 2)
        .unwrap_err()
        .0
        .contains("committing frontier"));
    for frontier in [-1, 2] {
        let mut c = capture(1);
        c.frontier = frontier;
        assert!(context_with_captures(&context(&frame()), &frame(), &[c], 1)
            .unwrap_err()
            .0
            .contains("frontier"));
    }
    assert!(
        context_with_captures(&context(&frame()), &frame(), &[capture(1), capture(1)], 1)
            .unwrap_err()
            .0
            .contains("twice")
    );
    let mut e = event(&frame(), &[capture(1)], 2);
    e.sequence = 1;
    assert!(Journal::default()
        .apply(&e)
        .unwrap_err()
        .0
        .contains("frontier"));
    e.payload_json = "{".into();
    assert!(Journal::default()
        .apply(&e)
        .unwrap_err()
        .0
        .contains("invalid rule commit JSON"));
    e.event_type = "unrelated".into();
    Journal::default().apply(&e).unwrap();
}

#[test]
fn action_capture_encoding_preserves_legacy_bytes_and_refuses_overwrite() {
    let f = frame();
    let original =
        "{ \"identity\": \"ticket-1\", \"trigger_event_id\": \"admission-1\", \"bindings\": [] }";
    assert_eq!(
        context_with_captures(original, &f, &[], 1).unwrap(),
        original
    );
    let encoded = context_with_captures(original, &f, &[capture(1)], 1).unwrap();
    let error = context_with_captures(&encoded, &f, &[capture(2)], 1).unwrap_err();
    assert!(error.0.contains("overwrite"));
    for (input, message) in [
        ("{", "invalid pinned context JSON"),
        ("[]", "object pinned context"),
        ("{}", "firing differs"),
    ] {
        assert!(context_with_captures(input, &f, &[capture(1)], 1)
            .unwrap_err()
            .0
            .contains(message));
    }
}

#[test]
fn action_capture_only_lowerings_have_distinct_stable_commit_contributions() {
    use crate::lowering::OwnedLowering;
    use crate::rule_pass::lowering_idempotency_key as key;
    let empty = OwnedLowering::default();
    let mut first = OwnedLowering {
        action_captures: vec![capture(1), capture(2)],
        ..Default::default()
    };
    assert_ne!(key(&empty), key(&first));
    let original = key(&first);
    first.action_captures.reverse();
    assert_eq!(original, key(&first));
    first.action_captures[0].frontier = 2;
    assert_ne!(original, key(&first));
    first.action_captures[0].frontier = 1;
    first.action_captures[0].arguments[0] = json!([]).into();
    assert_ne!(original, key(&first));
}

#[test]
fn action_fact_subject_call_schema_and_immutable_capture_preserve_authority() {
    use crate::source_action::arguments::{
        FactSubject, ObservationKind, ObservationMember, QueryObservation, ValueSource,
    };
    let f = frame();
    let mut c = capture(1);
    c.arguments[1].sources.insert(ValueSource::Fact {
        fact_id: "ticket".into(),
        admission_event: "admitted".into(),
    });
    c.arguments[1].subjects.insert(
        String::new(),
        FactSubject {
            fact_id: "ticket".into(),
            admission_event: "admitted".into(),
        },
    );
    c.arguments[1].validity.insert(QueryObservation {
        frontier: 1,
        kind: ObservationKind::Fact,
        head: "Ticket".into(),
        guard_json: None,
        members: [ObservationMember::Fact {
            fact_id: "ticket".into(),
            admission_event: "admitted".into(),
        }]
        .into(),
    });
    let current = event(&f, &[c.clone()], 2);
    let payload: Value = serde_json::from_str(&current.payload_json).unwrap();
    assert_eq!(
        payload["context"]["action_captures"]["schema"],
        "whipplescript-action-captures/v3"
    );
    let mut journal = Journal::default();
    journal.apply(&current).unwrap();
    assert_eq!(journal.calls(&f).unwrap()[&1], c);
    let mut stripped = c.clone();
    stripped.arguments[1].subjects.clear();
    assert!(journal
        .apply(&event(&f, &[stripped], 3))
        .unwrap_err()
        .0
        .contains("captured differently"));
    let mut legacy = payload.clone();
    legacy["context"]["action_captures"]["schema"] = json!("whipplescript-action-captures/v1");
    let mut old = current.clone();
    old.payload_json = legacy.to_string();
    assert!(Journal::default()
        .apply(&old)
        .unwrap_err()
        .0
        .contains("subject map"));
    for argument in legacy["context"]["action_captures"]["calls"][0]["arguments"]
        .as_array_mut()
        .unwrap()
    {
        argument.as_object_mut().unwrap().remove("subjects");
        argument.as_object_mut().unwrap().remove("validity");
    }
    old.payload_json = legacy.to_string();
    let mut journal = Journal::default();
    journal.apply(&old).unwrap();
    assert!(journal.calls(&f).unwrap()[&1]
        .arguments
        .iter()
        .all(|a| a.subjects.is_empty()));
    legacy["context"]["action_captures"]["schema"] = json!("whipplescript-action-captures/v2");
    for argument in legacy["context"]["action_captures"]["calls"][0]["arguments"]
        .as_array_mut()
        .unwrap()
    {
        argument["subjects"] = json!({});
    }
    old.payload_json = legacy.to_string();
    Journal::default().apply(&old).unwrap();
    let mut missing_validity = payload.clone();
    missing_validity["context"]["action_captures"]["calls"][0]["arguments"][0]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    let mut missing_event = current.clone();
    missing_event.payload_json = missing_validity.to_string();
    assert!(Journal::default()
        .apply(&missing_event)
        .unwrap_err()
        .0
        .contains("validity set"));
    for (path, value) in [
        (
            "/missing",
            json!({"fact_id":"ticket","admission_event":"admitted"}),
        ),
        ("", json!({"fact_id":"ticket","admission_event":"other"})),
        ("", json!({"fact_id":"","admission_event":"admitted"})),
    ] {
        let mut corrupt = payload.clone();
        corrupt["context"]["action_captures"]["calls"][0]["arguments"][1]["subjects"] =
            json!({path:value});
        old.payload_json = corrupt.to_string();
        assert!(Journal::default().apply(&old).is_err());
    }

    for mutation in 0..4 {
        let mut invalid = c.clone();
        let mut observation = invalid.arguments[1]
            .validity
            .pop_first()
            .expect("query observation");
        match mutation {
            0 => observation.frontier = 2,
            1 => observation.head = "   ".into(),
            2 => {
                observation.kind = ObservationKind::Effect;
            }
            _ => observation.guard_json = Some("{".into()),
        }
        invalid.arguments[1].validity.insert(observation);
        assert!(
            Journal::default().check(&f, &[invalid], 1).is_err(),
            "mutation {mutation}"
        );
    }
}
