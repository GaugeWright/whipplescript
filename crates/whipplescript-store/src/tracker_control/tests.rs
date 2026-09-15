use super::*;
fn request() -> TrackerControl {
    TrackerControl {
        operation_id: "operation".into(),
        instance_id: "instance".into(),
        effect_id: "effect".into(),
        actor: "alice".into(),
        queue: "tasks".into(),
        item_id: "WS-1".into(),
        subject_id: "subject".into(),
        action: TrackerControlAction::Assign {
            expected_assignee: None,
            assignee: Some("bob".into()),
        },
    }
}
#[test]
fn tracker_control_empty_coordinates_and_present_empty_options_refuse() {
    let original = serde_json::to_value(request()).unwrap();
    for field in [
        "operation_id",
        "instance_id",
        "effect_id",
        "actor",
        "queue",
        "item_id",
        "subject_id",
    ] {
        let mut value = original.clone();
        value[field] = " ".into();
        let request: TrackerControl = serde_json::from_value(value).unwrap();
        assert!(
            matches!(request.fingerprint(), Err(StoreError::Conflict(message)) if message == "tracker control coordinates are incomplete"),
            "{field}"
        );
    }
    for action in [
        TrackerControlAction::Claim {
            expires_at: "".into(),
        },
        TrackerControlAction::Renew {
            expires_at: "".into(),
        },
        TrackerControlAction::Release {
            expected_holder: Some("".into()),
        },
        TrackerControlAction::Assign {
            expected_assignee: Some("".into()),
            assignee: None,
        },
        TrackerControlAction::Assign {
            expected_assignee: None,
            assignee: Some("".into()),
        },
    ] {
        assert!(TrackerControl {
            action,
            ..request()
        }
        .fingerprint()
        .is_err());
    }
    assert!(request().fingerprint().is_ok());
}
#[test]
fn tracker_control_receipt_rejects_wrong_request_outcome_and_event_references() {
    let request = request();
    let receipt = TrackerControlReceipt {
        operation_id: request.operation_id.clone(),
        fingerprint: request.fingerprint().unwrap(),
        queue: request.queue.clone(),
        item_id: request.item_id.clone(),
        subject_id: request.subject_id.clone(),
        actor: request.actor.clone(),
        outcome: TrackerControlOutcome::Assigned,
        event_ids: vec!["event".into()],
        recorded_at: "2090-01-01 00:00:00".into(),
    };
    receipt.validate_for(&request).unwrap();
    for (field, value) in [
        ("operation_id", json!("wrong")),
        ("fingerprint", json!("wrong")),
        ("queue", json!("wrong")),
        ("item_id", json!("wrong")),
        ("subject_id", json!("wrong")),
        ("actor", json!("wrong")),
        ("recorded_at", json!("")),
        ("event_ids", json!([])),
        ("event_ids", json!([""])),
        ("event_ids", json!(["event", "event"])),
        ("outcome", json!({"kind":"released"})),
        (
            "outcome",
            json!({"kind":"assignment_changed", "assignee":""}),
        ),
    ] {
        let mut value_json = serde_json::to_value(&receipt).unwrap();
        value_json[field] = value;
        let changed: TrackerControlReceipt = serde_json::from_value(value_json).unwrap();
        assert!(
            matches!(changed.validate_for(&request), Err(StoreError::Conflict(message)) if message == "tracker control receipt differs from its request"),
            "{field}"
        );
    }
    let mut value = serde_json::to_value(&request).unwrap();
    value["action"]["extra"] = true.into();
    assert!(serde_json::from_value::<TrackerControl>(value).is_err());
}
