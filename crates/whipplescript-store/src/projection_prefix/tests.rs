use super::*;

fn event(sequence: i64, event_type: &str, payload: Value) -> EventView {
    EventView {
        event_id: format!("event-{sequence}"),
        sequence,
        event_type: event_type.into(),
        payload_json: payload.to_string(),
        source: "test".into(),
        occurred_at: format!("time-{sequence}"),
    }
}

fn creation() -> EventView {
    event(
        1,
        "instance.created",
        serde_json::json!({"version_id":"v1","revision_epoch":0}),
    )
}

fn commit(sequence: i64) -> EventView {
    event(
        sequence,
        "rule.committed",
        serde_json::json!({
            "rule":"review",
            "program_version_id":"v1",
            "revision_epoch":0,
            "facts":[{
                "fact_id":"fact-1", "name":"Ticket", "key":"one",
                "value":{"status":"open"}, "provenance_class":"rule",
                "source_span":{"start":1,"end":2}
            }],
            "consumed_facts":[],
            "effects":[{
                "effect_id":"effect-1", "kind":"timer.wait", "target":null,
                "input":{"duration":"1s"}, "status":"queued", "profile":null
            }],
            "dependencies":[]
        }),
    )
}

#[test]
fn exact_prefix_excludes_future_consumption_terminal_and_cancellation() {
    let events = vec![
        creation(),
        commit(2),
        event(
            3,
            "effect.cancellation_requested",
            serde_json::json!({"request_id":"request-1","effect_id":"effect-1"}),
        ),
        event(
            4,
            "rule.committed",
            serde_json::json!({
                "rule":"consume", "facts":[],
                "consumed_facts":[{"fact_id":"fact-1"}],
                "effects":[], "dependencies":[]
            }),
        ),
        event(
            5,
            "effect.terminal",
            serde_json::json!({"effect_id":"effect-1","status":"completed"}),
        ),
    ];
    let early = fold(&events, 2).expect("prefix folds");
    assert_eq!(early.events.len(), 2);
    assert_eq!(early.facts.len(), 1);
    assert_eq!(early.effects[0].status, "queued");
    assert!(!early.effects[0].cancel_requested);

    let requested = fold(&events, 3).expect("prefix folds");
    assert!(requested.effects[0].cancel_requested);

    let terminal = fold(&events, 5).expect("prefix folds");
    assert!(terminal.facts.is_empty());
    assert_eq!(terminal.effects[0].status, "completed");
    assert!(!terminal.effects[0].cancel_requested);
}

#[test]
fn restore_discards_the_abandoned_suffix_but_anchors_the_exact_frontier() {
    let events = vec![
        creation(),
        commit(2),
        event(
            3,
            "rule.committed",
            serde_json::json!({
                "rule":"consume", "facts":[],
                "consumed_facts":[{"fact_id":"fact-1"}],
                "effects":[], "dependencies":[]
            }),
        ),
        event(
            4,
            "effect.terminal",
            serde_json::json!({"effect_id":"effect-1","status":"failed"}),
        ),
        event(
            5,
            "context.restored",
            serde_json::json!({"restored_to_sequence":2}),
        ),
    ];
    let prefix = fold(&events, 5).expect("restored prefix folds");
    assert_eq!(
        prefix
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        [1, 2, 5]
    );
    assert_eq!(prefix.facts.len(), 1);
    assert_eq!(prefix.effects[0].status, "queued");
}

#[test]
fn absent_or_incomplete_frontiers_refuse() {
    let events = vec![creation(), commit(3)];
    assert!(matches!(
        fold(&events, 3),
        Err(StoreError::Conflict(message)) if message.contains("incomplete at event 2")
    ));
    assert!(matches!(
        fold(&[creation()], 2),
        Err(StoreError::Conflict(message))
            if message.contains("no complete prefix ending at event 2")
    ));
    assert!(matches!(
        fold(&[], -1),
        Err(StoreError::Conflict(message)) if message.contains("cannot be negative")
    ));
    assert!(matches!(
        fold(&[event(0, "invalid", Value::Null)], 0),
        Err(StoreError::Conflict(message)) if message.contains("frontier zero")
    ));
}

#[test]
fn repeated_effect_identity_in_a_durable_commit_refuses() {
    let duplicate = event(
        2,
        "rule.committed",
        serde_json::json!({
            "rule":"review", "facts":[], "consumed_facts":[],
            "effects":[
                {"effect_id":"same","kind":"timer.wait","input":{},"status":"queued"},
                {"effect_id":"same","kind":"timer.wait","input":{},"status":"queued"}
            ],
            "dependencies":[]
        }),
    );
    assert!(matches!(
        fold(&[creation(), duplicate], 2),
        Err(StoreError::Conflict(message)) if message.contains("repeated effect identity")
    ));
}

#[cfg(feature = "native")]
#[test]
fn native_store_supplies_the_shared_projection_prefix_contract() {
    super::conformance::run(crate::SqliteStore::open_in_memory().expect("store opens"));
}
