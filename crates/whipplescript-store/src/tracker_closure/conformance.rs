use super::*;
use crate::items::{ClaimOutcome, WorkItems};

pub fn setup(store: &mut impl WorkItems, actor: &str) -> TrackerClosure {
    let item = store
        .file_item(
            "tutorials",
            "Create a chat",
            "Mark complete after creating a chat",
            &[],
            &json!({}),
            Some("person:author"),
            Some("person:learner"),
        )
        .expect("file closure fixture");
    let subject = store
        .subject_content_id(&item.id)
        .expect("resolve fixture")
        .expect("fixture subject");
    TrackerClosure {
        operation_id: "closing:one".into(),
        instance_id: "action:one".into(),
        effect_id: "effect:one".into(),
        actor: actor.into(),
        queue: item.queue,
        item_id: item.id,
        subject_id: subject,
        summary: Some("Self-reported completion".into()),
        expected_holder: Some("workflow:holder".into()),
    }
}

pub fn run(store: &mut (impl WorkItems + TrackerClosures), actor: &str) {
    let request = setup(store, actor);
    assert_eq!(
        store
            .closing_receipt(&request.operation_id)
            .expect("receipt"),
        None
    );
    assert_eq!(
        store
            .claim_item(&request.item_id, "workflow:holder", None)
            .expect("claim"),
        ClaimOutcome::Claimed
    );
    let receipt = store.close_issue_once(&request).expect("close once");
    receipt.validate_for(&request).expect("exact receipt");
    assert_eq!(receipt.actor, actor);
    let after = store.event_position().expect("closed position");
    assert_eq!(
        store.close_issue_once(&request).expect("redelivery"),
        receipt
    );
    assert_eq!(store.event_position().expect("redelivered position"), after);
    let item = store
        .get_item(&request.item_id)
        .expect("closed item")
        .expect("fixture item");
    assert_eq!(item.status, "closed");
    assert!(item.claimed_by.is_none());
    assert!(store
        .active_claim_subjects("workflow:holder")
        .expect("released claim")
        .is_empty());
    let closings = store
        .closings(&request.queue)
        .expect("ordinary closure observation");
    assert_eq!(closings.len(), 1);
    assert_eq!(closings[0].event_id, receipt.event_id);
    assert_eq!(closings[0].issue, request.item_id);
    assert_eq!(closings[0].closed_at, receipt.closed_at);

    for field in [
        "instance_id",
        "effect_id",
        "actor",
        "queue",
        "item_id",
        "subject_id",
        "summary",
        "expected_holder",
    ] {
        let mut value = serde_json::to_value(&request).expect("request");
        value[field] = "different".into();
        let changed: TrackerClosure = serde_json::from_value(value).expect("changed request");
        let error = store
            .close_issue_once(&changed)
            .expect_err("changed request must refuse");
        assert!(
            matches!(error, StoreError::Conflict(message)
            if message == "tracker closure identity already binds a different request"),
            "{field}"
        );
        assert_eq!(store.event_position().expect("refusal position"), after);
    }
}

pub const REFUSAL_CASES: &[&str] = &["missing", "queue", "subject", "closed", "holder"];

pub fn refuse(store: &mut (impl WorkItems + TrackerClosures), case: &str) {
    let mut request = setup(store, "person:learner");
    let expected = match case {
        "missing" => {
            request.item_id = "WS-absent".into();
            "tracker closure issue is unavailable"
        }
        "queue" => {
            request.queue = "private".into();
            "tracker closure subject differs from its binding"
        }
        "subject" => {
            request.subject_id = "another-permanent-subject".into();
            "tracker closure subject differs from its binding"
        }
        "closed" => {
            store
                .finish_item(&request.item_id, None, None)
                .expect("independent legacy completion");
            "tracker closure issue is not open"
        }
        "holder" => {
            store
                .claim_item(&request.item_id, "workflow:other", None)
                .expect("another holder");
            "tracker closure issue has another live holder"
        }
        _ => panic!("unknown closure refusal case"),
    };
    let before = store.event_position().expect("original history");
    let item = store.get_item(&request.item_id).expect("original item");
    let error = store
        .close_issue_once(&request)
        .expect_err("invalid closing must refuse");
    assert!(
        matches!(error, StoreError::Conflict(message) if message == expected),
        "{case}"
    );
    assert_eq!(
        store.event_position().expect("history after refusal"),
        before
    );
    assert_eq!(
        store
            .get_item(&request.item_id)
            .expect("item after refusal"),
        item
    );
    assert_eq!(
        store
            .closing_receipt(&request.operation_id)
            .expect("absent receipt"),
        None
    );
}
