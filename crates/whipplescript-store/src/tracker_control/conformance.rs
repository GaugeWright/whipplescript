//! Shared native/hosted contract. These fixtures confer no runtime authority.
use super::*;
use crate::items::WorkItems;

pub fn setup(store: &mut impl WorkItems) -> TrackerControl {
    let item = store
        .file_item(
            "tasks",
            "Create a chat",
            "Self-reported tutorial step",
            &[],
            &json!({}),
            Some("author"),
            Some("alice"),
        )
        .expect("tracker control conformance fixture");
    TrackerControl {
        operation_id: "control:1".into(),
        instance_id: "action:1".into(),
        effect_id: "effect:1".into(),
        actor: "alice".into(),
        queue: item.queue,
        subject_id: store
            .subject_content_id(&item.id)
            .expect("tracker control conformance fixture")
            .expect("tracker control conformance fixture"),
        item_id: item.id,
        action: TrackerControlAction::Claim {
            expires_at: "2090-01-01 00:00:00".into(),
        },
    }
}

pub fn next(
    request: &TrackerControl,
    number: usize,
    actor: &str,
    action: TrackerControlAction,
) -> TrackerControl {
    TrackerControl {
        operation_id: format!("control:{number}"),
        instance_id: format!("action:{number}"),
        effect_id: format!("effect:{number}"),
        actor: actor.into(),
        action,
        ..request.clone()
    }
}

pub fn run_suite(store: &mut (impl WorkItems + TrackerControls)) {
    use TrackerControlAction as A;
    use TrackerControlOutcome as O;
    let claim = setup(store);
    let first = store
        .control_issue_once(&claim)
        .expect("tracker control conformance fixture");
    assert_eq!(
        first.outcome,
        O::Claimed {
            expires_at: "2090-01-01 00:00:00".into()
        }
    );
    let other = next(&claim, 2, "bob", claim.action.clone());
    let refused = store
        .control_issue_once(&other)
        .expect("tracker control conformance fixture");
    assert_eq!(
        refused.outcome,
        O::AlreadyClaimed {
            holder: "alice".into()
        }
    );
    let assign = next(
        &claim,
        3,
        "alice",
        A::Assign {
            expected_assignee: Some("alice".into()),
            assignee: Some("bob".into()),
        },
    );
    let assigned = store
        .control_issue_once(&assign)
        .expect("tracker control conformance fixture");
    assert_eq!(assigned.outcome, O::Assigned);
    let item = store
        .get_item(&claim.item_id)
        .expect("tracker control conformance fixture")
        .expect("tracker control conformance fixture");
    assert_eq!(item.assigned_to.as_deref(), Some("bob"));
    assert_eq!(item.claimed_by.as_deref(), Some("alice"));
    let stale = next(&assign, 4, "alice", assign.action.clone());
    let stale_receipt = store
        .control_issue_once(&stale)
        .expect("tracker control conformance fixture");
    assert_eq!(
        stale_receipt.outcome,
        O::AssignmentChanged {
            assignee: Some("bob".into())
        }
    );
    let renew = next(
        &claim,
        5,
        "alice",
        A::Renew {
            expires_at: "2091-01-01 00:00:00".into(),
        },
    );
    assert!(matches!(
        store
            .control_issue_once(&renew)
            .expect("tracker control conformance fixture")
            .outcome,
        O::Renewed { .. }
    ));
    let backward = next(
        &claim,
        6,
        "alice",
        A::Renew {
            expires_at: "2090-01-01 00:00:00".into(),
        },
    );
    assert_eq!(
        store
            .control_issue_once(&backward)
            .expect("tracker control conformance fixture")
            .outcome,
        O::NotMonotonic
    );
    let wrong_renew = next(&renew, 7, "bob", renew.action.clone());
    assert_eq!(
        store
            .control_issue_once(&wrong_renew)
            .expect("tracker control conformance fixture")
            .outcome,
        O::NotHeld
    );
    let wrong_release = next(
        &claim,
        8,
        "bob",
        A::Release {
            expected_holder: Some("bob".into()),
        },
    );
    assert_eq!(
        store
            .control_issue_once(&wrong_release)
            .expect("tracker control conformance fixture")
            .outcome,
        O::HeldByOther {
            holder: "alice".into()
        }
    );
    let release = next(
        &claim,
        9,
        "operator",
        A::Release {
            expected_holder: Some("alice".into()),
        },
    );
    let released = store
        .control_issue_once(&release)
        .expect("tracker control conformance fixture");
    assert_eq!(released.outcome, O::Released);
    let clear = next(
        &claim,
        10,
        "bob",
        A::Assign {
            expected_assignee: Some("bob".into()),
            assignee: None,
        },
    );
    assert_eq!(
        store
            .control_issue_once(&clear)
            .expect("tracker control conformance fixture")
            .outcome,
        O::Assigned
    );
    let before = store
        .event_position()
        .expect("tracker control conformance fixture");
    // Replaying successful and unsuccessful operations must never reevaluate
    // against today's assignment or reacquire a released claim.
    for (request, receipt) in [
        (&claim, &first),
        (&other, &refused),
        (&assign, &assigned),
        (&stale, &stale_receipt),
        (&release, &released),
    ] {
        assert_eq!(
            &store
                .control_issue_once(request)
                .expect("tracker control conformance fixture"),
            receipt
        );
        assert_eq!(
            store
                .control_receipt(&request.operation_id)
                .expect("tracker control conformance fixture")
                .as_ref(),
            Some(receipt)
        );
    }
    assert_eq!(
        store
            .event_position()
            .expect("tracker control conformance fixture"),
        before
    );
    let item = store
        .get_item(&claim.item_id)
        .expect("tracker control conformance fixture")
        .expect("tracker control conformance fixture");
    assert!(item.claimed_by.is_none());
    assert!(item.assigned_to.is_none());
    for field in [
        "instance_id",
        "effect_id",
        "actor",
        "queue",
        "item_id",
        "subject_id",
    ] {
        let mut value = serde_json::to_value(&claim).expect("tracker control conformance fixture");
        value[field] = "different".into();
        let changed = serde_json::from_value(value).expect("tracker control conformance fixture");
        assert!(
            matches!(store.control_issue_once(&changed), Err(StoreError::Conflict(message)) if message == "tracker control receipt differs from its request"),
            "{field}"
        );
    }
    assert_eq!(
        store
            .event_position()
            .expect("tracker control conformance fixture"),
        before
    );
}

pub const REFUSAL_CASES: &[&str] = &["missing", "queue", "subject", "deadline"];
pub fn refuse(store: &mut (impl WorkItems + TrackerControls), case: &str) {
    let mut request = setup(store);
    let message = match case {
        "missing" => {
            request.item_id = "missing".into();
            "tracker control issue is unavailable"
        }
        "queue" => {
            request.queue = "private".into();
            "tracker control subject differs from its binding"
        }
        "subject" => {
            request.subject_id = "wrong".into();
            "tracker control subject differs from its binding"
        }
        "deadline" => {
            request.action = TrackerControlAction::Claim {
                expires_at: "not-a-time".into(),
            };
            "tracker control deadline must use canonical UTC time"
        }
        _ => panic!("unknown control refusal"),
    };
    let before = store
        .event_position()
        .expect("tracker control conformance fixture");
    let item = store
        .get_item(&request.item_id)
        .expect("tracker control conformance fixture");
    assert!(
        matches!(store.control_issue_once(&request), Err(StoreError::Conflict(actual)) if actual == message),
        "{case}"
    );
    assert_eq!(
        store
            .event_position()
            .expect("tracker control conformance fixture"),
        before
    );
    assert_eq!(
        store
            .get_item(&request.item_id)
            .expect("tracker control conformance fixture"),
        item
    );
    assert!(store
        .control_receipt(&request.operation_id)
        .expect("tracker control conformance fixture")
        .is_none());
}
