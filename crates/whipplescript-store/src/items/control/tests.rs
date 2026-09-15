use super::*;
use crate::tracker_control::conformance::{next, setup};

#[test]
fn tracker_control_native_conformance_and_event_attribution() {
    let mut store = WorkItemStore::open_in_memory().unwrap();
    crate::tracker_control::conformance::run_suite(&mut store);
    let events = store.event_metadata().unwrap();
    let assigned = events
        .iter()
        .find(|event| event.kind == "issue.assigned")
        .unwrap();
    assert_eq!(assigned.actor.as_deref(), Some("alice"));
    assert_eq!(assigned.effect_id.as_deref(), Some("effect:3"));
    let released = events
        .iter()
        .find(|event| event.kind == "claim.released")
        .unwrap();
    assert_eq!(released.actor.as_deref(), Some("operator"));
    assert_eq!(released.effect_id.as_deref(), Some("effect:9"));
    assert_eq!(released.operational["actor"], "alice");
}

#[test]
fn tracker_control_binding_and_deadline_refusals_do_not_write() {
    for (field, value, message) in [
        ("item_id", "missing", "tracker control issue is unavailable"),
        (
            "queue",
            "private",
            "tracker control subject differs from its binding",
        ),
        (
            "subject_id",
            "wrong",
            "tracker control subject differs from its binding",
        ),
        (
            "deadline",
            "2090-01-01T00:00:00Z",
            "tracker control deadline must use canonical UTC time",
        ),
        (
            "deadline",
            "nonsense",
            "tracker control deadline must use canonical UTC time",
        ),
    ] {
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let request = setup(&mut store);
        let mut value_json = serde_json::to_value(&request).unwrap();
        if field == "deadline" {
            value_json["action"]["expires_at"] = value.into();
        } else {
            value_json[field] = value.into();
        }
        let bad = serde_json::from_value(value_json).unwrap();
        let before = store.export_events().unwrap();
        assert!(
            matches!(store.control_issue_once(&bad), Err(StoreError::Conflict(actual)) if actual == message),
            "{field}:{value}"
        );
        assert_eq!(store.export_events().unwrap(), before);
        assert!(store
            .control_receipt(&request.operation_id)
            .unwrap()
            .is_none());
    }
}

#[test]
fn tracker_control_no_op_outcomes_are_durable() {
    let mut store = WorkItemStore::open_in_memory().unwrap();
    let request = setup(&mut store);
    let elapsed = next(
        &request,
        2,
        "alice",
        Action::Claim {
            expires_at: "2000-01-01 00:00:00".into(),
        },
    );
    assert_eq!(
        store.control_issue_once(&elapsed).unwrap().outcome,
        Outcome::DeadlineElapsed
    );
    let absent = next(
        &request,
        3,
        "alice",
        Action::Release {
            expected_holder: None,
        },
    );
    let not_held = store.control_issue_once(&absent).unwrap();
    assert_eq!(not_held.outcome, Outcome::NotHeld);
    store.control_issue_once(&request).unwrap();
    assert_eq!(store.control_issue_once(&absent).unwrap(), not_held);
    assert_eq!(
        store
            .get_item(&request.item_id)
            .unwrap()
            .unwrap()
            .claimed_by
            .as_deref(),
        Some("alice")
    );
    store.finish_item(&request.item_id, None, None).unwrap();
    for (number, action) in [
        (4, request.action.clone()),
        (
            5,
            Action::Assign {
                expected_assignee: Some("alice".into()),
                assignee: Some("bob".into()),
            },
        ),
    ] {
        let closed = next(&request, number, "alice", action);
        assert_eq!(
            store.control_issue_once(&closed).unwrap().outcome,
            Outcome::NotOpen
        );
    }
}

#[test]
fn tracker_control_every_transaction_boundary_rolls_back() {
    for (number, action, table, operation) in [
        (
            1,
            Action::Claim {
                expires_at: "2090-01-01 00:00:00".into(),
            },
            "tracker_events",
            "INSERT",
        ),
        (
            2,
            Action::Claim {
                expires_at: "2090-01-01 00:00:00".into(),
            },
            "tracker_leases",
            "INSERT",
        ),
        (
            3,
            Action::Claim {
                expires_at: "2090-01-01 00:00:00".into(),
            },
            "tracker_control_receipts",
            "INSERT",
        ),
        (
            4,
            Action::Assign {
                expected_assignee: Some("alice".into()),
                assignee: Some("bob".into()),
            },
            "tracker_issues",
            "UPDATE",
        ),
        (
            5,
            Action::Renew {
                expires_at: "2091-01-01 00:00:00".into(),
            },
            "tracker_leases",
            "UPDATE",
        ),
        (
            6,
            Action::Release {
                expected_holder: Some("alice".into()),
            },
            "tracker_leases",
            "UPDATE",
        ),
    ] {
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let base = setup(&mut store);
        if number >= 5 {
            store.control_issue_once(&base).unwrap();
        }
        let request = next(&base, number + 10, "alice", action);
        let before = store.export_events().unwrap();
        let item = store.get_item(&base.item_id).unwrap();
        store.connection.execute_batch(&format!("CREATE TRIGGER fail_control BEFORE {operation} ON {table} BEGIN SELECT RAISE(ABORT, 'control fault'); END;")).unwrap();
        assert!(store.control_issue_once(&request).is_err(), "{table}");
        assert_eq!(store.export_events().unwrap(), before);
        assert_eq!(store.get_item(&base.item_id).unwrap(), item);
        assert!(store
            .control_receipt(&request.operation_id)
            .unwrap()
            .is_none());
        store
            .connection
            .execute_batch("DROP TRIGGER fail_control")
            .unwrap();
        let receipt = store.control_issue_once(&request).unwrap();
        assert!(!receipt.event_ids.is_empty());
        assert_eq!(store.control_issue_once(&request).unwrap(), receipt);
    }
}

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "whip-controls-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("tracker.sqlite")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn generation_four(store: &WorkItemStore) {
    store.connection.execute_batch("DELETE FROM schema_migrations; INSERT INTO schema_migrations VALUES (4, 'work-item'); DROP TABLE tracker_control_receipts;").unwrap();
}

#[test]
fn tracker_control_restart_rebuild_and_competing_writers() {
    let fixture = Fixture::new();
    let mut store = WorkItemStore::open(fixture.path()).unwrap();
    let request = setup(&mut store);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let mut connection = WorkItemStore::open_existing(fixture.path()).unwrap();
            let request = request.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                connection.control_issue_once(&request).unwrap()
            })
        })
        .collect();
    let receipts: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(receipts[0], receipts[1]);
    assert_eq!(
        store
            .event_metadata()
            .unwrap()
            .iter()
            .filter(|event| event.kind == "claim.acquired")
            .count(),
        1
    );
    store.release_item(&request.item_id, None).unwrap();
    let before = store.export_events().unwrap();
    drop(store);
    let mut store = WorkItemStore::open_existing(fixture.path()).unwrap();
    store.rebuild_projection().unwrap();
    assert_eq!(store.control_issue_once(&request).unwrap(), receipts[0]);
    assert_eq!(store.export_events().unwrap(), before);
    assert!(store
        .get_item(&request.item_id)
        .unwrap()
        .unwrap()
        .claimed_by
        .is_none());
    let mut imported = WorkItemStore::open_in_memory().unwrap();
    imported.import_events(&before).unwrap();
    assert!(imported
        .control_receipt(&request.operation_id)
        .unwrap()
        .is_none());
}

#[test]
fn tracker_control_upgrade_preserves_history_and_does_not_invent_receipts() {
    let fixture = Fixture::new();
    let mut store = WorkItemStore::open(fixture.path()).unwrap();
    let request = setup(&mut store);
    store.claim_item(&request.item_id, "legacy", None).unwrap();
    let events = store.export_events().unwrap();
    generation_four(&store);
    drop(store);
    let error = WorkItemStore::open_existing(fixture.path())
        .err()
        .expect("generation four requires an explicit upgrade");
    assert!(matches!(
        error,
        StoreError::UnsupportedVersion { found: 4, .. }
    ));
    let mut upgraded = WorkItemStore::upgrade_existing_controls(fixture.path(), None).unwrap();
    assert_eq!(upgraded.export_events().unwrap(), events);
    assert!(upgraded
        .control_receipt(&request.operation_id)
        .unwrap()
        .is_none());
    assert_eq!(
        upgraded.control_issue_once(&request).unwrap().outcome,
        Outcome::AlreadyClaimed {
            holder: "legacy".into()
        }
    );
    drop(upgraded);
    assert!(WorkItemStore::upgrade_existing_controls(fixture.path(), None).is_ok());
}

#[test]
fn tracker_control_upgrade_refuses_missing_damaged_foreign_and_newer_stores() {
    let fixture = Fixture::new();
    assert!(WorkItemStore::upgrade_existing_controls(fixture.path(), None).is_err());
    assert!(!fixture.path().exists());
    for damage in [
        "DROP TABLE tracker_control_receipts",
        "DELETE FROM schema_migrations; INSERT INTO schema_migrations VALUES (99, 'work-item')",
        "UPDATE schema_migrations SET name = 'foreign'",
        "DELETE FROM schema_migrations; INSERT INTO schema_migrations VALUES (4, 'work-item'); DROP TABLE tracker_control_receipts; CREATE TABLE tracker_control_receipts (wrong TEXT)",
        "DELETE FROM schema_migrations; INSERT INTO schema_migrations VALUES (4, 'work-item'); DROP TABLE tracker_payload_protection",
    ] {
        let fixture = Fixture::new();
        let store = WorkItemStore::open(fixture.path()).unwrap();
        store.connection.execute_batch(damage).unwrap();
        let before: Vec<(String, String)> = store.connection.prepare("SELECT name, sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name").unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap().collect::<Result<_,_>>().unwrap();
        let version: i64 = store.connection.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| row.get(0)).unwrap();
        assert!(WorkItemStore::upgrade_existing_controls(fixture.path(), None).is_err(), "{damage}");
        let after: Vec<(String, String)> = store.connection.prepare("SELECT name, sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name").unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?))).unwrap().collect::<Result<_,_>>().unwrap();
        assert_eq!(before, after, "{damage}");
        assert_eq!(store.connection.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| row.get::<_, i64>(0)).unwrap(), version);
    }
}

#[test]
fn tracker_control_shared_claim_helper_refuses_missing_permanent_identity() {
    let mut store = WorkItemStore::open_in_memory().unwrap();
    let request = setup(&mut store);
    store
        .connection
        .execute(
            "DELETE FROM tracker_aliases WHERE alias = ?1",
            [&request.item_id],
        )
        .unwrap();
    assert!(
        matches!(store.claim_item(&request.item_id, "alice", None), Err(StoreError::Conflict(message)) if message == format!("unknown issue alias {}", request.item_id))
    );
}
