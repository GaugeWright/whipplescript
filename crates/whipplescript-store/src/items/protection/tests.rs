use super::*;
use crate::{payload_protection::PayloadCodec, tracker_filing::TrackerFilings};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

// Reversible fixture only. Real authenticated encryption belongs to the host.
#[derive(Default)]
struct Codec {
    erased: AtomicBool,
}
impl PayloadCodec for Codec {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> StoreResult<Vec<u8>> {
        if self.erased.load(Ordering::SeqCst) {
            return Err(StoreError::fault("fixture", "erased"));
        }
        let bytes: Vec<u8> = plaintext.iter().map(|b| b ^ 93).collect();
        Ok(serde_json::to_vec(&(aad, bytes))?)
    }
    fn open(&self, aad: &[u8], ciphertext: &[u8]) -> StoreResult<Vec<u8>> {
        if self.erased.load(Ordering::SeqCst) {
            return Err(StoreError::fault("fixture", "erased"));
        }
        let (bound, bytes): (Vec<u8>, Vec<u8>) = serde_json::from_slice(ciphertext)?;
        if bound != aad {
            return Err(StoreError::fault("fixture", "coordinate changed"));
        }
        Ok(bytes.iter().map(|b| b ^ 93).collect())
    }
    fn retain(&self, callback: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
        callback()
    }
}
fn protection(codec: Arc<Codec>) -> PayloadProtection {
    PayloadProtection::new("party-project", codec).unwrap()
}
fn store() -> WorkItemStore {
    WorkItemStore::open_in_memory_protected(protection(Arc::new(Codec::default()))).unwrap()
}
fn file(store: &mut WorkItemStore) -> WorkItem {
    store
        .file_item(
            "tasks",
            "private-title-canary",
            "private-body-canary",
            &["private-label-canary".into()],
            &json!({"private": "private-metadata-canary"}),
            Some("human"),
            Some("learner"),
        )
        .unwrap()
}

#[test]
fn protected_governed_tracker_conformance() {
    crate::tracker_filing::conformance::run(&mut store());
    crate::tracker_closure::conformance::run(&mut store(), "human");
}

#[test]
fn protected_reads_replay_and_import_preserve_every_content_plane() {
    let mut store = store();
    let item = file(&mut store);
    store
        .add_comment(&item.id, Some("human"), "private-comment-canary")
        .unwrap();
    store
        .add_evidence(
            &item.id,
            Some("private-kind-canary"),
            Some("private-reference-canary"),
            Some("private-note-canary"),
            Some("human"),
        )
        .unwrap();
    store
        .attest(
            &item.id,
            Some("test"),
            None,
            None,
            Some("human"),
            Some("cut"),
            Some("private-basis-canary"),
            Some("{\"private\":\"private-fingerprint-canary\"}"),
        )
        .unwrap();
    store
        .add_anchor(&item.id, "private-region-canary", "subject", Some("human"))
        .unwrap();
    let assertion = store
        .create_assertion(
            "private-assertion-title-canary",
            "private-assertion-body-canary",
            Some("human"),
        )
        .unwrap();
    store
        .set_field(&item.id, "title", "private-new-title-canary")
        .unwrap();
    store
        .set_field(&item.id, "body", "private-new-body-canary")
        .unwrap();
    store
        .finish_item(&item.id, None, Some("private-summary-canary"))
        .unwrap();
    let expected_item = store.get_item(&item.id).unwrap();
    let expected_comments = store.comments(&item.id).unwrap();
    let expected_evidence = store.evidence(&item.id).unwrap();
    let expected_anchors = store.anchors(&item.id).unwrap();
    let events = store.export_events().unwrap();
    assert_eq!(store.closings("tasks").unwrap().len(), 1);
    assert_eq!(
        expected_item.as_ref().unwrap().body,
        "private-new-body-canary"
    );
    assert_eq!(expected_comments[0].body, "private-comment-canary");
    assert_eq!(expected_anchors[0].region, "private-region-canary");
    assert_eq!(
        store.get_assertion(&assertion.id).unwrap(),
        Some(assertion.clone())
    );
    assert_eq!(store.list_assertions(false).unwrap(), vec![assertion]);
    store.rebuild_projection().unwrap();
    assert_eq!(store.get_item(&item.id).unwrap(), expected_item);
    assert_eq!(store.comments(&item.id).unwrap(), expected_comments);
    assert_eq!(store.evidence(&item.id).unwrap(), expected_evidence);
    assert_eq!(store.anchors(&item.id).unwrap(), expected_anchors);
    assert_eq!(store.export_events().unwrap(), events);
    let mut imported =
        WorkItemStore::open_in_memory_protected(protection(Arc::new(Codec::default()))).unwrap();
    assert_eq!(
        imported.import_events(&events).unwrap().imported,
        events.len()
    );
    assert_eq!(imported.export_events().unwrap(), events);
    assert_eq!(imported.get_item(&item.id).unwrap(), expected_item);
    assert_eq!(imported.evidence(&item.id).unwrap(), expected_evidence);
    assert_eq!(
        imported.import_events(&events).unwrap().skipped,
        events.len()
    );
    // Every SQLite text/blob cell, including immutable events and projections.
    for table in [
        "tracker_issues",
        "tracker_comments",
        "tracker_evidence",
        "tracker_anchors",
        "tracker_assertions",
        "tracker_events",
    ] {
        let mut statement = store
            .connection
            .prepare(&format!("SELECT * FROM {table}"))
            .unwrap();
        let count = statement.column_count();
        let cells = statement
            .query_map([], |row| {
                (0..count)
                    .map(|i| row.get::<_, rusqlite::types::Value>(i))
                    .collect::<Result<Vec<_>, _>>()
            })
            .unwrap();
        for row in cells {
            for value in row.unwrap() {
                let raw = match value {
                    rusqlite::types::Value::Text(s) => s.into_bytes(),
                    rusqlite::types::Value::Blob(b) => b,
                    _ => continue,
                };
                assert!(
                    !raw.windows(b"private-".len())
                        .any(|part| part == b"private-"),
                    "plaintext in {table}"
                );
            }
        }
    }
}

#[test]
fn raw_event_bytes_survive_protection_without_rehashing_json() {
    let mut store = store();
    let raw = "{ \"queue\": \"tasks\", \"title\": \"private-title\", \"body\": \"body\" }\n";
    let at = "2026-09-11 12:00:00";
    let id = event_content_id("issue.created", None, raw, Some("human"), &[], at);
    let event = TrackerEvent {
        event_id: id.clone(),
        parents: vec![],
        issue_id: Some(id),
        kind: "issue.created".into(),
        payload_json: raw.into(),
        actor: Some("human".into()),
        created_at: at.into(),
    };
    assert_eq!(
        store
            .import_events(std::slice::from_ref(&event))
            .unwrap()
            .imported,
        1
    );
    assert_eq!(store.export_events().unwrap(), vec![event]);
}

#[test]
fn erasure_keeps_operational_history_and_refuses_full_content_and_new_receipts() {
    let codec = Arc::new(Codec::default());
    let mut store = WorkItemStore::open_in_memory_protected(protection(codec.clone())).unwrap();
    let filing = crate::tracker_filing::conformance::request();
    let receipt = store.file_issue_once(&filing).unwrap();
    let before = store.event_metadata().unwrap();
    assert_eq!(
        before[0].operational["assigned_to"],
        filing.assigned_to.unwrap()
    );
    codec.erased.store(true, Ordering::SeqCst);
    assert_eq!(store.event_metadata().unwrap(), before);
    assert!(store.export_events().is_err());
    assert!(store.get_item(&receipt.item_id).is_err());
    assert!(store.rebuild_projection().is_err());
    assert_eq!(store.event_metadata().unwrap(), before);
    assert_eq!(
        store.filing_receipt(&receipt.operation_id).unwrap(),
        Some(receipt)
    );
    let mut another = crate::tracker_filing::conformance::request();
    another.operation_id = "another".into();
    assert!(store.file_issue_once(&another).is_err());
    assert_eq!(store.filing_receipt("another").unwrap(), None);
    assert_eq!(store.event_metadata().unwrap(), before);
}

#[test]
fn cell_and_event_transplants_and_summary_tampering_are_refused() {
    let mut store = store();
    let item = file(&mut store);
    store
        .connection
        .execute(
            "UPDATE tracker_issues SET body = title WHERE issue_id = ?1",
            [&item.id],
        )
        .unwrap();
    assert!(store.get_item(&item.id).is_err());
    store.rebuild_projection().unwrap();
    let id = store.export_events().unwrap()[0].event_id.clone();
    let raw: String = store
        .connection
        .query_row(
            "SELECT payload_json FROM tracker_events WHERE event_id = ?1",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    let mut env = envelope(&raw).unwrap();
    env.operational["assigned_to"] = json!("other");
    store
        .connection
        .execute(
            "UPDATE tracker_events SET payload_json = ?1 WHERE event_id = ?2",
            params![serde_json::to_string(&env).unwrap(), id],
        )
        .unwrap();
    assert!(store.export_events().is_err());
    assert!(store.rebuild_projection().is_err());
}

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "whip-tracker-protection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("items.sqlite")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fault<T>(result: StoreResult<T>, detail: &str) {
    let error = result.err().expect("operation must refuse");
    assert!(
        format!("{error:?}").contains(detail),
        "wrong refusal: {error:?}"
    );
}

#[test]
fn file_reopen_readonly_and_sqlite_wal_never_expose_content() {
    let fixture = Fixture::new();
    let codec = Arc::new(Codec::default());
    let mut original =
        WorkItemStore::create_protected(fixture.path(), protection(codec.clone())).unwrap();
    let item = file(&mut original);
    original
        .add_comment(&item.id, Some("human"), "private-comment-canary")
        .unwrap();
    let events = original.export_events().unwrap();
    // Read the database and its live WAL before closing the writing connection.
    for path in [fixture.path(), fixture.path().with_extension("sqlite-wal")] {
        let raw = std::fs::read(path).unwrap();
        assert!(!raw.windows(b"private-".len()).any(|w| w == b"private-"));
    }
    let readonly =
        WorkItemStore::open_read_only_protected(fixture.path(), protection(codec.clone())).unwrap();
    assert_eq!(readonly.export_events().unwrap(), events);
    drop(readonly);
    drop(original);
    let mut reopened =
        WorkItemStore::open_existing_protected(fixture.path(), protection(codec.clone())).unwrap();
    assert_eq!(reopened.get_item(&item.id).unwrap(), Some(item));
    assert_eq!(reopened.export_events().unwrap(), events);
    reopened.rebuild_projection().unwrap();
    assert_eq!(reopened.export_events().unwrap(), events);
    fault(
        WorkItemStore::open(fixture.path()),
        "protected store requires its host codec",
    );
    fault(
        WorkItemStore::open_existing(fixture.path()),
        "host codec domain does not match",
    );
    fault(
        WorkItemStore::open_existing_protected(
            fixture.path(),
            PayloadProtection::new("different", codec).unwrap(),
        ),
        "host codec domain does not match",
    );
    assert!(WorkItemStore::create_protected(
        fixture.path(),
        protection(Arc::new(Codec::default()))
    )
    .is_err());
}

#[test]
fn protection_binding_damage_and_plaintext_conversion_are_not_repaired() {
    for damage in [
        "DROP TABLE tracker_payload_protection",
        "DELETE FROM tracker_payload_protection",
    ] {
        let fixture = Fixture::new();
        let store =
            WorkItemStore::create_protected(fixture.path(), protection(Arc::new(Codec::default())))
                .unwrap();
        store.connection.execute_batch(damage).unwrap();
        drop(store);
        if damage.starts_with("DROP") {
            fault(
                WorkItemStore::open(fixture.path()),
                "missing durable protection binding",
            );
        } else {
            assert!(WorkItemStore::open(fixture.path()).is_err());
        }
        assert!(WorkItemStore::open_existing_protected(
            fixture.path(),
            protection(Arc::new(Codec::default()))
        )
        .is_err());
    }
    let fixture = Fixture::new();
    drop(WorkItemStore::open(fixture.path()).unwrap());
    fault(
        WorkItemStore::open_existing_protected(
            fixture.path(),
            protection(Arc::new(Codec::default())),
        ),
        "host codec domain does not match",
    );
    let connection = Connection::open_in_memory().unwrap();
    connection
        .execute_batch("CREATE TABLE unrelated(x)")
        .unwrap();
    fault(
        WorkItemStore::initialize_protected(connection, protection(Arc::new(Codec::default()))),
        "protected initialization requires an empty new store",
    );
}

#[test]
fn malformed_envelopes_and_authenticated_wrong_summaries_refuse_precisely() {
    let codec = protection(Arc::new(Codec::default()));
    let mut value =
        envelope(&seal_event(&codec, "id", "issue.created", "{\"queue\":\"tasks\"}").unwrap())
            .unwrap();
    value.version = 2;
    fault(
        envelope(&serde_json::to_string(&value).unwrap()),
        "unsupported event envelope version",
    );
    value.version = 1;
    // Simulate a writer that authenticated a false summary: authentication alone
    // must not replace checking the summary against the original payload.
    value.operational = json!({"queue":"wrong"});
    value.sealed = codec
        .seal(
            "tracker.event",
            &event_coordinate("id", "issue.created", &value.operational).unwrap(),
            b"{\"queue\":\"tasks\"}",
        )
        .unwrap();
    fault(
        open_event(
            &codec,
            "id",
            "issue.created",
            &serde_json::to_string(&value).unwrap(),
        ),
        "event operational summary differs from sealed payload",
    );
    let store = store();
    let result: StoreResult<String> = store
        .connection
        .query_row(
            "SELECT whip_payload_open('tracker.issue.body', 'WS-1', ?1)",
            [3.5],
            |r| r.get(0),
        )
        .map_err(Into::into);
    fault(result, "invalid SQL payload representation");
}

#[test]
fn operational_projection_preserves_closure_lineage_and_hides_unknown_content() {
    let value = operational(
        "issue.closed",
        &json!({"summary":"private", "operation":{"id":"operation", "instance_id":"run", "effect_id":"effect", "fingerprint":"hash", "custom":"private"}}),
    );
    assert_eq!(
        value,
        json!({"operation":{"id":"operation", "instance_id":"run", "effect_id":"effect", "fingerprint":"hash"}})
    );
    assert_eq!(
        operational(
            "issue.field_set",
            &json!({"field":"title", "value":"private"})
        ),
        json!({})
    );
    assert_eq!(
        operational(
            "issue.field_set",
            &json!({"field":"status", "value":"private"})
        ),
        json!({})
    );
    assert_eq!(
        operational("unknown", &json!({"actor":"private"})),
        json!({})
    );
    assert_eq!(
        operational("issue.created", &json!({"queue":{"content":"private"}})),
        json!({})
    );
    assert_eq!(
        operational(
            "issue.field_set",
            &json!({"field":"status", "value":"closed"})
        ),
        json!({"field":"status","value":"closed"})
    );
}

#[test]
fn protected_receipt_failure_rolls_back_event_and_projection() {
    use crate::tracker_closure::TrackerClosures;
    let mut store = store();
    let request = crate::tracker_closure::conformance::setup(&mut store, "human");
    let events = store.export_events().unwrap();
    store.connection.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON tracker_closure_receipts BEGIN SELECT RAISE(ABORT, 'fixture'); END;").unwrap();
    assert!(store.close_issue_once(&request).is_err());
    assert_eq!(store.export_events().unwrap(), events);
    assert_eq!(
        store.get_item(&request.item_id).unwrap().unwrap().status,
        "open"
    );
    assert_eq!(store.closing_receipt(&request.operation_id).unwrap(), None);
}

#[test]
fn concurrent_protected_deliveries_share_one_durable_filing_receipt() {
    let fixture = Fixture::new();
    let codec = Arc::new(Codec::default());
    drop(WorkItemStore::create_protected(fixture.path(), protection(codec.clone())).unwrap());
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = fixture.path();
            let codec = codec.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store =
                    WorkItemStore::open_existing_protected(path, protection(codec)).unwrap();
                barrier.wait();
                store
                    .file_issue_once(&crate::tracker_filing::conformance::request())
                    .unwrap()
            })
        })
        .collect();
    let receipts: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(receipts[0], receipts[1]);
    let store = WorkItemStore::open_existing_protected(fixture.path(), protection(codec)).unwrap();
    assert_eq!(store.export_events().unwrap().len(), 1);
    assert_eq!(store.list_items(None, None).unwrap().len(), 1);
    assert_eq!(
        store.filing_receipt(&receipts[0].operation_id).unwrap(),
        Some(receipts[0].clone())
    );
}

#[test]
fn stored_sql_cannot_invoke_host_decryption() {
    let mut store = store();
    file(&mut store);
    for expression in [
        "whip_payload_open('tracker.issue.title', issue_id, title) FROM tracker_issues",
        "whip_tracker_event_open(event_id, kind, payload_json) FROM tracker_events",
    ] {
        store
            .connection
            .execute_batch(&format!("CREATE VIEW injected AS SELECT {expression}"))
            .unwrap();
        let result: StoreResult<()> = store
            .connection
            .prepare("SELECT * FROM injected")
            .map(|_| ())
            .map_err(Into::into);
        fault(result, "unsafe use");
        store
            .connection
            .execute_batch("DROP VIEW injected")
            .unwrap();
    }
    store.connection.execute_batch("CREATE TABLE extracted(value); CREATE TRIGGER injected AFTER INSERT ON tracker_issues BEGIN INSERT INTO extracted SELECT whip_payload_open('tracker.issue.title', NEW.issue_id, NEW.title); END;").unwrap();
    let before = store.export_events().unwrap();
    let request = crate::tracker_filing::conformance::request();
    fault(store.file_issue_once(&request), "unsafe use");
    assert_eq!(store.export_events().unwrap(), before);
    assert_eq!(store.filing_receipt(&request.operation_id).unwrap(), None);
    assert_eq!(
        store
            .connection
            .query_row("SELECT count(*) FROM extracted", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
