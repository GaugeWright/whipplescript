use super::*;
use crate::payload_protection::PayloadCodec;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

#[derive(Default)]
struct Codec {
    erased: AtomicBool,
    deny: AtomicBool,
    retained: RwLock<()>,
}

impl Codec {
    fn available(&self) -> StoreResult<()> {
        if self.erased.load(Ordering::SeqCst) {
            return Err(StoreError::fault("fixture", "key erased"));
        }
        Ok(())
    }
}

// Reversible coordinate-checking fixture only; the embedding supplies AEAD.
impl PayloadCodec for Codec {
    fn seal(&self, aad: &[u8], body: &[u8]) -> StoreResult<Vec<u8>> {
        self.available()?;
        Ok(serde_json::to_vec(&(
            aad,
            body.iter().map(|b| b ^ 93).collect::<Vec<_>>(),
        ))?)
    }
    fn open(&self, aad: &[u8], body: &[u8]) -> StoreResult<Vec<u8>> {
        self.available()?;
        let (coordinate, body): (Vec<u8>, Vec<u8>) = serde_json::from_slice(body)?;
        if coordinate != aad {
            return Err(StoreError::fault("fixture", "coordinate changed"));
        }
        Ok(body.iter().map(|b| b ^ 93).collect())
    }
    fn retain(&self, publish: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
        let _lease = self.retained.read().unwrap();
        self.available()?;
        if self.deny.load(Ordering::SeqCst) {
            return Err(StoreError::fault("fixture", "retention refused"));
        }
        publish()
    }
}

fn protection(codec: Arc<Codec>) -> PayloadProtection {
    PayloadProtection::new("workspace", codec).unwrap()
}

struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "whip-protected-coordination-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("coord.sqlite")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn populate(store: &mut CoordinationStore) {
    for owner in ["a", "b"] {
        for key in ["private-z", "private-a"] {
            assert_eq!(
                store
                    .try_acquire_for_owner(owner, "slot", key, 1, 3600, "holder")
                    .unwrap(),
                AcquireOutcome::Held
            );
            assert_eq!(
                store
                    .consume_for_owner(owner, "budget", key, 2, 10, "day")
                    .unwrap(),
                ConsumeOutcome::Ok { remaining: 8 }
            );
            store
                .append_for_owner(
                    owner,
                    "decisions",
                    key,
                    "{ \"body\": \"private-payload\" }\n",
                    "actor",
                    3600,
                )
                .unwrap();
        }
    }
}

fn no_canaries(store: &CoordinationStore) {
    for table in [
        "leases",
        "counters",
        "ledger_entries",
        "ledger_seq",
        "coord_applied",
    ] {
        let mut stmt = store
            .connection
            .prepare(&format!("SELECT * FROM {table}"))
            .unwrap();
        let columns = stmt.column_count();
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            for column in 0..columns {
                let bytes = match row.get::<_, SqlValue>(column).unwrap() {
                    SqlValue::Text(text) => text.into_bytes(),
                    SqlValue::Blob(bytes) => bytes,
                    _ => continue,
                };
                assert!(
                    !bytes.windows(8).any(|bytes| bytes == b"private-"),
                    "payload leaked in {table}"
                );
            }
        }
    }
}

#[test]
fn protected_coordination_preserves_keys_partitions_ordering_and_retries() {
    for protected in [false, true] {
        let mut store = if protected {
            CoordinationStore::open_in_memory_protected(protection(Arc::new(Codec::default())))
                .unwrap()
        } else {
            CoordinationStore::open_in_memory().unwrap()
        };
        populate(&mut store);
        let leases = store.list_leases(None).unwrap();
        assert_eq!(
            leases
                .iter()
                .map(|row| (row.owner.as_str(), row.key.as_str()))
                .collect::<Vec<_>>(),
            [
                ("a", "private-a"),
                ("a", "private-z"),
                ("b", "private-a"),
                ("b", "private-z")
            ]
        );
        let counters = store.list_counters(None).unwrap();
        assert_eq!(
            counters
                .iter()
                .map(|row| (row.owner.as_str(), row.key.as_str()))
                .collect::<Vec<_>>(),
            [
                ("a", "private-a"),
                ("a", "private-z"),
                ("b", "private-a"),
                ("b", "private-z")
            ]
        );
        let entries = store.list_entries(None, Some("private-a")).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|row| row.partition == "private-a"
            && row.payload_json == "{ \"body\": \"private-payload\" }\n"));
        assert_eq!(
            store
                .list_entries_for_owner(Some("a"), Some("decisions"), Some("private-z"))
                .unwrap()
                .len(),
            1
        );
        assert!(store
            .list_entries(None, Some("missing"))
            .unwrap()
            .is_empty());
        assert_eq!(
            store
                .try_acquire_for_owner("a", "slot", "private-a", 1, 3600, "other")
                .unwrap(),
            AcquireOutcome::Contended {
                holders: vec!["holder".into()]
            }
        );
        assert!(store
            .renew_lease_for_owner("a", "slot", "private-a", 3600, "holder")
            .unwrap()
            .is_some());
        assert!(store
            .release_for_owner("a", "slot", "private-a", "holder")
            .unwrap());
        assert!(!store
            .release_for_owner("a", "slot", "private-a", "holder")
            .unwrap());
        for _ in 0..2 {
            assert_eq!(
                store
                    .consume_for_owner_idempotent(
                        "a",
                        "budget",
                        "private-a",
                        3,
                        10,
                        "day",
                        "charge"
                    )
                    .unwrap(),
                ConsumeOutcome::Ok { remaining: 5 }
            );
            assert_eq!(
                store
                    .append_for_owner_idempotent(
                        "a",
                        "decisions",
                        "private-a",
                        "private-retry",
                        "actor",
                        3600,
                        "append"
                    )
                    .unwrap(),
                3
            );
        }
        assert_eq!(store.list_entries(None, None).unwrap().len(), 5);
        assert_eq!(
            store
                .consume_for_owner("a", "budget", "private-a", 6, 10, "day")
                .unwrap(),
            ConsumeOutcome::Over { remaining: 5 }
        );
        assert_eq!(
            store
                .consume_for_owner("a", "budget", "private-a", 1, 10, "next-day")
                .unwrap(),
            ConsumeOutcome::Ok { remaining: 9 }
        );
        if protected {
            no_canaries(&store);
        }
        assert_eq!(store.release_all_for_holder("holder").unwrap(), 3);
        assert_eq!(
            store
                .try_acquire_for_owner("a", "slot", "private-expired", 1, 3600, "old")
                .unwrap(),
            AcquireOutcome::Held
        );
        store
            .connection
            .execute_batch("UPDATE leases SET expires_at = '2000-01-01 00:00:00'")
            .unwrap();
        assert!(store
            .renew_lease_for_owner("a", "slot", "private-expired", 3600, "old")
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .try_acquire_for_owner("a", "slot", "private-expired", 1, 3600, "new")
                .unwrap(),
            AcquireOutcome::Held
        );
        let remaining = store.list_leases(None).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].key, "private-expired");
        assert_eq!(remaining[0].holder, "new");
        if protected {
            no_canaries(&store);
        }
    }
}

#[test]
fn protected_coordination_reopens_with_exact_values_without_plain_fallback() {
    let fixture = Fixture::new();
    let codec = Arc::new(Codec::default());
    let binding = protection(codec.clone());
    let mut store = CoordinationStore::create_protected(fixture.path(), binding.clone()).unwrap();
    populate(&mut store);
    let leases = store.list_leases(None).unwrap();
    let entries = store.list_entries(None, None).unwrap();
    let counters = store.list_counters(None).unwrap();
    for path in [fixture.path(), fixture.path().with_extension("sqlite-wal")] {
        assert!(!std::fs::read(path)
            .unwrap()
            .windows(8)
            .any(|bytes| bytes == b"private-"));
    }
    assert!(CoordinationStore::open(fixture.path()).is_err());
    assert!(CoordinationStore::open_existing(fixture.path()).is_err());
    assert!(CoordinationStore::create_protected(fixture.path(), binding.clone()).is_err());
    assert!(CoordinationStore::open_existing_protected(
        fixture.path(),
        PayloadProtection::new("foreign", codec.clone()).unwrap()
    )
    .is_err());
    assert!(crate::stamp_satellite_schema(&store.connection, "coordination", 1).is_err());
    drop(store);
    let readonly =
        CoordinationStore::open_read_only_protected(fixture.path(), binding.clone()).unwrap();
    assert_eq!(readonly.list_entries(None, None).unwrap(), entries);
    drop(readonly);
    let mut reopened = CoordinationStore::open_existing_protected(fixture.path(), binding).unwrap();
    assert_eq!(reopened.list_leases(None).unwrap(), leases);
    assert_eq!(reopened.list_entries(None, None).unwrap(), entries);
    assert_eq!(reopened.list_counters(None).unwrap(), counters);
    let positions = reopened.ledger_positions_impl().unwrap();
    codec.erased.store(true, Ordering::SeqCst);
    assert!(reopened.list_leases(None).is_err());
    assert!(reopened.list_entries(None, None).is_err());
    assert!(reopened.list_counters(None).is_err());
    assert!(reopened
        .try_acquire("slot", "private-new", 1, 3600, "new")
        .is_err());
    assert!(reopened
        .append("decisions", "private-new", "private-new", "new", 3600)
        .is_err());
    assert!(reopened
        .consume("budget", "private-new", 1, 10, "day")
        .is_err());
    assert!(reopened.release_all_for_holder("holder").is_err());
    assert_eq!(reopened.ledger_positions_impl().unwrap(), positions);
    no_canaries(&reopened);
}

#[test]
fn protected_coordination_refuses_mode_repair_and_existing_database_adoption() {
    let fixture = Fixture::new();
    let binding = protection(Arc::new(Codec::default()));
    let store = CoordinationStore::create_protected(fixture.path(), binding.clone()).unwrap();
    store
        .connection
        .execute_batch("DROP TABLE ledger_seq")
        .unwrap();
    assert!(CoordinationStore::open(fixture.path()).is_err());
    assert!(!table_exists(&store.connection, "ledger_seq").unwrap());
    store
        .connection
        .execute_batch("DROP TABLE coordination_payload_protection")
        .unwrap();
    assert!(CoordinationStore::open(fixture.path()).is_err());
    assert!(CoordinationStore::open_existing_protected(fixture.path(), binding.clone()).is_err());
    assert!(!table_exists(&store.connection, "coordination_payload_protection").unwrap());
    let existing = Connection::open_in_memory().unwrap();
    existing
        .execute_batch("CREATE TABLE retained (value TEXT)")
        .unwrap();
    assert!(CoordinationStore::initialize_protected(existing, binding.clone()).is_err());
    let plain = CoordinationStore::open_in_memory().unwrap();
    assert!(CoordinationStore::from_existing_connection(plain.connection, Some(binding)).is_err());
}

#[test]
fn protected_coordination_authenticates_coordinates_types_and_key_indexes() {
    let binding = protection(Arc::new(Codec::default()));
    for (table, field) in [
        ("leases", "key_payload"),
        ("counters", "key_payload"),
        ("ledger_entries", "partition_payload"),
        ("ledger_entries", "payload_json"),
    ] {
        let mut store = CoordinationStore::open_in_memory_protected(binding.clone()).unwrap();
        populate(&mut store);
        store.connection.execute_batch(&format!("UPDATE {table} SET {field} = (SELECT {field} FROM {table} ORDER BY rowid DESC LIMIT 1) WHERE rowid = (SELECT min(rowid) FROM {table})")).unwrap();
        match table {
            "leases" => assert!(store.list_leases(None).is_err()),
            "counters" => assert!(store.list_counters(None).is_err()),
            _ => assert!(store.list_entries(None, None).is_err()),
        }
    }
    for (mode, value) in [
        (Some(&binding), SqlValue::Text("plaintext".into())),
        (None, SqlValue::Blob(vec![1])),
    ] {
        let error = open(mode, "test", &[], value).unwrap_err();
        let StoreError::Fault { subject, detail } = error else {
            panic!("expected a protection fault, got {error:?}");
        };
        assert_eq!(subject, "coordination protection");
        assert_eq!(
            detail,
            "payload representation does not match protection mode"
        );
    }
    let invalid = binding.seal("test", "[]", &[255]).unwrap();
    assert!(open(Some(&binding), "test", &[], SqlValue::Blob(invalid)).is_err());
    let index = key_index(Some(&binding), "key", "owner", "resource", "original").unwrap();
    let changed = seal(Some(&binding), "key", &[&index], "different").unwrap();
    assert!(open_key(
        Some(&binding),
        "key",
        "owner",
        "resource",
        &index,
        &[&index],
        changed
    )
    .is_err());
}

#[test]
fn retention_refusal_and_sql_failure_do_not_publish_coordination_state() {
    let codec = Arc::new(Codec::default());
    let mut store = CoordinationStore::open_in_memory_protected(protection(codec.clone())).unwrap();
    populate(&mut store);
    let leases = store.list_leases(None).unwrap();
    let counters = store.list_counters(None).unwrap();
    let entries = store.list_entries(None, None).unwrap();
    let positions = store.ledger_positions_impl().unwrap();
    codec.deny.store(true, Ordering::SeqCst);
    assert!(store
        .try_acquire_for_owner("a", "slot", "private-other", 1, 3600, "holder")
        .is_err());
    assert!(store
        .release_for_owner("a", "slot", "private-a", "holder")
        .is_err());
    assert!(store
        .renew_lease_for_owner("a", "slot", "private-a", 1, "holder")
        .is_err());
    assert!(store.release_all_for_holder("holder").is_err());
    assert!(store
        .append_for_owner_idempotent(
            "a",
            "decisions",
            "private-new",
            "private-new",
            "actor",
            3600,
            "new"
        )
        .is_err());
    assert!(store
        .consume_for_owner_idempotent("a", "budget", "private-a", 1, 10, "day", "new")
        .is_err());
    codec.deny.store(false, Ordering::SeqCst);
    store.connection.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON coord_applied BEGIN SELECT RAISE(ABORT, 'fixture receipt failure'); END").unwrap();
    assert!(store
        .append_for_owner_idempotent(
            "a",
            "decisions",
            "private-new",
            "private-new",
            "actor",
            3600,
            "new"
        )
        .is_err());
    assert!(store
        .consume_for_owner_idempotent("a", "budget", "private-a", 1, 10, "day", "new")
        .is_err());
    assert_eq!(store.list_leases(None).unwrap(), leases);
    assert_eq!(store.list_counters(None).unwrap(), counters);
    assert_eq!(store.list_entries(None, None).unwrap(), entries);
    assert_eq!(store.ledger_positions_impl().unwrap(), positions);
    no_canaries(&store);
}

#[test]
fn corrupt_coordination_retry_outcomes_refuse_without_reapplying() {
    for protected in [false, true] {
        let mut store = if protected {
            CoordinationStore::open_in_memory_protected(protection(Arc::new(Codec::default())))
                .unwrap()
        } else {
            CoordinationStore::open_in_memory().unwrap()
        };
        populate(&mut store);
        let counters = store.list_counters(None).unwrap();
        let entries = store.list_entries(None, None).unwrap();
        let positions = store.ledger_positions_impl().unwrap();
        store.connection.execute_batch("INSERT INTO coord_applied (owner, effect_id, outcome_json) VALUES ('a', 'charge', 'broken'), ('a', 'append', 'broken');").unwrap();
        assert!(matches!(
            store.consume_for_owner_idempotent("a", "budget", "private-a", 3, 10, "day", "charge"),
            Err(StoreError::Conflict(message)) if message == "corrupt coord_applied outcome for effect `charge`: `broken`"
        ));
        assert!(matches!(
            store.append_for_owner_idempotent("a", "decisions", "private-a", "private-new", "actor", 3600, "append"),
            Err(StoreError::Conflict(message)) if message == "corrupt coord_applied outcome for effect `append`: `broken`"
        ));
        assert_eq!(store.list_counters(None).unwrap(), counters);
        assert_eq!(store.list_entries(None, None).unwrap(), entries);
        assert_eq!(store.ledger_positions_impl().unwrap(), positions);
    }
}

#[test]
fn plaintext_coordination_upgrade_retains_original_keys_and_rolls_back_failure() {
    let fixture = Fixture::new();
    let mut store = CoordinationStore::open(fixture.path()).unwrap();
    populate(&mut store);
    let leases = store.list_leases(None).unwrap();
    let counters = store.list_counters(None).unwrap();
    let entries = store.list_entries(None, None).unwrap();
    store.connection.execute_batch("ALTER TABLE leases DROP COLUMN key_payload; ALTER TABLE counters DROP COLUMN key_payload; ALTER TABLE ledger_entries DROP COLUMN partition_payload; DROP TABLE coordination_payload_protection; DELETE FROM schema_migrations WHERE version = 2; INSERT OR IGNORE INTO schema_migrations (version, name) VALUES (1, 'coordination'); CREATE TRIGGER migration_failure BEFORE UPDATE ON leases BEGIN SELECT RAISE(ABORT, 'fixture migration failure'); END;").unwrap();
    assert!(CoordinationStore::open(fixture.path()).is_err());
    assert!(!column_exists(&store.connection, "leases", "key_payload").unwrap());
    assert!(!table_exists(&store.connection, "coordination_payload_protection").unwrap());
    assert_eq!(
        store
            .connection
            .query_row("SELECT max(version) FROM schema_migrations", [], |row| row
                .get::<_, i64>(
                0
            ))
            .unwrap(),
        1
    );
    store
        .connection
        .execute_batch("DROP TRIGGER migration_failure")
        .unwrap();
    drop(store);
    let reopened = CoordinationStore::open(fixture.path()).unwrap();
    assert_eq!(reopened.list_leases(None).unwrap(), leases);
    assert_eq!(reopened.list_counters(None).unwrap(), counters);
    assert_eq!(reopened.list_entries(None, None).unwrap(), entries);
}

#[test]
fn coordination_publication_retains_the_key_until_its_receipt_commits() {
    use std::{sync::mpsc, time::Duration};
    let fixture = Fixture::new();
    let codec = Arc::new(Codec::default());
    let mut store =
        CoordinationStore::create_protected(fixture.path(), protection(codec.clone())).unwrap();
    let (paused_tx, paused_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    store
        .connection
        .create_scalar_function(
            "fixture_pause",
            0,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8,
            move |_| {
                paused_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                Ok(1)
            },
        )
        .unwrap();
    store.connection.execute_batch("CREATE TRIGGER pause_before_commit AFTER INSERT ON coord_applied BEGIN SELECT fixture_pause(); END;").unwrap();
    let worker = std::thread::spawn(move || {
        let result = store.append_for_owner_idempotent(
            "owner",
            "decisions",
            "private-partition",
            "private-body",
            "actor",
            3600,
            "append",
        );
        (store, result)
    });
    paused_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    // The target and its retry receipt have been inserted, but neither is
    // committed yet. Key retention must still cover this exact interval.
    let observer = Connection::open(fixture.path()).unwrap();
    assert_eq!(
        observer
            .query_row("SELECT count(*) FROM coord_applied", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(codec.retained.try_write().is_err());
    let eraser_codec = codec.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (erased_tx, erased_rx) = mpsc::channel();
    let eraser = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let _exclusive = eraser_codec.retained.write().unwrap();
        eraser_codec.erased.store(true, Ordering::SeqCst);
        erased_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(erased_rx.try_recv().unwrap_err(), mpsc::TryRecvError::Empty);
    resume_tx.send(()).unwrap();
    let (store, result) = worker.join().unwrap();
    assert_eq!(result.unwrap(), 1);
    erased_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    eraser.join().unwrap();
    assert_eq!(
        observer
            .query_row(
                "SELECT outcome_json FROM coord_applied WHERE effect_id = 'append'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        "1"
    );
    assert_eq!(
        store.ledger_positions_impl().unwrap(),
        vec![("owner".into(), "decisions".into(), 2)]
    );
    assert!(store.list_entries(None, None).is_err());
    no_canaries(&store);
}
