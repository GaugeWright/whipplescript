//! Workers connect to the initialized runtime without taking a migration lock.
#![cfg(feature = "native")]
use whipplescript_store::{NewInstance, SqliteStore, StoreError, SUPPORTED_SCHEMA_VERSION};
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "whip-runtime-reopen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("fixture clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("fixture directory");
        Self(root)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("runtime.sqlite")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn initialized_connection_opens_under_a_writer_lock_and_keeps_write_constraints() {
    let fixture = Fixture::new();
    drop(SqliteStore::open(fixture.path()).expect("coordinator initializes"));
    let mut writer = rusqlite::Connection::open(fixture.path()).expect("writer");
    let tx = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .expect("hold writer lock");
    // Any migrating opener times out here: this transaction stays held until
    // the new connection has returned. No sleeps or timing thresholds needed.
    let worker =
        SqliteStore::open_initialized(fixture.path()).expect("worker connects without migration");
    assert!(worker
        .list_instances()
        .expect("read while writer holds lock")
        .is_empty());
    tx.commit().expect("release writer");
    assert!(!worker
        .put_content("worker write")
        .expect("normal writes remain available")
        .is_empty());
    let error = worker
        .create_instance(NewInstance {
            program_id: "missing",
            version_id: "missing",
            input_json: "{}",
        })
        .expect_err("foreign keys remain enforced");
    assert!(
        matches!(error, StoreError::Sqlite(rusqlite::Error::SqliteFailure(code, _))
        if code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY)
    );
}
#[test]
fn initialized_connection_never_creates_or_upgrades_a_store() {
    let fixture = Fixture::new();
    assert!(SqliteStore::open_initialized(fixture.path()).is_err());
    assert!(!fixture.path().exists());
    let empty = rusqlite::Connection::open(fixture.path()).expect("empty store");
    assert!(SqliteStore::open_initialized(fixture.path()).is_err());
    let count: i64 = empty
        .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
        .expect("schema");
    assert_eq!(count, 0);
    drop(empty);
    drop(SqliteStore::open(fixture.path()).expect("initialize"));
    let connection = rusqlite::Connection::open(fixture.path()).expect("fixture");
    for version in [SUPPORTED_SCHEMA_VERSION - 1, SUPPORTED_SCHEMA_VERSION + 1] {
        connection
            .execute("DELETE FROM schema_migrations", [])
            .expect("fixture");
        connection
            .execute(
                "INSERT INTO schema_migrations(version,name) VALUES (?1,'fixture')",
                [version],
            )
            .expect("fixture");
        let result = SqliteStore::open_initialized(fixture.path());
        assert!(
            matches!(result, Err(StoreError::UnsupportedVersion { found, supported, .. })
            if found == version && supported == SUPPORTED_SCHEMA_VERSION)
        );
        let count: i64 = connection
            .query_row("SELECT count(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("schema");
        assert_eq!(count, 1, "no repair on refusal");
    }
}
#[test]
fn initialized_connection_refuses_to_change_an_unprepared_journal() {
    let fixture = Fixture::new();
    drop(SqliteStore::open(fixture.path()).expect("initialize"));
    let connection = rusqlite::Connection::open(fixture.path()).expect("fixture");
    connection
        .pragma_update(None, "journal_mode", "DELETE")
        .expect("unprepared journal");
    assert!(
        matches!(SqliteStore::open_initialized(fixture.path()), Err(StoreError::Fault { subject, detail })
        if subject == "initialized runtime journal" && detail == "coordinator has not established WAL")
    );
    let mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal");
    assert_eq!(mode, "delete");
}
