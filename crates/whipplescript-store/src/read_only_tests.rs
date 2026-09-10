//! Native observation must not silently initialize, repair, or mutate a store.
use super::*;
use std::{
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "whip-runtime-read-only-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir(&path).expect("isolated fixture");
        Self(path)
    }

    fn database(&self) -> PathBuf {
        self.0.join("runtime.sqlite")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove closed fixture");
    }
}

fn seed(store: &mut SqliteStore) -> String {
    let version = store
        .create_program_version(NewProgramVersion {
            program_name: "ReadOnlyObservation",
            source_hash: "source",
            ir_hash: "ir",
            compiler_version: "test",
            ir_snapshot: None,
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: r#"{"workflow":"ReadOnlyObservation","workflow_contracts":[],"schemas":[]}"#,
            generated_artifacts_json: "[]",
            artifact_root: None,
        })
        .expect("program");
    store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("instance")
        .instance_id
}

fn event<'a>(instance: &'a str, payload: &'a str) -> NewEvent<'a> {
    NewEvent {
        instance_id: instance,
        event_type: "observation.fixture",
        payload_json: payload,
        source: "test",
        causation_id: None,
        correlation_id: None,
        idempotency_key: None,
    }
}

fn database_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("database bytes")
}

#[test]
fn missing_runtime_observation_creates_neither_database_nor_directory() {
    let fixture = Fixture::new();
    let path = fixture.database();
    assert!(SqliteStore::open_read_only(&path).is_err());
    assert!(!path.exists());
    let absent_parent = fixture.0.join("missing");
    assert!(SqliteStore::open_read_only(absent_parent.join("runtime.sqlite")).is_err());
    assert!(!absent_parent.exists());
}

#[test]
fn observation_does_not_initialize_incompatible_schema_or_change_journal_mode() {
    let fixture = Fixture::new();
    let path = fixture.database();
    let connection = Connection::open(&path).expect("unrelated database");
    connection
        .execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE unrelated (value TEXT);")
        .expect("fixture schema");
    drop(connection);
    let before = database_bytes(&path);
    {
        let reader = SqliteStore::open_read_only(&path).expect("existing database opens");
        assert!(reader.schema_version().is_err());
        assert!(reader.list_instances().is_err());
        let mode: String = reader
            .connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");
        assert_eq!(mode, "delete");
    }
    assert_eq!(database_bytes(&path), before);
    assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
}

#[test]
fn runtime_observation_reads_later_wal_commits_and_refuses_database_writes() {
    let fixture = Fixture::new();
    let mut writer = SqliteStore::open(fixture.database()).expect("writer");
    let instance = seed(&mut writer);
    let reader = SqliteStore::open_read_only(fixture.database()).expect("reader");
    assert_eq!(
        reader.schema_version().unwrap(),
        writer.schema_version().unwrap()
    );
    assert_eq!(reader.list_instances().unwrap()[0].instance_id, instance);
    for value in [r#"{"revision":1}"#, r#"{"revision":2}"#] {
        let committed = writer
            .append_event(event(&instance, value))
            .expect("writer commit");
        let observed = reader.list_events(&instance).expect("live observation");
        let last = observed.last().expect("committed event is visible");
        assert_eq!(last.event_id, committed.event_id);
        assert_eq!(last.sequence, committed.sequence);
        assert_eq!(last.payload_json, value);
        assert!(reader.append_event(event(&instance, "{}")).is_err());
        assert_eq!(reader.list_events(&instance).unwrap(), observed);
        assert_eq!(writer.list_events(&instance).unwrap(), observed);
    }
    drop(reader);
    drop(writer);
}

#[cfg(unix)]
#[test]
fn runtime_observation_preserves_existing_file_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let path = fixture.database();
    {
        let mut writer = SqliteStore::open(&path).expect("writer");
        seed(&mut writer);
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
    let before = database_bytes(&path);
    {
        let reader = SqliteStore::open_read_only(&path).expect("reader");
        assert_eq!(reader.list_instances().unwrap().len(), 1);
    }
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(database_bytes(&path), before);
}
