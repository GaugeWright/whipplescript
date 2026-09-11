//! Reopen a current native store without initializing or repairing authority.
//! Schema ownership stays with each store; this helper checks its exact stamp.

use std::path::Path;

use rusqlite::{Connection, OpenFlags};

use crate::{StoreError, StoreResult, STORE_BUSY_TIMEOUT};

pub(crate) fn open(path: &Path, name: &str, version: i64) -> StoreResult<Connection> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.busy_timeout(STORE_BUSY_TIMEOUT)?;
    validate(&connection, name, version)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    // VACUUM INTO snapshots may use a rollback journal. Restoring the ordinary
    // native WAL posture changes no logical records and creates no schema.
    crate::establish_wal(&connection)?;
    Ok(connection)
}

pub(crate) fn validate(connection: &Connection, name: &str, version: i64) -> StoreResult<()> {
    let (found, owner): (i64, String) = connection.query_row(
        "SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if found != version {
        return Err(StoreError::UnsupportedVersion {
            subject: format!("existing {name} schema"),
            found,
            supported: version,
        });
    }
    if owner != name {
        return Err(StoreError::Conflict(format!(
            "existing {name} store has a different schema owner"
        )));
    }
    let integrity: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(StoreError::fault("existing native store", integrity));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        content::ContentStore, coordination::CoordinationStore, items::WorkItemStore,
        native_stores::NativeStores, SqliteStore,
    };

    const KINDS: [&str; 4] = ["runtime", "coordination", "work-item", "content"];

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let root =
                std::env::temp_dir().join(format!("whip-existing-{}-{id}", std::process::id()));
            std::fs::create_dir(&root).expect("isolated fixture");
            Self(root)
        }
        fn path(&self, name: &str) -> std::path::PathBuf {
            self.0.join(format!("{name}.sqlite"))
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn initialize(kind: &str, path: &Path) {
        match kind {
            "runtime" => SqliteStore::open(path).map(drop),
            "coordination" => CoordinationStore::open(path).map(drop),
            "work-item" => WorkItemStore::open(path).map(drop),
            "content" => ContentStore::open(path).map(drop),
            _ => panic!("unknown fixture store"),
        }
        .expect("initialize actual owner schema");
    }

    fn reopen(kind: &str, path: &Path) -> StoreResult<()> {
        match kind {
            "runtime" => SqliteStore::open_existing(path).map(drop),
            "coordination" => CoordinationStore::open_existing(path).map(drop),
            "work-item" => WorkItemStore::open_existing(path).map(drop),
            "content" => ContentStore::open_existing(path).map(drop),
            _ => panic!("unknown fixture store"),
        }
    }

    #[test]
    fn existing_native_stores_never_create_missing_or_empty_authority() {
        let fixture = Fixture::new();
        for kind in KINDS {
            let path = fixture.path(kind);
            assert!(reopen(kind, &path).is_err());
            assert!(!path.exists());
            let missing_parent = fixture.0.join("absent").join(kind);
            assert!(reopen(kind, &missing_parent).is_err());
            assert!(!fixture.0.join("absent").exists());
            drop(Connection::open(&path).unwrap());
            assert!(reopen(kind, &path).is_err());
            let db = Connection::open(&path).unwrap();
            let count: i64 = db
                .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 0, "{kind} repaired an empty schema");
        }
        assert!(NativeStores::open_existing(
            fixture.path("absent-runtime"),
            fixture.path("absent-coord"),
            fixture.path("absent-items")
        )
        .is_err());
        assert!(!fixture.path("absent-runtime").exists());
    }

    #[test]
    fn existing_native_stores_refuse_wrong_owner_and_version_before_repair() {
        for kind in KINDS {
            for change in ["owner", "older", "newer"] {
                let fixture = Fixture::new();
                let path = fixture.path(kind);
                initialize(kind, &path);
                let db = Connection::open(&path).unwrap();
                let (version, name): (i64, String) = db
                    .query_row(
                        "SELECT version, name FROM schema_migrations ORDER BY version DESC LIMIT 1",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .unwrap();
                db.execute("DELETE FROM schema_migrations", []).unwrap();
                let changed_version = match change {
                    "older" => version - 1,
                    "newer" => version + 1,
                    _ => version,
                };
                let changed_name = if change == "owner" { "foreign" } else { &name };
                db.execute(
                    "INSERT INTO schema_migrations(version,name) VALUES (?1,?2)",
                    rusqlite::params![changed_version, changed_name],
                )
                .unwrap();
                drop(db);
                let error = reopen(kind, &path).expect_err("mismatched store must refuse");
                match change {
                    "owner" => assert!(
                        matches!(error, StoreError::Conflict(ref s) if s.contains("different schema owner")),
                        "{error:?}"
                    ),
                    _ => assert!(
                        matches!(error, StoreError::UnsupportedVersion { found, .. } if found == changed_version),
                        "{error:?}"
                    ),
                }
                let db = Connection::open(&path).unwrap();
                let retained: (i64, String) = db
                    .query_row("SELECT version,name FROM schema_migrations", [], |r| {
                        Ok((r.get(0)?, r.get(1)?))
                    })
                    .unwrap();
                assert_eq!(retained, (changed_version, changed_name.to_owned()));
            }
        }
    }

    #[test]
    fn existing_native_stores_refuse_sqlite_integrity_failures() {
        for kind in KINDS {
            let fixture = Fixture::new();
            let path = fixture.path(kind);
            initialize(kind, &path);
            let db = Connection::open(&path).unwrap();
            db.execute_batch("CREATE TABLE integrity_fixture(value INTEGER CHECK(value > 0)); PRAGMA ignore_check_constraints=ON; INSERT INTO integrity_fixture VALUES(0);").unwrap();
            drop(db);
            let error = reopen(kind, &path).expect_err("invalid stored record");
            assert!(
                format!("{error:?}").contains("CHECK constraint failed"),
                "{error:?}"
            );
        }
    }

    #[test]
    fn existing_native_stores_reopen_snapshots_without_rewriting_records() {
        let fixture = Fixture::new();
        for kind in KINDS {
            let source = fixture.path(kind);
            let snapshot = fixture.path(&format!("snapshot-{kind}"));
            initialize(kind, &source);
            let db = Connection::open(&source).unwrap();
            db.execute_batch("CREATE TABLE retained_fixture(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO retained_fixture VALUES(1,'history');").unwrap();
            db.execute("VACUUM INTO ?1", [snapshot.to_str().unwrap()])
                .unwrap();
            drop(db);
            for _ in 0..2 {
                reopen(kind, &snapshot).unwrap();
            }
            let db = Connection::open(&snapshot).unwrap();
            let records: String = db
                .query_row("SELECT value FROM retained_fixture WHERE id=1", [], |r| {
                    r.get(0)
                })
                .unwrap();
            assert_eq!(records, "history");
            let journal: String = db
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .unwrap();
            assert_eq!(journal, "wal");
        }
        NativeStores::open_existing(
            fixture.path("snapshot-runtime"),
            fixture.path("snapshot-coordination"),
            fixture.path("snapshot-work-item"),
        )
        .unwrap();
    }

    #[test]
    fn existing_native_stores_do_not_reconstruct_dropped_schema() {
        let fixture = Fixture::new();
        let path = fixture.path("runtime");
        initialize("runtime", &path);
        let db = Connection::open(&path).unwrap();
        db.execute_batch("DROP TABLE events").unwrap();
        drop(db);
        let store = SqliteStore::open_existing(&path).unwrap();
        assert!(store.list_events("missing").is_err());
        drop(store);
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='events'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
}
