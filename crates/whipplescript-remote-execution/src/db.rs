//! The endpoint's tables in one SQLite database, so the store and the action
//! cache outlive the process that wrote them: blobs by digest, each
//! principal's uses of them with their labels, the principals as last
//! declared, and every cached result with its origin and classification.
//!
//! A use and a submission belong to a principal by name — the trust
//! document's binding, which a restart keeps — and never to a handle token,
//! which is a credential minted per process and remembered by nothing. A
//! database the endpoint cannot open, or one a newer endpoint wrote, is
//! refused before anything is served from it.

use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::Connection;

use crate::store::Labels;

/// The schema this endpoint reads and writes, as `PRAGMA user_version`.
pub const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS blobs (
    hash TEXT PRIMARY KEY,
    bytes BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS principals (
    name TEXT PRIMARY KEY,
    labels TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS uses (
    principal TEXT NOT NULL,
    hash TEXT NOT NULL REFERENCES blobs(hash),
    labels TEXT NOT NULL,
    PRIMARY KEY (principal, hash)
);
CREATE TABLE IF NOT EXISTS actions (
    hash TEXT PRIMARY KEY,
    result BLOB NOT NULL,
    origin TEXT NOT NULL,
    classification TEXT NOT NULL,
    submitted_by TEXT
);
";

/// One connection, shared by the store and the action cache.
#[derive(Clone)]
pub struct Db {
    connection: Arc<Mutex<Connection>>,
}

impl Db {
    /// A database that lives as long as the process: what a test, and an
    /// endpoint started without a state file, use.
    pub fn in_memory() -> Self {
        Connection::open_in_memory()
            .map_err(Opening::Sqlite)
            .and_then(|connection| Self::prepare(connection, false))
            .unwrap_or_else(|error| panic!("an in-memory database opens: {error:?}"))
    }

    /// The database at `path`, created with the schema when absent.
    pub fn open(path: &Path) -> Result<Self, String> {
        match Connection::open(path)
            .map_err(Opening::Sqlite)
            .and_then(|connection| Self::prepare(connection, true))
        {
            Ok(db) => Ok(db),
            Err(Opening::Newer(version)) => Err(format!(
                "{} was written by a newer endpoint (schema {version}); this one reads schema {SCHEMA_VERSION}",
                path.display()
            )),
            Err(Opening::Sqlite(error)) => Err(format!(
                "cannot open the endpoint's state {}: {error}",
                path.display()
            )),
        }
    }

    fn prepare(connection: Connection, on_disk: bool) -> Result<Self, Opening> {
        if on_disk {
            connection
                .execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")
                .map_err(Opening::Sqlite)?;
        }
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(Opening::Sqlite)?;
        if version > SCHEMA_VERSION {
            return Err(Opening::Newer(version));
        }
        connection
            .execute_batch(SCHEMA)
            .and_then(|()| {
                connection.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
            })
            .map_err(Opening::Sqlite)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Make every later write fail, as a full disk or a revoked file would.
    #[cfg(test)]
    pub(crate) fn refuse_writes(&self) {
        self.lock()
            .execute_batch("PRAGMA query_only = ON")
            .expect("the fixture's own step");
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Connection> {
        self.connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Debug)]
enum Opening {
    Sqlite(rusqlite::Error),
    Newer(i64),
}

pub(crate) fn labels_to_text(labels: &Labels) -> String {
    serde_json::to_string(labels).unwrap_or_else(|_| "[]".into())
}

/// A stored label set. Text that does not decode is read as the one label
/// no principal holds, so a damaged row reads as nothing rather than as
/// unlabeled.
pub(crate) fn labels_from_text(text: &str) -> Labels {
    serde_json::from_str(text)
        .unwrap_or_else(|_| [UNREADABLE_LABELS.to_owned()].into_iter().collect())
}

/// The label a damaged label set reads as.
pub const UNREADABLE_LABELS: &str = "whipplescript.unreadable-labels";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_a_newer_endpoint_wrote_is_refused_and_damaged_labels_read_as_nothing() {
        let dir = tempfile::tempdir().expect("scratch");
        let path = dir.path().join("endpoint.sqlite");
        drop(Db::open(&path).expect("created"));
        Db::open(&path).expect("reopened at the same schema");
        Connection::open(&path)
            .and_then(|c| c.execute_batch("PRAGMA user_version = 99"))
            .expect("the fixture's own step");
        assert_eq!(
            Db::open(&path).err(),
            Some(format!(
                "{} was written by a newer endpoint (schema 99); this one reads schema 1",
                path.display()
            ))
        );
        let not_a_database = dir.path().join("notes.txt");
        std::fs::write(&not_a_database, vec![b'x'; 4096]).expect("the fixture's own step");
        assert_eq!(
            Db::open(&not_a_database).err(),
            Some(format!(
                "cannot open the endpoint's state {}: file is not a database",
                not_a_database.display()
            ))
        );
        assert_eq!(
            labels_from_text("not json"),
            [UNREADABLE_LABELS.to_owned()].into_iter().collect()
        );
        let labels: Labels = ["a".to_owned(), "b".to_owned()].into_iter().collect();
        assert_eq!(labels_from_text(&labels_to_text(&labels)), labels);
    }
}
