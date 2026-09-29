//! The native reviewed-contribution record under DR-0141. This first slice
//! persists stable identity and predecessor declarations. Candidate revisions,
//! Git pins, authenticated transport and admission follow behind this record.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::StoreError;

const SCHEMA_VERSION: i64 = 1;

#[derive(Debug)]
pub enum ReviewError {
    Invalid(String),
    Missing(String),
    Conflict(String),
    Corrupt(String),
    Git(String),
    Sqlite(rusqlite::Error),
    Store(StoreError),
    Io(std::io::Error),
}

impl From<rusqlite::Error> for ReviewError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

impl From<StoreError> for ReviewError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<std::io::Error> for ReviewError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub type ReviewResult<T> = Result<T, ReviewError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contribution {
    pub id: String,
    pub author: String,
    pub intent: String,
    pub target_ref: String,
    pub predecessors: Vec<String>,
}

pub struct ReviewStore {
    connection: Connection,
}

impl ReviewStore {
    pub fn open(path: impl AsRef<Path>) -> ReviewResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let connection = Connection::open(path)?;
        crate::establish_wal(&connection)?;
        crate::stamp_satellite_schema(&connection, "source-review", SCHEMA_VERSION)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS contributions (
                id TEXT PRIMARY KEY,
                author TEXT NOT NULL,
                intent TEXT NOT NULL,
                target_ref TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (unixepoch())
            );
            CREATE TABLE IF NOT EXISTS predecessors (
                contribution_id TEXT NOT NULL REFERENCES contributions(id),
                predecessor_id TEXT NOT NULL REFERENCES contributions(id),
                PRIMARY KEY (contribution_id, predecessor_id)
            );",
        )?;
        Ok(Self { connection })
    }

    /// Author is the identity supplied by a trusted caller. This store does
    /// not authenticate a network request or infer authority from Git authors.
    pub fn create_contribution(
        &mut self,
        id: &str,
        author: &str,
        intent: &str,
        target_ref: &str,
        predecessors: &[&str],
    ) -> ReviewResult<Contribution> {
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            return Err(ReviewError::Invalid(
                "id must be an opaque 1-64 character ASCII token".into(),
            ));
        }
        if author.trim().is_empty() || intent.trim().is_empty() {
            return Err(ReviewError::Invalid(
                "author and intent are required".into(),
            ));
        }
        if !target_ref.starts_with("refs/heads/") || target_ref == "refs/heads/" {
            return Err(ReviewError::Invalid(
                "target must name a full branch ref".into(),
            ));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO contributions (id, author, intent, target_ref)
             VALUES (?1, ?2, ?3, ?4)",
            params![id, author, intent, target_ref],
        )?;
        for predecessor in predecessors {
            if *predecessor == id {
                return Err(ReviewError::Invalid(
                    "a contribution cannot precede itself".into(),
                ));
            }
            tx.execute(
                "INSERT INTO predecessors (contribution_id, predecessor_id) VALUES (?1, ?2)",
                params![id, predecessor],
            )?;
        }
        tx.commit()?;
        self.contribution(id)
    }

    pub fn contribution(&self, id: &str) -> ReviewResult<Contribution> {
        let value = self
            .connection
            .query_row(
                "SELECT id, author, intent, target_ref FROM contributions WHERE id=?1",
                [id],
                |row| {
                    Ok(Contribution {
                        id: row.get(0)?,
                        author: row.get(1)?,
                        intent: row.get(2)?,
                        target_ref: row.get(3)?,
                        predecessors: Vec::new(),
                    })
                },
            )
            .optional()?;
        if value.is_none() {
            return Err(ReviewError::Missing(format!("contribution {id}")));
        }
        let mut value = value.expect("checked contribution presence above");
        let mut statement = self.connection.prepare(
            "SELECT predecessor_id FROM predecessors
             WHERE contribution_id=?1 ORDER BY predecessor_id",
        )?;
        value.predecessors = statement
            .query_map([id], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn store_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "whipplescript-source-review-{}-{}.sqlite",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn contribution_identity_and_dependencies_survive_restart() {
        let path = store_path();
        let mut store = ReviewStore::open(&path).expect("open");
        store
            .create_contribution("A", "alice", "First", "refs/heads/main", &[])
            .expect("first");
        let b = store
            .create_contribution("B", "bob", "Second", "refs/heads/main", &["A"])
            .expect("dependent");
        assert_eq!(b.predecessors, vec!["A"]);
        drop(store);
        let reopened = ReviewStore::open(&path).expect("reopen");
        assert_eq!(reopened.contribution("B").expect("read"), b);
        std::fs::remove_file(path).expect("remove db");
    }

    #[test]
    fn invalid_identity_scope_and_dependency_leave_no_record() {
        let path = store_path();
        let mut store = ReviewStore::open(&path).expect("open");
        assert!(matches!(
            store.create_contribution("../bad", "alice", "First", "refs/heads/main", &[]),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            store.create_contribution("A", "", "First", "refs/heads/main", &[]),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            store.create_contribution("A", "alice", "", "refs/heads/main", &[]),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            store.create_contribution("A", "alice", "First", "refs/tags/v1", &[]),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            store.create_contribution("A", "alice", "First", "refs/heads/main", &["A"]),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            store.create_contribution("A", "alice", "First", "refs/heads/main", &["missing"]),
            Err(ReviewError::Sqlite(_))
        ));
        assert!(matches!(
            store.contribution("A"),
            Err(ReviewError::Missing(_))
        ));
        store
            .create_contribution("A", "alice", "First", "refs/heads/main", &[])
            .expect("failed writes rolled back");
        assert!(matches!(
            store.create_contribution("A", "alice", "Different", "refs/heads/main", &[]),
            Err(ReviewError::Sqlite(_))
        ));
        std::fs::remove_file(path).expect("remove db");
    }
}
