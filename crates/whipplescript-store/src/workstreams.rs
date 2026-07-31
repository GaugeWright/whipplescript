//! Workstream tier: named shared lines + membership
//! (spec/versioned-workspace-research-note.md §7.2; untie-substrate
//! readiness tracker Phase 1; invariants modeled in workstream.maude).
//!
//! A workstream owns a NAME and a MEMBERSHIP set over a shared line (a
//! branch id); the merge engine owns every line advance — this store never
//! moves a head. Membership is single-valued BY SCHEMA (the member table's
//! primary key is the branch id), so joining a second stream leaves the
//! first in the same atomic step and the sync topology stays a tree. A
//! branch with no membership row homes to mainline — "a workstream of
//! one". Archive closes the line immediately (no further joins; the
//! daemon's admission check consults stream status) and re-homes every
//! member to mainline in the same transaction, returning them so the
//! caller runs the rebase-down pass — no branch is left syncing into a
//! dead line. Archived streams are immutable history, and their names
//! free up (unique among ACTIVE streams only).

#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use rusqlite::{params, Connection, OptionalExtension};

use crate::StoreResult;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamStatus {
    Active,
    Archived,
}

impl StreamStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            StreamStatus::Active => "active",
            StreamStatus::Archived => "archived",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(StreamStatus::Active),
            "archived" => Some(StreamStatus::Archived),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkstreamRow {
    pub stream_id: String,
    pub name: Option<String>,
    /// The stream's shared line — a branch id whose advances the merge
    /// engine owns.
    pub line_branch_id: String,
    pub status: StreamStatus,
    /// The §7.1 staleness bound, in seconds (DR-0052 S1's one real
    /// knob): a member whose base lags the line by more than this must
    /// rebase down before it may merge up; the reconcile pass emits
    /// `vcs.staleness.exceeded` past it. `None` = unbounded.
    pub staleness_seconds: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateStreamOutcome {
    Created(WorkstreamRow),
    Existing(WorkstreamRow),
    NameTaken { holder_stream_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JoinOutcome {
    /// Joined; `left_stream_id` is the membership given up in the same
    /// step (single-valued membership).
    Joined {
        left_stream_id: Option<String>,
    },
    StreamMissing,
    /// A dead line accepts no members.
    StreamArchived,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveOutcome {
    /// Archived; every member was re-homed to mainline in the same
    /// transaction and is returned for the caller's rebase-down pass.
    Archived {
        rehomed_branch_ids: Vec<String>,
    },
    AlreadyArchived,
    StreamMissing,
}

/// Object-safe workstream seam, mirroring `Branches`: the DO host supplies
/// its own implementation.
pub trait Workstreams {
    fn create_stream(
        &mut self,
        stream_id: &str,
        name: Option<&str>,
        line_branch_id: &str,
        created_at: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<CreateStreamOutcome>;
    fn get_stream(&self, stream_id: &str) -> StoreResult<Option<WorkstreamRow>>;
    fn list_streams(&self, status: Option<StreamStatus>) -> StoreResult<Vec<WorkstreamRow>>;
    fn join(&mut self, branch_id: &str, stream_id: &str, at: &str) -> StoreResult<JoinOutcome>;
    /// Leave = re-home to mainline (drop the membership row). Returns the
    /// stream left, if any.
    fn leave(&mut self, branch_id: &str) -> StoreResult<Option<String>>;
    /// The stream a branch homes to; `None` = mainline (a workstream of
    /// one).
    fn home_of(&self, branch_id: &str) -> StoreResult<Option<String>>;
    fn members(&self, stream_id: &str) -> StoreResult<Vec<String>>;
    fn archive_stream(&mut self, stream_id: &str, at: &str) -> StoreResult<ArchiveOutcome>;
}

#[cfg(feature = "native")]
pub struct WorkstreamStore {
    connection: Connection,
}

#[cfg(feature = "native")]
impl WorkstreamStore {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;
            "#,
        )?;
        ensure_workstream_schema(&connection)?;
        Ok(Self { connection })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> StoreResult<Self> {
        let connection = Connection::open_in_memory()?;
        ensure_workstream_schema(&connection)?;
        Ok(Self { connection })
    }

    fn stream_by_id(
        connection: &Connection,
        stream_id: &str,
    ) -> StoreResult<Option<WorkstreamRow>> {
        let row = connection
            .query_row(
                "SELECT stream_id, name, line_branch_id, status, staleness_seconds, \
                 created_at, updated_at \
                 FROM workstreams WHERE stream_id = ?1",
                params![stream_id],
                map_stream_row,
            )
            .optional()?;
        Ok(row)
    }
}

#[cfg(feature = "native")]
fn map_stream_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkstreamRow> {
    let status_text: String = row.get(3)?;
    Ok(WorkstreamRow {
        stream_id: row.get(0)?,
        name: row.get(1)?,
        line_branch_id: row.get(2)?,
        status: StreamStatus::parse(&status_text).unwrap_or(StreamStatus::Active),
        staleness_seconds: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

#[cfg(feature = "native")]
fn ensure_workstream_schema(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS workstreams (
            stream_id TEXT PRIMARY KEY,
            name TEXT,
            line_branch_id TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            idempotency_key TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS workstreams_idempotency_idx
            ON workstreams(idempotency_key)
            WHERE idempotency_key IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS workstreams_active_name_idx
            ON workstreams(name)
            WHERE name IS NOT NULL AND status = 'active';
        CREATE TABLE IF NOT EXISTS workstream_members (
            branch_id TEXT PRIMARY KEY,
            stream_id TEXT NOT NULL,
            joined_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS workstream_members_stream_idx
            ON workstream_members(stream_id);
        "#,
    )?;
    // The staleness bound arrived with DR-0052 S1; earlier stores gain
    // the column in place (NULL = unbounded, the prior behavior).
    let columns: Vec<String> = {
        let mut stmt = connection.prepare("PRAGMA table_info(workstreams)")?;
        let mapped = stmt.query_map([], |row| row.get::<_, String>(1))?;
        mapped.collect::<Result<_, _>>()?
    };
    if !columns.iter().any(|name| name == "staleness_seconds") {
        connection.execute(
            "ALTER TABLE workstreams ADD COLUMN staleness_seconds INTEGER",
            [],
        )?;
    }
    Ok(())
}

#[cfg(feature = "native")]
impl WorkstreamStore {
    /// Set (or clear) the stream's staleness bound — governance surface,
    /// not a member verb.
    pub fn set_staleness(
        &mut self,
        stream_id: &str,
        staleness_seconds: Option<i64>,
        at: &str,
    ) -> StoreResult<Option<WorkstreamRow>> {
        self.connection.execute(
            "UPDATE workstreams SET staleness_seconds = ?2, updated_at = ?3 \
             WHERE stream_id = ?1",
            rusqlite::params![stream_id, staleness_seconds, at],
        )?;
        Self::stream_by_id(&self.connection, stream_id)
    }
}

#[cfg(feature = "native")]
impl Workstreams for WorkstreamStore {
    fn create_stream(
        &mut self,
        stream_id: &str,
        name: Option<&str>,
        line_branch_id: &str,
        created_at: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<CreateStreamOutcome> {
        let tx = self.connection.transaction()?;
        if let Some(existing) = Self::stream_by_id(&tx, stream_id)? {
            tx.commit()?;
            return Ok(CreateStreamOutcome::Existing(existing));
        }
        if let Some(key) = idempotency_key {
            let by_key: Option<String> = tx
                .query_row(
                    "SELECT stream_id FROM workstreams WHERE idempotency_key = ?1",
                    params![key],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(existing_id) = by_key {
                let row = Self::stream_by_id(&tx, &existing_id)?.expect("row for key");
                tx.commit()?;
                return Ok(CreateStreamOutcome::Existing(row));
            }
        }
        if let Some(name) = name {
            let holder: Option<String> = tx
                .query_row(
                    "SELECT stream_id FROM workstreams \
                     WHERE name = ?1 AND status = 'active'",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(holder_stream_id) = holder {
                return Ok(CreateStreamOutcome::NameTaken { holder_stream_id });
            }
        }
        tx.execute(
            "INSERT INTO workstreams \
             (stream_id, name, line_branch_id, status, created_at, updated_at, \
              idempotency_key) \
             VALUES (?1, ?2, ?3, 'active', ?4, ?4, ?5)",
            params![stream_id, name, line_branch_id, created_at, idempotency_key],
        )?;
        let row = Self::stream_by_id(&tx, stream_id)?.expect("created stream");
        tx.commit()?;
        Ok(CreateStreamOutcome::Created(row))
    }

    fn get_stream(&self, stream_id: &str) -> StoreResult<Option<WorkstreamRow>> {
        Self::stream_by_id(&self.connection, stream_id)
    }

    fn list_streams(&self, status: Option<StreamStatus>) -> StoreResult<Vec<WorkstreamRow>> {
        let mut rows = Vec::new();
        match status {
            Some(status) => {
                let mut stmt = self.connection.prepare(
                    "SELECT stream_id, name, line_branch_id, status, created_at, updated_at \
                     FROM workstreams WHERE status = ?1 ORDER BY stream_id",
                )?;
                let mapped = stmt.query_map(params![status.as_str()], map_stream_row)?;
                for row in mapped {
                    rows.push(row?);
                }
            }
            None => {
                let mut stmt = self.connection.prepare(
                    "SELECT stream_id, name, line_branch_id, status, created_at, updated_at \
                     FROM workstreams ORDER BY stream_id",
                )?;
                let mapped = stmt.query_map([], map_stream_row)?;
                for row in mapped {
                    rows.push(row?);
                }
            }
        }
        Ok(rows)
    }

    fn join(&mut self, branch_id: &str, stream_id: &str, at: &str) -> StoreResult<JoinOutcome> {
        let tx = self.connection.transaction()?;
        let Some(stream) = Self::stream_by_id(&tx, stream_id)? else {
            return Ok(JoinOutcome::StreamMissing);
        };
        if stream.status != StreamStatus::Active {
            return Ok(JoinOutcome::StreamArchived);
        }
        let previous: Option<String> = tx
            .query_row(
                "SELECT stream_id FROM workstream_members WHERE branch_id = ?1",
                params![branch_id],
                |row| row.get(0),
            )
            .optional()?;
        // The primary key on branch_id makes membership single-valued: the
        // upsert IS the leave-then-join, one atomic step.
        tx.execute(
            "INSERT INTO workstream_members (branch_id, stream_id, joined_at) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(branch_id) DO UPDATE SET stream_id = ?2, joined_at = ?3",
            params![branch_id, stream_id, at],
        )?;
        tx.commit()?;
        Ok(JoinOutcome::Joined {
            left_stream_id: previous.filter(|prev| prev != stream_id),
        })
    }

    fn leave(&mut self, branch_id: &str) -> StoreResult<Option<String>> {
        let tx = self.connection.transaction()?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT stream_id FROM workstream_members WHERE branch_id = ?1",
                params![branch_id],
                |row| row.get(0),
            )
            .optional()?;
        tx.execute(
            "DELETE FROM workstream_members WHERE branch_id = ?1",
            params![branch_id],
        )?;
        tx.commit()?;
        Ok(previous)
    }

    fn home_of(&self, branch_id: &str) -> StoreResult<Option<String>> {
        let home: Option<String> = self
            .connection
            .query_row(
                "SELECT stream_id FROM workstream_members WHERE branch_id = ?1",
                params![branch_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(home)
    }

    fn members(&self, stream_id: &str) -> StoreResult<Vec<String>> {
        let mut stmt = self.connection.prepare(
            "SELECT branch_id FROM workstream_members \
             WHERE stream_id = ?1 ORDER BY branch_id",
        )?;
        let mapped = stmt.query_map(params![stream_id], |row| row.get(0))?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row?);
        }
        Ok(rows)
    }

    fn archive_stream(&mut self, stream_id: &str, at: &str) -> StoreResult<ArchiveOutcome> {
        let tx = self.connection.transaction()?;
        let Some(stream) = Self::stream_by_id(&tx, stream_id)? else {
            return Ok(ArchiveOutcome::StreamMissing);
        };
        if stream.status == StreamStatus::Archived {
            return Ok(ArchiveOutcome::AlreadyArchived);
        }
        let mut rehomed = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT branch_id FROM workstream_members \
                 WHERE stream_id = ?1 ORDER BY branch_id",
            )?;
            let mapped = stmt.query_map(params![stream_id], |row| row.get::<_, String>(0))?;
            for row in mapped {
                rehomed.push(row?);
            }
        }
        // Close the line and re-home every member in ONE transaction: no
        // observable state has an archived stream with members, so no
        // branch is ever left syncing into a dead line.
        tx.execute(
            "DELETE FROM workstream_members WHERE stream_id = ?1",
            params![stream_id],
        )?;
        tx.execute(
            "UPDATE workstreams SET status = 'archived', updated_at = ?2 \
             WHERE stream_id = ?1",
            params![stream_id, at],
        )?;
        tx.commit()?;
        Ok(ArchiveOutcome::Archived {
            rehomed_branch_ids: rehomed,
        })
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    fn store() -> WorkstreamStore {
        WorkstreamStore::open_in_memory().expect("open store")
    }

    #[test]
    fn create_is_idempotent_and_names_are_active_unique() {
        let mut store = store();
        let CreateStreamOutcome::Created(created) = store
            .create_stream("ws_1", Some("triage"), "line_ws_1", "t0", Some("key_1"))
            .expect("op")
        else {
            panic!("expected creation");
        };
        assert_eq!(
            store
                .create_stream("ws_1", Some("triage"), "line_ws_1", "t1", None)
                .expect("op"),
            CreateStreamOutcome::Existing(created.clone())
        );
        assert_eq!(
            store
                .create_stream("ws_1_retry", None, "line_x", "t1", Some("key_1"))
                .expect("op"),
            CreateStreamOutcome::Existing(created)
        );
        assert_eq!(
            store
                .create_stream("ws_2", Some("triage"), "line_ws_2", "t1", None)
                .expect("op"),
            CreateStreamOutcome::NameTaken {
                holder_stream_id: "ws_1".to_owned()
            }
        );
        // Archiving frees the name.
        assert!(matches!(
            store.archive_stream("ws_1", "t2").expect("op"),
            ArchiveOutcome::Archived { .. }
        ));
        assert!(matches!(
            store
                .create_stream("ws_2", Some("triage"), "line_ws_2", "t3", None)
                .expect("op"),
            CreateStreamOutcome::Created(_)
        ));
    }

    /// Single-valued membership: joining a second stream leaves the first
    /// in the same step (workstream.maude double-home bite, by schema).
    #[test]
    fn membership_is_single_valued() {
        let mut store = store();
        store
            .create_stream("ws_1", None, "line_1", "t0", None)
            .expect("op");
        store
            .create_stream("ws_2", None, "line_2", "t0", None)
            .expect("op");
        assert_eq!(
            store.join("draft_a", "ws_1", "t1").expect("op"),
            JoinOutcome::Joined {
                left_stream_id: None
            }
        );
        assert_eq!(
            store.join("draft_a", "ws_2", "t2").expect("op"),
            JoinOutcome::Joined {
                left_stream_id: Some("ws_1".to_owned())
            }
        );
        assert_eq!(
            store.home_of("draft_a").expect("op"),
            Some("ws_2".to_owned())
        );
        assert_eq!(store.members("ws_1").expect("op"), Vec::<String>::new());
        assert_eq!(
            store.members("ws_2").expect("op"),
            vec!["draft_a".to_owned()]
        );
        // Re-joining the same stream is idempotent, not a leave.
        assert_eq!(
            store.join("draft_a", "ws_2", "t3").expect("op"),
            JoinOutcome::Joined {
                left_stream_id: None
            }
        );
    }

    /// Archive re-homes every member atomically and the dead line refuses
    /// joins (workstream.maude archive-rehomes-members + dead-line bites).
    #[test]
    fn archive_rehomes_members_and_closes_the_line() {
        let mut store = store();
        store
            .create_stream("ws_1", None, "line_1", "t0", None)
            .expect("op");
        store.join("draft_a", "ws_1", "t1").expect("op");
        store.join("draft_b", "ws_1", "t1").expect("op");
        assert_eq!(
            store.archive_stream("ws_1", "t2").expect("op"),
            ArchiveOutcome::Archived {
                rehomed_branch_ids: vec!["draft_a".to_owned(), "draft_b".to_owned()]
            }
        );
        // Members now home to mainline (no membership rows).
        assert_eq!(store.home_of("draft_a").expect("op"), None);
        assert_eq!(store.home_of("draft_b").expect("op"), None);
        assert_eq!(store.members("ws_1").expect("op"), Vec::<String>::new());
        // The dead line accepts no members; archive is terminal.
        assert_eq!(
            store.join("draft_c", "ws_1", "t3").expect("op"),
            JoinOutcome::StreamArchived
        );
        assert_eq!(
            store.archive_stream("ws_1", "t4").expect("op"),
            ArchiveOutcome::AlreadyArchived
        );
    }

    #[test]
    fn leave_rehomes_to_mainline() {
        let mut store = store();
        store
            .create_stream("ws_1", None, "line_1", "t0", None)
            .expect("op");
        store.join("draft_a", "ws_1", "t1").expect("op");
        assert_eq!(store.leave("draft_a").expect("op"), Some("ws_1".to_owned()));
        assert_eq!(store.home_of("draft_a").expect("op"), None);
        assert_eq!(store.leave("draft_a").expect("op"), None);
    }
}
