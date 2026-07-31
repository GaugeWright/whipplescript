//! Repair incidents (DR-0052 Decision 8; vw note §7.6): the mediator's
//! record of structural stalls — the table that ARMS repair. An incident
//! is opened only from mediator-observed conditions (a stalled
//! reconcile, a refused op, a detected revert-war), carries the DERIVED
//! slice the eventual grant is scoped to, and evaporates (resolves) when
//! the situation clears or a repair lands. Agents cannot reach this
//! store: raising rides the tracker ledger, and the two ledgers stay
//! deliberately unjoined — if they ever merge, the self-arming proof is
//! dead.
//!
//! The store also keeps the contention pair-counter (`recurring`
//! detection): frequent contention between the same two lines is a
//! work-decomposition problem, and the mediator is uniquely placed to
//! say so.

#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use rusqlite::{params, Connection, OptionalExtension};

use crate::StoreResult;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IncidentStatus {
    Open,
    Resolved,
}

impl IncidentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            IncidentStatus::Open => "open",
            IncidentStatus::Resolved => "resolved",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(IncidentStatus::Open),
            "resolved" => Some(IncidentStatus::Resolved),
            _ => None,
        }
    }
}

/// One mediator-observed repair situation. `slice_expr` is a selection
/// expression over the incident's branch — the extent any repair grant
/// derives from; it is computed by the mediator, never stated by a
/// grantee.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncidentRow {
    pub incident_id: String,
    /// `reconcile_stalled` | `op_refused` | `revert_war`
    /// (| `staleness_exceeded` once the S1 knob exists).
    pub kind: String,
    pub branch_id: String,
    pub stream_id: Option<String>,
    pub slice_expr: String,
    /// Kind-specific evidence (paths, refusal reason, counterparties).
    pub detail_json: String,
    pub status: IncidentStatus,
    pub opened_at: String,
    pub updated_at: String,
    pub resolved_at: Option<String>,
    /// Who closed it (a repair apply, an explicit close, or the
    /// mediator observing the situation cleared).
    pub resolved_by: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenOutcome {
    Opened(IncidentRow),
    /// The same situation is already open: refreshed in place
    /// (re-detection is not a second incident).
    Refreshed(IncidentRow),
}

#[cfg(feature = "native")]
pub struct IncidentStore {
    connection: Connection,
}

#[cfg(feature = "native")]
impl IncidentStore {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let connection = Connection::open(path)?;
        let store = Self { connection };
        store.ensure_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> StoreResult<Self> {
        let connection = Connection::open_in_memory()?;
        let store = Self { connection };
        store.ensure_schema()?;
        Ok(store)
    }

    fn ensure_schema(&self) -> StoreResult<()> {
        self.connection.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                branch_id TEXT NOT NULL,
                stream_id TEXT,
                slice_expr TEXT NOT NULL,
                detail_json TEXT NOT NULL,
                status TEXT NOT NULL,
                opened_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT,
                resolved_by TEXT
            );
            CREATE INDEX IF NOT EXISTS incidents_status_idx
                ON incidents(status, branch_id);
            CREATE UNIQUE INDEX IF NOT EXISTS incidents_open_situation_idx
                ON incidents(kind, branch_id, slice_expr)
                WHERE status = 'open';
            CREATE TABLE IF NOT EXISTS contention_pairs (
                pair_key TEXT PRIMARY KEY,
                branch_a TEXT NOT NULL,
                branch_b TEXT NOT NULL,
                count INTEGER NOT NULL,
                last_at TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    /// Open (or refresh) the incident for one observed situation.
    /// Identity = (kind, branch, slice) among OPEN incidents, so
    /// re-detection refreshes rather than duplicating; a new slice is a
    /// new situation.
    pub fn open_incident(
        &mut self,
        kind: &str,
        branch_id: &str,
        stream_id: Option<&str>,
        slice_expr: &str,
        detail_json: &str,
        at: &str,
    ) -> StoreResult<OpenOutcome> {
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT incident_id FROM incidents \
                 WHERE kind = ?1 AND branch_id = ?2 AND slice_expr = ?3 \
                 AND status = 'open'",
                params![kind, branch_id, slice_expr],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(incident_id) = existing {
            self.connection.execute(
                "UPDATE incidents SET detail_json = ?2, updated_at = ?3 \
                 WHERE incident_id = ?1",
                params![incident_id, detail_json, at],
            )?;
            let row = self.get(&incident_id)?.expect("refreshed row exists");
            return Ok(OpenOutcome::Refreshed(row));
        }
        let incident_id = format!(
            "inc-{}",
            &crate::stable_hash_hex(&format!("{kind}|{branch_id}|{slice_expr}|{at}"))[..16]
        );
        self.connection.execute(
            "INSERT INTO incidents \
             (incident_id, kind, branch_id, stream_id, slice_expr, detail_json, \
              status, opened_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'open', ?7, ?7)",
            params![
                incident_id,
                kind,
                branch_id,
                stream_id,
                slice_expr,
                detail_json,
                at
            ],
        )?;
        let row = self.get(&incident_id)?.expect("inserted row exists");
        Ok(OpenOutcome::Opened(row))
    }

    pub fn get(&self, incident_id: &str) -> StoreResult<Option<IncidentRow>> {
        let row = self
            .connection
            .query_row(
                "SELECT incident_id, kind, branch_id, stream_id, slice_expr, \
                 detail_json, status, opened_at, updated_at, resolved_at, \
                 resolved_by FROM incidents WHERE incident_id = ?1",
                params![incident_id],
                map_incident_row,
            )
            .optional()?;
        Ok(row)
    }

    pub fn list(&self, status: Option<IncidentStatus>) -> StoreResult<Vec<IncidentRow>> {
        let mut rows = Vec::new();
        match status {
            Some(status) => {
                let mut stmt = self.connection.prepare(
                    "SELECT incident_id, kind, branch_id, stream_id, slice_expr, \
                     detail_json, status, opened_at, updated_at, resolved_at, \
                     resolved_by FROM incidents WHERE status = ?1 \
                     ORDER BY opened_at DESC",
                )?;
                let mapped = stmt.query_map(params![status.as_str()], map_incident_row)?;
                for row in mapped {
                    rows.push(row?);
                }
            }
            None => {
                let mut stmt = self.connection.prepare(
                    "SELECT incident_id, kind, branch_id, stream_id, slice_expr, \
                     detail_json, status, opened_at, updated_at, resolved_at, \
                     resolved_by FROM incidents ORDER BY opened_at DESC",
                )?;
                let mapped = stmt.query_map([], map_incident_row)?;
                for row in mapped {
                    rows.push(row?);
                }
            }
        }
        Ok(rows)
    }

    /// Close one incident. Closing is terminal (the record is immutable
    /// history); a recurrence opens a NEW incident.
    pub fn close(
        &mut self,
        incident_id: &str,
        resolved_by: &str,
        at: &str,
    ) -> StoreResult<Option<IncidentRow>> {
        self.connection.execute(
            "UPDATE incidents SET status = 'resolved', resolved_at = ?2, \
             resolved_by = ?3, updated_at = ?2 \
             WHERE incident_id = ?1 AND status = 'open'",
            params![incident_id, at, resolved_by],
        )?;
        self.get(incident_id)
    }

    /// The mediator observed the situation cleared (a later reconcile
    /// succeeded): close every open incident of `kind` on the branch.
    pub fn close_cleared(&mut self, kind: &str, branch_id: &str, at: &str) -> StoreResult<usize> {
        let closed = self.connection.execute(
            "UPDATE incidents SET status = 'resolved', resolved_at = ?3, \
             resolved_by = 'mediator', updated_at = ?3 \
             WHERE kind = ?1 AND branch_id = ?2 AND status = 'open'",
            params![kind, branch_id, at],
        )?;
        Ok(closed)
    }

    /// Bump the contention pair-counter; returns the new count. The
    /// caller emits `vcs.contention.recurring` at its threshold —
    /// the diagnostic is a fact, never an incident (nothing to repair;
    /// the plan is the problem).
    pub fn bump_contention(
        &mut self,
        branch_a: &str,
        branch_b: &str,
        at: &str,
    ) -> StoreResult<i64> {
        let (first, second) = if branch_a <= branch_b {
            (branch_a, branch_b)
        } else {
            (branch_b, branch_a)
        };
        let pair_key = format!("{first}|{second}");
        self.connection.execute(
            "INSERT INTO contention_pairs (pair_key, branch_a, branch_b, count, last_at) \
             VALUES (?1, ?2, ?3, 1, ?4) \
             ON CONFLICT(pair_key) DO UPDATE SET count = count + 1, last_at = ?4",
            params![pair_key, first, second, at],
        )?;
        let count = self.connection.query_row(
            "SELECT count FROM contention_pairs WHERE pair_key = ?1",
            params![pair_key],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

#[cfg(feature = "native")]
fn map_incident_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<IncidentRow> {
    Ok(IncidentRow {
        incident_id: row.get(0)?,
        kind: row.get(1)?,
        branch_id: row.get(2)?,
        stream_id: row.get(3)?,
        slice_expr: row.get(4)?,
        detail_json: row.get(5)?,
        status: IncidentStatus::parse(&row.get::<_, String>(6)?).unwrap_or(IncidentStatus::Open),
        opened_at: row.get(7)?,
        updated_at: row.get(8)?,
        resolved_at: row.get(9)?,
        resolved_by: row.get(10)?,
    })
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    /// Re-detection refreshes the open incident (one situation, one
    /// row); closing is terminal and a recurrence opens a NEW incident;
    /// `close_cleared` resolves by kind+branch as the mediator.
    #[test]
    fn incident_identity_lifecycle_and_clearing() {
        let mut store = IncidentStore::open_in_memory().expect("open");
        let first = store
            .open_incident(
                "reconcile_stalled",
                "line-1",
                Some("triage"),
                "path(src/a.rs)",
                r#"{"paths":["src/a.rs"]}"#,
                "t1",
            )
            .expect("open");
        let OpenOutcome::Opened(row) = first else {
            panic!("first detection opens");
        };
        let again = store
            .open_incident(
                "reconcile_stalled",
                "line-1",
                Some("triage"),
                "path(src/a.rs)",
                r#"{"paths":["src/a.rs"]}"#,
                "t2",
            )
            .expect("refresh");
        let OpenOutcome::Refreshed(refreshed) = again else {
            panic!("re-detection refreshes");
        };
        assert_eq!(refreshed.incident_id, row.incident_id);
        assert_eq!(refreshed.updated_at, "t2");
        assert_eq!(
            store.list(Some(IncidentStatus::Open)).expect("list").len(),
            1
        );
        // Mediator clearing closes it; the record persists as history.
        let cleared = store
            .close_cleared("reconcile_stalled", "line-1", "t3")
            .expect("clear");
        assert_eq!(cleared, 1);
        let closed = store.get(&row.incident_id).expect("get").expect("row");
        assert_eq!(closed.status, IncidentStatus::Resolved);
        assert_eq!(closed.resolved_by.as_deref(), Some("mediator"));
        // Recurrence = a new incident, not a resurrection.
        let recurred = store
            .open_incident(
                "reconcile_stalled",
                "line-1",
                Some("triage"),
                "path(src/a.rs)",
                "{}",
                "t4",
            )
            .expect("reopen");
        assert!(
            matches!(recurred, OpenOutcome::Opened(ref new) if new.incident_id != row.incident_id)
        );
    }

    /// The pair-counter is order-independent and monotonic — the
    /// `recurring` threshold's substrate.
    #[test]
    fn contention_pair_counter_is_symmetric() {
        let mut store = IncidentStore::open_in_memory().expect("open");
        assert_eq!(store.bump_contention("b", "a", "t1").expect("bump"), 1);
        assert_eq!(store.bump_contention("a", "b", "t2").expect("bump"), 2);
        assert_eq!(store.bump_contention("a", "b", "t3").expect("bump"), 3);
    }
}
