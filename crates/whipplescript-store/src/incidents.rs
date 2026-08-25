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
        // WAL and a busy timeout, the posture every other store in this crate
        // takes on open. The mediator opens this store per process and several
        // whip processes share the one file, so reads and writes here genuinely
        // overlap. Left in rollback-journal mode they cannot: a writer's commit
        // needs EXCLUSIVE, which any held reader denies, so an incident write
        // stalls behind every concurrent reader and fails outright once one
        // outlives the busy timeout. An observed stall that could not be
        // recorded because a sibling was reading is a lost observation, and the
        // mediator's record of a stall is exactly what arms repair.
        //
        // The timeout matters less than it looks — rusqlite already installs a
        // 5s one on every connection — but going through `establish_wal` makes
        // it this crate's `STORE_BUSY_TIMEOUT`, so changing that constant
        // reaches this store too.
        crate::establish_wal(&connection)?;
        let store = Self { connection };
        store.ensure_schema()?;
        Ok(store)
    }

    pub fn open_in_memory() -> StoreResult<Self> {
        let connection = Connection::open_in_memory()?;
        // WAL does not apply in memory, but the busy timeout is set anyway so
        // both constructors behave the same under contention — the same posture
        // `SqliteStore::open_in_memory` takes.
        connection.busy_timeout(crate::STORE_BUSY_TIMEOUT)?;
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
        // Deciding "same situation or new one" is a read the write depends on,
        // so the whole decision is one transaction. Two mediators observing the
        // one stall concurrently would otherwise both miss the SELECT, both
        // INSERT, and the loser would come back holding a unique-index
        // violation from `incidents_open_situation_idx` — a store error exactly
        // where the contract promises re-detection refreshes. `Immediate`
        // rather than deferred because this reads before it writes: a deferred
        // transaction's SHARED->RESERVED upgrade fails at once and does not run
        // the busy handler, so the wait would not happen. See
        // `STORE_BUSY_TIMEOUT`.
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT incident_id FROM incidents \
                 WHERE kind = ?1 AND branch_id = ?2 AND slice_expr = ?3 \
                 AND status = 'open'",
                params![kind, branch_id, slice_expr],
                |row| row.get(0),
            )
            .optional()?;
        let outcome = if let Some(incident_id) = existing {
            transaction.execute(
                "UPDATE incidents SET detail_json = ?2, updated_at = ?3 \
                 WHERE incident_id = ?1",
                params![incident_id, detail_json, at],
            )?;
            let row = read_incident(&transaction, &incident_id)?.expect("refreshed row exists");
            OpenOutcome::Refreshed(row)
        } else {
            let incident_id = format!(
                "inc-{}",
                &crate::stable_hash_hex(&format!("{kind}|{branch_id}|{slice_expr}|{at}"))[..16]
            );
            transaction.execute(
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
            let row = read_incident(&transaction, &incident_id)?.expect("inserted row exists");
            OpenOutcome::Opened(row)
        };
        transaction.commit()?;
        Ok(outcome)
    }

    pub fn get(&self, incident_id: &str) -> StoreResult<Option<IncidentRow>> {
        read_incident(&self.connection, incident_id)
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
        // `RETURNING` rather than a follow-up SELECT: the caller compares this
        // against the `recurring` threshold, so it has to be the count *this*
        // bump produced. Read back separately, two concurrent bumps can land
        // between one of them and its SELECT and both report the same number —
        // a threshold tested at equality then fires twice or not at all. One
        // statement makes the increment and its answer the same atom.
        let count = self.connection.query_row(
            "INSERT INTO contention_pairs (pair_key, branch_a, branch_b, count, last_at) \
             VALUES (?1, ?2, ?3, 1, ?4) \
             ON CONFLICT(pair_key) DO UPDATE SET count = count + 1, last_at = ?4 \
             RETURNING count",
            params![pair_key, first, second, at],
            |row| row.get(0),
        )?;
        Ok(count)
    }
}

/// Read one incident by id. Free-standing so `open_incident` can read the row
/// it just wrote from *inside* its transaction, where `&self` is not available.
#[cfg(feature = "native")]
fn read_incident(connection: &Connection, incident_id: &str) -> StoreResult<Option<IncidentRow>> {
    let row = connection
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

    /// An incident write must not be blocked by a concurrent reader.
    ///
    /// This is the regression for an omission rather than a mistake: `open`
    /// never called `establish_wal`, alone among this crate's stores, so the
    /// file stayed in rollback-journal mode unless some peer happened to
    /// convert it. There a reader and a writer cannot coexist — the writer
    /// takes RESERVED but its commit needs EXCLUSIVE, which any held SHARED
    /// read lock denies — so an incident write stalls behind every concurrent
    /// reader and fails outright once one outlives the busy timeout. An
    /// observed stall that could not be recorded because a sibling process was
    /// reading is a lost observation, and the mediator's record of a stall is
    /// exactly what arms repair.
    ///
    /// Note what is *not* the defect: rusqlite installs a 5s busy timeout on
    /// every connection it opens, so a bare writer-versus-writer contention
    /// waits correctly even without this fix. Calling `establish_wal` is what
    /// buys reader/writer coexistence — and, secondarily, makes the timeout
    /// this crate's `STORE_BUSY_TIMEOUT` rather than a library default that
    /// changing the constant would not reach.
    ///
    /// The elapsed-time bound is the whole assertion: the write *succeeds*
    /// either way given a reader that eventually lets go, so only "it did not
    /// wait" distinguishes a WAL store from a rollback-journal one.
    #[test]
    fn an_incident_write_is_not_blocked_by_a_concurrent_reader() {
        const HELD: std::time::Duration = std::time::Duration::from_millis(2_000);
        // A WAL writer ignores readers entirely, so this is generous; anything
        // near HELD means the write queued behind the read lock.
        const PROMPTLY: std::time::Duration = std::time::Duration::from_millis(500);

        let dir = TempIncidentDir::new("reader-vs-writer");
        let path = dir.store_path();
        let mut store = IncidentStore::open(&path).expect("open store");

        // A plain reader that does *not* call `establish_wal`: the point is
        // that this store must put its own file in WAL rather than inherit the
        // mode from whichever peer happened to open it first.
        let reader_path = path.clone();
        let reading = std::sync::Arc::new(std::sync::Barrier::new(2));
        let held = std::sync::Arc::clone(&reading);
        let reader = std::thread::spawn(move || {
            let connection = Connection::open(&reader_path).expect("open reader");
            connection.execute_batch("BEGIN").expect("begin the read");
            // A deferred transaction takes no lock until it actually reads, so
            // the SHARED lock this test needs is acquired here, not by `BEGIN`.
            let _: i64 = connection
                .query_row("SELECT COUNT(*) FROM incidents", [], |row| row.get(0))
                .expect("read inside the transaction");
            held.wait();
            std::thread::sleep(HELD);
            connection
                .execute_batch("COMMIT")
                .expect("release the read lock");
        });

        reading.wait();
        let started = std::time::Instant::now();
        let outcome = store.open_incident(
            "reconcile_stalled",
            "line-1",
            None,
            "path(src/a.rs)",
            r#"{"paths":["src/a.rs"]}"#,
            "t1",
        );
        let waited = started.elapsed();
        reader.join().expect("reader thread");

        assert!(
            matches!(outcome, Ok(OpenOutcome::Opened(_))),
            "a contended incident write must not fail: {outcome:?}"
        );
        assert!(
            waited < PROMPTLY,
            "the write waited {waited:?} on a concurrent reader, so this store is not in WAL \
             and a reader that outlived the busy timeout would have failed it outright"
        );
    }

    /// Several connections bumping the same pair concurrently on one file all
    /// land, and each is told the count *its own* bump produced: across every
    /// worker the reported counts are exactly 1..=N, no value twice.
    ///
    /// Both halves bite. The distinctness half is the property `RETURNING` on
    /// the upsert buys — the increment and its answer are one statement, so no
    /// other bump can land between them — and it takes the two pragmas below
    /// to catch its absence. Against a read-back version this fails 5 runs in
    /// 5, in about 0.03s.
    ///
    /// Those pragmas are worth explaining, because without them this test
    /// passes against the read-back version and proves nothing. The window is
    /// the microsecond-wide gap between a worker's upsert committing and its
    /// read-back taking a snapshot, and two things hide it — both timing,
    /// neither isolation:
    ///
    /// 1. SQLite's busy handler *sleeps* before retrying, a millisecond on the
    ///    first attempt, so a writer that lost the lock wakes three orders of
    ///    magnitude later than the window it would have to land in. A handler
    ///    that retries at once polls at the window's own scale.
    /// 2. `synchronous = FULL` fsyncs the WAL on every commit, and that fsync
    ///    is itself wider than the window — so the interposing writer, spinning
    ///    or not, cannot *finish* inside it. This is the dominant shield: with
    ///    the spin handler alone the read-back version still passed 3 runs in
    ///    5; dropping the fsync took it to 5 failures in 5.
    ///
    /// Neither pragma invents a race. Real processes do back off and do fsync;
    /// what these remove is the machine-dependent shield that keeps a real
    /// interleaving from being observed here — the same shield a faster disk
    /// or a busier box removes on its own. And the defect they expose is not
    /// cosmetic: the count feeds the `recurring` threshold, where a value
    /// reported twice makes a check written at equality fire twice or slip
    /// past unseen.
    ///
    /// The barrier before `open` is doing separate work: the opens contend too,
    /// and that is the fresh-file WAL conversion race `establish_wal` exists
    /// for, which takes an exclusive lock the busy handler does not cover.
    #[test]
    fn concurrent_bumps_each_report_their_own_count() {
        const WORKERS: usize = 4;
        const ROUNDS: usize = 25;

        let dir = TempIncidentDir::new("concurrent-bumps");
        let path = dir.store_path();
        let opening = std::sync::Arc::new(std::sync::Barrier::new(WORKERS));
        let rounds = std::sync::Arc::new(std::sync::Barrier::new(WORKERS));

        let workers: Vec<_> = (0..WORKERS)
            .map(|worker| {
                let path = path.clone();
                let open_together = std::sync::Arc::clone(&opening);
                let bump_together = std::sync::Arc::clone(&rounds);
                std::thread::spawn(move || {
                    open_together.wait();
                    let mut store = IncidentStore::open(&path).expect("open store");
                    // Retry at once rather than sleeping, and give up long
                    // after any contention here could still be live, so a lock
                    // that never frees surfaces as an error instead of hanging.
                    store
                        .connection
                        .busy_handler(Some(|attempts| attempts < 1_000_000))
                        .expect("install the spinning busy handler");
                    // See the doc comment: the commit fsync is wider than the
                    // window this test has to observe, so it is the shield that
                    // has to go.
                    store
                        .connection
                        .execute_batch("PRAGMA synchronous = OFF")
                        .expect("drop the commit fsync");
                    (0..ROUNDS)
                        .map(|bump| {
                            // A barrier per round, not just one at the start:
                            // left to free-run the workers drift apart and each
                            // one's upsert and read land back to back, so the
                            // gap between them is almost never occupied.
                            // Re-aligning every round puts all the upserts in
                            // flight at once, which is what makes a separate
                            // read-back observably stale — given the two
                            // pragmas above, without which no alignment is
                            // fine enough to matter.
                            bump_together.wait();
                            // Argument order alternates: the pair key is
                            // symmetric, so every worker contends for one row.
                            let at = format!("t{worker}-{bump}");
                            let outcome = if bump % 2 == 0 {
                                store.bump_contention("line-a", "line-b", &at)
                            } else {
                                store.bump_contention("line-b", "line-a", &at)
                            };
                            outcome.unwrap_or_else(|error| {
                                panic!("contended bump must wait, not fail: {error:?}")
                            })
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();

        let mut reported: Vec<i64> = workers
            .into_iter()
            .flat_map(|worker| worker.join().expect("worker thread"))
            .collect();
        reported.sort_unstable();

        let expected: Vec<i64> = (1..=(WORKERS * ROUNDS) as i64).collect();
        assert_eq!(
            reported, expected,
            "every bump must report the count it produced, so the reported counts \
             are exactly 1..=N with no value twice"
        );
    }

    /// Several mediators detecting the same situation at once open exactly one
    /// incident: one `Opened`, the rest `Refreshed`, one open row.
    ///
    /// This is the regression for a read-then-write that was not a
    /// transaction. Every caller ran the "is it already open?" SELECT, all of
    /// them missed, and all of them inserted — so all but the first hit the
    /// `incidents_open_situation_idx` unique index and got a store error where
    /// `Refreshed` was promised. Identity is (kind, branch, slice) and each
    /// worker passes a distinct `at`, which is what a real re-detection looks
    /// like and what keeps the ids from colliding on the primary key instead.
    #[test]
    fn concurrent_detections_of_one_situation_open_exactly_one_incident() {
        const WORKERS: usize = 4;

        let dir = TempIncidentDir::new("concurrent-detections");
        let path = dir.store_path();
        let opening = std::sync::Arc::new(std::sync::Barrier::new(WORKERS));
        let detecting = std::sync::Arc::new(std::sync::Barrier::new(WORKERS));

        let workers: Vec<_> = (0..WORKERS)
            .map(|worker| {
                let path = path.clone();
                let open_together = std::sync::Arc::clone(&opening);
                let detect_together = std::sync::Arc::clone(&detecting);
                std::thread::spawn(move || {
                    open_together.wait();
                    let mut store = IncidentStore::open(&path).expect("open store");
                    // A second barrier after the opens: opening runs the schema
                    // batch, which takes long enough and unevenly enough to
                    // desynchronize workers that started together. The window
                    // this test aims at is the one between the "already open?"
                    // read and the write that follows it, so the detections are
                    // what have to be simultaneous.
                    detect_together.wait();
                    store
                        .open_incident(
                            "reconcile_stalled",
                            "line-1",
                            Some("triage"),
                            "path(src/a.rs)",
                            &format!(r#"{{"observer":{worker}}}"#),
                            &format!("t{worker}"),
                        )
                        .unwrap_or_else(|error| {
                            panic!("concurrent detection must refresh, not fail: {error:?}")
                        })
                })
            })
            .collect();

        let outcomes: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker thread"))
            .collect();

        let opened = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, OpenOutcome::Opened(_)))
            .count();
        assert_eq!(
            opened, 1,
            "one situation is one incident: exactly one detection opens it, \
             the rest refresh it"
        );

        let store = IncidentStore::open(&path).expect("reopen store");
        let open_rows = store.list(Some(IncidentStatus::Open)).expect("list open");
        assert_eq!(
            open_rows.len(),
            1,
            "the situation must leave exactly one open row behind"
        );
        // Whichever detection won, every worker was handed that same row.
        for outcome in &outcomes {
            let row = match outcome {
                OpenOutcome::Opened(row) | OpenOutcome::Refreshed(row) => row,
            };
            assert_eq!(row.incident_id, open_rows[0].incident_id);
        }
    }

    /// A temp directory removed when the binding drops, panic included. Owning
    /// the directory rather than the `.sqlite` file means the `-shm`/`-wal`
    /// sidecars go with it.
    struct TempIncidentDir(std::path::PathBuf);

    impl TempIncidentDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "whipplescript-incidents-{}-{}-{}",
                label,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos(),
            ));
            std::fs::create_dir_all(&dir).expect("create incidents temp dir");
            Self(dir)
        }

        fn store_path(&self) -> std::path::PathBuf {
            self.0.join("incidents.sqlite")
        }
    }

    impl Drop for TempIncidentDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
