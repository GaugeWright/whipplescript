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
//! free up (unique among non-archived streams only).

#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use rusqlite::{params, Connection, OptionalExtension};

#[cfg(feature = "native")]
use crate::StoreError;
use crate::StoreResult;
use crate::{
    branches::Branches,
    content::ContentBlobs,
    vcs::{ExactInstanceForkBinding, WorkspaceVcs},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    Active,
    BoundaryReserved,
    RefAdvanced,
    Archived,
}

impl StreamStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            StreamStatus::Active => "active",
            StreamStatus::BoundaryReserved => "boundary_reserved",
            StreamStatus::RefAdvanced => "ref_advanced",
            StreamStatus::Archived => "archived",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(StreamStatus::Active),
            "boundary_reserved" => Some(StreamStatus::BoundaryReserved),
            "ref_advanced" => Some(StreamStatus::RefAdvanced),
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
    /// DR-0078's durable promotion coordinate. These fields are populated as
    /// one reservation record before any boundary work begins and retained in
    /// the terminal row as evidence.
    pub reservation_id: Option<String>,
    pub expected_line_cut: Option<String>,
    pub expected_main_cut: Option<String>,
    pub proposed_main_cut: Option<String>,
    pub ref_position: Option<u64>,
    pub ref_receipt_handle: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundaryReservation<'a> {
    pub reservation_id: &'a str,
    pub expected_line_cut: &'a str,
    pub expected_main_cut: &'a str,
    pub proposed_main_cut: &'a str,
    pub at: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReserveBoundaryOutcome {
    Reserved(WorkstreamRow),
    Existing(WorkstreamRow),
    Busy { holder_reservation_id: String },
    StreamMissing,
    StreamArchived,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseBoundaryOutcome {
    Released,
    AlreadyActive,
    ReservationMismatch,
    RefAlreadyAdvanced,
    StreamArchived,
    StreamMissing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecordRefAdvancedOutcome {
    Recorded(WorkstreamRow),
    Existing(WorkstreamRow),
    ReservationMismatch,
    NotReserved,
    StreamArchived,
    StreamMissing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClosePromotedOutcome {
    Closed { rehomed_branch_ids: Vec<String> },
    AlreadyClosed,
    ReservationMismatch,
    RefNotAdvanced,
    StreamMissing,
}

/// Stable, body-free host evidence. It is deliberately a projection of the
/// durable workstream row: copying it carries no ref or external effect
/// authority (DR-0078 §6).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WorkstreamBoundaryReceiptV1 {
    pub schema: String,
    pub workspace_authority_id: String,
    pub stream_id: String,
    pub reservation_id: String,
    pub outcome: String,
    pub expected_stream_cut: String,
    pub expected_main_cut: String,
    pub proposed_main_cut: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub main_ref_position: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_receipt_handle: Option<String>,
    pub recorded_at: String,
}

/// Current authoritative home of one branch. `authority_position` advances
/// whenever that branch transfers between Main and a named workstream, so a
/// leave-and-rejoin cannot masquerade as the earlier home in a host snapshot.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BranchHomeReceiptV1 {
    pub schema: String,
    pub branch_id: String,
    pub stream_id: Option<String>,
    pub line_branch_id: Option<String>,
    pub stream_status: Option<StreamStatus>,
    pub authority_position: u64,
    pub evidence_handle: String,
    pub recorded_at: Option<String>,
}

/// Body-free digest used by native and Durable Object implementations.
pub fn branch_home_evidence_handle(
    branch_id: &str,
    stream_id: Option<&str>,
    line_branch_id: Option<&str>,
    stream_status: Option<StreamStatus>,
    authority_position: u64,
) -> String {
    format!(
        "sha256:{}",
        crate::chunking::content_hash_hex(
            format!(
                "branch-home-v1|{branch_id}|{}|{}|{}|{authority_position}",
                stream_id.unwrap_or("main"),
                line_branch_id.unwrap_or("main"),
                stream_status.map(StreamStatus::as_str).unwrap_or("main")
            )
            .as_bytes()
        )
    )
}

impl WorkstreamRow {
    #[must_use]
    pub fn boundary_receipt(
        &self,
        workspace_authority_id: &str,
    ) -> Option<WorkstreamBoundaryReceiptV1> {
        Some(WorkstreamBoundaryReceiptV1 {
            schema: "workstream_boundary_receipt_v1".to_owned(),
            workspace_authority_id: workspace_authority_id.to_owned(),
            stream_id: self.stream_id.clone(),
            reservation_id: self.reservation_id.clone()?,
            outcome: self.status.as_str().to_owned(),
            expected_stream_cut: self.expected_line_cut.clone()?,
            expected_main_cut: self.expected_main_cut.clone()?,
            proposed_main_cut: self.proposed_main_cut.clone()?,
            main_ref_position: self.ref_position,
            ref_receipt_handle: self.ref_receipt_handle.clone(),
            recorded_at: self.updated_at.clone(),
        })
    }
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
    /// The destination's boundary is frozen.
    StreamReserved,
    /// Atomic transfer cannot escape a frozen source stream.
    SourceReserved {
        stream_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ArchiveOutcome {
    /// Archived; every member was re-homed to mainline in the same
    /// transaction and is returned for the caller's rebase-down pass.
    Archived {
        rehomed_branch_ids: Vec<String>,
    },
    AlreadyArchived,
    BoundaryReserved,
    RefAlreadyAdvanced,
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
    /// Host-facing spelling of `join`: membership is an atomic transfer, not
    /// an add that can leave the branch in two workstreams.
    fn transfer(&mut self, branch_id: &str, stream_id: &str, at: &str) -> StoreResult<JoinOutcome> {
        self.join(branch_id, stream_id, at)
    }
    /// Leave = re-home to mainline (drop the membership row). Returns the
    /// stream left, if any.
    fn leave(&mut self, branch_id: &str) -> StoreResult<Option<String>>;
    /// The stream a branch homes to; `None` = mainline (a workstream of
    /// one).
    fn home_of(&self, branch_id: &str) -> StoreResult<Option<String>>;
    /// Structured, position-bearing projection for host fork snapshots.
    fn home_receipt(&self, branch_id: &str) -> StoreResult<BranchHomeReceiptV1>;
    fn members(&self, stream_id: &str) -> StoreResult<Vec<String>>;
    fn archive_stream(&mut self, stream_id: &str, at: &str) -> StoreResult<ArchiveOutcome>;
    fn reserve_boundary(
        &mut self,
        stream_id: &str,
        reservation: BoundaryReservation<'_>,
    ) -> StoreResult<ReserveBoundaryOutcome>;
    fn release_boundary(
        &mut self,
        stream_id: &str,
        reservation_id: &str,
        at: &str,
    ) -> StoreResult<ReleaseBoundaryOutcome>;
    fn record_ref_advanced(
        &mut self,
        stream_id: &str,
        reservation_id: &str,
        ref_position: u64,
        ref_receipt_handle: &str,
        at: &str,
    ) -> StoreResult<RecordRefAdvancedOutcome>;
    fn close_promoted(
        &mut self,
        stream_id: &str,
        reservation_id: &str,
        at: &str,
    ) -> StoreResult<ClosePromotedOutcome>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactForkDestination<'a> {
    Main,
    Workstream(&'a str),
}

/// Host-facing result of composing exact immutable content with a current
/// destination admission. The two receipts stay separate so admission can
/// never be mistaken for a replacement content cut.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactForkAdmissionOutcome {
    Forked {
        branch_id: String,
        source_cut_id: String,
        fork_evidence_handle: String,
        home: BranchHomeReceiptV1,
    },
    HistoricalHomeClosed {
        stream_id: String,
    },
    DestinationMissing {
        stream_id: String,
    },
    DestinationReserved {
        stream_id: String,
    },
    DestinationChanged {
        detail: String,
    },
    ForkRefused(ExactInstanceForkBinding),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ExactForkAdmissionV1 {
    pub schema: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_cut_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork_evidence_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home: Option<BranchHomeReceiptV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ExactForkAdmissionOutcome {
    pub fn receipt(&self) -> ExactForkAdmissionV1 {
        let mut receipt = ExactForkAdmissionV1 {
            schema: "exact_fork_admission_v1".to_owned(),
            outcome: String::new(),
            branch_id: None,
            source_cut_id: None,
            fork_evidence_handle: None,
            home: None,
            stream_id: None,
            detail: None,
        };
        match self {
            Self::Forked {
                branch_id,
                source_cut_id,
                fork_evidence_handle,
                home,
            } => {
                receipt.outcome = "forked".to_owned();
                receipt.branch_id = Some(branch_id.clone());
                receipt.source_cut_id = Some(source_cut_id.clone());
                receipt.fork_evidence_handle = Some(fork_evidence_handle.clone());
                receipt.home = Some(home.clone());
            }
            Self::HistoricalHomeClosed { stream_id } => {
                receipt.outcome = "historical_home_closed".to_owned();
                receipt.stream_id = Some(stream_id.clone());
            }
            Self::DestinationMissing { stream_id } => {
                receipt.outcome = "destination_missing".to_owned();
                receipt.stream_id = Some(stream_id.clone());
            }
            Self::DestinationReserved { stream_id } => {
                receipt.outcome = "destination_reserved".to_owned();
                receipt.stream_id = Some(stream_id.clone());
            }
            Self::DestinationChanged { detail } => {
                receipt.outcome = "destination_changed".to_owned();
                receipt.detail = Some(detail.clone());
            }
            Self::ForkRefused(detail) => {
                receipt.outcome = "fork_refused".to_owned();
                receipt.detail = Some(format!("{detail:?}"));
            }
        }
        receipt
    }
}

/// DR-0078 exact historical fork coordinator. Destination validity is checked
/// before any branch operation. For a named destination, the future stable
/// branch id is admitted first through the authoritative single-valued home
/// store; the exact source cut is then forked without reading the destination
/// line head. Hosts serialize this coordinator with their workspace mediator,
/// just as they serialize ordinary topology commands.
#[allow(clippy::too_many_arguments)]
pub fn fork_at_cut_and_admit<W, B, C>(
    streams: &mut W,
    vcs: &mut WorkspaceVcs<B, C>,
    source_instance: &str,
    source_cut_id: &str,
    target_instance: &str,
    fork_branch_id: &str,
    name: Option<&str>,
    destination: ExactForkDestination<'_>,
    at: &str,
) -> StoreResult<ExactForkAdmissionOutcome>
where
    W: Workstreams,
    B: Branches,
    C: ContentBlobs,
{
    let admitted_stream = match destination {
        ExactForkDestination::Main => None,
        ExactForkDestination::Workstream(stream_id) => {
            let Some(stream) = streams.get_stream(stream_id)? else {
                return Ok(ExactForkAdmissionOutcome::DestinationMissing {
                    stream_id: stream_id.to_owned(),
                });
            };
            match stream.status {
                StreamStatus::Archived => {
                    return Ok(ExactForkAdmissionOutcome::HistoricalHomeClosed {
                        stream_id: stream_id.to_owned(),
                    })
                }
                StreamStatus::BoundaryReserved | StreamStatus::RefAdvanced => {
                    return Ok(ExactForkAdmissionOutcome::DestinationReserved {
                        stream_id: stream_id.to_owned(),
                    })
                }
                StreamStatus::Active => {}
            }
            match streams.transfer(fork_branch_id, stream_id, at)? {
                JoinOutcome::Joined { .. } => Some(stream_id),
                other => {
                    return Ok(ExactForkAdmissionOutcome::DestinationChanged {
                        detail: format!("{other:?}"),
                    })
                }
            }
        }
    };

    let fork = vcs.fork_binding_for_instance_at_cut(
        source_instance,
        source_cut_id,
        target_instance,
        fork_branch_id,
        name,
        at,
    )?;
    let ExactInstanceForkBinding::Forked {
        source_cut_id,
        fork_branch,
        evidence_handle,
        ..
    } = fork
    else {
        if admitted_stream.is_some() {
            // No branch exists on every refusal from the exact fork preflight.
            // Remove the prospective membership so failure is externally null.
            let _ = streams.leave(fork_branch_id);
        }
        return Ok(ExactForkAdmissionOutcome::ForkRefused(fork));
    };
    let home = streams.home_receipt(&fork_branch.branch_id)?;
    let fork_evidence_handle = format!(
        "sha256:{}",
        crate::chunking::content_hash_hex(
            format!(
                "exact-fork-admission-v1|{evidence_handle}|{}",
                home.evidence_handle
            )
            .as_bytes()
        )
    );
    Ok(ExactForkAdmissionOutcome::Forked {
        branch_id: fork_branch.branch_id,
        source_cut_id,
        fork_evidence_handle,
        home,
    })
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
        crate::establish_wal(&connection)?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
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
                 reservation_id, expected_line_cut, expected_main_cut, proposed_main_cut, \
                 ref_position, ref_receipt_handle, created_at, updated_at \
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
        reservation_id: row.get(5)?,
        expected_line_cut: row.get(6)?,
        expected_main_cut: row.get(7)?,
        proposed_main_cut: row.get(8)?,
        ref_position: row
            .get::<_, Option<i64>>(9)?
            .and_then(|position| u64::try_from(position).ok()),
        ref_receipt_handle: row.get(10)?,
        created_at: row.get(11)?,
        updated_at: row.get(12)?,
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
        CREATE TABLE IF NOT EXISTS workstream_members (
            branch_id TEXT PRIMARY KEY,
            stream_id TEXT NOT NULL,
            joined_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS workstream_members_stream_idx
            ON workstream_members(stream_id);
        CREATE TABLE IF NOT EXISTS workstream_home_positions (
            branch_id TEXT PRIMARY KEY,
            authority_position INTEGER NOT NULL,
            home_stream_id TEXT,
            recorded_at TEXT NOT NULL
        );
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
    for (name, sql_type) in [
        ("reservation_id", "TEXT"),
        ("expected_line_cut", "TEXT"),
        ("expected_main_cut", "TEXT"),
        ("proposed_main_cut", "TEXT"),
        ("ref_position", "INTEGER"),
        ("ref_receipt_handle", "TEXT"),
    ] {
        if !columns.iter().any(|column| column == name) {
            connection.execute(
                &format!("ALTER TABLE workstreams ADD COLUMN {name} {sql_type}"),
                [],
            )?;
        }
    }
    // Reservations retain the live name. The prior partial index covered only
    // `active`, which would let a second stream claim the name while the first
    // was frozen.
    connection.execute_batch(
        "DROP INDEX IF EXISTS workstreams_active_name_idx;
         CREATE UNIQUE INDEX IF NOT EXISTS workstreams_live_name_idx
           ON workstreams(name)
           WHERE name IS NOT NULL AND status != 'archived';
         INSERT OR IGNORE INTO workstream_home_positions
           (branch_id, authority_position, home_stream_id, recorded_at)
           SELECT branch_id, 1, stream_id, joined_at FROM workstream_members;",
    )?;
    Ok(())
}

#[cfg(feature = "native")]
impl WorkstreamStore {
    fn record_home_position(
        tx: &rusqlite::Transaction<'_>,
        branch_id: &str,
        stream_id: Option<&str>,
        at: &str,
    ) -> StoreResult<()> {
        tx.execute(
            "INSERT INTO workstream_home_positions
               (branch_id, authority_position, home_stream_id, recorded_at)
             VALUES (?1, 1, ?2, ?3)
             ON CONFLICT(branch_id) DO UPDATE SET
               authority_position = authority_position + 1,
               home_stream_id = ?2,
               recorded_at = ?3",
            params![branch_id, stream_id, at],
        )?;
        Ok(())
    }

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
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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
                     WHERE name = ?1 AND status != 'archived'",
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
                    "SELECT stream_id, name, line_branch_id, status, staleness_seconds, \
                     reservation_id, expected_line_cut, expected_main_cut, proposed_main_cut, \
                     ref_position, ref_receipt_handle, created_at, updated_at \
                     FROM workstreams WHERE status = ?1 ORDER BY stream_id",
                )?;
                let mapped = stmt.query_map(params![status.as_str()], map_stream_row)?;
                for row in mapped {
                    rows.push(row?);
                }
            }
            None => {
                let mut stmt = self.connection.prepare(
                    "SELECT stream_id, name, line_branch_id, status, staleness_seconds, \
                     reservation_id, expected_line_cut, expected_main_cut, proposed_main_cut, \
                     ref_position, ref_receipt_handle, created_at, updated_at \
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
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(stream) = Self::stream_by_id(&tx, stream_id)? else {
            return Ok(JoinOutcome::StreamMissing);
        };
        match stream.status {
            StreamStatus::Active => {}
            StreamStatus::BoundaryReserved | StreamStatus::RefAdvanced => {
                return Ok(JoinOutcome::StreamReserved)
            }
            StreamStatus::Archived => return Ok(JoinOutcome::StreamArchived),
        }
        let previous: Option<String> = tx
            .query_row(
                "SELECT stream_id FROM workstream_members WHERE branch_id = ?1",
                params![branch_id],
                |row| row.get(0),
            )
            .optional()?;
        if previous.as_deref() == Some(stream_id) {
            // Idempotent retry: the authoritative fact did not change, so its
            // evidence position must not change either.
            tx.commit()?;
            return Ok(JoinOutcome::Joined {
                left_stream_id: None,
            });
        }
        if let Some(previous_id) = previous.as_deref().filter(|id| *id != stream_id) {
            if let Some(source) = Self::stream_by_id(&tx, previous_id)? {
                if matches!(
                    source.status,
                    StreamStatus::BoundaryReserved | StreamStatus::RefAdvanced
                ) {
                    return Ok(JoinOutcome::SourceReserved {
                        stream_id: previous_id.to_owned(),
                    });
                }
            }
        }
        // The primary key on branch_id makes membership single-valued: the
        // upsert IS the leave-then-join, one atomic step.
        tx.execute(
            "INSERT INTO workstream_members (branch_id, stream_id, joined_at) \
             VALUES (?1, ?2, ?3) \
             ON CONFLICT(branch_id) DO UPDATE SET stream_id = ?2, joined_at = ?3",
            params![branch_id, stream_id, at],
        )?;
        Self::record_home_position(&tx, branch_id, Some(stream_id), at)?;
        tx.commit()?;
        Ok(JoinOutcome::Joined {
            left_stream_id: previous.filter(|prev| prev != stream_id),
        })
    }

    fn leave(&mut self, branch_id: &str) -> StoreResult<Option<String>> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT stream_id FROM workstream_members WHERE branch_id = ?1",
                params![branch_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(previous_id) = previous.as_deref() {
            if let Some(source) = Self::stream_by_id(&tx, previous_id)? {
                if matches!(
                    source.status,
                    StreamStatus::BoundaryReserved | StreamStatus::RefAdvanced
                ) {
                    return Err(StoreError::Conflict(format!(
                        "workstream `{previous_id}` has a reserved promotion boundary"
                    )));
                }
            }
        }
        tx.execute(
            "DELETE FROM workstream_members WHERE branch_id = ?1",
            params![branch_id],
        )?;
        if previous.is_some() {
            Self::record_home_position(&tx, branch_id, None, "leave")?;
        }
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

    fn home_receipt(&self, branch_id: &str) -> StoreResult<BranchHomeReceiptV1> {
        let stream_id = self.home_of(branch_id)?;
        let stream = match stream_id.as_deref() {
            Some(stream_id) => Self::stream_by_id(&self.connection, stream_id)?,
            None => None,
        };
        let position: Option<(i64, String)> = self
            .connection
            .query_row(
                "SELECT authority_position, recorded_at
                 FROM workstream_home_positions WHERE branch_id = ?1",
                params![branch_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let authority_position = position
            .as_ref()
            .and_then(|(value, _)| u64::try_from(*value).ok())
            .unwrap_or(0);
        let line_branch_id = stream.as_ref().map(|row| row.line_branch_id.clone());
        let stream_status = stream.as_ref().map(|row| row.status);
        let evidence_handle = branch_home_evidence_handle(
            branch_id,
            stream_id.as_deref(),
            line_branch_id.as_deref(),
            stream_status,
            authority_position,
        );
        Ok(BranchHomeReceiptV1 {
            schema: "branch_home_receipt_v1".to_owned(),
            branch_id: branch_id.to_owned(),
            stream_id,
            line_branch_id,
            stream_status,
            authority_position,
            evidence_handle,
            recorded_at: position.map(|(_, at)| at),
        })
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
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(stream) = Self::stream_by_id(&tx, stream_id)? else {
            return Ok(ArchiveOutcome::StreamMissing);
        };
        match stream.status {
            StreamStatus::Active => {}
            StreamStatus::BoundaryReserved => return Ok(ArchiveOutcome::BoundaryReserved),
            StreamStatus::RefAdvanced => return Ok(ArchiveOutcome::RefAlreadyAdvanced),
            StreamStatus::Archived => return Ok(ArchiveOutcome::AlreadyArchived),
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
        for branch_id in &rehomed {
            Self::record_home_position(&tx, branch_id, None, at)?;
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

    fn reserve_boundary(
        &mut self,
        stream_id: &str,
        reservation: BoundaryReservation<'_>,
    ) -> StoreResult<ReserveBoundaryOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(stream) = Self::stream_by_id(&tx, stream_id)? else {
            return Ok(ReserveBoundaryOutcome::StreamMissing);
        };
        match stream.status {
            StreamStatus::Archived => return Ok(ReserveBoundaryOutcome::StreamArchived),
            StreamStatus::BoundaryReserved | StreamStatus::RefAdvanced => {
                if stream.reservation_id.as_deref() == Some(reservation.reservation_id) {
                    let exact = stream.expected_line_cut.as_deref()
                        == Some(reservation.expected_line_cut)
                        && stream.expected_main_cut.as_deref()
                            == Some(reservation.expected_main_cut)
                        && stream.proposed_main_cut.as_deref()
                            == Some(reservation.proposed_main_cut);
                    if exact {
                        return Ok(ReserveBoundaryOutcome::Existing(stream));
                    }
                }
                return Ok(ReserveBoundaryOutcome::Busy {
                    holder_reservation_id: stream.reservation_id.unwrap_or_default(),
                });
            }
            StreamStatus::Active => {}
        }
        tx.execute(
            "UPDATE workstreams SET status = 'boundary_reserved', reservation_id = ?2, \
             expected_line_cut = ?3, expected_main_cut = ?4, proposed_main_cut = ?5, \
             ref_position = NULL, ref_receipt_handle = NULL, updated_at = ?6 \
             WHERE stream_id = ?1 AND status = 'active'",
            params![
                stream_id,
                reservation.reservation_id,
                reservation.expected_line_cut,
                reservation.expected_main_cut,
                reservation.proposed_main_cut,
                reservation.at,
            ],
        )?;
        let row = Self::stream_by_id(&tx, stream_id)?.expect("reserved stream");
        tx.commit()?;
        Ok(ReserveBoundaryOutcome::Reserved(row))
    }

    fn release_boundary(
        &mut self,
        stream_id: &str,
        reservation_id: &str,
        at: &str,
    ) -> StoreResult<ReleaseBoundaryOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(stream) = Self::stream_by_id(&tx, stream_id)? else {
            return Ok(ReleaseBoundaryOutcome::StreamMissing);
        };
        match stream.status {
            StreamStatus::Active => return Ok(ReleaseBoundaryOutcome::AlreadyActive),
            StreamStatus::Archived => return Ok(ReleaseBoundaryOutcome::StreamArchived),
            StreamStatus::RefAdvanced => return Ok(ReleaseBoundaryOutcome::RefAlreadyAdvanced),
            StreamStatus::BoundaryReserved => {}
        }
        if stream.reservation_id.as_deref() != Some(reservation_id) {
            return Ok(ReleaseBoundaryOutcome::ReservationMismatch);
        }
        tx.execute(
            "UPDATE workstreams SET status = 'active', reservation_id = NULL, \
             expected_line_cut = NULL, expected_main_cut = NULL, \
             proposed_main_cut = NULL, ref_position = NULL, \
             ref_receipt_handle = NULL, updated_at = ?3 \
             WHERE stream_id = ?1 AND reservation_id = ?2 \
               AND status = 'boundary_reserved'",
            params![stream_id, reservation_id, at],
        )?;
        tx.commit()?;
        Ok(ReleaseBoundaryOutcome::Released)
    }

    fn record_ref_advanced(
        &mut self,
        stream_id: &str,
        reservation_id: &str,
        ref_position: u64,
        ref_receipt_handle: &str,
        at: &str,
    ) -> StoreResult<RecordRefAdvancedOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(stream) = Self::stream_by_id(&tx, stream_id)? else {
            return Ok(RecordRefAdvancedOutcome::StreamMissing);
        };
        if stream.status == StreamStatus::Archived {
            return Ok(RecordRefAdvancedOutcome::StreamArchived);
        }
        if stream.reservation_id.as_deref() != Some(reservation_id) {
            return Ok(RecordRefAdvancedOutcome::ReservationMismatch);
        }
        if stream.status == StreamStatus::RefAdvanced {
            if stream.ref_position == Some(ref_position)
                && stream.ref_receipt_handle.as_deref() == Some(ref_receipt_handle)
            {
                return Ok(RecordRefAdvancedOutcome::Existing(stream));
            }
            return Ok(RecordRefAdvancedOutcome::ReservationMismatch);
        }
        if stream.status != StreamStatus::BoundaryReserved {
            return Ok(RecordRefAdvancedOutcome::NotReserved);
        }
        let ref_position = i64::try_from(ref_position).map_err(|_| {
            StoreError::Conflict("ref authority position exceeds SQLite range".to_owned())
        })?;
        tx.execute(
            "UPDATE workstreams SET status = 'ref_advanced', ref_position = ?3, \
             ref_receipt_handle = ?4, updated_at = ?5 \
             WHERE stream_id = ?1 AND reservation_id = ?2 \
               AND status = 'boundary_reserved'",
            params![
                stream_id,
                reservation_id,
                ref_position,
                ref_receipt_handle,
                at
            ],
        )?;
        let row = Self::stream_by_id(&tx, stream_id)?.expect("advanced stream");
        tx.commit()?;
        Ok(RecordRefAdvancedOutcome::Recorded(row))
    }

    fn close_promoted(
        &mut self,
        stream_id: &str,
        reservation_id: &str,
        at: &str,
    ) -> StoreResult<ClosePromotedOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(stream) = Self::stream_by_id(&tx, stream_id)? else {
            return Ok(ClosePromotedOutcome::StreamMissing);
        };
        if stream.reservation_id.as_deref() != Some(reservation_id) {
            return Ok(ClosePromotedOutcome::ReservationMismatch);
        }
        if stream.status == StreamStatus::Archived {
            return Ok(ClosePromotedOutcome::AlreadyClosed);
        }
        if stream.status != StreamStatus::RefAdvanced {
            return Ok(ClosePromotedOutcome::RefNotAdvanced);
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
        for branch_id in &rehomed {
            Self::record_home_position(&tx, branch_id, None, at)?;
        }
        tx.execute(
            "DELETE FROM workstream_members WHERE stream_id = ?1",
            params![stream_id],
        )?;
        tx.execute(
            "UPDATE workstreams SET status = 'archived', updated_at = ?3 \
             WHERE stream_id = ?1 AND reservation_id = ?2 \
               AND status = 'ref_advanced'",
            params![stream_id, reservation_id, at],
        )?;
        tx.commit()?;
        Ok(ClosePromotedOutcome::Closed {
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

    #[test]
    fn home_receipt_positions_distinguish_rejoin_history() {
        let mut store = store();
        store
            .create_stream("one", None, "line-one", "t0", None)
            .expect("one");
        store
            .create_stream("two", None, "line-two", "t0", None)
            .expect("two");
        store.join("branch", "one", "t1").expect("join one");
        let first = store.home_receipt("branch").expect("first receipt");
        assert_eq!(first.schema, "branch_home_receipt_v1");
        assert_eq!(first.authority_position, 1);
        assert_eq!(first.stream_id.as_deref(), Some("one"));

        // An idempotent retry is the same authority fact.
        store.join("branch", "one", "t2").expect("retry one");
        assert_eq!(store.home_receipt("branch").expect("retry"), first);

        store.transfer("branch", "two", "t3").expect("transfer");
        let second = store.home_receipt("branch").expect("second receipt");
        assert_eq!(second.authority_position, 2);
        assert_ne!(second.evidence_handle, first.evidence_handle);
        store.transfer("branch", "one", "t4").expect("rejoin one");
        let rejoined = store.home_receipt("branch").expect("rejoined receipt");
        assert_eq!(rejoined.authority_position, 3);
        assert_eq!(rejoined.stream_id.as_deref(), Some("one"));
        assert_ne!(rejoined.evidence_handle, first.evidence_handle);
    }

    #[test]
    fn exact_fork_admission_keeps_source_content_and_rejects_closed_home_first() {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-exact-fork-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let mut vcs = crate::vcs::NativeWorkspaceVcs::open(
            dir.join("branches.sqlite"),
            dir.join("content.sqlite"),
        )
        .expect("vcs");
        vcs.init("t0").expect("init");
        vcs.create_branch("chat", None, crate::branches::MAINLINE_BRANCH_ID, "t1")
            .expect("chat");
        vcs.bind_instance("parent", "chat", "t1")
            .expect("bind parent");
        vcs.write("chat", "state.txt", Some("point"), "chat-1", "t2")
            .expect("point");
        vcs.write("chat", "state.txt", Some("new tip"), "chat-2", "t3")
            .expect("tip");
        vcs.create_branch("line-live", None, crate::branches::MAINLINE_BRANCH_ID, "t3")
            .expect("line");
        vcs.write(
            "line-live",
            "state.txt",
            Some("destination head"),
            "line-1",
            "t4",
        )
        .expect("line head");

        let mut streams = store();
        streams
            .create_stream("live", None, "line-live", "t4", None)
            .expect("live stream");
        let forked = fork_at_cut_and_admit(
            &mut streams,
            &mut vcs,
            "parent",
            "chat-1",
            "child",
            "chat-child",
            None,
            ExactForkDestination::Workstream("live"),
            "t5",
        )
        .expect("fork");
        let fork_receipt = forked.receipt();
        assert_eq!(fork_receipt.schema, "exact_fork_admission_v1");
        assert_eq!(fork_receipt.outcome, "forked");
        let ExactForkAdmissionOutcome::Forked { home, .. } = forked else {
            panic!("expected admitted fork");
        };
        assert_eq!(home.stream_id.as_deref(), Some("live"));
        assert_eq!(
            vcs.read("chat-child", "state.txt").expect("child read"),
            Some("point".to_owned()),
            "destination admission must not rematerialize its head"
        );

        streams
            .create_stream("closed", None, "line-closed", "t6", None)
            .expect("closed stream");
        streams.archive_stream("closed", "t7").expect("archive");
        let refused = fork_at_cut_and_admit(
            &mut streams,
            &mut vcs,
            "parent",
            "chat-1",
            "child-closed",
            "chat-child-closed",
            None,
            ExactForkDestination::Workstream("closed"),
            "t8",
        )
        .expect("closed refusal");
        assert_eq!(
            refused,
            ExactForkAdmissionOutcome::HistoricalHomeClosed {
                stream_id: "closed".to_owned()
            }
        );
        assert_eq!(refused.receipt().outcome, "historical_home_closed");
        assert!(vcs
            .get_branch("chat-child-closed")
            .expect("branch lookup")
            .is_none());
        assert_eq!(streams.home_of("chat-child-closed").expect("home"), None);
        let _ = std::fs::remove_dir_all(dir);
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

    fn reservation<'a>(id: &'a str) -> BoundaryReservation<'a> {
        BoundaryReservation {
            reservation_id: id,
            expected_line_cut: "line-cut-1",
            expected_main_cut: "main-cut-1",
            proposed_main_cut: "main-cut-2",
            at: "t2",
        }
    }

    #[test]
    fn reservation_freezes_both_sides_of_atomic_transfer() {
        let mut store = store();
        store
            .create_stream("source", None, "line-source", "t0", None)
            .expect("source");
        store
            .create_stream("dest", None, "line-dest", "t0", None)
            .expect("dest");
        store.join("branch", "source", "t1").expect("join");
        assert!(matches!(
            store
                .reserve_boundary("source", reservation("reservation-source"))
                .expect("reserve"),
            ReserveBoundaryOutcome::Reserved(_)
        ));
        assert_eq!(
            store.join("branch", "dest", "t3").expect("transfer"),
            JoinOutcome::SourceReserved {
                stream_id: "source".to_owned()
            }
        );
        assert!(store.leave("branch").is_err());
        assert_eq!(
            store.archive_stream("source", "t3").expect("archive"),
            ArchiveOutcome::BoundaryReserved
        );
        assert_eq!(
            store.home_of("branch").expect("home"),
            Some("source".into())
        );
    }

    #[test]
    fn concurrent_boundary_reservations_have_one_winner() {
        let path = std::env::temp_dir().join(format!(
            "whipplescript-workstream-race-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let mut setup = WorkstreamStore::open(&path).expect("setup store");
        setup
            .create_stream("ws", None, "line-ws", "t0", None)
            .expect("stream");
        drop(setup);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut joins = Vec::new();
        for reservation_id in ["race-a", "race-b"] {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                let mut store = WorkstreamStore::open(path).expect("racing store");
                barrier.wait();
                store
                    .reserve_boundary(
                        "ws",
                        BoundaryReservation {
                            reservation_id,
                            expected_line_cut: "line-1",
                            expected_main_cut: "main-1",
                            proposed_main_cut: reservation_id,
                            at: "race",
                        },
                    )
                    .expect("reserve")
            }));
        }
        barrier.wait();
        let outcomes = joins
            .into_iter()
            .map(|join| join.join().expect("thread"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ReserveBoundaryOutcome::Reserved(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ReserveBoundaryOutcome::Busy { .. }))
                .count(),
            1
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn promotion_state_is_idempotent_and_closes_only_forward() {
        let mut store = store();
        store
            .create_stream("ws", Some("shared"), "line-ws", "t0", None)
            .expect("create");
        store.join("a", "ws", "t1").expect("join");
        let ReserveBoundaryOutcome::Reserved(reserved) = store
            .reserve_boundary("ws", reservation("reservation-1"))
            .expect("reserve")
        else {
            panic!("reservation did not land");
        };
        assert_eq!(reserved.status, StreamStatus::BoundaryReserved);
        assert!(matches!(
            store
                .reserve_boundary("ws", reservation("reservation-1"))
                .expect("retry"),
            ReserveBoundaryOutcome::Existing(_)
        ));
        assert_eq!(
            store
                .release_boundary("ws", "stale-reservation", "t3")
                .expect("stale release"),
            ReleaseBoundaryOutcome::ReservationMismatch
        );
        let RecordRefAdvancedOutcome::Recorded(advanced) = store
            .record_ref_advanced("ws", "reservation-1", 7, "sha256:receipt", "t4")
            .expect("record")
        else {
            panic!("ref advance was not recorded");
        };
        assert_eq!(advanced.status, StreamStatus::RefAdvanced);
        assert_eq!(
            store
                .release_boundary("ws", "reservation-1", "t5")
                .expect("rollback"),
            ReleaseBoundaryOutcome::RefAlreadyAdvanced
        );
        assert_eq!(
            store
                .close_promoted("ws", "reservation-1", "t6")
                .expect("close"),
            ClosePromotedOutcome::Closed {
                rehomed_branch_ids: vec!["a".to_owned()]
            }
        );
        assert_eq!(
            store
                .close_promoted("ws", "reservation-1", "t7")
                .expect("close retry"),
            ClosePromotedOutcome::AlreadyClosed
        );
        let receipt = store
            .get_stream("ws")
            .expect("read")
            .expect("stream")
            .boundary_receipt("sha256:workspace")
            .expect("receipt");
        assert_eq!(receipt.schema, "workstream_boundary_receipt_v1");
        assert_eq!(receipt.outcome, "archived");
        assert_eq!(receipt.main_ref_position, Some(7));
    }

    #[test]
    fn conflict_release_returns_to_active_without_evidence() {
        let mut store = store();
        store
            .create_stream("ws", None, "line-ws", "t0", None)
            .expect("create");
        store
            .reserve_boundary("ws", reservation("reservation-1"))
            .expect("reserve");
        assert_eq!(
            store
                .release_boundary("ws", "reservation-1", "t3")
                .expect("release"),
            ReleaseBoundaryOutcome::Released
        );
        let row = store.get_stream("ws").expect("read").expect("stream");
        assert_eq!(row.status, StreamStatus::Active);
        assert!(row.reservation_id.is_none());
        assert!(row.boundary_receipt("workspace").is_none());
    }

    #[test]
    fn migrates_prior_active_and_archived_rows() {
        let connection = Connection::open_in_memory().expect("sqlite");
        connection
            .execute_batch(
                "CREATE TABLE workstreams (
                   stream_id TEXT PRIMARY KEY, name TEXT, line_branch_id TEXT NOT NULL,
                   status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                   idempotency_key TEXT, staleness_seconds INTEGER
                 );
                 CREATE TABLE workstream_members (
                   branch_id TEXT PRIMARY KEY, stream_id TEXT NOT NULL, joined_at TEXT NOT NULL
                 );
                 INSERT INTO workstreams VALUES
                   ('active', 'live', 'line-active', 'active', 't0', 't0', NULL, NULL),
                   ('closed', 'old', 'line-closed', 'archived', 't0', 't1', NULL, NULL);
                 INSERT INTO workstream_members VALUES
                   ('legacy-branch', 'active', 't0');",
            )
            .expect("prior schema");
        ensure_workstream_schema(&connection).expect("migration");
        let active = WorkstreamStore::stream_by_id(&connection, "active")
            .expect("active read")
            .expect("active row");
        let closed = WorkstreamStore::stream_by_id(&connection, "closed")
            .expect("closed read")
            .expect("closed row");
        assert_eq!(active.status, StreamStatus::Active);
        assert_eq!(closed.status, StreamStatus::Archived);
        assert!(active.reservation_id.is_none());
        assert!(closed.ref_receipt_handle.is_none());
        let migrated = WorkstreamStore { connection };
        let home = migrated
            .home_receipt("legacy-branch")
            .expect("migrated home receipt");
        assert_eq!(home.authority_position, 1);
        assert_eq!(home.stream_id.as_deref(), Some("active"));
    }
}
