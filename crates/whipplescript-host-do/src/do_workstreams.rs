//! Durable-object workstream tier: the `Workstreams` seam over the DO's
//! SQLite, so streams / membership / staleness run on the DO with the
//! SAME store-crate logic as native — parity by reuse (native
//! counterpart `whipplescript-store/src/workstreams.rs`; DR-0052 S1/S2
//! DO-parity residual, closed 2026-07-31).
//!
//! Semantics mirror the native store exactly: the stream owns a NAME and
//! a MEMBERSHIP set (single-valued BY SCHEMA — the member table's
//! primary key is the branch id, so the upsert IS leave-then-join, one
//! atomic step); the merge engine owns every line advance; archive
//! re-homes members. The DO is single-writer, so the native store's
//! transactions collapse to plain statement sequences (the do_branches
//! posture).

use whipplescript_store::workstreams::{
    branch_home_evidence_handle, AcknowledgeBoundaryReleaseOutcome, ArchiveOutcome,
    BoundaryReservation, BranchHomeReceiptV1, ClosePromotedOutcome, CreateStreamOutcome,
    JoinOutcome, RecordRefAdvancedOutcome, ReleaseBoundaryOutcome, ReserveBoundaryOutcome,
    StreamStatus, WorkstreamRow, Workstreams,
};
use whipplescript_store::{StoreError, StoreResult};

use crate::do_store::{as_opt_text, as_text, opt_text, sql_err, text, DoSql, SqlValue};

pub struct DoWorkstreams<S: DoSql> {
    sql: S,
}

impl<S: DoSql> DoWorkstreams<S> {
    pub fn new(sql: S) -> StoreResult<Self> {
        let store = Self { sql };
        store.ensure_schema()?;
        Ok(store)
    }

    fn ensure_schema(&self) -> StoreResult<()> {
        for statement in [
            "CREATE TABLE IF NOT EXISTS workstreams (
                stream_id TEXT PRIMARY KEY,
                name TEXT,
                line_branch_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                idempotency_key TEXT
            )",
            "CREATE UNIQUE INDEX IF NOT EXISTS workstreams_idempotency_idx
                ON workstreams(idempotency_key)
                WHERE idempotency_key IS NOT NULL",
            "CREATE TABLE IF NOT EXISTS workstream_members (
                branch_id TEXT PRIMARY KEY,
                stream_id TEXT NOT NULL,
                joined_at TEXT NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS workstream_members_stream_idx
                ON workstream_members(stream_id)",
            "CREATE TABLE IF NOT EXISTS workstream_home_positions (
                branch_id TEXT PRIMARY KEY,
                authority_position INTEGER NOT NULL,
                home_stream_id TEXT,
                recorded_at TEXT NOT NULL
            )",
        ] {
            self.sql.execute(statement, &[]).map_err(sql_err)?;
        }
        // The staleness bound arrived with DR-0052 S1 (exactly as native):
        // earlier stores gain the column in place (NULL = unbounded).
        let info = self
            .sql
            .query("PRAGMA table_info(workstreams)", &[])
            .map_err(sql_err)?;
        for (name, sql_type) in [
            ("staleness_seconds", "INTEGER"),
            ("reservation_id", "TEXT"),
            ("expected_line_cut", "TEXT"),
            ("expected_main_cut", "TEXT"),
            ("proposed_main_cut", "TEXT"),
            ("ref_position", "INTEGER"),
            ("ref_receipt_handle", "TEXT"),
        ] {
            let present = info.iter().any(|row| {
                row.get(1)
                    .map(|value| as_text(value) == name)
                    .unwrap_or(false)
            });
            if !present {
                self.sql
                    .execute(
                        &format!("ALTER TABLE workstreams ADD COLUMN {name} {sql_type}"),
                        &[],
                    )
                    .map_err(sql_err)?;
            }
        }
        self.sql
            .execute("DROP INDEX IF EXISTS workstreams_active_name_idx", &[])
            .map_err(sql_err)?;
        self.sql
            .execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS workstreams_live_name_idx
                   ON workstreams(name)
                   WHERE name IS NOT NULL AND status != 'archived'",
                &[],
            )
            .map_err(sql_err)?;
        self.sql
            .execute(
                "INSERT OR IGNORE INTO workstream_home_positions
                   (branch_id, authority_position, home_stream_id, recorded_at)
                 SELECT branch_id, 1, stream_id, joined_at FROM workstream_members",
                &[],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    const ROW_COLUMNS: &'static str = "stream_id, name, line_branch_id, status, \
        staleness_seconds, reservation_id, expected_line_cut, expected_main_cut, \
        proposed_main_cut, ref_position, ref_receipt_handle, created_at, updated_at";

    fn decode_row(row: &[SqlValue]) -> WorkstreamRow {
        WorkstreamRow {
            stream_id: as_text(&row[0]),
            name: as_opt_text(&row[1]),
            line_branch_id: as_text(&row[2]),
            status: StreamStatus::parse(&as_text(&row[3])).unwrap_or(StreamStatus::Active),
            staleness_seconds: match &row[4] {
                SqlValue::Int(value) => Some(*value),
                _ => None,
            },
            reservation_id: as_opt_text(&row[5]),
            expected_line_cut: as_opt_text(&row[6]),
            expected_main_cut: as_opt_text(&row[7]),
            proposed_main_cut: as_opt_text(&row[8]),
            ref_position: match &row[9] {
                SqlValue::Int(value) => u64::try_from(*value).ok(),
                _ => None,
            },
            ref_receipt_handle: as_opt_text(&row[10]),
            created_at: as_text(&row[11]),
            updated_at: as_text(&row[12]),
        }
    }

    fn row_by_id(&self, stream_id: &str) -> StoreResult<Option<WorkstreamRow>> {
        let rows = self
            .sql
            .query(
                &format!(
                    "SELECT {} FROM workstreams WHERE stream_id = ?1",
                    Self::ROW_COLUMNS
                ),
                &[text(stream_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| Self::decode_row(row)))
    }

    fn record_home_position(
        &self,
        branch_id: &str,
        stream_id: Option<&str>,
        at: &str,
    ) -> StoreResult<()> {
        self.sql
            .execute(
                "INSERT INTO workstream_home_positions
                   (branch_id, authority_position, home_stream_id, recorded_at)
                 VALUES (?1, 1, ?2, ?3)
                 ON CONFLICT(branch_id) DO UPDATE SET
                   authority_position = authority_position + 1,
                   home_stream_id = ?2,
                   recorded_at = ?3",
                &[text(branch_id), opt_text(stream_id), text(at)],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    /// Set (or clear) the staleness bound — governance surface, exactly
    /// as native.
    pub fn set_staleness(
        &mut self,
        stream_id: &str,
        staleness_seconds: Option<i64>,
        at: &str,
    ) -> StoreResult<Option<WorkstreamRow>> {
        self.sql
            .execute(
                "UPDATE workstreams SET staleness_seconds = ?2, updated_at = ?3 \
                 WHERE stream_id = ?1",
                &[
                    text(stream_id),
                    match staleness_seconds {
                        Some(seconds) => SqlValue::Int(seconds),
                        None => SqlValue::Null,
                    },
                    text(at),
                ],
            )
            .map_err(sql_err)?;
        self.row_by_id(stream_id)
    }
}

impl<S: DoSql> Workstreams for DoWorkstreams<S> {
    fn create_stream(
        &mut self,
        stream_id: &str,
        name: Option<&str>,
        line_branch_id: &str,
        created_at: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<CreateStreamOutcome> {
        if let Some(existing) = self.row_by_id(stream_id)? {
            return Ok(CreateStreamOutcome::Existing(existing));
        }
        if let Some(key) = idempotency_key {
            let rows = self
                .sql
                .query(
                    "SELECT stream_id FROM workstreams WHERE idempotency_key = ?1",
                    &[text(key)],
                )
                .map_err(sql_err)?;
            if let Some(row) = rows.first() {
                let existing_id = as_text(&row[0]);
                let row = self
                    .row_by_id(&existing_id)?
                    .ok_or_else(|| StoreError::Conflict("row for key vanished".to_owned()))?;
                return Ok(CreateStreamOutcome::Existing(row));
            }
        }
        if let Some(name) = name {
            let rows = self
                .sql
                .query(
                    "SELECT stream_id FROM workstreams \
                     WHERE name = ?1 AND status != 'archived'",
                    &[text(name)],
                )
                .map_err(sql_err)?;
            if let Some(row) = rows.first() {
                return Ok(CreateStreamOutcome::NameTaken {
                    holder_stream_id: as_text(&row[0]),
                });
            }
        }
        self.sql
            .execute(
                "INSERT INTO workstreams \
                 (stream_id, name, line_branch_id, status, created_at, updated_at, \
                  idempotency_key) \
                 VALUES (?1, ?2, ?3, 'active', ?4, ?4, ?5)",
                &[
                    text(stream_id),
                    opt_text(name),
                    text(line_branch_id),
                    text(created_at),
                    opt_text(idempotency_key),
                ],
            )
            .map_err(sql_err)?;
        let row = self
            .row_by_id(stream_id)?
            .ok_or_else(|| StoreError::Conflict("created stream missing".to_owned()))?;
        Ok(CreateStreamOutcome::Created(row))
    }

    fn get_stream(&self, stream_id: &str) -> StoreResult<Option<WorkstreamRow>> {
        self.row_by_id(stream_id)
    }

    fn list_streams(&self, status: Option<StreamStatus>) -> StoreResult<Vec<WorkstreamRow>> {
        let rows = match status {
            Some(status) => self
                .sql
                .query(
                    &format!(
                        "SELECT {} FROM workstreams WHERE status = ?1 ORDER BY stream_id",
                        Self::ROW_COLUMNS
                    ),
                    &[text(status.as_str())],
                )
                .map_err(sql_err)?,
            None => self
                .sql
                .query(
                    &format!(
                        "SELECT {} FROM workstreams ORDER BY stream_id",
                        Self::ROW_COLUMNS
                    ),
                    &[],
                )
                .map_err(sql_err)?,
        };
        Ok(rows.iter().map(|row| Self::decode_row(row)).collect())
    }

    fn join(&mut self, branch_id: &str, stream_id: &str, at: &str) -> StoreResult<JoinOutcome> {
        let Some(stream) = self.row_by_id(stream_id)? else {
            return Ok(JoinOutcome::StreamMissing);
        };
        match stream.status {
            StreamStatus::Active => {}
            StreamStatus::BoundaryReserved | StreamStatus::RefAdvanced => {
                return Ok(JoinOutcome::StreamReserved)
            }
            StreamStatus::Archived => return Ok(JoinOutcome::StreamArchived),
        }
        let previous = self.home_of(branch_id)?;
        if previous.as_deref() == Some(stream_id) {
            return Ok(JoinOutcome::Joined {
                left_stream_id: None,
            });
        }
        if let Some(previous_id) = previous.as_deref().filter(|id| *id != stream_id) {
            if let Some(source) = self.row_by_id(previous_id)? {
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
        self.sql
            .execute(
                "INSERT INTO workstream_members (branch_id, stream_id, joined_at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(branch_id) DO UPDATE SET stream_id = ?2, joined_at = ?3",
                &[text(branch_id), text(stream_id), text(at)],
            )
            .map_err(sql_err)?;
        self.record_home_position(branch_id, Some(stream_id), at)?;
        Ok(JoinOutcome::Joined {
            left_stream_id: previous.filter(|prev| prev != stream_id),
        })
    }

    fn leave(&mut self, branch_id: &str) -> StoreResult<Option<String>> {
        let previous = self.home_of(branch_id)?;
        if let Some(previous_id) = previous.as_deref() {
            if let Some(source) = self.row_by_id(previous_id)? {
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
        self.sql
            .execute(
                "DELETE FROM workstream_members WHERE branch_id = ?1",
                &[text(branch_id)],
            )
            .map_err(sql_err)?;
        if previous.is_some() {
            self.record_home_position(branch_id, None, "leave")?;
        }
        Ok(previous)
    }

    fn home_of(&self, branch_id: &str) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query(
                "SELECT stream_id FROM workstream_members WHERE branch_id = ?1",
                &[text(branch_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn home_receipt(&self, branch_id: &str) -> StoreResult<BranchHomeReceiptV1> {
        let stream_id = self.home_of(branch_id)?;
        let stream = match stream_id.as_deref() {
            Some(stream_id) => self.row_by_id(stream_id)?,
            None => None,
        };
        let rows = self
            .sql
            .query(
                "SELECT authority_position, recorded_at
                 FROM workstream_home_positions WHERE branch_id = ?1",
                &[text(branch_id)],
            )
            .map_err(sql_err)?;
        let authority_position = rows
            .first()
            .and_then(|row| match row.first() {
                Some(SqlValue::Int(value)) => u64::try_from(*value).ok(),
                _ => None,
            })
            .unwrap_or(0);
        let recorded_at = rows
            .first()
            .and_then(|row| row.get(1))
            .and_then(as_opt_text);
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
            recorded_at,
        })
    }

    fn members(&self, stream_id: &str) -> StoreResult<Vec<String>> {
        let rows = self
            .sql
            .query(
                "SELECT branch_id FROM workstream_members \
                 WHERE stream_id = ?1 ORDER BY branch_id",
                &[text(stream_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|row| as_text(&row[0])).collect())
    }

    fn archive_stream(&mut self, stream_id: &str, at: &str) -> StoreResult<ArchiveOutcome> {
        let Some(stream) = self.row_by_id(stream_id)? else {
            // MUTATION-SUCCESS: ArchiveOutcome::AlreadyArchived
            return Ok(ArchiveOutcome::StreamMissing);
        };
        match stream.status {
            StreamStatus::Active if stream.reservation_id.is_some() => {
                // MUTATION-SUCCESS: ArchiveOutcome::AlreadyArchived
                return Ok(ArchiveOutcome::BoundaryReserved);
            }
            StreamStatus::Active => {}
            StreamStatus::BoundaryReserved => return Ok(ArchiveOutcome::BoundaryReserved),
            StreamStatus::RefAdvanced => return Ok(ArchiveOutcome::RefAlreadyAdvanced),
            StreamStatus::Archived => return Ok(ArchiveOutcome::AlreadyArchived),
        }
        let rehomed = self.members(stream_id)?;
        for branch_id in &rehomed {
            self.record_home_position(branch_id, None, at)?;
        }
        self.sql
            .execute(
                "UPDATE workstreams SET status = 'archived', updated_at = ?2 \
                 WHERE stream_id = ?1",
                &[text(stream_id), text(at)],
            )
            .map_err(sql_err)?;
        self.sql
            .execute(
                "DELETE FROM workstream_members WHERE stream_id = ?1",
                &[text(stream_id)],
            )
            .map_err(sql_err)?;
        Ok(ArchiveOutcome::Archived {
            rehomed_branch_ids: rehomed,
        })
    }

    fn reserve_boundary(
        &mut self,
        stream_id: &str,
        reservation: BoundaryReservation<'_>,
    ) -> StoreResult<ReserveBoundaryOutcome> {
        let Some(stream) = self.row_by_id(stream_id)? else {
            // MUTATION-SUCCESS: ReserveBoundaryOutcome::StreamArchived
            return Ok(ReserveBoundaryOutcome::StreamMissing);
        };
        match stream.status {
            StreamStatus::Archived => return Ok(ReserveBoundaryOutcome::StreamArchived),
            StreamStatus::BoundaryReserved | StreamStatus::RefAdvanced => {
                if stream.reservation_id.as_deref() != Some(reservation.reservation_id)
                    || stream.expected_line_cut.as_deref() != Some(reservation.expected_line_cut)
                    || stream.expected_main_cut.as_deref() != Some(reservation.expected_main_cut)
                    || stream.proposed_main_cut.as_deref() != Some(reservation.proposed_main_cut)
                {
                    return Ok(ReserveBoundaryOutcome::Busy {
                        holder_reservation_id: stream.reservation_id.unwrap_or_default(),
                    });
                }
                return Ok(ReserveBoundaryOutcome::Existing(stream));
            }
            StreamStatus::Active => {
                if let Some(holder_reservation_id) = stream.reservation_id {
                    return Ok(ReserveBoundaryOutcome::Busy {
                        holder_reservation_id,
                    });
                }
            }
        }
        self.sql
            .execute(
                "UPDATE workstreams SET status = 'boundary_reserved', reservation_id = ?2,
                 expected_line_cut = ?3, expected_main_cut = ?4, proposed_main_cut = ?5,
                 ref_position = NULL, ref_receipt_handle = NULL, updated_at = ?6
                 WHERE stream_id = ?1 AND status = 'active'",
                &[
                    text(stream_id),
                    text(reservation.reservation_id),
                    text(reservation.expected_line_cut),
                    text(reservation.expected_main_cut),
                    text(reservation.proposed_main_cut),
                    text(reservation.at),
                ],
            )
            .map_err(sql_err)?;
        let row = self
            .row_by_id(stream_id)?
            .ok_or_else(|| StoreError::Conflict("reserved stream missing".to_owned()))?;
        Ok(ReserveBoundaryOutcome::Reserved(row))
    }

    fn release_boundary(
        &mut self,
        stream_id: &str,
        reservation_id: &str,
        at: &str,
    ) -> StoreResult<ReleaseBoundaryOutcome> {
        let Some(stream) = self.row_by_id(stream_id)? else {
            // MUTATION-SUCCESS: ReleaseBoundaryOutcome::AlreadyActive
            return Ok(ReleaseBoundaryOutcome::StreamMissing);
        };
        match stream.status {
            StreamStatus::Active => {
                return Ok(
                    if stream
                        .reservation_id
                        .as_deref()
                        .is_none_or(|id| id == reservation_id)
                    {
                        ReleaseBoundaryOutcome::AlreadyActive
                    } else {
                        // MUTATION-SUCCESS: ReleaseBoundaryOutcome::AlreadyActive
                        ReleaseBoundaryOutcome::ReservationMismatch
                    },
                );
            }
            StreamStatus::Archived => return Ok(ReleaseBoundaryOutcome::StreamArchived),
            StreamStatus::RefAdvanced => return Ok(ReleaseBoundaryOutcome::RefAlreadyAdvanced),
            StreamStatus::BoundaryReserved => {}
        }
        if stream.reservation_id.as_deref() != Some(reservation_id) {
            return Ok(ReleaseBoundaryOutcome::ReservationMismatch);
        }
        self.sql
            .execute(
                "UPDATE workstreams SET status = 'active',
                 expected_line_cut = NULL, expected_main_cut = NULL,
                 proposed_main_cut = NULL, ref_position = NULL,
                 ref_receipt_handle = NULL, updated_at = ?3
                 WHERE stream_id = ?1 AND reservation_id = ?2
                   AND status = 'boundary_reserved'",
                &[text(stream_id), text(reservation_id), text(at)],
            )
            .map_err(sql_err)?;
        Ok(ReleaseBoundaryOutcome::Released)
    }

    fn acknowledge_boundary_release(
        &mut self,
        stream_id: &str,
        reservation_id: &str,
        at: &str,
    ) -> StoreResult<AcknowledgeBoundaryReleaseOutcome> {
        let Some(stream) = self.row_by_id(stream_id)? else {
            // MUTATION-SUCCESS: AcknowledgeBoundaryReleaseOutcome::Acknowledged
            return Ok(AcknowledgeBoundaryReleaseOutcome::StreamMissing);
        };
        if stream.status != StreamStatus::Active {
            return Ok(AcknowledgeBoundaryReleaseOutcome::NotReleased);
        }
        let Some(pending) = stream.reservation_id.as_deref() else {
            return Ok(AcknowledgeBoundaryReleaseOutcome::AlreadyAcknowledged);
        };
        if pending != reservation_id {
            return Ok(AcknowledgeBoundaryReleaseOutcome::ReservationMismatch);
        }
        self.sql
            .execute(
                "UPDATE workstreams SET reservation_id = NULL, updated_at = ?3
             WHERE stream_id = ?1 AND status = 'active' AND reservation_id = ?2",
                &[text(stream_id), text(reservation_id), text(at)],
            )
            .map_err(sql_err)?;
        Ok(AcknowledgeBoundaryReleaseOutcome::Acknowledged)
    }

    fn record_ref_advanced(
        &mut self,
        stream_id: &str,
        reservation_id: &str,
        ref_position: u64,
        ref_receipt_handle: &str,
        at: &str,
    ) -> StoreResult<RecordRefAdvancedOutcome> {
        let Some(stream) = self.row_by_id(stream_id)? else {
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
        let position = i64::try_from(ref_position).map_err(|_| {
            StoreError::Conflict("ref authority position exceeds SQLite range".to_owned())
        })?;
        self.sql
            .execute(
                "UPDATE workstreams SET status = 'ref_advanced', ref_position = ?3,
                 ref_receipt_handle = ?4, updated_at = ?5
                 WHERE stream_id = ?1 AND reservation_id = ?2
                   AND status = 'boundary_reserved'",
                &[
                    text(stream_id),
                    text(reservation_id),
                    SqlValue::Int(position),
                    text(ref_receipt_handle),
                    text(at),
                ],
            )
            .map_err(sql_err)?;
        let row = self
            .row_by_id(stream_id)?
            .ok_or_else(|| StoreError::Conflict("advanced stream missing".to_owned()))?;
        Ok(RecordRefAdvancedOutcome::Recorded(row))
    }

    fn close_promoted(
        &mut self,
        stream_id: &str,
        reservation_id: &str,
        at: &str,
    ) -> StoreResult<ClosePromotedOutcome> {
        let Some(stream) = self.row_by_id(stream_id)? else {
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
        let rehomed = self.members(stream_id)?;
        for branch_id in &rehomed {
            self.record_home_position(branch_id, None, at)?;
        }
        self.sql
            .execute(
                "DELETE FROM workstream_members WHERE stream_id = ?1",
                &[text(stream_id)],
            )
            .map_err(sql_err)?;
        self.sql
            .execute(
                "UPDATE workstreams SET status = 'archived', updated_at = ?3
                 WHERE stream_id = ?1 AND reservation_id = ?2
                   AND status = 'ref_advanced'",
                &[text(stream_id), text(reservation_id), text(at)],
            )
            .map_err(sql_err)?;
        Ok(ClosePromotedOutcome::Closed {
            rehomed_branch_ids: rehomed,
        })
    }
}

/// Stream homing at DO turn start (DR-0052 Decision 5, DO parity with
/// the native owned-turn seam): resolve the homing target — the tell's
/// `on_stream` input override first, else the agent's declared
/// membership from the program IR — and join the turn's bound line,
/// creating the stream and its shared line on first use and seeding the
/// declared staleness. Fail-closed on contradictory topology (a line
/// already homed to a DIFFERENT stream), exactly as native. Unbound
/// instances and non-member agents home nothing.
pub fn home_do_turn_branch<Sql: DoSql + Clone>(
    sql: &Sql,
    ir: &whipplescript_parser::IrProgram,
    instance_id: &str,
    agent: &str,
    input: &serde_json::Value,
) -> StoreResult<()> {
    use whipplescript_store::branches::Branches;
    let branches = crate::do_branches::DoBranches::new(sql.clone())?;
    let Some(branch_id) = branches.instance_branch(instance_id)? else {
        return Ok(());
    };
    let on_stream = input
        .get("on_stream")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let (target, staleness) = match on_stream {
        Some(target) => (Some(target), None),
        None => match ir
            .streams
            .iter()
            .find(|stream| stream.members.iter().any(|member| member == agent))
        {
            Some(stream) => (
                Some(stream.name.clone()),
                stream.staleness_seconds.map(|seconds| seconds as i64),
            ),
            None => (None, None),
        },
    };
    let Some(stream_id) = target else {
        return Ok(());
    };
    let mut streams = DoWorkstreams::new(sql.clone())?;
    let at = format!("home:{instance_id}");
    match streams.home_of(&branch_id)? {
        Some(existing) if existing == stream_id => return Ok(()),
        Some(existing) => {
            return Err(StoreError::Conflict(format!(
                "turn line `{branch_id}` is homed to stream `{existing}` but this \
                 turn declares stream `{stream_id}` — contradictory topology; fix \
                 the stream declarations (membership is single-valued)"
            )));
        }
        None => {}
    }
    let line_branch_id = format!("line-{stream_id}");
    let mut branches = crate::do_branches::DoBranches::new(sql.clone())?;
    branches.ensure_mainline(&at)?;
    match branches.create_branch(whipplescript_store::branches::CreateBranch {
        branch_id: &line_branch_id,
        name: None,
        parent_branch_id: whipplescript_store::branches::MAINLINE_BRANCH_ID,
        at_cut: None,
        created_at: &at,
        idempotency_key: None,
    })? {
        whipplescript_store::branches::CreateBranchOutcome::Created(_)
        | whipplescript_store::branches::CreateBranchOutcome::Existing(_) => {}
        other => {
            return Err(StoreError::Conflict(format!(
                "stream line not created: {other:?}"
            )));
        }
    }
    streams.create_stream(&stream_id, None, &line_branch_id, &at, None)?;
    if let Some(bound) = staleness {
        let _ = streams.set_staleness(&stream_id, Some(bound), &at);
    }
    match streams.join(&branch_id, &stream_id, &at)? {
        JoinOutcome::Joined { .. } => Ok(()),
        other => Err(StoreError::Conflict(format!(
            "stream join refused: {other:?}"
        ))),
    }
}

/// The DO-side `vcs.promote` provider: since DR-0091 W1 a dispatch onto
/// the kernel's one promotion choreography, over the DO's own
/// branch/workstream tables. The two deliberate divergences from the
/// native door are both host-supplied seams, not copies: **no adoption
/// lease** — the DO is single-writer per object, so its turn is the
/// serialization (`SingleWriterSerialization`, vw note §7); and **no
/// fact routing** — vcs.* fact delivery is the mediator surface (A5),
/// which lives native-side.
pub struct DoVcsPromoteCapabilityProvider<Sql: DoSql + Clone> {
    /// The shared DO SQLite handle (an `Rc<…>` in every real
    /// instantiation, so cloning is a refcount bump).
    pub sql: Sql,
}

impl<Sql: DoSql + Clone> whipplescript_kernel::effect_handlers::CapabilityProvider
    for DoVcsPromoteCapabilityProvider<Sql>
{
    fn label(&self) -> &'static str {
        "std.vcs.do"
    }

    fn produce(
        &self,
        effect: &whipplescript_store::ClaimableEffect,
        _config: &whipplescript_kernel::effect_config::EffectConfig,
    ) -> whipplescript_kernel::effect_handlers::CapabilityOutcome {
        use whipplescript_kernel::effect_handlers::CapabilityOutcome;
        let failed = |message: String| CapabilityOutcome::Failed {
            error_kind: "vcs_promote".to_owned(),
            message,
        };
        let input: serde_json::Value = match serde_json::from_str(&effect.input_json) {
            Ok(value) => value,
            Err(error) => return failed(format!("invalid vcs.promote input: {error}")),
        };
        let Some(stream_id) = whipplescript_kernel::effect_handlers::promote_stream_id(&input)
        else {
            return failed("vcs.promote input names no stream".to_owned());
        };
        let mut streams = match DoWorkstreams::new(self.sql.clone()) {
            Ok(streams) => streams,
            Err(error) => return failed(format!("workstream store unavailable: {error:?}")),
        };
        let mut vcs = match crate::do_branches::compose_vcs(&self.sql) {
            Ok(vcs) => vcs,
            Err(error) => return failed(format!("branch stores unavailable: {error:?}")),
        };
        // The identity-bearing coordinates, exactly as this door has always
        // minted them: deterministic in the effect id, never a clock.
        let seed = crate::do_store::stable_hash_hex(&format!("promote|{}", effect.effect_id));
        let at = format!("promote:{}", effect.effect_id);
        let reservation_id = format!("effect-{}", effect.effect_id);
        let proposed_main = format!("cut-{seed}-promote");
        // Single-writer per object: the DO's turn IS the serialization
        // (DR-0091 Decision 2), so the kernel choreography runs unleased.
        let result = whipplescript_kernel::effect_handlers::run_reserved_boundary_promotion_generic(
            &mut streams,
            &mut vcs,
            &whipplescript_kernel::effect_handlers::PromoteDoorRequest {
                stream_id,
                reservation_id: &reservation_id,
                proposed_main: &proposed_main,
                at: &at,
                receipt_scope: "durable-object-workspace",
            },
            &mut whipplescript_kernel::effect_handlers::SingleWriterSerialization,
        );
        // No fact routing: vcs.* fact delivery is the mediator surface (A5),
        // which lives native-side.
        whipplescript_kernel::effect_handlers::promote_effect_outcome(stream_id, &result)
    }
}

/// The DO-side selective-verb provider (DR-0052 R4, DO parity):
/// `undo`/`transport` over the instance's own bound line via the DO
/// branch/workstream tables. Same architectural divergences as promote:
/// no vcs.* fact routing (the mediator surface is native by A5's
/// design); refusals are data.
pub struct DoVcsSelectiveCapabilityProvider<Sql: DoSql + Clone> {
    pub sql: Sql,
    pub instance_id: String,
}

impl<Sql: DoSql + Clone> whipplescript_kernel::effect_handlers::CapabilityProvider
    for DoVcsSelectiveCapabilityProvider<Sql>
{
    fn label(&self) -> &'static str {
        "std.vcs.do"
    }

    fn produce(
        &self,
        effect: &whipplescript_store::ClaimableEffect,
        _config: &whipplescript_kernel::effect_config::EffectConfig,
    ) -> whipplescript_kernel::effect_handlers::CapabilityOutcome {
        use whipplescript_kernel::effect_handlers::CapabilityOutcome;
        use whipplescript_store::branches::Branches;
        let failed = |message: String| CapabilityOutcome::Failed {
            error_kind: "vcs_selective".to_owned(),
            message,
        };
        let input: serde_json::Value = match serde_json::from_str(&effect.input_json) {
            Ok(value) => value,
            Err(error) => return failed(format!("invalid input: {error}")),
        };
        let expr = match whipplescript_kernel::effect_handlers::selective_selection(&input) {
            Ok(expr) => expr,
            Err(message) => return failed(message),
        };
        let branches = match crate::do_branches::DoBranches::new(self.sql.clone()) {
            Ok(branches) => branches,
            Err(error) => return failed(format!("branch store unavailable: {error:?}")),
        };
        let Ok(Some(branch_id)) = branches.instance_branch(&self.instance_id) else {
            return failed(
                "this instance has no bound line (selective verbs operate on the \
                 instance's own line)"
                    .to_owned(),
            );
        };
        drop(branches);
        let mut vcs = match crate::do_branches::compose_vcs(&self.sql) {
            Ok(vcs) => vcs,
            Err(error) => return failed(format!("branch stores unavailable: {error:?}")),
        };
        vcs.set_actor(Some(format!("instance:{}", self.instance_id)));
        vcs.set_intent(Some(effect.effect_id.clone()));
        let seed = crate::do_store::stable_hash_hex(&format!("selective|{}", effect.effect_id));
        let cut_id = format!("cut-{seed}");
        let at = format!("selective:{}", effect.effect_id);
        // DR-0091 W2: the verb is the kernel's one choreography. This door's
        // seams: stream lines resolve through the DO's own workstream table,
        // and the staleness advisory lists this store's issues + assertions.
        // No fact routing — the mediator surface is native (A5).
        let sql = self.sql.clone();
        let result = whipplescript_kernel::effect_handlers::run_selective_verb_generic(
            &mut vcs,
            effect.target.as_deref(),
            &input,
            &expr,
            &branch_id,
            &cut_id,
            &at,
            &mut |onto| {
                DoWorkstreams::new(sql.clone())
                    .ok()
                    .and_then(|streams| streams.get_stream(onto).ok().flatten())
                    .map(|stream| stream.line_branch_id)
            },
            &mut |vcs, line, cut| do_staleness_deltas(&sql, vcs, line, cut),
        );
        whipplescript_kernel::effect_handlers::selective_effect_outcome(result)
    }
}

/// DR-0086 F4: the DO half of the receipt staleness-delta advisory — the
/// same kernel evaluation native uses, over the DO's own views. Subjects are the
/// listable issues and active assertions (DR-0086 F5).
fn do_staleness_deltas<Sql: crate::do_store::DoSql + Clone>(
    sql: &Sql,
    vcs: &whipplescript_store::vcs::WorkspaceVcs<
        crate::do_branches::DoBranches<Sql>,
        crate::do_branches::DoContentBlobs<Sql>,
    >,
    branch_id: &str,
    cut_id: &str,
) -> Vec<serde_json::Value> {
    use whipplescript_store::items::WorkItems;
    let items = crate::do_store::DoSqliteStore::new(sql.clone());
    let mut subjects: Vec<String> = items
        .list_items(None, None)
        .unwrap_or_default()
        .into_iter()
        .map(|issue| issue.id)
        .collect();
    // DR-0086 F5: assertions are listable on the DO now, so the receipt
    // advisory covers both nouns, native parity complete.
    subjects.extend(
        items
            .list_assertions(false)
            .unwrap_or_default()
            .into_iter()
            .map(|assertion| assertion.id),
    );
    whipplescript_kernel::effect_handlers::staleness_deltas_generic(
        &items, vcs, &subjects, branch_id, cut_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    use crate::do_store::test_support::RusqliteDoSql;

    fn sql() -> Rc<RusqliteDoSql> {
        Rc::new(RusqliteDoSql::in_memory())
    }

    #[test]
    fn do_missing_stream_boundary_operations_return_typed_outcomes() {
        let sql = sql();
        let mut streams = DoWorkstreams::new(Rc::clone(&sql)).unwrap();

        assert_eq!(
            streams.archive_stream("missing", "t1").unwrap(),
            ArchiveOutcome::StreamMissing
        );
        assert_eq!(
            streams
                .reserve_boundary(
                    "missing",
                    BoundaryReservation {
                        reservation_id: "reservation",
                        expected_line_cut: "line-1",
                        expected_main_cut: "main-1",
                        proposed_main_cut: "main-2",
                        at: "t1",
                    },
                )
                .unwrap(),
            ReserveBoundaryOutcome::StreamMissing
        );
        assert_eq!(
            streams
                .release_boundary("missing", "reservation", "t1")
                .unwrap(),
            ReleaseBoundaryOutcome::StreamMissing
        );
    }

    #[test]
    fn do_cancellation_cleanup_retains_its_token_until_both_stores_finish() {
        use crate::do_branches::{DoBranches, DoContentBlobs};
        use whipplescript_kernel::effect_handlers::release_reserved_boundary_generic;
        use whipplescript_store::vcs::WorkspaceVcs;
        for fault in ["topology", "line", "acknowledgement", "foreign-lock"] {
            let sql = sql();
            let mut streams = DoWorkstreams::new(Rc::clone(&sql)).unwrap();
            let mut vcs = WorkspaceVcs::from_parts(
                DoBranches::new(Rc::clone(&sql)).unwrap(),
                DoContentBlobs::new(Rc::clone(&sql)).unwrap(),
            );
            vcs.init("t0").unwrap();
            vcs.create_branch("line", None, "main", "t0").unwrap();
            streams
                .create_stream("ws", None, "line", "t0", None)
                .unwrap();
            let reservation = |id| BoundaryReservation {
                reservation_id: id,
                expected_line_cut: "",
                expected_main_cut: "",
                proposed_main_cut: "proposed",
                at: "t1",
            };
            streams
                .reserve_boundary("ws", reservation("cancelled"))
                .unwrap();
            assert_eq!(
                streams.release_boundary("ws", "stale", "t1").unwrap(),
                ReleaseBoundaryOutcome::ReservationMismatch
            );
            let reserved = streams.get_stream("ws").unwrap().unwrap();
            assert_eq!(reserved.status, StreamStatus::BoundaryReserved);
            assert_eq!(reserved.reservation_id.as_deref(), Some("cancelled"));
            assert_eq!(
                streams
                    .acknowledge_boundary_release("ws", "cancelled", "t1")
                    .unwrap(),
                AcknowledgeBoundaryReleaseOutcome::NotReleased
            );
            vcs.reserve_branch_head("line", "cancelled", "t1").unwrap();
            let trigger = match fault {
                "topology" => "CREATE TRIGGER fail_cleanup BEFORE UPDATE ON workstreams WHEN NEW.status = 'active' BEGIN SELECT RAISE(FAIL, 'topology'); END;",
                "line" => "CREATE TRIGGER fail_cleanup BEFORE DELETE ON branch_head_reservations BEGIN SELECT RAISE(FAIL, 'line'); END;",
                "acknowledgement" => "CREATE TRIGGER fail_cleanup BEFORE UPDATE ON workstreams WHEN NEW.status = 'active' AND NEW.reservation_id IS NULL BEGIN SELECT RAISE(FAIL, 'acknowledgement'); END;",
                _ => "",
            };
            if fault == "foreign-lock" {
                vcs.release_branch_head_reservation("line", "cancelled")
                    .unwrap();
                vcs.reserve_branch_head("line", "other", "t1").unwrap();
            } else {
                sql.execute(trigger, &[]).unwrap();
            }
            let error =
                release_reserved_boundary_generic(&mut streams, &mut vcs, "ws", "cancelled", "t2")
                    .unwrap_err();
            assert!(error.contains("cleanup"), "{fault}: {error}");
            let pending = streams.get_stream("ws").unwrap().unwrap();
            assert_eq!(pending.reservation_id.as_deref(), Some("cancelled"));
            assert_eq!(
                pending.status,
                if fault == "topology" {
                    StreamStatus::BoundaryReserved
                } else {
                    StreamStatus::Active
                }
            );
            assert_eq!(
                vcs.branch_head_reservation("line").unwrap().as_deref(),
                match fault {
                    "acknowledgement" => None,
                    "foreign-lock" => Some("other"),
                    _ => Some("cancelled"),
                }
            );
            assert!(matches!(
                streams
                    .reserve_boundary("ws", reservation("fresh"))
                    .unwrap(),
                ReserveBoundaryOutcome::Busy { .. }
            ));
            assert_eq!(
                streams.archive_stream("ws", "t2").unwrap(),
                ArchiveOutcome::BoundaryReserved
            );
            assert!(
                release_reserved_boundary_generic(&mut streams, &mut vcs, "ws", "stale", "t2")
                    .is_err()
            );
            if fault == "foreign-lock" {
                assert_eq!(
                    vcs.branch_head_reservation("line").unwrap().as_deref(),
                    Some("other")
                );
                vcs.release_branch_head_reservation("line", "other")
                    .unwrap();
            } else {
                sql.execute("DROP TRIGGER fail_cleanup", &[]).unwrap();
            }
            // Recreate the host adapters over the retained DO storage.
            drop(streams);
            drop(vcs);
            let mut streams = DoWorkstreams::new(Rc::clone(&sql)).unwrap();
            let mut vcs = WorkspaceVcs::from_parts(
                DoBranches::new(Rc::clone(&sql)).unwrap(),
                DoContentBlobs::new(Rc::clone(&sql)).unwrap(),
            );
            release_reserved_boundary_generic(&mut streams, &mut vcs, "ws", "cancelled", "t3")
                .unwrap();
            release_reserved_boundary_generic(&mut streams, &mut vcs, "ws", "cancelled", "t3")
                .unwrap();
            assert!(streams
                .get_stream("ws")
                .unwrap()
                .unwrap()
                .reservation_id
                .is_none());
            assert!(vcs.branch_head_reservation("line").unwrap().is_none());
            assert!(vcs
                .get_branch("main")
                .unwrap()
                .unwrap()
                .head_cut_id
                .is_none());
            streams
                .reserve_boundary("ws", reservation("fresh"))
                .unwrap();
            vcs.reserve_branch_head("line", "fresh", "t4").unwrap();
            assert!(release_reserved_boundary_generic(
                &mut streams,
                &mut vcs,
                "ws",
                "cancelled",
                "t4"
            )
            .is_err());
            assert_eq!(
                vcs.branch_head_reservation("line").unwrap().as_deref(),
                Some("fresh")
            );
            assert_eq!(
                streams.release_boundary("ws", "fresh", "t5").unwrap(),
                ReleaseBoundaryOutcome::Released
            );
            assert_eq!(
                streams.release_boundary("ws", "cancelled", "t5").unwrap(),
                ReleaseBoundaryOutcome::ReservationMismatch
            );
            assert_eq!(
                streams
                    .acknowledge_boundary_release("ws", "cancelled", "t5")
                    .unwrap(),
                AcknowledgeBoundaryReleaseOutcome::ReservationMismatch
            );
            assert_eq!(
                streams
                    .acknowledge_boundary_release("missing", "fresh", "t5")
                    .unwrap(),
                AcknowledgeBoundaryReleaseOutcome::StreamMissing
            );
            release_reserved_boundary_generic(&mut streams, &mut vcs, "ws", "fresh", "t6").unwrap();
            assert_eq!(
                streams
                    .acknowledge_boundary_release("ws", "fresh", "t6")
                    .unwrap(),
                AcknowledgeBoundaryReleaseOutcome::AlreadyAcknowledged
            );
        }
    }

    /// DO workstream parity: create/join (single-valued upsert), staleness
    /// column round-trip, archive re-homes members — the native store's
    /// semantics byte-for-byte over `DoSql`.
    #[test]
    fn do_workstreams_mirror_native_semantics() {
        let sql = sql();
        let mut streams = DoWorkstreams::new(Rc::clone(&sql)).expect("open");
        let created = streams
            .create_stream("triage", None, "line-triage", "t1", None)
            .expect("create");
        assert!(matches!(created, CreateStreamOutcome::Created(_)));
        streams
            .set_staleness("triage", Some(7200), "t1")
            .expect("set");
        assert_eq!(
            streams
                .get_stream("triage")
                .expect("get")
                .expect("row")
                .staleness_seconds,
            Some(7200)
        );
        streams
            .create_stream("hotfix", None, "line-hotfix", "t2", None)
            .expect("create");
        let joined = streams.join("member-1", "triage", "t3").expect("join");
        assert!(matches!(
            joined,
            JoinOutcome::Joined {
                left_stream_id: None
            }
        ));
        let first_home = streams.home_receipt("member-1").expect("home receipt");
        assert_eq!(first_home.authority_position, 1);
        assert_eq!(first_home.stream_id.as_deref(), Some("triage"));
        // Single-valued membership: joining hotfix leaves triage in one step.
        let rehomed = streams.join("member-1", "hotfix", "t4").expect("join");
        assert!(
            matches!(rehomed, JoinOutcome::Joined { left_stream_id: Some(ref left) } if left == "triage")
        );
        assert_eq!(
            streams.home_of("member-1").expect("home").as_deref(),
            Some("hotfix")
        );
        let transferred = streams.home_receipt("member-1").expect("transferred");
        assert_eq!(transferred.authority_position, 2);
        assert_ne!(transferred.evidence_handle, first_home.evidence_handle);
        // Archive re-homes members and refuses further joins.
        let archived = streams.archive_stream("hotfix", "t5").expect("archive");
        assert!(
            matches!(archived, ArchiveOutcome::Archived { ref rehomed_branch_ids } if rehomed_branch_ids == &["member-1"])
        );
        assert!(matches!(
            streams.join("member-2", "hotfix", "t6").expect("join"),
            JoinOutcome::StreamArchived
        ));
        let main_home = streams.home_receipt("member-1").expect("main receipt");
        assert_eq!(main_home.authority_position, 3);
        assert_eq!(main_home.stream_id, None);
    }

    /// DR-0052 R4 (DO parity): the selective verbs over the instance's
    /// own bound line — undo applies as a proposal cut and refuses as
    /// Stranded when a retained later write consumed the undone output;
    /// transport lands on mainline or refuses as Conflicted.
    #[test]
    fn do_selective_provider_covers_all_variants() {
        use whipplescript_kernel::effect_handlers::{CapabilityOutcome, CapabilityProvider};
        use whipplescript_store::branches::Branches;

        let sql = sql();
        let mut branches = crate::do_branches::DoBranches::new(Rc::clone(&sql)).expect("open");
        branches.ensure_mainline("t0").expect("mainline");
        let mut vcs = crate::do_branches::compose_vcs(&sql).expect("open");
        vcs.init("t0").expect("init");
        vcs.create_branch(
            "member-line",
            None,
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            "t1",
        )
        .expect("line");
        branches
            .bind_instance("ins-r4", "member-line", "t1")
            .expect("bind");
        vcs.set_actor(Some("instance:ins-r4".to_owned()));
        vcs.write(
            "member-line",
            "scratch/tmp.md",
            Some("scratch"),
            "cut_s1",
            "t2",
        )
        .expect("write");
        vcs.write("member-line", "src/keep.md", Some("keep"), "cut_k1", "t3")
            .expect("write");

        let provider = DoVcsSelectiveCapabilityProvider {
            sql: Rc::clone(&sql),
            instance_id: "ins-r4".to_owned(),
        };
        let effect = |id: &str, target: &str, input: &str| whipplescript_store::ClaimableEffect {
            effect_id: id.to_owned(),
            kind: "capability.call".to_owned(),
            target: Some(target.to_owned()),
            profile: None,
            input_json: input.to_owned(),
            required_capabilities_json: "[]".to_owned(),
            declared_profiles_json: "[]".to_owned(),
        };
        let config = whipplescript_kernel::effect_config::EffectConfig::default();

        // Undo the scratch write: applies as a proposal cut.
        let outcome = provider.produce(
            &effect("e1", "vcs.undo", r#"{"selection":"path(scratch/**)"}"#),
            &config,
        );
        let CapabilityOutcome::Produced(value) = outcome else {
            panic!("expected produced");
        };
        assert_eq!(value["variant"], "Applied");
        assert!(vcs
            .read("member-line", "scratch/tmp.md")
            .expect("read")
            .is_none());

        // A dependent later write strands: refusal as data.
        vcs.write(
            "member-line",
            "src/keep.md",
            Some("keep v2"),
            "cut_k2",
            "t4",
        )
        .expect("write");
        let outcome = provider.produce(
            &effect("e2", "vcs.undo", r#"{"selection":"cut(cut_k1)"}"#),
            &config,
        );
        let CapabilityOutcome::Produced(value) = outcome else {
            panic!("expected produced");
        };
        assert_eq!(value["variant"], "Stranded");
        // DR-0091 W2 parity gain: the stranded detail carries native's
        // three-field shape — the DO's pre-lift copy dropped the `by`
        // attribution, so a stranded refusal named the unit but not whose
        // work would strand.
        let stranded: serde_json::Value =
            serde_json::from_str(value["detail"].as_str().expect("detail is a string"))
                .expect("detail parses");
        assert!(stranded[0]["path"].is_string());
        assert!(stranded[0]["cut"].is_string());
        assert!(
            stranded[0].get("by").is_some(),
            "the stranded unit names its actor: {stranded}"
        );

        // Transport the kept work onto mainline: applies.
        let outcome = provider.produce(
            &effect(
                "e3",
                "vcs.transport",
                r#"{"selection":"path(src/**)","onto":"mainline"}"#,
            ),
            &config,
        );
        let CapabilityOutcome::Produced(value) = outcome else {
            panic!("expected produced");
        };
        assert_eq!(value["variant"], "Applied");
        // DR-0086 F4: the DO receipt carries the staleness-delta advisory
        // (empty here — no anchored evidence in the fixture — but present
        // on every applied proposal, native parity).
        assert!(value["staleness"].is_array(), "{value}");
        assert_eq!(
            vcs.read(
                whipplescript_store::branches::MAINLINE_BRANCH_ID,
                "src/keep.md"
            )
            .expect("read")
            .as_deref(),
            Some("keep v2")
        );

        // A divergent mainline edit conflicts the next transport.
        vcs.write(
            "member-line",
            "src/keep.md",
            Some("member v3"),
            "cut_k3",
            "t5",
        )
        .expect("write");
        vcs.write(
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            "src/keep.md",
            Some("main divergent"),
            "cut_m1",
            "t6",
        )
        .expect("write");
        let outcome = provider.produce(
            &effect(
                "e4",
                "vcs.transport",
                r#"{"selection":"cut(cut_k3)","onto":"mainline"}"#,
            ),
            &config,
        );
        let CapabilityOutcome::Produced(value) = outcome else {
            panic!("expected produced");
        };
        assert_eq!(value["variant"], "Conflicted");
    }

    /// DO promote parity: a member's synced work on the stream line
    /// promotes to mainline (variant Promoted); a conflicting mainline
    /// edit refuses honestly (variant Conflicted). No adoption lease —
    /// the DO is single-writer.
    #[test]
    fn do_promote_provider_produces_both_variants() {
        use whipplescript_kernel::effect_handlers::{CapabilityOutcome, CapabilityProvider};
        use whipplescript_store::branches::Branches;

        let sql = sql();
        let mut streams = DoWorkstreams::new(Rc::clone(&sql)).expect("open");
        let mut branches = crate::do_branches::DoBranches::new(Rc::clone(&sql)).expect("open");
        branches.ensure_mainline("t0").expect("mainline");
        let mut vcs = crate::do_branches::compose_vcs(&sql).expect("open");
        vcs.init("t0").expect("init");
        vcs.create_branch(
            "line-triage",
            None,
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            "t1",
        )
        .expect("line");
        streams
            .create_stream("triage", None, "line-triage", "t1", None)
            .expect("create");
        vcs.write(
            "line-triage",
            "feature.md",
            Some("stream work"),
            "cut_1",
            "t2",
        )
        .expect("write");

        let provider = DoVcsPromoteCapabilityProvider {
            sql: Rc::clone(&sql),
        };
        let effect = |id: &str, stream: &str| whipplescript_store::ClaimableEffect {
            effect_id: id.to_owned(),
            kind: "capability.call".to_owned(),
            target: Some("vcs.promote".to_owned()),
            profile: None,
            input_json: serde_json::json!({ "stream": stream }).to_string(),
            required_capabilities_json: "[]".to_owned(),
            declared_profiles_json: "[]".to_owned(),
        };
        let config = whipplescript_kernel::effect_config::EffectConfig::default();
        let outcome = provider.produce(&effect("eff-1", "triage"), &config);
        let CapabilityOutcome::Produced(value) = outcome else {
            panic!("expected produced, got failure");
        };
        assert_eq!(value["variant"], "Promoted");
        // DR-0091 W1 identity pin: the proposed Main cut is minted from the
        // effect id exactly as this door always minted it — the lift must
        // reproduce the exactly-once key byte for byte.
        let seed = crate::do_store::stable_hash_hex("promote|eff-1");
        assert_eq!(
            value["sync_cut_id"],
            serde_json::Value::String(format!("cut-{seed}-promote")),
            "the deterministic promote cut id survives the kernel dispatch"
        );
        assert_eq!(value["detail"], "");
        // Mainline actually received the stream's work.
        let main_manifest = vcs
            .read(
                whipplescript_store::branches::MAINLINE_BRANCH_ID,
                "feature.md",
            )
            .expect("read")
            .expect("present");
        assert_eq!(main_manifest, "stream work");

        // A promoted stream is closed historical evidence. Use a distinct
        // live stream for the conflict case; retrying eff-1 would correctly
        // recover its Promoted receipt instead of reopening history.
        vcs.create_branch(
            "line-conflict",
            None,
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            "t3",
        )
        .expect("conflict line");
        streams
            .create_stream("conflict", None, "line-conflict", "t3", None)
            .expect("conflict stream");
        // Divergent edits on both sides: the hop refuses as data.
        vcs.write(
            "line-conflict",
            "contested.md",
            Some("stream side"),
            "cut_2",
            "t3",
        )
        .expect("write");
        vcs.write(
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            "contested.md",
            Some("main side"),
            "cut_3",
            "t4",
        )
        .expect("write");
        let outcome = provider.produce(&effect("eff-2", "conflict"), &config);
        let CapabilityOutcome::Produced(value) = outcome else {
            panic!("expected produced, got failure");
        };
        assert_eq!(value["variant"], "Conflicted");
        // DR-0091 W1 parity gain: the conflict detail carries native's full
        // eight-field shape — the DO's pre-lift copy dropped the side
        // provenance, so a DO conflict named paths but not which side at
        // which cut.
        let detail: serde_json::Value =
            serde_json::from_str(value["detail"].as_str().expect("detail is a string"))
                .expect("detail parses");
        assert_eq!(detail[0]["path"], "contested.md");
        assert_eq!(detail[0]["ours_branch"], "line-conflict");
        assert_eq!(detail[0]["theirs_branch"], "main");
        assert!(detail[0]["theirs_cut"].is_string());

        // Replaying the promoted effect recovers the archived stream's
        // receipt and says so — recovery is data, not a second promotion.
        let outcome = provider.produce(&effect("eff-1", "triage"), &config);
        let CapabilityOutcome::Produced(value) = outcome else {
            panic!("expected produced, got failure");
        };
        assert_eq!(value["variant"], "Promoted");
        assert_eq!(value["detail"], "recovered");
        assert_eq!(
            value["sync_cut_id"],
            serde_json::Value::String(format!("cut-{seed}-promote")),
            "the recovered receipt replays the original coordinate"
        );
    }

    #[test]
    fn do_promote_releases_both_reservations_after_proven_pre_cas_error() {
        use whipplescript_kernel::effect_handlers::{CapabilityOutcome, CapabilityProvider};
        use whipplescript_store::branches::{Branches, HeadReservationOutcome};

        let sql = sql();
        let mut streams = DoWorkstreams::new(Rc::clone(&sql)).expect("open");
        let mut branches = crate::do_branches::DoBranches::new(Rc::clone(&sql)).expect("open");
        branches.ensure_mainline("t0").expect("mainline");
        let mut vcs = crate::do_branches::compose_vcs(&sql).expect("open");
        vcs.init("t0").expect("init");
        vcs.create_branch(
            "line-pre-cas",
            None,
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            "t1",
        )
        .expect("line");
        streams
            .create_stream("pre-cas", None, "line-pre-cas", "t1", None)
            .expect("create");
        vcs.write(
            "line-pre-cas",
            "feature.md",
            Some("stream work"),
            "line-cut",
            "t2",
        )
        .expect("write");

        let effect_id = "eff-pre-cas";
        let seed = crate::do_store::stable_hash_hex(&format!("promote|{effect_id}"));
        let proposed_main = format!("cut-{seed}-promote");
        vcs.create_branch(
            "unrelated",
            None,
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            "t2",
        )
        .expect("unrelated branch");
        vcs.write(
            "unrelated",
            "unrelated.md",
            Some("occupy immutable cut id"),
            &proposed_main,
            "t2",
        )
        .expect("occupy proposed cut identity");

        let provider = DoVcsPromoteCapabilityProvider {
            sql: Rc::clone(&sql),
        };
        let effect = whipplescript_store::ClaimableEffect {
            effect_id: effect_id.to_owned(),
            kind: "capability.call".to_owned(),
            target: Some("vcs.promote".to_owned()),
            profile: None,
            input_json: serde_json::json!({ "stream": "pre-cas" }).to_string(),
            required_capabilities_json: "[]".to_owned(),
            declared_profiles_json: "[]".to_owned(),
        };
        let config = whipplescript_kernel::effect_config::EffectConfig::default();
        let outcome = provider.produce(&effect, &config);
        let CapabilityOutcome::Failed { message, .. } = outcome else {
            panic!("a conflicting immutable cut identity must fail");
        };
        assert!(message.contains("reservations released"), "{message}");
        assert_eq!(
            streams
                .get_stream("pre-cas")
                .expect("stream read")
                .expect("stream")
                .status,
            StreamStatus::Active
        );
        assert_eq!(
            vcs.reserve_branch_head("line-pre-cas", "next-attempt", "t3")
                .expect("line can be reserved again"),
            HeadReservationOutcome::Reserved
        );
        vcs.release_branch_head_reservation("line-pre-cas", "next-attempt")
            .expect("release probe");
        vcs.write(
            "line-pre-cas",
            "feature.md",
            Some("later work"),
            "later-line-cut",
            "t4",
        )
        .expect("later write");
        assert_eq!(
            vcs.get_branch("main")
                .expect("main")
                .expect("main")
                .head_cut_id,
            None
        );

        for (stream_id, lose_cut) in [("post-cas", false), ("missing-evidence", true)] {
            let line = format!("line-{stream_id}");
            vcs.create_branch(&line, None, "main", "t5").expect("line");
            vcs.write(
                &line,
                "next.md",
                Some(stream_id),
                &format!("cut-{stream_id}"),
                "t5",
            )
            .expect("line write");
            streams
                .create_stream(stream_id, None, &line, "t5", None)
                .expect("stream");
            let seed = crate::do_store::stable_hash_hex(&format!("promote|{stream_id}"));
            let proposed_main = format!("cut-{seed}-promote");
            let lose_evidence = if lose_cut {
                format!("DELETE FROM cuts WHERE cut_id = '{proposed_main}';")
            } else {
                String::new()
            };
            sql.execute(
                &format!(
                    "CREATE TRIGGER fail_promotion_log BEFORE INSERT ON ops
                 WHEN NEW.kind = 'promote-boundary' BEGIN
                 {lose_evidence} SELECT RAISE(FAIL, 'injected post-CAS failure'); END;"
                ),
                &[],
            )
            .expect("inject post-CAS fault");
            let effect = whipplescript_store::ClaimableEffect {
                effect_id: stream_id.to_owned(),
                kind: "capability.call".to_owned(),
                target: Some("vcs.promote".to_owned()),
                profile: None,
                input_json: serde_json::json!({ "stream": stream_id }).to_string(),
                required_capabilities_json: "[]".to_owned(),
                declared_profiles_json: "[]".to_owned(),
            };
            let outcome = provider.produce(&effect, &config);
            sql.execute("DROP TRIGGER fail_promotion_log;", &[])
                .expect("remove fault");
            assert_eq!(
                vcs.get_branch("main")
                    .expect("main")
                    .expect("main")
                    .head_cut_id
                    .as_deref(),
                Some(proposed_main.as_str()),
                "the fault was after the Main CAS"
            );
            let row = streams
                .get_stream(stream_id)
                .expect("read stream")
                .expect("stream");
            if lose_cut {
                let CapabilityOutcome::Failed { message, .. } = outcome else {
                    panic!("missing cut evidence must retain the reservation");
                };
                assert!(message.contains("reservations retained"), "{message}");
                assert_eq!(row.status, StreamStatus::BoundaryReserved);
                let error = vcs
                    .write(&line, "next.md", Some("not allowed"), "cut-forbidden", "t7")
                    .expect_err("line remains frozen");
                assert!(format!("{error:?}").contains("reserved"));
            } else {
                let CapabilityOutcome::Produced(value) = outcome else {
                    panic!("a landed Main CAS must close forward");
                };
                assert_eq!(value["variant"], "Promoted");
                assert_eq!(row.status, StreamStatus::Archived);
                assert!(matches!(
                    provider.produce(&effect, &config),
                    CapabilityOutcome::Produced(_)
                ));
            }
        }
    }
}
