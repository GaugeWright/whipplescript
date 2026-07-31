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
    ArchiveOutcome, CreateStreamOutcome, JoinOutcome, StreamStatus, WorkstreamRow, Workstreams,
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
            "CREATE UNIQUE INDEX IF NOT EXISTS workstreams_active_name_idx
                ON workstreams(name)
                WHERE name IS NOT NULL AND status = 'active'",
            "CREATE TABLE IF NOT EXISTS workstream_members (
                branch_id TEXT PRIMARY KEY,
                stream_id TEXT NOT NULL,
                joined_at TEXT NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS workstream_members_stream_idx
                ON workstream_members(stream_id)",
        ] {
            self.sql.execute(statement, &[]).map_err(sql_err)?;
        }
        // The staleness bound arrived with DR-0052 S1 (exactly as native):
        // earlier stores gain the column in place (NULL = unbounded).
        let info = self
            .sql
            .query("PRAGMA table_info(workstreams)", &[])
            .map_err(sql_err)?;
        let present = info.iter().any(|row| {
            row.get(1)
                .map(|value| as_text(value) == "staleness_seconds")
                .unwrap_or(false)
        });
        if !present {
            self.sql
                .execute(
                    "ALTER TABLE workstreams ADD COLUMN staleness_seconds INTEGER",
                    &[],
                )
                .map_err(sql_err)?;
        }
        Ok(())
    }

    const ROW_COLUMNS: &'static str = "stream_id, name, line_branch_id, status, \
        staleness_seconds, created_at, updated_at";

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
            created_at: as_text(&row[5]),
            updated_at: as_text(&row[6]),
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
                     WHERE name = ?1 AND status = 'active'",
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
        if stream.status != StreamStatus::Active {
            return Ok(JoinOutcome::StreamArchived);
        }
        let previous = self.home_of(branch_id)?;
        self.sql
            .execute(
                "INSERT INTO workstream_members (branch_id, stream_id, joined_at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(branch_id) DO UPDATE SET stream_id = ?2, joined_at = ?3",
                &[text(branch_id), text(stream_id), text(at)],
            )
            .map_err(sql_err)?;
        Ok(JoinOutcome::Joined {
            left_stream_id: previous.filter(|prev| prev != stream_id),
        })
    }

    fn leave(&mut self, branch_id: &str) -> StoreResult<Option<String>> {
        let previous = self.home_of(branch_id)?;
        self.sql
            .execute(
                "DELETE FROM workstream_members WHERE branch_id = ?1",
                &[text(branch_id)],
            )
            .map_err(sql_err)?;
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
            return Ok(ArchiveOutcome::StreamMissing);
        };
        if stream.status != StreamStatus::Active {
            return Ok(ArchiveOutcome::AlreadyArchived);
        }
        let rehomed = self.members(stream_id)?;
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

/// The DO-side `vcs.promote` provider (DR-0052 grammar-pass DO-parity
/// residual, closed 2026-07-31): the boundary hop over the DO's own
/// branch/workstream tables, sharing `WorkspaceVcs`'s sync logic with
/// native byte-for-byte. Two deliberate divergences from the native
/// provider, both architectural rather than gaps: **no adoption lease**
/// — the DO is single-writer per object, so the mediator's
/// serialization is literal (vw note §7) and a lease would guard
/// against a writer that cannot exist; and **no fact routing** — vcs.*
/// fact delivery is the mediator surface (A5), which lives native-side.
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
        let Some(stream_id) = input
            .get("stream")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return failed("vcs.promote input names no stream".to_owned());
        };
        let streams = match DoWorkstreams::new(self.sql.clone()) {
            Ok(streams) => streams,
            Err(error) => return failed(format!("workstream store unavailable: {error:?}")),
        };
        let Ok(Some(stream)) = streams.get_stream(stream_id) else {
            return failed(format!("no such stream `{stream_id}`"));
        };
        if stream.status != StreamStatus::Active {
            return failed(format!("stream `{stream_id}` is archived"));
        }
        let branches = match crate::do_branches::DoBranches::new(self.sql.clone()) {
            Ok(branches) => branches,
            Err(error) => return failed(format!("branch store unavailable: {error:?}")),
        };
        let content = match crate::do_branches::DoContentBlobs::new(self.sql.clone()) {
            Ok(content) => content,
            Err(error) => return failed(format!("content blobs unavailable: {error:?}")),
        };
        let mut vcs = whipplescript_store::vcs::WorkspaceVcs::from_parts(branches, content);
        let seed = crate::do_store::stable_hash_hex(&format!("promote|{}", effect.effect_id));
        let at = format!("promote:{}", effect.effect_id);
        match vcs.sync_to_line(
            &stream.line_branch_id,
            whipplescript_store::branches::MAINLINE_BRANCH_ID,
            &format!("cut-{seed}-promote"),
            &at,
        ) {
            Ok(whipplescript_store::vcs::SyncOutcome::Synced { sync_cut_id }) => {
                CapabilityOutcome::Produced(serde_json::json!({
                    "variant": "Promoted",
                    "stream": stream_id,
                    "sync_cut_id": sync_cut_id,
                    "detail": "",
                }))
            }
            Ok(whipplescript_store::vcs::SyncOutcome::UpToDate) => {
                CapabilityOutcome::Produced(serde_json::json!({
                    "variant": "Promoted",
                    "stream": stream_id,
                    "sync_cut_id": "",
                    "detail": "up_to_date",
                }))
            }
            Ok(whipplescript_store::vcs::SyncOutcome::Conflicts { conflicts }) => {
                CapabilityOutcome::Produced(serde_json::json!({
                    "variant": "Conflicted",
                    "stream": stream_id,
                    "sync_cut_id": "",
                    "detail": serde_json::to_string(
                        &conflicts
                            .iter()
                            .map(|conflict| {
                                serde_json::json!({
                                    "path": conflict.path,
                                    "base": conflict.base,
                                    "ours": conflict.ours,
                                    "theirs": conflict.theirs,
                                })
                            })
                            .collect::<Vec<_>>()
                    )
                    .unwrap_or_default(),
                }))
            }
            Ok(other) => failed(format!("promotion refused: {other:?}")),
            Err(error) => failed(format!("promotion failed: {error:?}")),
        }
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
        let Some(selection) = input
            .get("selection")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return failed("the effect names no selection".to_owned());
        };
        let expr = match whipplescript_store::selection::parse(selection) {
            Ok(expr) => expr,
            Err(error) => return failed(format!("selection does not parse: {error}")),
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
        let content = match crate::do_branches::DoContentBlobs::new(self.sql.clone()) {
            Ok(content) => content,
            Err(error) => return failed(format!("content blobs unavailable: {error:?}")),
        };
        let mut vcs = whipplescript_store::vcs::WorkspaceVcs::from_parts(branches, content);
        vcs.set_actor(Some(format!("instance:{}", self.instance_id)));
        vcs.set_intent(Some(effect.effect_id.clone()));
        let seed = crate::do_store::stable_hash_hex(&format!("selective|{}", effect.effect_id));
        let cut_id = format!("cut-{seed}");
        let at = format!("selective:{}", effect.effect_id);
        if effect.target.as_deref() == Some("vcs.undo") {
            match vcs.apply_undo_selection(&branch_id, &expr, &cut_id, &at) {
                Ok(whipplescript_store::vcs::UndoSelectionOutcome::Proposed {
                    cut_id,
                    reverted_paths,
                    ..
                }) => CapabilityOutcome::Produced(serde_json::json!({
                    "variant": "Applied",
                    "cut_id": cut_id,
                    "detail": serde_json::to_string(&reverted_paths).unwrap_or_default(),
                })),
                Ok(whipplescript_store::vcs::UndoSelectionOutcome::WouldStrand { stranded }) => {
                    CapabilityOutcome::Produced(serde_json::json!({
                        "variant": "Stranded",
                        "cut_id": "",
                        "detail": serde_json::to_string(
                            &stranded
                                .iter()
                                .map(|unit| {
                                    serde_json::json!({"path": unit.path, "cut": unit.cut_id})
                                })
                                .collect::<Vec<_>>()
                        )
                        .unwrap_or_default(),
                    }))
                }
                Ok(whipplescript_store::vcs::UndoSelectionOutcome::NothingSelected) => {
                    CapabilityOutcome::Produced(serde_json::json!({
                        "variant": "Applied",
                        "cut_id": "",
                        "detail": "nothing_selected",
                    }))
                }
                Ok(other) => failed(format!("undo refused: {other:?}")),
                Err(error) => failed(format!("undo failed: {error:?}")),
            }
        } else {
            let onto = input
                .get("onto")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            let onto_line = if onto == "mainline" {
                whipplescript_store::branches::MAINLINE_BRANCH_ID.to_owned()
            } else {
                let streams = match DoWorkstreams::new(self.sql.clone()) {
                    Ok(streams) => streams,
                    Err(error) => {
                        return failed(format!("workstream store unavailable: {error:?}"))
                    }
                };
                match streams.get_stream(onto) {
                    Ok(Some(stream)) => stream.line_branch_id,
                    _ => return failed(format!("`onto {onto}` names no stream")),
                }
            };
            match vcs.transport_selection(&branch_id, &expr, &onto_line, &cut_id, &at) {
                Ok(whipplescript_store::vcs::TransportOutcome::Transported {
                    cut_id,
                    moved_paths,
                    ..
                }) => CapabilityOutcome::Produced(serde_json::json!({
                    "variant": "Applied",
                    "cut_id": cut_id,
                    "detail": serde_json::to_string(&moved_paths).unwrap_or_default(),
                })),
                Ok(whipplescript_store::vcs::TransportOutcome::Conflicted { conflicts }) => {
                    CapabilityOutcome::Produced(serde_json::json!({
                        "variant": "Conflicted",
                        "cut_id": "",
                        "detail": serde_json::to_string(
                            &conflicts
                                .iter()
                                .map(|conflict| serde_json::json!({"path": conflict.path}))
                                .collect::<Vec<_>>()
                        )
                        .unwrap_or_default(),
                    }))
                }
                Ok(
                    whipplescript_store::vcs::TransportOutcome::UpToDate
                    | whipplescript_store::vcs::TransportOutcome::NothingSelected,
                ) => CapabilityOutcome::Produced(serde_json::json!({
                    "variant": "Applied",
                    "cut_id": "",
                    "detail": "nothing_to_move",
                })),
                Ok(other) => failed(format!("transport refused: {other:?}")),
                Err(error) => failed(format!("transport failed: {error:?}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::types::{Value as RValue, ValueRef};
    use rusqlite::Connection;
    use std::rc::Rc;

    /// Minimal rusqlite-backed `DoSql` (the do_memory test harness's
    /// shape) so the ported SQL runs against a real engine.
    struct TestSql {
        conn: Connection,
    }
    fn to_value(v: &SqlValue) -> RValue {
        match v {
            SqlValue::Null => RValue::Null,
            SqlValue::Int(n) => RValue::Integer(*n),
            SqlValue::Text(s) => RValue::Text(s.clone()),
        }
    }
    fn from_ref(r: ValueRef<'_>) -> SqlValue {
        match r {
            ValueRef::Null => SqlValue::Null,
            ValueRef::Integer(n) => SqlValue::Int(n),
            ValueRef::Real(f) => SqlValue::Int(f as i64),
            ValueRef::Text(t) => SqlValue::Text(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(_) => SqlValue::Null,
        }
    }
    impl DoSql for TestSql {
        fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
            self.conn
                .execute(sql, rusqlite::params_from_iter(params.iter().map(to_value)))
                .map(|n| n as u64)
                .map_err(|e| e.to_string())
        }
        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            let mut stmt = self.conn.prepare(sql).map_err(|e| e.to_string())?;
            let cols = stmt.column_count();
            let rows = stmt
                .query_map(
                    rusqlite::params_from_iter(params.iter().map(to_value)),
                    |row| Ok((0..cols).map(|i| from_ref(row.get_ref_unwrap(i))).collect()),
                )
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<Vec<SqlValue>>, _>>()
                .map_err(|e| e.to_string())?;
            Ok(rows)
        }
    }

    fn sql() -> Rc<TestSql> {
        Rc::new(TestSql {
            conn: Connection::open_in_memory().expect("sqlite"),
        })
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
        // Single-valued membership: joining hotfix leaves triage in one step.
        let rehomed = streams.join("member-1", "hotfix", "t4").expect("join");
        assert!(
            matches!(rehomed, JoinOutcome::Joined { left_stream_id: Some(ref left) } if left == "triage")
        );
        assert_eq!(
            streams.home_of("member-1").expect("home").as_deref(),
            Some("hotfix")
        );
        // Archive re-homes members and refuses further joins.
        let archived = streams.archive_stream("hotfix", "t5").expect("archive");
        assert!(
            matches!(archived, ArchiveOutcome::Archived { ref rehomed_branch_ids } if rehomed_branch_ids == &["member-1"])
        );
        assert!(matches!(
            streams.join("member-2", "hotfix", "t6").expect("join"),
            JoinOutcome::StreamArchived
        ));
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
        let mut vcs = whipplescript_store::vcs::WorkspaceVcs::from_parts(
            crate::do_branches::DoBranches::new(Rc::clone(&sql)).expect("open"),
            crate::do_branches::DoContentBlobs::new(Rc::clone(&sql)).expect("open"),
        );
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
        let content = crate::do_branches::DoContentBlobs::new(Rc::clone(&sql)).expect("open");
        let mut vcs = whipplescript_store::vcs::WorkspaceVcs::from_parts(
            crate::do_branches::DoBranches::new(Rc::clone(&sql)).expect("open"),
            content,
        );
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
        let effect = |id: &str| whipplescript_store::ClaimableEffect {
            effect_id: id.to_owned(),
            kind: "capability.call".to_owned(),
            target: Some("vcs.promote".to_owned()),
            profile: None,
            input_json: r#"{"stream":"triage"}"#.to_owned(),
            required_capabilities_json: "[]".to_owned(),
            declared_profiles_json: "[]".to_owned(),
        };
        let config = whipplescript_kernel::effect_config::EffectConfig::default();
        let outcome = provider.produce(&effect("eff-1"), &config);
        let CapabilityOutcome::Produced(value) = outcome else {
            panic!("expected produced, got failure");
        };
        assert_eq!(value["variant"], "Promoted");
        // Mainline actually received the stream's work.
        let main_manifest = vcs
            .read(
                whipplescript_store::branches::MAINLINE_BRANCH_ID,
                "feature.md",
            )
            .expect("read")
            .expect("present");
        assert_eq!(main_manifest, "stream work");

        // Divergent edits on both sides: the hop refuses as data.
        vcs.write(
            "line-triage",
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
        let outcome = provider.produce(&effect("eff-2"), &config);
        let CapabilityOutcome::Produced(value) = outcome else {
            panic!("expected produced, got failure");
        };
        assert_eq!(value["variant"], "Conflicted");
        assert!(value["detail"]
            .as_str()
            .unwrap_or("")
            .contains("contested.md"));
    }
}
