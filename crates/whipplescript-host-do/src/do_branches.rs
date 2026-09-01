//! Durable-object branch tier: the `Branches` + `ContentBlobs` seams over
//! the DO's SQLite, so the versioned workspace (working sets, merge,
//! `WorkspaceVcs`) runs on the DO with the SAME store-crate logic as
//! native — parity by reuse, not reimplementation (untie-substrate
//! readiness tracker Phase 1; native counterpart
//! `whipplescript-store/src/branches.rs`).
//!
//! Schema and semantics mirror the native store exactly: O(1) pointer
//! creation, pinned branch points, optimistic head guards, fail-closed
//! terminal statuses, write-once instance binding. The DO is
//! single-writer, so the native store's transactions collapse to plain
//! statement sequences here (the same posture the coordination parity
//! impl takes). Content blobs share the DO's existing `content_blobs`
//! table (the one checkpoint manifests already live in), created
//! defensively for stores that predate it.

use std::collections::BTreeSet;

use whipplescript_store::branches::{
    AdvanceOutcome, BindOutcome, BranchRow, BranchStatus, Branches, ClosurePinState, ConflictRow,
    CreateBranch, CreateBranchOutcome, CutRecord, CutRow, OpBranchDelta, OpRow, RetargetOutcome,
    StatusOutcome, MAINLINE_BRANCH_ID,
};
use whipplescript_store::content::{BlobStatus, ContentBlobs, EraseOutcome};
use whipplescript_store::event_chain;
use whipplescript_store::{StoreError, StoreResult};

use crate::do_store::{
    as_i64, as_opt_text, as_text, opt_text, sql_err, stable_hash_hex, text, DoSql, SqlValue,
};

pub struct DoBranches<S: DoSql> {
    sql: S,
}

impl<S: DoSql> DoBranches<S> {
    pub fn new(sql: S) -> StoreResult<Self> {
        let store = Self { sql };
        store.ensure_schema()?;
        Ok(store)
    }

    fn ensure_schema(&self) -> StoreResult<()> {
        for statement in [
            "CREATE TABLE IF NOT EXISTS branches (
                branch_id TEXT PRIMARY KEY,
                name TEXT,
                parent_branch_id TEXT,
                branch_point_cut_id TEXT,
                branch_point_manifest_hash TEXT,
                head_cut_id TEXT,
                head_manifest_hash TEXT,
                adopted_merge_cut_id TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                idempotency_key TEXT
            )",
            "CREATE UNIQUE INDEX IF NOT EXISTS branches_idempotency_idx
                ON branches(idempotency_key)
                WHERE idempotency_key IS NOT NULL",
            "CREATE UNIQUE INDEX IF NOT EXISTS branches_active_name_idx
                ON branches(name)
                WHERE name IS NOT NULL AND status = 'active'",
            "CREATE INDEX IF NOT EXISTS branches_parent_idx
                ON branches(parent_branch_id)",
            "CREATE TABLE IF NOT EXISTS branch_instances (
                instance_id TEXT PRIMARY KEY,
                branch_id TEXT NOT NULL,
                bound_at TEXT NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS branch_instances_branch_idx
                ON branch_instances(branch_id)",
            "CREATE TABLE IF NOT EXISTS cuts (
                cut_id TEXT PRIMARY KEY,
                change_id TEXT NOT NULL,
                branch_id TEXT NOT NULL,
                manifest_hash TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS cuts_change_idx ON cuts(change_id)",
            "CREATE INDEX IF NOT EXISTS cuts_branch_idx ON cuts(branch_id)",
            "CREATE TABLE IF NOT EXISTS ops (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                op_id TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                deltas TEXT NOT NULL,
                origin TEXT,
                recorded_at TEXT NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS conflicts (
                conflict_id TEXT PRIMARY KEY,
                branch_id TEXT NOT NULL,
                path TEXT NOT NULL,
                base TEXT,
                ours TEXT,
                theirs TEXT,
                ours_label TEXT NOT NULL,
                theirs_label TEXT NOT NULL,
                state TEXT NOT NULL,
                resolution TEXT,
                recorded_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
            "CREATE INDEX IF NOT EXISTS conflicts_branch_idx
                ON conflicts(branch_id, state)",
            "CREATE TABLE IF NOT EXISTS resolution_memory (
                triple_key TEXT PRIMARY KEY,
                resolution TEXT NOT NULL,
                recorded_at TEXT NOT NULL
            )",
            "CREATE TABLE IF NOT EXISTS change_units (
                branch_id TEXT NOT NULL,
                cut_seq INTEGER NOT NULL,
                cut_id TEXT NOT NULL,
                path TEXT NOT NULL,
                before_hash TEXT,
                after_hash TEXT,
                decl_units TEXT
            )",
            "CREATE INDEX IF NOT EXISTS change_units_branch_idx
                ON change_units(branch_id, cut_seq)",
            "CREATE TABLE IF NOT EXISTS change_unit_cursor (
                branch_id TEXT PRIMARY KEY,
                indexed_cuts INTEGER NOT NULL,
                last_indexed_cut_id TEXT
            )",
            // DR-0068 §5: run-scoped closure pins, keyed by (cut, holder) so a
            // re-dispatch renews rather than accumulating.
            "CREATE TABLE IF NOT EXISTS closure_pins (
                cut_id     TEXT NOT NULL,
                holder     TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                PRIMARY KEY (cut_id, holder)
            )",
            "CREATE INDEX IF NOT EXISTS closure_pins_holder_idx
                ON closure_pins(holder)",
        ] {
            self.sql.execute(statement, &[]).map_err(sql_err)?;
        }
        // Provenance columns arrived with Phase 2 (exactly as native):
        // stores minted before that gain them in place. DR-0054 adds the
        // change-unit index's declaration sub-rows the same way.
        for (table, column) in [
            ("cuts", "parent_cut_id"),
            ("cuts", "origin"),
            ("cuts", "actor"),
            ("cuts", "intent"),
            // DR-0068 §2: the cut's log half — the pinned
            // `(sequence, head_digest)` per in-scope instance. NULL reads as
            // "not captured", never as "no instances".
            ("cuts", "log_heads"),
            ("change_units", "decl_units"),
        ] {
            let info = self
                .sql
                .query(&format!("PRAGMA table_info({table})"), &[])
                .map_err(sql_err)?;
            let present = info.iter().any(|row| {
                row.get(1)
                    .map(|value| as_text(value) == column)
                    .unwrap_or(false)
            });
            if !present {
                self.sql
                    .execute(
                        &format!("ALTER TABLE {table} ADD COLUMN {column} TEXT"),
                        &[],
                    )
                    .map_err(sql_err)?;
            }
        }
        Ok(())
    }

    const ROW_COLUMNS: &'static str = "branch_id, name, parent_branch_id, \
        branch_point_cut_id, branch_point_manifest_hash, head_cut_id, \
        head_manifest_hash, adopted_merge_cut_id, status, created_at, \
        updated_at";

    fn decode_row(row: &[SqlValue]) -> BranchRow {
        BranchRow {
            branch_id: as_text(&row[0]),
            name: as_opt_text(&row[1]),
            parent_branch_id: as_opt_text(&row[2]),
            branch_point_cut_id: as_opt_text(&row[3]),
            branch_point_manifest_hash: as_opt_text(&row[4]),
            head_cut_id: as_opt_text(&row[5]),
            head_manifest_hash: as_opt_text(&row[6]),
            adopted_merge_cut_id: as_opt_text(&row[7]),
            status: BranchStatus::parse(&as_text(&row[8])).unwrap_or(BranchStatus::Active),
            created_at: as_text(&row[9]),
            updated_at: as_text(&row[10]),
        }
    }

    fn row_by_id(&self, branch_id: &str) -> StoreResult<Option<BranchRow>> {
        let rows = self
            .sql
            .query(
                &format!(
                    "SELECT {} FROM branches WHERE branch_id = ?1",
                    Self::ROW_COLUMNS
                ),
                &[text(branch_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| Self::decode_row(row)))
    }
}

impl<S: DoSql> Branches for DoBranches<S> {
    fn ensure_mainline(&mut self, created_at: &str) -> StoreResult<BranchRow> {
        self.sql
            .execute(
                "INSERT OR IGNORE INTO branches \
                 (branch_id, name, parent_branch_id, status, created_at, updated_at) \
                 VALUES (?1, ?1, NULL, 'active', ?2, ?2)",
                &[text(MAINLINE_BRANCH_ID), text(created_at)],
            )
            .map_err(sql_err)?;
        self.row_by_id(MAINLINE_BRANCH_ID)?
            .ok_or_else(|| StoreError::Conflict("mainline row missing after insert".to_owned()))
    }

    fn create_branch(&mut self, request: CreateBranch<'_>) -> StoreResult<CreateBranchOutcome> {
        if let Some(existing) = self.row_by_id(request.branch_id)? {
            return Ok(CreateBranchOutcome::Existing(existing));
        }
        if let Some(key) = request.idempotency_key {
            let rows = self
                .sql
                .query(
                    "SELECT branch_id FROM branches WHERE idempotency_key = ?1",
                    &[text(key)],
                )
                .map_err(sql_err)?;
            if let Some(row) = rows.first() {
                let existing = self
                    .row_by_id(&as_text(&row[0]))?
                    .ok_or_else(|| StoreError::Conflict("row for key missing".to_owned()))?;
                return Ok(CreateBranchOutcome::Existing(existing));
            }
        }
        let Some(parent) = self.row_by_id(request.parent_branch_id)? else {
            return Ok(CreateBranchOutcome::ParentMissing);
        };
        if parent.status != BranchStatus::Active {
            return Ok(CreateBranchOutcome::ParentNotActive {
                status: parent.status,
            });
        }
        if let Some(name) = request.name {
            let rows = self
                .sql
                .query(
                    "SELECT branch_id FROM branches WHERE name = ?1 AND status = 'active'",
                    &[text(name)],
                )
                .map_err(sql_err)?;
            if let Some(row) = rows.first() {
                return Ok(CreateBranchOutcome::NameTaken {
                    holder_branch_id: as_text(&row[0]),
                });
            }
        }
        let (point_cut, point_manifest) = match request.at_cut {
            Some((cut, manifest)) => (Some(cut.to_owned()), Some(manifest.to_owned())),
            None => (
                parent.head_cut_id.clone(),
                parent.head_manifest_hash.clone(),
            ),
        };
        self.sql
            .execute(
                "INSERT INTO branches \
                 (branch_id, name, parent_branch_id, branch_point_cut_id, \
                  branch_point_manifest_hash, head_cut_id, head_manifest_hash, \
                  status, created_at, updated_at, idempotency_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?4, ?5, 'active', ?6, ?6, ?7)",
                &[
                    text(request.branch_id),
                    opt_text(request.name),
                    text(request.parent_branch_id),
                    opt_text(point_cut.as_deref()),
                    opt_text(point_manifest.as_deref()),
                    text(request.created_at),
                    opt_text(request.idempotency_key),
                ],
            )
            .map_err(sql_err)?;
        let row = self
            .row_by_id(request.branch_id)?
            .ok_or_else(|| StoreError::Conflict("created row missing".to_owned()))?;
        Ok(CreateBranchOutcome::Created(row))
    }

    fn get_branch(&self, branch_id: &str) -> StoreResult<Option<BranchRow>> {
        self.row_by_id(branch_id)
    }

    fn list_branches(&self, status: Option<BranchStatus>) -> StoreResult<Vec<BranchRow>> {
        let rows = match status {
            Some(status) => self
                .sql
                .query(
                    &format!(
                        "SELECT {} FROM branches WHERE status = ?1 ORDER BY branch_id",
                        Self::ROW_COLUMNS
                    ),
                    &[text(status.as_str())],
                )
                .map_err(sql_err)?,
            None => self
                .sql
                .query(
                    &format!(
                        "SELECT {} FROM branches ORDER BY branch_id",
                        Self::ROW_COLUMNS
                    ),
                    &[],
                )
                .map_err(sql_err)?,
        };
        Ok(rows.iter().map(|row| Self::decode_row(row)).collect())
    }

    fn list_children(&self, parent_branch_id: &str) -> StoreResult<Vec<BranchRow>> {
        let rows = self
            .sql
            .query(
                &format!(
                    "SELECT {} FROM branches WHERE parent_branch_id = ?1 ORDER BY branch_id",
                    Self::ROW_COLUMNS
                ),
                &[text(parent_branch_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|row| Self::decode_row(row)).collect())
    }

    fn lineage(&self, branch_id: &str) -> StoreResult<Vec<BranchRow>> {
        let mut rows = Vec::new();
        let mut cursor = Some(branch_id.to_owned());
        let mut visited = BTreeSet::new();
        while let Some(current) = cursor {
            if !visited.insert(current.clone()) {
                break;
            }
            let Some(row) = self.row_by_id(&current)? else {
                break;
            };
            cursor = row.parent_branch_id.clone();
            rows.push(row);
        }
        Ok(rows)
    }

    fn retarget_branch(
        &mut self,
        branch_id: &str,
        new_parent_branch_id: &str,
        at: &str,
    ) -> StoreResult<RetargetOutcome> {
        let Some(row) = self.row_by_id(branch_id)? else {
            return Ok(RetargetOutcome::BranchMissing);
        };
        if row.status != BranchStatus::Active {
            return Ok(RetargetOutcome::BranchNotActive { status: row.status });
        }
        let Some(parent) = self.row_by_id(new_parent_branch_id)? else {
            return Ok(RetargetOutcome::ParentMissing);
        };
        if parent.status != BranchStatus::Active {
            return Ok(RetargetOutcome::ParentNotActive {
                status: parent.status,
            });
        }
        // Parent pointers must stay a tree: refuse if the new parent's
        // lineage passes through the branch itself (self-parent is the
        // one-step case). Visited guard bounds the walk even against a
        // manually corrupted store.
        let mut cursor = Some(new_parent_branch_id.to_owned());
        let mut visited = BTreeSet::new();
        while let Some(current) = cursor {
            if current == branch_id {
                return Ok(RetargetOutcome::WouldCycle);
            }
            if !visited.insert(current.clone()) {
                break;
            }
            cursor = self
                .row_by_id(&current)?
                .and_then(|row| row.parent_branch_id);
        }
        self.sql
            .execute(
                "UPDATE branches SET parent_branch_id = ?2, updated_at = ?3 WHERE branch_id = ?1",
                &[text(branch_id), text(new_parent_branch_id), text(at)],
            )
            .map_err(sql_err)?;
        let row = self
            .row_by_id(branch_id)?
            .ok_or_else(|| StoreError::Conflict("retargeted row missing".to_owned()))?;
        Ok(RetargetOutcome::Retargeted(Box::new(row)))
    }

    fn advance_head(
        &mut self,
        branch_id: &str,
        expected_head_cut_id: Option<&str>,
        cut_id: &str,
        manifest_hash: &str,
        at: &str,
    ) -> StoreResult<AdvanceOutcome> {
        let Some(row) = self.row_by_id(branch_id)? else {
            return Ok(AdvanceOutcome::NotFound);
        };
        if row.status != BranchStatus::Active {
            return Ok(AdvanceOutcome::NotActive { status: row.status });
        }
        if row.head_cut_id.as_deref() != expected_head_cut_id {
            return Ok(AdvanceOutcome::Stale {
                current_head_cut_id: row.head_cut_id,
            });
        }
        self.sql
            .execute(
                "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, \
                 updated_at = ?4 WHERE branch_id = ?1",
                &[text(branch_id), text(cut_id), text(manifest_hash), text(at)],
            )
            .map_err(sql_err)?;
        let row = self
            .row_by_id(branch_id)?
            .ok_or_else(|| StoreError::Conflict("advanced row missing".to_owned()))?;
        Ok(AdvanceOutcome::Advanced(Box::new(row)))
    }

    fn rebase_branch(
        &mut self,
        branch_id: &str,
        expected_head_cut_id: Option<&str>,
        point_cut_id: &str,
        point_manifest_hash: &str,
        head_cut_id: &str,
        head_manifest_hash: &str,
        at: &str,
    ) -> StoreResult<AdvanceOutcome> {
        let Some(row) = self.row_by_id(branch_id)? else {
            return Ok(AdvanceOutcome::NotFound);
        };
        if row.status != BranchStatus::Active {
            return Ok(AdvanceOutcome::NotActive { status: row.status });
        }
        if row.head_cut_id.as_deref() != expected_head_cut_id {
            return Ok(AdvanceOutcome::Stale {
                current_head_cut_id: row.head_cut_id,
            });
        }
        self.sql
            .execute(
                "UPDATE branches SET branch_point_cut_id = ?2, \
                 branch_point_manifest_hash = ?3, head_cut_id = ?4, \
                 head_manifest_hash = ?5, updated_at = ?6 WHERE branch_id = ?1",
                &[
                    text(branch_id),
                    text(point_cut_id),
                    text(point_manifest_hash),
                    text(head_cut_id),
                    text(head_manifest_hash),
                    text(at),
                ],
            )
            .map_err(sql_err)?;
        let row = self
            .row_by_id(branch_id)?
            .ok_or_else(|| StoreError::Conflict("rebased row missing".to_owned()))?;
        Ok(AdvanceOutcome::Advanced(Box::new(row)))
    }

    fn discard_branch(&mut self, branch_id: &str, at: &str) -> StoreResult<StatusOutcome> {
        let Some(row) = self.row_by_id(branch_id)? else {
            return Ok(StatusOutcome::NotFound);
        };
        if row.status != BranchStatus::Active {
            return Ok(StatusOutcome::InvalidTransition { from: row.status });
        }
        self.sql
            .execute(
                "UPDATE branches SET status = 'discarded', updated_at = ?2 \
                 WHERE branch_id = ?1",
                &[text(branch_id), text(at)],
            )
            .map_err(sql_err)?;
        let row = self
            .row_by_id(branch_id)?
            .ok_or_else(|| StoreError::Conflict("discarded row missing".to_owned()))?;
        Ok(StatusOutcome::Done(Box::new(row)))
    }

    fn adopt_branch(
        &mut self,
        branch_id: &str,
        merge_cut_id: &str,
        at: &str,
    ) -> StoreResult<StatusOutcome> {
        let Some(row) = self.row_by_id(branch_id)? else {
            return Ok(StatusOutcome::NotFound);
        };
        if row.status != BranchStatus::Active {
            return Ok(StatusOutcome::InvalidTransition { from: row.status });
        }
        self.sql
            .execute(
                "UPDATE branches SET status = 'adopted', adopted_merge_cut_id = ?2, \
                 updated_at = ?3 WHERE branch_id = ?1",
                &[text(branch_id), text(merge_cut_id), text(at)],
            )
            .map_err(sql_err)?;
        let row = self
            .row_by_id(branch_id)?
            .ok_or_else(|| StoreError::Conflict("adopted row missing".to_owned()))?;
        Ok(StatusOutcome::Done(Box::new(row)))
    }

    fn bind_instance(
        &mut self,
        instance_id: &str,
        branch_id: &str,
        at: &str,
    ) -> StoreResult<BindOutcome> {
        let existing = self
            .sql
            .query(
                "SELECT branch_id FROM branch_instances WHERE instance_id = ?1",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        if let Some(row) = existing.first() {
            let existing_branch = as_text(&row[0]);
            return Ok(if existing_branch == branch_id {
                BindOutcome::Bound
            } else {
                BindOutcome::AlreadyBound {
                    branch_id: existing_branch,
                }
            });
        }
        let Some(row) = self.row_by_id(branch_id)? else {
            return Ok(BindOutcome::BranchMissing);
        };
        if row.status != BranchStatus::Active {
            return Ok(BindOutcome::BranchNotActive { status: row.status });
        }
        self.sql
            .execute(
                "INSERT INTO branch_instances (instance_id, branch_id, bound_at) \
                 VALUES (?1, ?2, ?3)",
                &[text(instance_id), text(branch_id), text(at)],
            )
            .map_err(sql_err)?;
        Ok(BindOutcome::Bound)
    }

    fn instance_branch(&self, instance_id: &str) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query(
                "SELECT branch_id FROM branch_instances WHERE instance_id = ?1",
                &[text(instance_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn list_bound_instances(&self, branch_id: &str) -> StoreResult<Vec<String>> {
        let rows = self
            .sql
            .query(
                "SELECT instance_id FROM branch_instances \
                 WHERE branch_id = ?1 ORDER BY instance_id",
                &[text(branch_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|row| as_text(&row[0])).collect())
    }

    fn record_cut(&mut self, cut: CutRecord<'_>) -> StoreResult<()> {
        self.sql
            .execute(
                "INSERT OR IGNORE INTO cuts \
                 (cut_id, change_id, branch_id, manifest_hash, parent_cut_id, \
                  origin, actor, intent, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                &[
                    text(cut.cut_id),
                    text(cut.change_id),
                    text(cut.branch_id),
                    text(cut.manifest_hash),
                    opt_text(cut.parent_cut_id),
                    opt_text(cut.origin),
                    opt_text(cut.actor),
                    opt_text(cut.intent),
                    text(cut.recorded_at),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn pin_closure(&mut self, cut_id: &str, holder: &str, expires_at: &str) -> StoreResult<()> {
        self.sql
            .execute(
                "INSERT INTO closure_pins (cut_id, holder, expires_at) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(cut_id, holder) DO UPDATE SET expires_at = excluded.expires_at",
                &[text(cut_id), text(holder), text(expires_at)],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn release_closure_pins(&mut self, holder: &str) -> StoreResult<usize> {
        let released = self
            .sql
            .execute(
                "DELETE FROM closure_pins WHERE holder = ?1",
                &[text(holder)],
            )
            .map_err(sql_err)?;
        Ok(usize::try_from(released).unwrap_or(0))
    }

    fn pinned_cuts(&self, now: &str) -> StoreResult<BTreeSet<String>> {
        let rows = self
            .sql
            .query(
                "SELECT cut_id FROM closure_pins WHERE expires_at > ?1",
                &[text(now)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|row| as_text(&row[0])).collect())
    }

    /// Native parity for DR-0068 §5's refusal-on-lapse. See the trait.
    fn closure_pin_state(
        &self,
        cut_id: &str,
        holder: &str,
        now: &str,
    ) -> StoreResult<ClosurePinState> {
        let rows = self
            .sql
            .query(
                "SELECT expires_at FROM closure_pins WHERE cut_id = ?1 AND holder = ?2",
                &[text(cut_id), text(holder)],
            )
            .map_err(sql_err)?;
        let Some(row) = rows.first() else {
            return Ok(ClosurePinState::Absent);
        };
        let expires_at = as_text(&row[0]);
        Ok(if expires_at.as_str() > now {
            ClosurePinState::Held { expires_at }
        } else {
            ClosurePinState::Lapsed {
                expired_at: expires_at,
            }
        })
    }

    fn attach_cut_log_heads(
        &mut self,
        cut_id: &str,
        heads: &event_chain::LogHeads,
    ) -> StoreResult<()> {
        let rows = self
            .sql
            .query(
                "SELECT log_heads FROM cuts WHERE cut_id = ?1",
                &[text(cut_id)],
            )
            .map_err(sql_err)?;
        let Some(row) = rows.first() else {
            return Err(StoreError::Conflict(format!(
                "cut `{cut_id}` does not exist, so its log heads cannot be attached"
            )));
        };
        if as_opt_text(&row[0]).is_some() {
            return Err(StoreError::Conflict(format!(
                "cut `{cut_id}` already pinned its log heads; a cut is immutable and a \
                 second pin would be a second answer to what world it names"
            )));
        }
        let encoded = event_chain::encode_log_heads(heads)?;
        let updated = self
            .sql
            .execute(
                // `AND log_heads IS NULL` for the same reason as native: the
                // refusal has to be part of the write, or two callers both see
                // it unpinned and the second silently overwrites a pin the
                // record calls immutable.
                //
                // This host is single-writer by platform guarantee, so the race
                // should not arise — but the guard is here anyway, because
                // "the two hosts behave the same" is the property DR-0066
                // exists to hold, and a difference justified by a guarantee
                // made elsewhere is still a difference.
                "UPDATE cuts SET log_heads = ?1 WHERE cut_id = ?2 AND log_heads IS NULL",
                &[text(&encoded), text(cut_id)],
            )
            .map_err(sql_err)?;
        if updated == 0 {
            return Err(StoreError::Conflict(format!(
                "cut `{cut_id}` was pinned concurrently; a cut is immutable and a second \
                 pin would be a second answer to what world it names"
            )));
        }
        Ok(())
    }

    fn cut_log_heads(&self, cut_id: &str) -> StoreResult<Option<event_chain::LogHeads>> {
        let rows = self
            .sql
            .query(
                "SELECT log_heads FROM cuts WHERE cut_id = ?1",
                &[text(cut_id)],
            )
            .map_err(sql_err)?;
        match rows.first().and_then(|row| as_opt_text(&row[0])) {
            None => Ok(None),
            Some(encoded) => Ok(Some(event_chain::decode_log_heads(&encoded)?)),
        }
    }

    fn cut_manifest_hash(&self, cut_id: &str) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query(
                "SELECT manifest_hash FROM cuts WHERE cut_id = ?1",
                &[text(cut_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn cut_change_id(&self, cut_id: &str) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query(
                "SELECT change_id FROM cuts WHERE cut_id = ?1",
                &[text(cut_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn change_unit_cursor(
        &self,
        branch_id: &str,
    ) -> StoreResult<whipplescript_store::branches::ChangeUnitCursor> {
        let rows = self
            .sql
            .query(
                "SELECT indexed_cuts, last_indexed_cut_id FROM change_unit_cursor \
                 WHERE branch_id = ?1",
                &[text(branch_id)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .first()
            .map(|row| whipplescript_store::branches::ChangeUnitCursor {
                indexed_cuts: match &row[0] {
                    SqlValue::Int(value) => *value,
                    other => as_text(other).parse().unwrap_or(0),
                },
                last_indexed_cut_id: as_opt_text(&row[1]),
            })
            .unwrap_or(whipplescript_store::branches::ChangeUnitCursor {
                indexed_cuts: 0,
                last_indexed_cut_id: None,
            }))
    }

    fn append_change_unit_rows(
        &mut self,
        branch_id: &str,
        rows: &[whipplescript_store::branches::ChangeUnitRow],
        indexed_cuts: i64,
        last_indexed_cut_id: Option<&str>,
    ) -> StoreResult<()> {
        for row in rows {
            self.sql
                .execute(
                    "INSERT INTO change_units \
                     (branch_id, cut_seq, cut_id, path, before_hash, after_hash, decl_units) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    &[
                        text(&row.branch_id),
                        SqlValue::Int(row.cut_seq),
                        text(&row.cut_id),
                        text(&row.path),
                        opt_text(row.before_hash.as_deref()),
                        opt_text(row.after_hash.as_deref()),
                        opt_text(row.decl_units.as_deref()),
                    ],
                )
                .map_err(sql_err)?;
        }
        self.sql
            .execute(
                "INSERT INTO change_unit_cursor (branch_id, indexed_cuts, last_indexed_cut_id) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(branch_id) DO UPDATE SET indexed_cuts = ?2, \
                 last_indexed_cut_id = ?3",
                &[
                    text(branch_id),
                    SqlValue::Int(indexed_cuts),
                    opt_text(last_indexed_cut_id),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn list_change_unit_rows(
        &self,
        branch_id: &str,
        from_cut_seq: i64,
    ) -> StoreResult<Vec<whipplescript_store::branches::ChangeUnitRow>> {
        let rows = self
            .sql
            .query(
                "SELECT branch_id, cut_seq, cut_id, path, before_hash, after_hash, decl_units \
                 FROM change_units WHERE branch_id = ?1 AND cut_seq >= ?2 \
                 ORDER BY cut_seq ASC, rowid ASC",
                &[text(branch_id), SqlValue::Int(from_cut_seq)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| whipplescript_store::branches::ChangeUnitRow {
                branch_id: as_text(&row[0]),
                cut_seq: match &row[1] {
                    SqlValue::Int(value) => *value,
                    other => as_text(other).parse().unwrap_or(0),
                },
                cut_id: as_text(&row[2]),
                path: as_text(&row[3]),
                before_hash: as_opt_text(&row[4]),
                after_hash: as_opt_text(&row[5]),
                decl_units: as_opt_text(&row[6]),
            })
            .collect())
    }

    fn reset_change_unit_index(&mut self, branch_id: &str) -> StoreResult<()> {
        self.sql
            .execute(
                "DELETE FROM change_units WHERE branch_id = ?1",
                &[text(branch_id)],
            )
            .map_err(sql_err)?;
        self.sql
            .execute(
                "DELETE FROM change_unit_cursor WHERE branch_id = ?1",
                &[text(branch_id)],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn get_cut(&self, cut_id: &str) -> StoreResult<Option<CutRow>> {
        let rows = self
            .sql
            .query(
                "SELECT cut_id, change_id, branch_id, manifest_hash, \
                 parent_cut_id, origin, actor, intent, recorded_at \
                 FROM cuts WHERE cut_id = ?1",
                &[text(cut_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| decode_cut_row(row)))
    }

    fn list_cuts(&self, branch_id: &str, limit: usize) -> StoreResult<Vec<CutRow>> {
        let rows = self
            .sql
            .query(
                "SELECT cut_id, change_id, branch_id, manifest_hash, \
                 parent_cut_id, origin, actor, intent, recorded_at \
                 FROM cuts WHERE branch_id = ?1 ORDER BY rowid DESC LIMIT ?2",
                &[text(branch_id), SqlValue::Int(limit as i64)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|row| decode_cut_row(row)).collect())
    }

    fn restore_branch_state(
        &mut self,
        branch_id: &str,
        expected_head_cut_id: Option<&str>,
        state: &whipplescript_store::branches::OpBranchState,
        at: &str,
    ) -> StoreResult<AdvanceOutcome> {
        let Some(row) = self.row_by_id(branch_id)? else {
            return Ok(AdvanceOutcome::NotFound);
        };
        if row.head_cut_id.as_deref() != expected_head_cut_id {
            return Ok(AdvanceOutcome::Stale {
                current_head_cut_id: row.head_cut_id,
            });
        }
        self.sql
            .execute(
                "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, \
                 branch_point_cut_id = ?4, branch_point_manifest_hash = ?5, \
                 status = ?6, updated_at = ?7 WHERE branch_id = ?1",
                &[
                    text(branch_id),
                    opt_text(state.head_cut_id.as_deref()),
                    opt_text(state.head_manifest_hash.as_deref()),
                    opt_text(state.branch_point_cut_id.as_deref()),
                    opt_text(state.branch_point_manifest_hash.as_deref()),
                    text(&state.status),
                    text(at),
                ],
            )
            .map_err(sql_err)?;
        let row = self
            .row_by_id(branch_id)?
            .ok_or_else(|| StoreError::Conflict("restored row missing".to_owned()))?;
        Ok(AdvanceOutcome::Advanced(Box::new(row)))
    }

    fn record_op(
        &mut self,
        op_id: &str,
        kind: &str,
        deltas: &[OpBranchDelta],
        origin: Option<&str>,
        at: &str,
    ) -> StoreResult<()> {
        let deltas_json = serde_json::to_string(deltas)
            .map_err(|error| StoreError::Conflict(format!("op deltas encode: {error}")))?;
        self.sql
            .execute(
                "INSERT OR IGNORE INTO ops (op_id, kind, deltas, origin, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    text(op_id),
                    text(kind),
                    text(&deltas_json),
                    opt_text(origin),
                    text(at),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn list_ops(&self, limit: usize) -> StoreResult<Vec<OpRow>> {
        let rows = self
            .sql
            .query(
                "SELECT seq, op_id, kind, deltas, origin, recorded_at FROM ops \
                 ORDER BY seq DESC LIMIT ?1",
                &[SqlValue::Int(limit as i64)],
            )
            .map_err(sql_err)?;
        rows.iter().map(|row| decode_op_row(row)).collect()
    }

    fn get_op(&self, op_id: &str) -> StoreResult<Option<OpRow>> {
        let rows = self
            .sql
            .query(
                "SELECT seq, op_id, kind, deltas, origin, recorded_at FROM ops \
                 WHERE op_id = ?1",
                &[text(op_id)],
            )
            .map_err(sql_err)?;
        rows.first().map(|row| decode_op_row(row)).transpose()
    }

    fn record_conflict(&mut self, row: &ConflictRow) -> StoreResult<()> {
        self.sql
            .execute(
                "INSERT INTO conflicts (conflict_id, branch_id, path, base, ours, \
                 theirs, ours_label, theirs_label, state, resolution, recorded_at, \
                 updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'open', NULL, ?9, ?9) \
                 ON CONFLICT(conflict_id) DO UPDATE SET state = 'open', \
                 resolution = NULL, updated_at = ?9 WHERE state != 'open'",
                &[
                    text(&row.conflict_id),
                    text(&row.branch_id),
                    text(&row.path),
                    opt_text(row.base.as_deref()),
                    opt_text(row.ours.as_deref()),
                    opt_text(row.theirs.as_deref()),
                    text(&row.ours_label),
                    text(&row.theirs_label),
                    text(&row.recorded_at),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    fn open_conflicts(&self, branch_id: &str) -> StoreResult<Vec<ConflictRow>> {
        let rows = self
            .sql
            .query(
                "SELECT conflict_id, branch_id, path, base, ours, theirs, \
                 ours_label, theirs_label, state, resolution, recorded_at, updated_at \
                 FROM conflicts WHERE branch_id = ?1 AND state = 'open' ORDER BY path",
                &[text(branch_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|row| decode_conflict_row(row)).collect())
    }

    fn set_conflict_state(
        &mut self,
        conflict_id: &str,
        state: &str,
        resolution: Option<&str>,
        at: &str,
    ) -> StoreResult<bool> {
        self.sql
            .execute(
                "UPDATE conflicts SET state = ?2, resolution = ?3, updated_at = ?4 \
                 WHERE conflict_id = ?1",
                &[
                    text(conflict_id),
                    text(state),
                    opt_text(resolution),
                    text(at),
                ],
            )
            .map_err(sql_err)?;
        let rows = self
            .sql
            .query(
                "SELECT 1 FROM conflicts WHERE conflict_id = ?1",
                &[text(conflict_id)],
            )
            .map_err(sql_err)?;
        Ok(!rows.is_empty())
    }

    fn resolution_memory(&self, triple_key: &str) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query(
                "SELECT resolution FROM resolution_memory WHERE triple_key = ?1",
                &[text(triple_key)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn record_resolution_memory(
        &mut self,
        triple_key: &str,
        resolution: &str,
        at: &str,
    ) -> StoreResult<()> {
        self.sql
            .execute(
                "INSERT OR IGNORE INTO resolution_memory (triple_key, resolution, recorded_at) \
                 VALUES (?1, ?2, ?3)",
                &[text(triple_key), text(resolution), text(at)],
            )
            .map_err(sql_err)?;
        Ok(())
    }
}

fn decode_cut_row(row: &[SqlValue]) -> CutRow {
    CutRow {
        cut_id: as_text(&row[0]),
        change_id: as_text(&row[1]),
        branch_id: as_text(&row[2]),
        manifest_hash: as_text(&row[3]),
        parent_cut_id: as_opt_text(&row[4]),
        origin: as_opt_text(&row[5]),
        actor: as_opt_text(&row[6]),
        intent: as_opt_text(&row[7]),
        recorded_at: as_text(&row[8]),
    }
}

fn decode_conflict_row(row: &[SqlValue]) -> ConflictRow {
    ConflictRow {
        conflict_id: as_text(&row[0]),
        branch_id: as_text(&row[1]),
        path: as_text(&row[2]),
        base: as_opt_text(&row[3]),
        ours: as_opt_text(&row[4]),
        theirs: as_opt_text(&row[5]),
        ours_label: as_text(&row[6]),
        theirs_label: as_text(&row[7]),
        state: as_text(&row[8]),
        resolution: as_opt_text(&row[9]),
        recorded_at: as_text(&row[10]),
        updated_at: as_text(&row[11]),
    }
}

fn decode_op_row(row: &[SqlValue]) -> StoreResult<OpRow> {
    let deltas_json = as_text(&row[3]);
    let deltas = serde_json::from_str(&deltas_json)
        .map_err(|error| StoreError::Conflict(format!("op deltas decode: {error}")))?;
    Ok(OpRow {
        seq: match &row[0] {
            SqlValue::Int(seq) => *seq,
            _ => 0,
        },
        op_id: as_text(&row[1]),
        kind: as_text(&row[2]),
        deltas,
        origin: as_opt_text(&row[4]),
        recorded_at: as_text(&row[5]),
    })
}

/// Content blobs over the DO's `content_blobs` table — the same table
/// checkpoint manifests live in, so branch manifests and cut manifests
/// share one blob space (exactly as native).
pub struct DoContentBlobs<S: DoSql> {
    sql: S,
}

impl<S: DoSql> DoContentBlobs<S> {
    pub fn new(sql: S) -> StoreResult<Self> {
        // Defensive for stores predating the base schema; matches the
        // do_store DDL (no created_at column on the DO).
        sql.execute(
            "CREATE TABLE IF NOT EXISTS content_blobs (
                id TEXT PRIMARY KEY,
                body TEXT NOT NULL,
                byte_len INTEGER NOT NULL
            )",
            &[],
        )
        .map_err(sql_err)?;
        // DR-0066 §5's tombstone, added 2026-08-25. Without it this host could
        // not tell *erased* from *absent* — see the `erase` impl below for why
        // that was a conformance failure and not merely a missing feature.
        sql.execute(
            "CREATE TABLE IF NOT EXISTS content_erasures (
                id TEXT PRIMARY KEY,
                byte_len INTEGER NOT NULL,
                erased_at TEXT NOT NULL
            )",
            &[],
        )
        .map_err(sql_err)?;
        // DR-0071 §5: the authority of record, chained. Native parity —
        // `whipplescript_store::erasure_ledger` computes the digests for both
        // hosts, so an erasure recorded here and one recorded natively are the
        // same entry.
        sql.execute(
            "CREATE TABLE IF NOT EXISTS content_erasure_ledger (
                sequence INTEGER PRIMARY KEY,
                id TEXT NOT NULL,
                kind TEXT NOT NULL,
                byte_len INTEGER NOT NULL,
                erased_at TEXT NOT NULL,
                prev_digest TEXT NOT NULL,
                entry_digest TEXT NOT NULL
            )",
            &[],
        )
        .map_err(sql_err)?;
        sql.execute(
            "CREATE INDEX IF NOT EXISTS content_erasure_ledger_id_idx \
             ON content_erasure_ledger(id)",
            &[],
        )
        .map_err(sql_err)?;
        let store = Self { sql };
        store.backfill_erasure_ledger()?;
        Ok(store)
    }
}

impl<S: DoSql> DoContentBlobs<S> {
    /// Carry pre-ledger tombstones forward (DR-0071 §5).
    ///
    /// Idempotent and deterministic, ordered by `(erased_at, id)` because the
    /// chain commits to the order and the old table records no sequence. This
    /// host has no chunk tier, so unlike native there is only one old shape to
    /// reconcile.
    fn backfill_erasure_ledger(&self) -> StoreResult<()> {
        let rows = self
            .sql
            .query(
                "SELECT id, byte_len, erased_at FROM content_erasures \
                 WHERE id NOT IN (SELECT id FROM content_erasure_ledger) \
                 ORDER BY erased_at, id",
                &[],
            )
            .map_err(sql_err)?;
        for row in rows {
            self.append_erasure(
                &as_text(&row[0]),
                whipplescript_store::erasure_ledger::ErasedKind::Blob,
                as_i64(&row[1]),
                &as_text(&row[2]),
            )?;
        }
        Ok(())
    }

    /// The ledger's entry digests in order, for verification.
    ///
    /// # Errors
    /// Propagates store failures.
    pub fn erasure_ledger_digests(&self) -> StoreResult<Vec<String>> {
        Ok(self
            .sql
            .query(
                "SELECT entry_digest FROM content_erasure_ledger ORDER BY sequence",
                &[],
            )
            .map_err(sql_err)?
            .iter()
            .map(|row| as_text(&row[0]))
            .collect())
    }

    /// Append one entry, chained to the current head.
    fn append_erasure(
        &self,
        id: &str,
        kind: whipplescript_store::erasure_ledger::ErasedKind,
        byte_len: i64,
        erased_at: &str,
    ) -> StoreResult<()> {
        let head = self
            .sql
            .query(
                "SELECT sequence, entry_digest FROM content_erasure_ledger \
                 ORDER BY sequence DESC LIMIT 1",
                &[],
            )
            .map_err(sql_err)?;
        let (sequence, prev_digest) = match head.first() {
            Some(row) => (as_i64(&row[0]) + 1, as_text(&row[1])),
            None => (1, whipplescript_store::erasure_ledger::genesis_digest()),
        };
        // Takes the KIND, not a string to be parsed back — see the native
        // side. The parse was a refusal guarding against this crate's own
        // callers, all of which pass a literal.
        let entry = whipplescript_store::erasure_ledger::LedgerEntry {
            sequence,
            id,
            kind,
            byte_len,
            erased_at,
        };
        let digest = whipplescript_store::erasure_ledger::entry_digest(&prev_digest, &entry);
        self.sql
            .execute(
                "INSERT INTO content_erasure_ledger \
                 (sequence, id, kind, byte_len, erased_at, prev_digest, entry_digest) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &[
                    SqlValue::Int(sequence),
                    text(id),
                    text(kind.as_str()),
                    SqlValue::Int(byte_len),
                    text(erased_at),
                    text(&prev_digest),
                    text(&digest),
                ],
            )
            .map_err(sql_err)?;
        Ok(())
    }
}

impl<S: DoSql> ContentBlobs for DoContentBlobs<S> {
    fn put(&self, body: &str) -> StoreResult<String> {
        let id = stable_hash_hex(body);
        self.sql
            .execute(
                "INSERT OR IGNORE INTO content_blobs (id, body, byte_len) VALUES (?1, ?2, ?3)",
                &[text(&id), text(body), SqlValue::Int(body.len() as i64)],
            )
            .map_err(sql_err)?;
        Ok(id)
    }

    fn get(&self, id: &str) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query("SELECT body FROM content_blobs WHERE id = ?1", &[text(id)])
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    /// Native parity for DR-0066 §5. Live from the blob row, else the
    /// tombstone, else unknown.
    ///
    /// No pack or chunk-root arms, because this host has neither tier — the
    /// native `status` consults both and would report `Live` for a packed
    /// chunk. If a chunk tier ever lands here, those arms come with it.
    fn status(&self, id: &str) -> StoreResult<BlobStatus> {
        let live = self
            .sql
            .query(
                "SELECT byte_len FROM content_blobs WHERE id = ?1",
                &[text(id)],
            )
            .map_err(sql_err)?;
        if let Some(row) = live.first() {
            return Ok(BlobStatus::Live {
                byte_len: as_i64(&row[0]) as u64,
            });
        }
        let erased = self
            .sql
            .query(
                "SELECT byte_len FROM content_erasure_ledger WHERE id = ?1 \
                 ORDER BY sequence LIMIT 1",
                &[text(id)],
            )
            .map_err(sql_err)?;
        if let Some(row) = erased.first() {
            return Ok(BlobStatus::Erased {
                byte_len: as_i64(&row[0]) as u64,
            });
        }
        Ok(BlobStatus::Unknown)
    }

    /// Per-blob erasure: drop the payload, keep hash and size.
    ///
    /// **This host had no erasure at all until 2026-08-25**, inheriting the
    /// trait defaults — `status` derived Live/Unknown from `get`, and `erase`
    /// answered `Unsupported`. That default is honest for a store that *cannot*
    /// delete bytes; it was not honest here, where bytes can be deleted and the
    /// store simply had no memory of it. The consequence was that DR-0066 §5's
    /// distinguished answer did not exist on the shipped cloud host: a caller
    /// asking about erased content was told *absent* and would retry forever
    /// for bytes that are gone, which is §5's own definition of non-conforming.
    ///
    /// The gap survived because the shared content conformance suite accepts
    /// `Unsupported` unconditionally, so this host passed the suite by
    /// declining the obligation rather than by meeting it.
    fn erase(&self, id: &str, at: &str) -> StoreResult<EraseOutcome> {
        let live = self
            .sql
            .query(
                "SELECT byte_len FROM content_blobs WHERE id = ?1",
                &[text(id)],
            )
            .map_err(sql_err)?;
        let Some(row) = live.first() else {
            // Not live. Either it was already erased — an idempotent retry,
            // which must not read as "never existed" — or nothing was stored.
            let tombstoned = self
                .sql
                .query(
                    "SELECT byte_len FROM content_erasure_ledger WHERE id = ?1 \
                     ORDER BY sequence LIMIT 1",
                    &[text(id)],
                )
                .map_err(sql_err)?;
            return Ok(match tombstoned.first() {
                Some(_) => EraseOutcome::AlreadyErased,
                None => EraseOutcome::Unknown,
            });
        };
        let byte_len = as_i64(&row[0]);
        // Tombstone BEFORE the delete. The other order has a crash window that
        // produces exactly the *absent*-for-*erased* substitution §5 refuses,
        // and it is the same bottom-up discipline DR-0066 §4 applies to
        // publication: the record that makes an absence honest must be durable
        // before the bytes stop being there.
        self.append_erasure(
            id,
            whipplescript_store::erasure_ledger::ErasedKind::Blob,
            byte_len,
            at,
        )?;
        self.sql
            .execute("DELETE FROM content_blobs WHERE id = ?1", &[text(id)])
            .map_err(sql_err)?;
        Ok(EraseOutcome::Erased {
            byte_len: byte_len as u64,
        })
    }
}

/// DR-0086 F5: the ONE way host-do composes a workspace view. Installs the
/// kernel canonicalizer so declaration sub-rows are recorded at
/// index-maintenance time — without this, every DO composition wrote a
/// decl-less change-unit index and `decl()` selection / witness scans were
/// silently path-level on the DO (fail closed per DR-0054, but a parity gap
/// F5 exposed). Actor/intent stay the caller's to set.
pub(crate) fn compose_vcs<Sql: crate::do_store::DoSql + Clone>(
    sql: &Sql,
) -> Result<
    whipplescript_store::vcs::WorkspaceVcs<DoBranches<Sql>, DoContentBlobs<Sql>>,
    whipplescript_store::StoreError,
> {
    let branches = DoBranches::new(sql.clone())?;
    let content = DoContentBlobs::new(sql.clone())?;
    let mut vcs = whipplescript_store::vcs::WorkspaceVcs::from_parts(branches, content);
    vcs.set_decl_canonicalizer(Box::new(
        whipplescript_kernel::source_merge::WhipDeclCanonicalizer,
    ));
    Ok(vcs)
}
