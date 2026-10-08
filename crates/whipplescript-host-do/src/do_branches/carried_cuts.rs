//! The hosted half of the carriage registry (DR-0139, FB-6): the same rows the
//! native branch store keeps, over the durable object's SQL.

use super::flowing_sources::exact_atomic;
use super::DoBranches;
use crate::do_store::{as_text, int, opt_text, sql_err, text, DoSql};
use whipplescript_store::branches::carried_cuts::{
    existing_seed, seed_origin, CarriageDirection, CarriedCutRow, CarriedCuts,
    CarriedTwigSeedReceipt, RecordCarriageOutcome, SeedCarriedTwig, SeedCarriedTwigOutcome,
};
use whipplescript_store::branches::{
    BranchStatus, Branches, OpBranchDelta, OpBranchState, MAINLINE_BRANCH_ID,
};
use whipplescript_store::{StoreError, StoreResult};

fn read<S: DoSql>(sql: &S, digest: &str) -> StoreResult<Option<CarriedCutRow>> {
    let rows = sql
        .query(
            "SELECT record_id, kind, direction, recorded_at FROM carried_cuts \
             WHERE digest = ?1",
            &[text(digest)],
        )
        .map_err(sql_err)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let steps = sql
        .query(
            "SELECT manifest_hash FROM carried_cut_steps WHERE digest = ?1 ORDER BY step",
            &[text(digest)],
        )
        .map_err(sql_err)?;
    Ok(Some(CarriedCutRow {
        digest: digest.to_owned(),
        record_id: as_text(&row[0]),
        kind: as_text(&row[1]),
        direction: CarriageDirection::parse(&as_text(&row[2]))?,
        step_manifest_hashes: steps.iter().map(|step| as_text(&step[0])).collect(),
        recorded_at: as_text(&row[3]),
    }))
}

impl<S: DoSql> CarriedCuts for DoBranches<S> {
    fn record_carriage(&mut self, row: &CarriedCutRow) -> StoreResult<RecordCarriageOutcome> {
        let sql = &self.sql;
        exact_atomic(sql, "carried cut registry", || {
            if let Some(existing) = read(sql, &row.digest)? {
                return Ok(RecordCarriageOutcome::AlreadyRecorded(existing));
            }
            sql.execute(
                "INSERT INTO carried_cuts (digest, record_id, kind, direction, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    text(&row.digest),
                    text(&row.record_id),
                    text(&row.kind),
                    text(row.direction.as_str()),
                    text(&row.recorded_at),
                ],
            )
            .map_err(sql_err)?;
            for (step, manifest_hash) in row.step_manifest_hashes.iter().enumerate() {
                sql.execute(
                    "INSERT INTO carried_cut_steps (digest, step, manifest_hash) \
                     VALUES (?1, ?2, ?3)",
                    &[text(&row.digest), int(step as i64), text(manifest_hash)],
                )
                .map_err(sql_err)?;
            }
            Ok(RecordCarriageOutcome::Recorded)
        })
    }

    fn carriage(&self, digest: &str) -> StoreResult<Option<CarriedCutRow>> {
        read(&self.sql, digest)
    }

    fn seed_carried_twig(
        &mut self,
        request: SeedCarriedTwig<'_>,
    ) -> StoreResult<SeedCarriedTwigOutcome> {
        let sql = &self.sql;
        exact_atomic(sql, "carried twig seed", || {
            let branch = self.row_by_id(request.twig_branch_id)?;
            let cut = self.get_cut(request.seed_cut_id)?;
            let op = self.get_op(&format!("op-{}", request.seed_cut_id))?;
            if let Some(receipt) =
                existing_seed(branch.as_ref(), cut.as_ref(), op.as_ref(), request)?
            {
                return Ok(SeedCarriedTwigOutcome::AlreadySeeded(receipt));
            }
            let carried = read(sql, request.carriage_digest)?.ok_or_else(|| {
                StoreError::Conflict("carried twig seed has no received carriage".into())
            })?;
            if carried.direction != CarriageDirection::Received
                || carried.kind == "peer_line"
                || carried.step_manifest_hashes.last().map(String::as_str)
                    != Some(request.head_manifest_hash)
            {
                return Err(StoreError::Conflict(
                    "carried twig seed does not match a received cut or prefix".into(),
                ));
            }
            let parent = self.row_by_id(MAINLINE_BRANCH_ID)?.ok_or_else(|| {
                StoreError::Conflict("carried twig seed has no local mainline".into())
            })?;
            if parent.status != BranchStatus::Active
                || parent.head_cut_id.as_deref() != request.expected_parent_cut_id
            {
                return Err(StoreError::Conflict(
                    "carried twig seed has a stale local parent".into(),
                ));
            }
            sql.execute(
                "INSERT INTO branches (branch_id, name, parent_branch_id, branch_point_cut_id, \
                 branch_point_manifest_hash, head_cut_id, head_manifest_hash, status, created_at, updated_at) \
                 VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, 'active', ?7, ?7)",
                &[
                    text(request.twig_branch_id), text(MAINLINE_BRANCH_ID),
                    opt_text(parent.head_cut_id.as_deref()),
                    opt_text(parent.head_manifest_hash.as_deref()),
                    text(request.seed_cut_id), text(request.head_manifest_hash),
                    text(request.recorded_at),
                ],
            ).map_err(sql_err)?;
            let origin = seed_origin(request.carriage_digest);
            sql.execute(
                "INSERT INTO cuts (cut_id, change_id, branch_id, manifest_hash, parent_cut_id, \
                 origin, actor, intent, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                &[
                    text(request.seed_cut_id),
                    text(request.seed_cut_id),
                    text(request.twig_branch_id),
                    text(request.head_manifest_hash),
                    opt_text(request.expected_parent_cut_id),
                    text(&origin),
                    text(request.actor),
                    text(request.intent),
                    text(request.recorded_at),
                ],
            )
            .map_err(sql_err)?;
            let after = self.row_by_id(request.twig_branch_id)?.ok_or_else(|| {
                StoreError::Conflict("carried twig seed branch disappeared".into())
            })?;
            let deltas = serde_json::to_string(&[OpBranchDelta {
                branch_id: request.twig_branch_id.to_owned(),
                before: None,
                after: OpBranchState::of(&after),
            }])?;
            sql.execute(
                "INSERT INTO ops (op_id, kind, deltas, origin, recorded_at) \
                 VALUES (?1, 'carried-seed', ?2, ?3, ?4)",
                &[
                    text(&format!("op-{}", request.seed_cut_id)),
                    text(&deltas),
                    text(&origin),
                    text(request.recorded_at),
                ],
            )
            .map_err(sql_err)?;
            Ok(SeedCarriedTwigOutcome::Seeded(CarriedTwigSeedReceipt {
                twig_branch_id: request.twig_branch_id.to_owned(),
                parent_cut_id: request.expected_parent_cut_id.map(str::to_owned),
                seed_cut_id: request.seed_cut_id.to_owned(),
                carriage_digest: request.carriage_digest.to_owned(),
                head_manifest_hash: request.head_manifest_hash.to_owned(),
                recorded_at: request.recorded_at.to_owned(),
            }))
        })
    }
}
