use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    check_current, digest, CommitFlowingRewrite, FlowingRewriteOutcome, FlowingRewriteReceipt,
    FlowingRewriteRefusal, FlowingRewrites, RewriteUnitState,
};
use crate::branches::flowing_fence;
use crate::branches::flowing_sources::{ContributionBasis, ContributionDeclaration, PrivateCutPin};
use crate::branches::write_commit::{INSERT_CUT, INSERT_OP};
use crate::branches::{BranchStore, OpBranchDelta, OpBranchState};
use crate::{StoreError, StoreResult};

fn read_receipt(
    db: &Connection,
    predicate: &str,
    value: &str,
) -> StoreResult<Option<FlowingRewriteReceipt>> {
    let sql = format!(
        "SELECT op_id, after_cut_id, witness_json, witness_digest \
         FROM flowing_rewrites WHERE {predicate} = ?1"
    );
    db.query_row(&sql, [value], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })
    .optional()?
    .map(|(op_id, after_cut_id, json, recorded_digest)| {
        let receipt: FlowingRewriteReceipt = serde_json::from_str(&json)?;
        if receipt.op_id != op_id
            || receipt.after_cut_id != after_cut_id
            || digest(&receipt) != recorded_digest
        {
            return Err(StoreError::Conflict(
                "flowing rewrite receipt differs from its row or digest".into(),
            ));
        }
        Ok(receipt)
    })
    .transpose()
}

fn read_units(db: &Connection, source: &str) -> StoreResult<Vec<RewriteUnitState>> {
    let mut statement = db.prepare(
        "SELECT unit_id, pin_id, source_branch_id, source_cut_id, \
         source_manifest_hash, principal, intent, read_basis_digest, \
         dependency_basis_digest, scope_digest, declared_at \
         FROM flowing_contributions WHERE source_branch_id = ?1 ORDER BY unit_id",
    )?;
    let declarations = statement
        .query_map([source], |row| {
            Ok(ContributionDeclaration {
                unit_id: row.get(0)?,
                pin_id: row.get(1)?,
                source_branch_id: row.get(2)?,
                source_cut_id: row.get(3)?,
                source_manifest_hash: row.get(4)?,
                principal: row.get(5)?,
                intent: row.get(6)?,
                read_basis_digest: row.get(7)?,
                dependency_basis_digest: row.get(8)?,
                scope_digest: row.get(9)?,
                declared_at: row.get(10)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut units = Vec::with_capacity(declarations.len());
    for declaration in declarations {
        let basis = db
            .query_row(
                "SELECT basis_digest, atoms_json, bound_at \
                 FROM flowing_contribution_basis WHERE unit_id = ?1",
                [&declaration.unit_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
            .map(
                |(basis_digest, atoms_json, bound_at)| -> StoreResult<ContributionBasis> {
                    Ok(ContributionBasis {
                        unit_id: declaration.unit_id.clone(),
                        basis_digest,
                        atoms: serde_json::from_str(&atoms_json)?,
                        bound_at,
                    })
                },
            )
            .transpose()?;
        let pin = db
            .query_row(
                "SELECT twig_branch_id, cut_id, manifest_hash, principal, retained_at, \
                 released_at, released_by, release_reason \
                 FROM flowing_private_pins WHERE pin_id = ?1",
                [&declaration.pin_id],
                |row| {
                    Ok(PrivateCutPin {
                        pin_id: declaration.pin_id.clone(),
                        twig_branch_id: row.get(0)?,
                        cut_id: row.get(1)?,
                        manifest_hash: row.get(2)?,
                        principal: row.get(3)?,
                        retained_at: row.get(4)?,
                        released_at: row.get(5)?,
                        released_by: row.get(6)?,
                        release_reason: row.get(7)?,
                    })
                },
            )
            .optional()?;
        let handed_off: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM flowing_handoffs WHERE unit_id = ?1)",
            [&declaration.unit_id],
            |row| row.get(0),
        )?;
        let admitted: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM flowing_admitted_units WHERE unit_id = ?1)",
            [&declaration.unit_id],
            |row| row.get(0),
        )?;
        units.push(RewriteUnitState {
            declaration,
            basis,
            pin,
            handed_off,
            admitted,
        });
    }
    Ok(units)
}

impl FlowingRewrites for BranchStore {
    fn commit_flowing_rewrite(
        &mut self,
        request: CommitFlowingRewrite<'_>,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<FlowingRewriteOutcome> {
        use FlowingRewriteOutcome as O;
        use FlowingRewriteRefusal as R;
        let receipt = request.receipt();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_receipt(&tx, "op_id", &receipt.op_id)? {
            if existing == receipt {
                return Ok(O::Existing(existing));
            }
            // MUTATION-SUCCESS-EXPR: Ok(O::Existing(existing))
            return Ok(O::Refused(R::IdentityMismatch));
        }
        if BranchStore::cut_by_id(&tx, &receipt.after_cut_id)?.is_some() {
            return Ok(O::Refused(R::CutAlreadyRecorded));
        }
        let other_op: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM ops WHERE op_id = ?1)",
            [&receipt.op_id],
            |row| row.get(0),
        )?;
        if other_op {
            return Ok(O::Refused(R::OperationAlreadyRecorded));
        }
        let source = BranchStore::row_by_id(&tx, &receipt.source_branch_id)?;
        let parent = BranchStore::row_by_id(&tx, &receipt.parent_branch_id)?;
        let fence = flowing_fence::native::read_state(&tx, &receipt.source_branch_id)?;
        let reserved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM branch_head_reservations WHERE branch_id = ?1)",
            [&receipt.source_branch_id],
            |row| row.get(0),
        )?;
        let units = read_units(&tx, &receipt.source_branch_id)?;
        let after = match check_current(
            &receipt,
            source.clone(),
            parent,
            fence.clone(),
            reserved,
            &units,
        ) {
            Ok(after) => after,
            Err(refusal) => return Ok(O::Refused(refusal)),
        };
        let old = source.expect("validated source exists");
        let deltas = serde_json::to_string(&[OpBranchDelta {
            branch_id: receipt.source_branch_id.clone(),
            before: Some(OpBranchState::of(&old)),
            after: OpBranchState::of(&after),
        }])?;
        check()?;
        tx.execute(
            INSERT_CUT,
            params![
                receipt.after_cut_id,
                receipt.after_cut_id,
                receipt.source_branch_id,
                receipt.after_manifest_hash,
                receipt.parent_head_cut_id,
                "flowing:rebase",
                receipt.actor,
                Option::<&str>::None,
                receipt.recorded_at,
            ],
        )?;
        let cut = BranchStore::cut_by_id(&tx, &receipt.after_cut_id)?;
        flowing_fence::require_head_move(
            &fence.expect("validated revision exists"),
            Some(&receipt.old_head_cut_id),
            &receipt.after_cut_id,
            &receipt.after_manifest_hash,
            cut.as_ref(),
        )?;
        tx.execute(
            "UPDATE branches SET branch_point_cut_id = ?2, branch_point_manifest_hash = ?3, \
             head_cut_id = ?4, head_manifest_hash = ?5, updated_at = ?6 WHERE branch_id = ?1",
            params![
                receipt.source_branch_id,
                receipt.parent_head_cut_id,
                receipt.parent_head_manifest_hash,
                receipt.after_cut_id,
                receipt.after_manifest_hash,
                receipt.recorded_at,
            ],
        )?;
        tx.execute(
            INSERT_OP,
            params![
                receipt.op_id,
                "flowing_rewrite",
                deltas,
                "flowing:rebase",
                receipt.recorded_at
            ],
        )?;
        tx.execute(
            "INSERT INTO flowing_rewrites (op_id, after_cut_id, witness_json, witness_digest) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                receipt.op_id,
                receipt.after_cut_id,
                serde_json::to_string(&receipt)?,
                digest(&receipt),
            ],
        )?;
        tx.commit()?;
        Ok(O::Committed(receipt))
    }

    fn flowing_rewrite_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingRewriteReceipt>> {
        read_receipt(&self.connection, "op_id", op_id)
    }

    fn flowing_rewrite_for_cut(&self, cut_id: &str) -> StoreResult<Option<FlowingRewriteReceipt>> {
        read_receipt(&self.connection, "after_cut_id", cut_id)
    }
}
