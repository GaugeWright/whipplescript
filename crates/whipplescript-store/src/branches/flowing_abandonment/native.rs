use std::collections::BTreeSet;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    check_current, digest, AbandonUnitState, CommitFlowingAbandonment, FlowingAbandonmentOutcome,
    FlowingAbandonmentReceipt, FlowingAbandonmentRefusal, FlowingAbandonments,
};
use crate::branches::flowing_fence;
use crate::branches::flowing_rewrite;
use crate::branches::write_commit::{INSERT_CUT, INSERT_OP};
use crate::branches::{BranchStore, OpBranchDelta, OpBranchState};
use crate::{StoreError, StoreResult};

pub(crate) fn read_receipt(
    db: &Connection,
    predicate: &str,
    value: &str,
) -> StoreResult<Option<FlowingAbandonmentReceipt>> {
    let sql = format!(
        "SELECT op_id, after_cut_id, witness_json, witness_digest \
         FROM flowing_abandonments WHERE {predicate} = ?1"
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
        let receipt: FlowingAbandonmentReceipt = serde_json::from_str(&json)?;
        if receipt.op_id != op_id
            || receipt.after_cut_id != after_cut_id
            || digest(&receipt) != recorded_digest
        {
            return Err(StoreError::Conflict(
                "flowing abandonment receipt differs from its row or digest".into(),
            ));
        }
        let cut = BranchStore::cut_by_id(db, &receipt.after_cut_id)?;
        if !cut.is_some_and(|cut| {
            cut.branch_id == receipt.source_branch_id
                && cut.manifest_hash == receipt.after_manifest_hash
                && cut.parent_cut_id == receipt.branch_point_cut_id
                && cut.origin.as_deref() == Some("flowing:abandon")
        }) {
            return Err(StoreError::Conflict(
                "flowing abandonment receipt lost its exact cut".into(),
            ));
        }
        let expected: BTreeSet<&str> = receipt.units.iter().map(|unit| unit.unit_id()).collect();
        let mut statement =
            db.prepare("SELECT unit_id FROM flowing_abandoned_units WHERE op_id = ?1")?;
        let actual: BTreeSet<String> = statement
            .query_map([&receipt.op_id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        if expected.is_empty()
            || expected.len() != receipt.units.len()
            || expected != actual.iter().map(String::as_str).collect()
        {
            return Err(StoreError::Conflict(
                "flowing abandonment receipt differs from unit dispositions".into(),
            ));
        }
        Ok(receipt)
    })
    .transpose()
}

fn unit_states(db: &Connection, source: &str) -> StoreResult<Vec<AbandonUnitState>> {
    let mut states = Vec::new();
    for unit in flowing_rewrite::native::read_units(db, source)? {
        let parked: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM flowing_parked_units WHERE unit_id = ?1)",
            [&unit.declaration.unit_id],
            |row| row.get(0),
        )?;
        let abandoned_op: Option<String> = db
            .query_row(
                "SELECT op_id FROM flowing_abandoned_units WHERE unit_id = ?1",
                [&unit.declaration.unit_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(op_id) = abandoned_op {
            let prior = read_receipt(db, "op_id", &op_id)?.ok_or_else(|| {
                StoreError::Conflict("abandoned flowing unit lost its receipt".into())
            })?;
            if prior.source_branch_id != source
                || !prior
                    .units
                    .iter()
                    .any(|root| root.unit_id() == unit.declaration.unit_id)
            {
                return Err(StoreError::Conflict(
                    "abandoned unit differs from its source receipt".into(),
                ));
            }
            continue;
        }
        states.push(AbandonUnitState {
            declaration: unit.declaration,
            basis: unit.basis,
            pin: unit.pin,
            handed_off: unit.handed_off,
            admitted: unit.admitted,
            parked,
            abandoned: false,
        });
    }
    Ok(states)
}

impl FlowingAbandonments for BranchStore {
    fn commit_flowing_abandonment(
        &mut self,
        request: CommitFlowingAbandonment<'_>,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<FlowingAbandonmentOutcome> {
        use FlowingAbandonmentOutcome as O;
        use FlowingAbandonmentRefusal as R;
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
            // MUTATION-SUCCESS-EXPR: Ok(O::Committed(receipt.clone()))
            return Ok(O::Refused(R::CutAlreadyRecorded));
        }
        let other_op: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM ops WHERE op_id = ?1)",
            [&receipt.op_id],
            |row| row.get(0),
        )?;
        if other_op {
            // MUTATION-SUCCESS-EXPR: Ok(O::Committed(receipt.clone()))
            return Ok(O::Refused(R::OperationAlreadyRecorded));
        }
        let source = BranchStore::row_by_id(&tx, &receipt.source_branch_id)?;
        let fence = flowing_fence::native::read_state(&tx, &receipt.source_branch_id)?;
        let reserved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM branch_head_reservations WHERE branch_id = ?1)",
            [&receipt.source_branch_id],
            |row| row.get(0),
        )?;
        let units = unit_states(&tx, &receipt.source_branch_id)?;
        let after = match check_current(&receipt, source.clone(), fence.clone(), reserved, &units) {
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
                receipt.branch_point_cut_id,
                "flowing:abandon",
                receipt.actor,
                Option::<&str>::None,
                receipt.recorded_at,
            ],
        )?;
        let cut = BranchStore::cut_by_id(&tx, &receipt.after_cut_id)?;
        flowing_fence::require_head_move(
            &fence.expect("validated revision exists"),
            Some(&receipt.before_cut_id),
            &receipt.after_cut_id,
            &receipt.after_manifest_hash,
            cut.as_ref(),
        )?;
        tx.execute(
            "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, updated_at = ?4 \
             WHERE branch_id = ?1",
            params![
                receipt.source_branch_id,
                receipt.after_cut_id,
                receipt.after_manifest_hash,
                receipt.recorded_at,
            ],
        )?;
        tx.execute(
            INSERT_OP,
            params![
                receipt.op_id,
                "flowing_abandonment",
                deltas,
                "flowing:abandon",
                receipt.recorded_at,
            ],
        )?;
        tx.execute(
            "INSERT INTO flowing_abandonments (op_id, after_cut_id, witness_json, witness_digest) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                receipt.op_id,
                receipt.after_cut_id,
                serde_json::to_string(&receipt)?,
                digest(&receipt),
            ],
        )?;
        for unit in &receipt.units {
            tx.execute(
                "INSERT INTO flowing_abandoned_units (unit_id, op_id) VALUES (?1, ?2)",
                params![unit.unit_id(), receipt.op_id],
            )?;
        }
        tx.commit()?;
        Ok(O::Committed(receipt))
    }

    fn flowing_abandonment_receipt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingAbandonmentReceipt>> {
        read_receipt(&self.connection, "op_id", op_id)
    }

    fn flowing_abandonment_for_cut(
        &self,
        after_cut_id: &str,
    ) -> StoreResult<Option<FlowingAbandonmentReceipt>> {
        read_receipt(&self.connection, "after_cut_id", after_cut_id)
    }

    fn abandoned_unit_operation(&self, unit_id: &str) -> StoreResult<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT op_id FROM flowing_abandoned_units WHERE unit_id = ?1",
                [unit_id],
                |row| row.get(0),
            )
            .optional()?)
    }
}
