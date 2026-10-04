//! Both merge-keeping heads and their attributed operation share one transaction.
use super::*;

impl BranchStore {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn commit_recorded_merge<T>(
        &self,
        source: &BranchRow,
        target: &BranchRow,
        inputs: &[CutRow],
        cut: CutRecord<'_>,
        check: &mut dyn FnMut() -> StoreResult<()>,
        judge: impl FnOnce(&mut dyn FnMut() -> StoreResult<()>) -> StoreResult<T>,
    ) -> StoreResult<T> {
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if Self::row_by_id(&tx, &source.branch_id)?.as_ref() != Some(source)
            || Self::row_by_id(&tx, &target.branch_id)?.as_ref() != Some(target)
            || inputs.iter().any(|expected| {
                Self::cut_by_id(&tx, &expected.cut_id)
                    .ok()
                    .flatten()
                    .as_ref()
                    != Some(expected)
            })
        {
            return Err(StoreError::Conflict(
                "recorded settlement inputs changed".into(),
            ));
        }
        for branch in [source, target] {
            let reservation: Option<String> = tx
                .query_row(
                    "SELECT reservation_id FROM branch_head_reservations WHERE branch_id=?1",
                    params![branch.branch_id],
                    |row| row.get(0),
                )
                .optional()?;
            if reservation.is_some_and(|held| branch == source || held != MAINLINE_GATE_LEASE) {
                return Err(StoreError::Conflict(
                    "recorded settlement head is reserved".into(),
                ));
            }
        }
        check()?;
        tx.execute(
            write_commit::INSERT_CUT,
            params![
                cut.cut_id,
                cut.change_id,
                cut.branch_id,
                cut.manifest_hash,
                cut.parent_cut_id,
                cut.origin,
                cut.actor,
                cut.intent,
                cut.recorded_at
            ],
        )?;
        let mut transaction = Some(tx);
        let result = judge(&mut || {
            let tx = transaction.take().ok_or_else(|| {
                StoreError::Conflict("recorded settlement gate invoked commit twice".into())
            })?;
            check()?;
            tx.execute(
                write_commit::ADVANCE_HEAD,
                params![
                    target.branch_id,
                    cut.cut_id,
                    cut.manifest_hash,
                    cut.recorded_at
                ],
            )?;
            tx.execute(
                "UPDATE branches SET head_cut_id=?2, head_manifest_hash=?3, branch_point_cut_id=?2, branch_point_manifest_hash=?3, updated_at=?4 WHERE branch_id=?1",
                params![source.branch_id, cut.cut_id, cut.manifest_hash, cut.recorded_at],
            )?;
            tx.execute("UPDATE conflicts SET state='superseded', updated_at=?2 WHERE branch_id=?1 AND state='open'", params![source.branch_id, cut.recorded_at])?;
            let source_after = Self::row_by_id(&tx, &source.branch_id)?.ok_or_else(|| {
                StoreError::Conflict("recorded settlement source disappeared".into())
            })?;
            let target_after = Self::row_by_id(&tx, &target.branch_id)?.ok_or_else(|| {
                StoreError::Conflict("recorded settlement target disappeared".into())
            })?;
            let deltas = serde_json::to_string(&[
                OpBranchDelta {
                    branch_id: target.branch_id.clone(),
                    before: Some(OpBranchState::of(target)),
                    after: OpBranchState::of(&target_after),
                },
                OpBranchDelta {
                    branch_id: source.branch_id.clone(),
                    before: Some(OpBranchState::of(source)),
                    after: OpBranchState::of(&source_after),
                },
            ])?;
            tx.execute(
                write_commit::INSERT_OP,
                params![
                    format!("op-{}", cut.cut_id),
                    "merge-keep",
                    deltas,
                    cut.origin,
                    cut.recorded_at
                ],
            )?;
            check()?;
            tx.commit()?;
            Ok(())
        })?;
        // The judge must invoke this transaction exactly once to report success.
        // A refusal is represented by its own result and leaves the cut uncommitted.
        Ok(result)
    }
}
