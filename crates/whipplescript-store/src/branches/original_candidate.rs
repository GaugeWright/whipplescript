//! Atomic original candidate custody. No live source pointer is moved.
use super::*;
use crate::vcs::original_candidate::OriginalWorkspaceCandidate;
use rusqlite::{params, OptionalExtension};

fn refuse(message: &str) -> StoreError {
    StoreError::Conflict(format!("original candidate: {message}"))
}

fn eligible(tx: &rusqlite::Transaction<'_>, id: &str) -> StoreResult<BranchRow> {
    let row = BranchStore::row_by_id(tx, id)?.ok_or_else(|| refuse("custody missing"))?;
    if row.status == BranchStatus::Discarded {
        return Err(refuse("custody discarded"));
    }
    let reserved: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM branch_head_reservations WHERE branch_id = ?1)",
        [id],
        |row| row.get(0),
    )?;
    if reserved || flowing_fence::native::read_state(tx, id)?.is_some() {
        return Err(refuse("controlled or reserved custody"));
    }
    Ok(row)
}

fn original_cut(tx: &rusqlite::Transaction<'_>, id: &str, hash: &str) -> StoreResult<CutRow> {
    let cut = BranchStore::cut_by_id(tx, id)?.ok_or_else(|| refuse("original cut missing"))?;
    if cut.manifest_hash != hash {
        return Err(refuse("original cut identity differs"));
    }
    Ok(cut)
}

/// All original metadata is checked in the same transaction that publishes.
pub(crate) fn commit(
    store: &mut BranchStore,
    original: &BranchRow,
    proposed: &OriginalWorkspaceCandidate,
    meaning: &str,
    check: &mut dyn FnMut() -> StoreResult<()>,
) -> StoreResult<OriginalWorkspaceCandidate> {
    let tx = store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    check()?;
    let source = eligible(&tx, &original.branch_id)?;
    let parent_id = original
        .parent_branch_id
        .as_deref()
        .ok_or_else(|| refuse("original parent missing"))?;
    let parent = eligible(&tx, parent_id)?;
    if original.status != BranchStatus::Active
        || source.status != BranchStatus::Active
        || parent.status != BranchStatus::Active
        || parent_id == original.branch_id
    {
        return Err(refuse("original source or parent is not active"));
    }
    let (Some(base_id), Some(base_hash)) = (&original.head_cut_id, &original.head_manifest_hash)
    else {
        return Err(refuse("original base missing"));
    };
    if original_cut(&tx, base_id, base_hash)?.branch_id != original.branch_id {
        return Err(refuse("original base belongs to another source"));
    }
    match (
        &original.branch_point_cut_id,
        &original.branch_point_manifest_hash,
    ) {
        (Some(id), Some(hash)) => {
            original_cut(&tx, id, hash)?;
        }
        (None, None) => {}
        _ => return Err(refuse("incomplete original divergence")),
    }
    let branch = BranchStore::row_by_id(&tx, &proposed.branch.branch_id)?;
    let cut = BranchStore::cut_by_id(&tx, &proposed.cut.cut_id)?;
    let op = tx
        .prepare_cached(
            "SELECT seq, op_id, kind, deltas, origin, recorded_at FROM ops WHERE op_id = ?1",
        )?
        .query_row([&proposed.operation.op_id], map_op_row)
        .optional()?
        .transpose()?;
    let evidence = tx
        .prepare_cached(write_evidence::SELECT)?
        .query_row([&proposed.cut.cut_id], |row| {
            Ok(write_evidence::WriteEvidenceRef {
                schema_ref: row.get(0)?,
                label_ref: row.get(1)?,
                content_hash: row.get(2)?,
            })
        })
        .optional()?;
    let result = match (branch, cut, op, evidence) {
        (None, None, None, None) => {
            let row = &proposed.branch;
            tx.execute("INSERT INTO branches (branch_id, name, parent_branch_id, branch_point_cut_id, branch_point_manifest_hash, head_cut_id, head_manifest_hash, adopted_merge_cut_id, status, created_at, updated_at) VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, NULL, 'active', ?7, ?7)",
                params![row.branch_id, row.parent_branch_id, row.branch_point_cut_id, row.branch_point_manifest_hash, row.head_cut_id, row.head_manifest_hash, row.created_at])?;
            let cut = &proposed.cut;
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
            let op = &proposed.operation;
            tx.execute(
                write_commit::INSERT_OP,
                params![
                    op.op_id,
                    op.kind,
                    serde_json::to_string(&op.deltas)?,
                    meaning,
                    op.recorded_at
                ],
            )?;
            let evidence = &proposed.evidence;
            tx.execute(
                write_evidence::INSERT,
                params![
                    cut.cut_id,
                    evidence.schema_ref,
                    evidence.label_ref,
                    evidence.content_hash
                ],
            )?;
            let mut result = proposed.clone();
            // Read the operation sequence, not the later evidence insert.
            result.operation.seq =
                tx.query_row("SELECT seq FROM ops WHERE op_id = ?1", [&op.op_id], |row| {
                    row.get(0)
                })?;
            result
        }
        (Some(_), Some(cut), Some(op), Some(evidence)) => {
            eligible(&tx, &proposed.branch.branch_id)?;
            let mut expected_cut = proposed.cut.clone();
            expected_cut.recorded_at = cut.recorded_at.clone();
            let mut expected_op = proposed.operation.clone();
            expected_op.seq = op.seq;
            expected_op.recorded_at = cut.recorded_at.clone();
            if cut != expected_cut
                || op != expected_op
                || op.origin.as_deref() != Some(meaning)
                || evidence != proposed.evidence
            {
                return Err(refuse("retry changes original meaning"));
            }
            let mut branch = proposed.branch.clone();
            branch.created_at = cut.recorded_at.clone();
            branch.updated_at = cut.recorded_at.clone();
            OriginalWorkspaceCandidate {
                branch,
                cut,
                operation: op,
                evidence,
            }
        }
        _ => return Err(refuse("partial original receipt")),
    };
    check()?;
    tx.commit()?;
    Ok(result)
}
