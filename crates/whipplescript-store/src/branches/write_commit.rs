//! A fresh file write publishes its head, cut and operation receipt in one
//! branch-authority transaction. Immutable blobs may be prepared beforehand;
//! failed preparation/commit never publishes them through a branch head.

use super::{AdvanceOutcome, BranchRow, BranchStatus, CutRecord, OpBranchDelta, OpBranchState};
use crate::{StoreError, StoreResult};

pub const INSERT_CUT: &str = "INSERT INTO cuts \
    (cut_id, change_id, branch_id, manifest_hash, parent_cut_id, origin, actor, intent, recorded_at) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";
pub const INSERT_OP: &str = "INSERT INTO ops (op_id, kind, deltas, origin, recorded_at) \
    VALUES (?1, 'write', ?2, ?3, ?4)";
pub const ADVANCE_HEAD: &str = "UPDATE branches SET head_cut_id = ?2, \
    head_manifest_hash = ?3, updated_at = ?4 WHERE branch_id = ?1";

/// Shared native/hosted preflight, evaluated inside the backend transaction.
pub enum WritePreparation {
    Ready {
        after: Box<BranchRow>,
        deltas: String,
    },
    Refused(AdvanceOutcome),
}

pub fn prepare(
    row: Option<BranchRow>,
    reservation: Option<String>,
    cut: CutRecord<'_>,
) -> StoreResult<WritePreparation> {
    let Some(row) = row else {
        // Model the dangerous false success: publish a cut/receipt even though
        // no branch exists to own its head. The ordinary path never fabricates
        // this row; it is only the explicit counterfactual for the sweep.
        // MUTATION-SUCCESS-EXPR: Ok(WritePreparation::Ready { after: Box::new(BranchRow { branch_id: cut.branch_id.into(), name: None, parent_branch_id: None, branch_point_cut_id: None, branch_point_manifest_hash: None, head_cut_id: Some(cut.cut_id.into()), head_manifest_hash: Some(cut.manifest_hash.into()), adopted_merge_cut_id: None, status: BranchStatus::Active, created_at: cut.recorded_at.into(), updated_at: cut.recorded_at.into() }), deltas: "[]".into() })
        return Ok(WritePreparation::Refused(AdvanceOutcome::NotFound));
    };
    if row.status != BranchStatus::Active {
        return Ok(WritePreparation::Refused(AdvanceOutcome::NotActive {
            status: row.status,
        }));
    }
    if let Some(reservation_id) = reservation {
        return Err(StoreError::Conflict(format!(
            "branch `{}` head is reserved by `{reservation_id}`",
            row.branch_id
        )));
    }
    if row.head_cut_id.as_deref() != cut.parent_cut_id {
        return Ok(WritePreparation::Refused(AdvanceOutcome::Stale {
            current_head_cut_id: row.head_cut_id,
        }));
    }
    let mut after = row.clone();
    after.head_cut_id = Some(cut.cut_id.into());
    after.head_manifest_hash = Some(cut.manifest_hash.into());
    after.updated_at = cut.recorded_at.into();
    let deltas = serde_json::to_string(&[OpBranchDelta {
        branch_id: row.branch_id.clone(),
        before: Some(OpBranchState::of(&row)),
        after: OpBranchState::of(&after),
    }])?;
    Ok(WritePreparation::Ready {
        after: Box::new(after),
        deltas,
    })
}

#[cfg(feature = "native")]
pub(super) fn native(
    store: &mut super::BranchStore,
    cut: CutRecord<'_>,
    evidence: Option<&super::write_evidence::WriteEvidenceRef>,
) -> StoreResult<AdvanceOutcome> {
    if let Some(evidence) = evidence {
        evidence.validate()?;
    }
    use rusqlite::{params, OptionalExtension};
    let tx = store
        .connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let row = super::BranchStore::row_by_id(&tx, cut.branch_id)?;
    let reservation = tx
        .query_row(
            "SELECT reservation_id FROM branch_head_reservations WHERE branch_id = ?1",
            params![cut.branch_id],
            |row| row.get(0),
        )
        .optional()?;
    let (after, deltas) = match prepare(row, reservation, cut)? {
        WritePreparation::Ready { after, deltas } => (after, deltas),
        WritePreparation::Refused(outcome) => return Ok(outcome),
    };
    // Strict INSERTs are deliberate: a first-wins no-op could bind the new
    // head to an earlier, different receipt under the same identity.
    tx.execute(
        INSERT_CUT,
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
    tx.execute(
        ADVANCE_HEAD,
        params![
            cut.branch_id,
            cut.cut_id,
            cut.manifest_hash,
            cut.recorded_at
        ],
    )?;
    tx.execute(
        INSERT_OP,
        params![
            format!("op-{}", cut.cut_id),
            deltas,
            cut.origin,
            cut.recorded_at
        ],
    )?;
    if let Some(evidence) = evidence {
        tx.execute(
            super::write_evidence::INSERT,
            params![
                cut.cut_id,
                evidence.schema_ref,
                evidence.label_ref,
                evidence.content_hash
            ],
        )?;
    }
    tx.commit()?;
    Ok(AdvanceOutcome::Advanced(after))
}

/// The same public branch contract is exercised by native and hosted tests.
#[doc(hidden)]
pub mod conformance {
    use super::*;
    use crate::branches::{Branches, CreateBranch, MAINLINE_BRANCH_ID};

    pub fn cut<'a>(id: &'a str, parent: Option<&'a str>) -> CutRecord<'a> {
        CutRecord {
            cut_id: id,
            change_id: id,
            branch_id: MAINLINE_BRANCH_ID,
            manifest_hash: id,
            parent_cut_id: parent,
            origin: Some("write:note.txt"),
            actor: Some("person:fixture"),
            intent: Some("action:fixture"),
            recorded_at: "t1",
        }
    }

    #[allow(clippy::unwrap_used)]
    pub fn check(store: &mut impl Branches) {
        let before = store.ensure_mainline("t0").unwrap();
        let AdvanceOutcome::Advanced(after) = store.commit_write(cut("first", None)).unwrap()
        else {
            panic!("fresh write must commit");
        };
        let receipt = store.get_op("op-first").unwrap().unwrap();
        assert_eq!(receipt.kind, "write");
        assert_eq!(
            receipt.deltas,
            vec![OpBranchDelta {
                branch_id: MAINLINE_BRANCH_ID.into(),
                before: Some(OpBranchState::of(&before)),
                after: OpBranchState::of(&after),
            }]
        );
        let original = store.get_cut("first").unwrap().unwrap();
        assert_eq!(original.actor.as_deref(), Some("person:fixture"));
        assert_eq!(original.intent.as_deref(), Some("action:fixture"));
        assert_eq!(original.manifest_hash, "first");

        // A fresh CAS with an already-used cut cannot silently replace its
        // meaning, even when it names the current branch head as its parent.
        let mut changed = cut("first", Some("first"));
        changed.manifest_hash = "substituted";
        assert!(store.commit_write(changed).is_err());
        assert_eq!(
            store.get_branch(MAINLINE_BRANCH_ID).unwrap().as_ref(),
            Some(after.as_ref())
        );
        assert_eq!(store.get_cut("first").unwrap(), Some(original.clone()));
        assert_eq!(store.get_op("op-first").unwrap(), Some(receipt.clone()));

        // A receipt collision occurs after the tentative head move; the
        // transaction must roll back both the new cut and that move.
        store
            .record_op("op-collision", "other", &[], None, "t0")
            .unwrap();
        assert!(store.commit_write(cut("collision", Some("first"))).is_err());
        assert!(store.get_cut("collision").unwrap().is_none());
        assert_eq!(
            store.get_branch(MAINLINE_BRANCH_ID).unwrap().as_ref(),
            Some(after.as_ref())
        );
        assert_eq!(store.get_op("op-collision").unwrap().unwrap().kind, "other");

        assert!(matches!(
            store.commit_write(cut("stale", None)).unwrap(),
            AdvanceOutcome::Stale { .. }
        ));
        assert!(store.get_cut("stale").unwrap().is_none());
        store
            .reserve_head(MAINLINE_BRANCH_ID, "reservation", "t2")
            .unwrap();
        assert!(store.commit_write(cut("reserved", Some("first"))).is_err());
        assert!(store.get_cut("reserved").unwrap().is_none());
        store
            .release_head_reservation(MAINLINE_BRANCH_ID, "reservation")
            .unwrap();

        let mut missing = cut("absent", None);
        missing.branch_id = "missing";
        assert_eq!(
            store.commit_write(missing).unwrap(),
            AdvanceOutcome::NotFound
        );
        store
            .create_branch(CreateBranch {
                branch_id: "closed",
                name: None,
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t2",
                idempotency_key: None,
            })
            .unwrap();
        store.discard_branch("closed", "t3").unwrap();
        let mut closed = cut("closed-write", Some("first"));
        closed.branch_id = "closed";
        assert!(matches!(
            store.commit_write(closed).unwrap(),
            AdvanceOutcome::NotActive { .. }
        ));
        assert!(store.get_cut("closed-write").unwrap().is_none());

        assert!(matches!(
            store.commit_write(cut("second", Some("first"))).unwrap(),
            AdvanceOutcome::Advanced(_)
        ));
        assert_eq!(store.get_cut("first").unwrap(), Some(original));
        assert_eq!(store.get_op("op-first").unwrap(), Some(receipt));
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::branches::{BranchStore, Branches, MAINLINE_BRANCH_ID};

    #[test]
    fn native_write_commit_conformance() {
        conformance::check(&mut BranchStore::open_in_memory().unwrap());
    }

    #[test]
    fn native_write_commit_rolls_back_each_mutation_boundary() {
        for (table, verb) in [
            ("cuts", "INSERT"),
            ("branches", "UPDATE"),
            ("ops", "INSERT"),
        ] {
            for moment in ["BEFORE", "AFTER"] {
                let mut store = BranchStore::open_in_memory().unwrap();
                let before = store.ensure_mainline("t0").unwrap();
                store.connection.execute_batch(&format!(
                    "CREATE TRIGGER fail_write {moment} {verb} ON {table} BEGIN SELECT RAISE(ABORT, 'write fault'); END"
                )).unwrap();
                assert!(
                    store.commit_write(conformance::cut("first", None)).is_err(),
                    "{moment} {table}"
                );
                assert_eq!(store.get_branch(MAINLINE_BRANCH_ID).unwrap(), Some(before));
                assert!(store.get_cut("first").unwrap().is_none());
                assert!(store.get_op("op-first").unwrap().is_none());
                store
                    .connection
                    .execute_batch("DROP TRIGGER fail_write")
                    .unwrap();
                assert!(matches!(
                    store.commit_write(conformance::cut("first", None)).unwrap(),
                    AdvanceOutcome::Advanced(_)
                ));
            }
        }
    }
}
