use rusqlite::{params, Connection, TransactionBehavior};

use super::{
    classify_attempt, classify_unit, complete_pair, FlowingCloseMember, FlowingClosePrivatePin,
    FlowingCloseRoster, FlowingCloseRosterReader, FlowingCloseUnit,
};
use crate::branches::flowing_admission::FlowingAttemptPin;
use crate::branches::{flowing_fence, flowing_member_parking};
use crate::branches::{BranchStatus, BranchStore};
use crate::{StoreError, StoreResult};

fn status(value: &str) -> StoreResult<BranchStatus> {
    BranchStatus::parse(value)
        .ok_or_else(|| StoreError::Conflict(format!("unknown flowing branch status `{value}`")))
}

pub(crate) fn read_roster(
    tx: &Connection,
    source_branch_id: &str,
) -> StoreResult<Option<FlowingCloseRoster>> {
    if source_branch_id.trim().is_empty() {
        return Err(StoreError::Conflict("flowing close source is empty".into()));
    }
    let Some(fence) = flowing_fence::native::read_state(tx, source_branch_id)? else {
        return Ok(None);
    };
    let source = BranchStore::row_by_id(tx, source_branch_id)?
        .ok_or_else(|| StoreError::Conflict("flowing close source branch is missing".into()))?;
    if fence.source_branch_id != source.branch_id {
        return Err(StoreError::Conflict(
            "flowing close source fence differs from branch".into(),
        ));
    }
    let close_request = flowing_fence::native::read_close_request(tx, source_branch_id)?;
    if close_request
        .as_ref()
        .is_some_and(|receipt| receipt.request.incarnation_id != fence.incarnation_id)
    {
        return Err(StoreError::Conflict(
            "flowing close request belongs to another incarnation".into(),
        ));
    }

    let mut members = Vec::new();
    let mut statement = tx.prepare(
        "SELECT b.branch_id, b.status, b.head_cut_id, f.state_json \
             FROM branches AS b LEFT JOIN flowing_source_fences AS f \
             ON f.source_branch_id = b.branch_id \
             WHERE b.parent_branch_id = ?1 ORDER BY b.branch_id",
    )?;
    let rows = statement.query_map([source_branch_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;
    for row in rows {
        let (branch_id, branch_status, head_cut_id, state_json) = row?;
        let source_fence = state_json
            .map(|json| serde_json::from_str::<flowing_fence::FlowingFenceState>(&json))
            .transpose()?;
        if source_fence
            .as_ref()
            .is_some_and(|fence| fence.source_branch_id != branch_id)
        {
            return Err(StoreError::Conflict(
                "flowing member fence differs from branch".into(),
            ));
        }
        members.push(FlowingCloseMember {
            parked: flowing_member_parking::native::read_by_member(tx, &branch_id)?,
            branch_id,
            status: status(&branch_status)?,
            head_cut_id,
            source_fence,
        });
    }
    drop(statement);

    let mut units = Vec::new();
    let mut statement = tx.prepare(
        "SELECT unit.unit_id, unit.source_branch_id, handoff.op_id, handoff.target_branch_id, \
                    admitted.op_id, parked.op_id, parked.holder_id \
             FROM flowing_contributions AS unit \
             LEFT JOIN flowing_handoffs AS handoff ON handoff.unit_id = unit.unit_id \
             LEFT JOIN flowing_admitted_units AS admitted ON admitted.unit_id = unit.unit_id \
             LEFT JOIN flowing_parked_units AS parked ON parked.unit_id = unit.unit_id \
             WHERE unit.source_branch_id = ?1 \
                OR unit.source_branch_id IN \
                   (SELECT branch_id FROM branches WHERE parent_branch_id = ?1) \
                OR handoff.target_branch_id = ?1 \
             ORDER BY unit.unit_id",
    )?;
    let rows = statement.query_map([source_branch_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
        ))
    })?;
    for row in rows {
        let (
            unit_id,
            original_source_branch_id,
            handoff_op,
            handoff_target,
            admitted,
            parked_op,
            holder,
        ) = row?;
        let parked = complete_pair("parking", parked_op, holder)?;
        let handoff = complete_pair("handoff", handoff_op, handoff_target)?;
        let handoff_op_id = handoff.as_ref().map(|(op_id, _)| op_id.clone());
        units.push(FlowingCloseUnit {
            unit_id,
            state: classify_unit(
                source_branch_id,
                original_source_branch_id.clone(),
                handoff,
                admitted,
                parked,
            )?,
            original_source_branch_id,
            handoff_op_id,
        });
    }
    drop(statement);

    let mut live_private_pins = Vec::new();
    let mut statement = tx.prepare(
        "SELECT pin_id, twig_branch_id, cut_id, manifest_hash \
             FROM flowing_private_pins \
             WHERE released_at IS NULL AND \
               (twig_branch_id = ?1 OR twig_branch_id IN \
                 (SELECT branch_id FROM branches WHERE parent_branch_id = ?1)) \
             ORDER BY pin_id",
    )?;
    let rows = statement.query_map(params![source_branch_id], |row| {
        Ok(FlowingClosePrivatePin {
            pin_id: row.get(0)?,
            twig_branch_id: row.get(1)?,
            cut_id: row.get(2)?,
            manifest_hash: row.get(3)?,
        })
    })?;
    for row in rows {
        live_private_pins.push(row?);
    }
    drop(statement);

    let mut live_attempts = Vec::new();
    let mut statement = tx.prepare(
        "SELECT pin.op_id, pin.witness_digest, pin.source_cut_id, pin.candidate_cut_id, \
                    pin.retained_at, witness.witness_json, admitted.receipt_json, \
                    cancelled.cancel_op_id, cancelled.request_json, finished.receipt_json \
             FROM flowing_attempt_pins AS pin \
             LEFT JOIN flowing_candidate_witnesses AS witness \
               ON witness.digest = pin.witness_digest \
             LEFT JOIN flowing_admissions AS admitted ON admitted.op_id = pin.op_id \
             LEFT JOIN flowing_admission_cancellations AS cancelled \
               ON cancelled.admission_op_id = pin.op_id \
             LEFT JOIN flowing_attempt_finishes AS finished ON finished.op_id = pin.op_id \
             WHERE pin.released_at IS NULL ORDER BY pin.op_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            FlowingAttemptPin {
                op_id: row.get(0)?,
                witness_digest: row.get(1)?,
                source_cut_id: row.get(2)?,
                candidate_cut_id: row.get(3)?,
                retained_at: row.get(4)?,
                released_at: None,
            },
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, Option<String>>(8)?,
            row.get::<_, Option<String>>(9)?,
        ))
    })?;
    for row in rows {
        let (pin, witness, admission, cancellation_op_id, cancellation_json, finish) = row?;
        let attempt = classify_attempt(
            pin,
            witness,
            admission,
            cancellation_op_id,
            cancellation_json,
            finish,
        )?;
        if attempt.source_branch_id == source_branch_id
            || members
                .iter()
                .any(|member| member.branch_id == attempt.source_branch_id)
        {
            live_attempts.push(attempt);
        }
    }
    drop(statement);

    let roster = FlowingCloseRoster {
        source_branch_id: source.branch_id,
        source_fence: fence,
        source_status: source.status,
        source_parent_branch_id: source.parent_branch_id,
        source_branch_point_cut_id: source.branch_point_cut_id,
        source_head_cut_id: source.head_cut_id,
        source_head_manifest_hash: source.head_manifest_hash,
        close_request,
        members,
        units,
        live_private_pins,
        live_attempts,
    };
    Ok(Some(roster))
}

impl FlowingCloseRosterReader for BranchStore {
    fn flowing_close_roster(
        &mut self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingCloseRoster>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let roster = read_roster(&tx, source_branch_id)?;
        tx.commit()?;
        Ok(roster)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_close_roster::FlowingCloseUnitState;
    use crate::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource,
    };
    use crate::branches::flowing_sources::{
        DeclareContribution, DeclareContributionOutcome, FlowingSources, PinPrivateCut,
        PinPrivateCutOutcome,
    };
    use crate::branches::{Branches, CreateBranch, CutRecord, MAINLINE_BRANCH_ID};

    #[test]
    fn close_roster_retains_member_work_after_admission_is_disabled() {
        let mut store = BranchStore::open_in_memory().unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "branch-inc".into(),
                kind: FlowingSourceKind::Branch,
                owner: "owner".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "member",
                name: None,
                parent_branch_id: "branch",
                at_cut: None,
                created_at: "t3",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "member".into(),
                incarnation_id: "member-inc".into(),
                kind: FlowingSourceKind::Twig,
                owner: "owner".into(),
                opened_at: "t4".into(),
            })
            .unwrap();
        store
            .record_cut(CutRecord {
                cut_id: "member-cut",
                change_id: "member-cut",
                branch_id: "member",
                manifest_hash: "member-manifest",
                parent_cut_id: None,
                origin: Some("write:work"),
                actor: Some("owner"),
                intent: None,
                recorded_at: "t5",
            })
            .unwrap();
        assert_eq!(
            store
                .pin_private_cut(PinPrivateCut {
                    pin_id: "member-pin",
                    twig_branch_id: "member",
                    cut_id: "member-cut",
                    manifest_hash: "member-manifest",
                    principal: "owner",
                    retained_at: "t6",
                })
                .unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        assert_eq!(
            store
                .declare_contribution(DeclareContribution {
                    unit_id: "member-unit",
                    pin_id: "member-pin",
                    principal: "owner",
                    intent: "fix a rule",
                    read_basis_digest: "read-basis",
                    dependency_basis_digest: "dependency-basis",
                    scope_digest: "scope",
                    declared_at: "t7",
                })
                .unwrap(),
            DeclareContributionOutcome::Declared
        );
        let before = store.flowing_close_roster("branch").unwrap().unwrap();
        assert!(before.source_fence.admission_enabled);
        assert_eq!(before.members.len(), 1);
        assert_eq!(before.members[0].branch_id, "member");
        assert!(before.members[0].source_fence.is_some());
        assert_eq!(before.units.len(), 1);
        assert_eq!(before.units[0].unit_id, "member-unit");
        assert_eq!(
            before.units[0].state,
            FlowingCloseUnitState::OwedByMember {
                branch_id: "member".into()
            }
        );
        assert_eq!(before.live_private_pins[0].pin_id, "member-pin");

        let state = store.flowing_source("branch").unwrap().unwrap();
        assert!(matches!(
            store
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "disable".into(),
                    source_branch_id: "branch".into(),
                    incarnation_id: "branch-inc".into(),
                    expected_eligibility_epoch: state.eligibility_epoch,
                    expected_owner_epoch: state.owner_epoch,
                    actor: "owner".into(),
                    action: FlowingFenceAction::DisableAdmission,
                    recorded_at: "t8".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        let after = store.flowing_close_roster("branch").unwrap().unwrap();
        assert!(!after.source_fence.admission_enabled);
        assert_eq!(
            after.source_fence.eligibility_epoch,
            before.source_fence.eligibility_epoch + 1
        );
        assert_eq!(after.members, before.members);
        assert_eq!(after.units, before.units);
        assert_eq!(after.live_private_pins, before.live_private_pins);
        assert!(store.flowing_close_roster("unrelated").unwrap().is_none());

        let member_fence = store.flowing_source("member").unwrap().unwrap();
        let mut foreign_fence = member_fence.clone();
        foreign_fence.source_branch_id = "foreign".into();
        store
            .test_connection()
            .execute(
                "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'member'",
                [serde_json::to_string(&foreign_fence).unwrap()],
            )
            .unwrap();
        assert!(matches!(
            store.flowing_close_roster("branch"),
            Err(StoreError::Conflict(message)) if message.contains("member fence differs")
        ));
        store
            .test_connection()
            .execute(
                "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'member'",
                [serde_json::to_string(&member_fence).unwrap()],
            )
            .unwrap();

        store
            .test_connection()
            .execute(
                "UPDATE branches SET status = 'unclassified' WHERE branch_id = 'member'",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.flowing_close_roster("branch"),
            Err(StoreError::Conflict(message)) if message.contains("unknown flowing branch status")
        ));
        assert!(matches!(
            store.flowing_close_roster(" "),
            Err(StoreError::Conflict(message)) if message.contains("source is empty")
        ));
        store
            .test_connection()
            .execute(
                "UPDATE branches SET status = 'active' WHERE branch_id = 'member'",
                [],
            )
            .unwrap();
        let source_fence = store.flowing_source("branch").unwrap().unwrap();
        let mut foreign_source = source_fence.clone();
        foreign_source.source_branch_id = "foreign".into();
        store
            .test_connection()
            .execute(
                "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'branch'",
                [serde_json::to_string(&foreign_source).unwrap()],
            )
            .unwrap();
        assert!(matches!(
            store.flowing_close_roster("branch"),
            Err(StoreError::Conflict(message)) if message.contains("source fence differs")
        ));
        store
            .test_connection()
            .execute(
                "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'branch'",
                [serde_json::to_string(&source_fence).unwrap()],
            )
            .unwrap();
        store
            .test_connection()
            .execute("DELETE FROM branches WHERE branch_id = 'branch'", [])
            .unwrap();
        assert!(matches!(
            store.flowing_close_roster("branch"),
            Err(StoreError::Conflict(message)) if message.contains("source branch is missing")
        ));
    }
}
