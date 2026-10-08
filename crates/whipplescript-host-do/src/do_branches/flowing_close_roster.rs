use super::flowing_sources::exact_atomic;
use super::{flowing_fence, DoBranches};
use crate::do_store::{as_opt_text, as_text, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_admission::FlowingAttemptPin;
use whipplescript_store::branches::flowing_close_roster::{
    classify_attempt, classify_unit, FlowingCloseMember, FlowingClosePrivatePin,
    FlowingCloseRoster, FlowingCloseRosterReader, FlowingCloseUnit,
};
use whipplescript_store::branches::BranchStatus;
use whipplescript_store::{StoreError, StoreResult};

fn status(value: &str) -> StoreResult<BranchStatus> {
    BranchStatus::parse(value)
        .ok_or_else(|| StoreError::Conflict(format!("unknown flowing branch status `{value}`")))
}

impl<S: DoSql> FlowingCloseRosterReader for DoBranches<S> {
    fn flowing_close_roster(
        &mut self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingCloseRoster>> {
        if source_branch_id.trim().is_empty() {
            return Err(StoreError::Conflict("flowing close source is empty".into()));
        }
        exact_atomic(&self.sql, "flowing close roster", || {
            let Some(fence) = flowing_fence::read_state(&self.sql, source_branch_id)? else {
                return Ok(None);
            };
            let source = self.row_by_id(source_branch_id)?.ok_or_else(|| {
                StoreError::Conflict("flowing close source branch is missing".into())
            })?;
            if fence.source_branch_id != source.branch_id {
                return Err(StoreError::Conflict(
                    "flowing close source fence differs from branch".into(),
                ));
            }

            let members = self
                .sql
                .query(
                    "SELECT b.branch_id, b.status, b.head_cut_id, f.state_json \
                     FROM branches AS b LEFT JOIN flowing_source_fences AS f \
                     ON f.source_branch_id = b.branch_id \
                     WHERE b.parent_branch_id = ?1 ORDER BY b.branch_id",
                    &[text(source_branch_id)],
                )
                .map_err(sql_err)?
                .into_iter()
                .map(|row| {
                    let branch_id = as_text(&row[0]);
                    let source_fence = as_opt_text(&row[3])
                        .map(|json| serde_json::from_str(&json))
                        .transpose()?;
                    if source_fence
                        .as_ref()
                        .is_some_and(|fence: &whipplescript_store::branches::flowing_fence::FlowingFenceState| fence.source_branch_id != branch_id)
                    {
                        return Err(StoreError::Conflict(
                            "flowing member fence differs from branch".into(),
                        ));
                    }
                    Ok(FlowingCloseMember {
                        branch_id,
                        status: status(&as_text(&row[1]))?,
                        head_cut_id: as_opt_text(&row[2]),
                        source_fence,
                    })
                })
                .collect::<StoreResult<Vec<_>>>()?;

            let units = self
                .sql
                .query(
                    "SELECT unit.unit_id, unit.source_branch_id, handoff.target_branch_id, \
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
                    &[text(source_branch_id)],
                )
                .map_err(sql_err)?
                .into_iter()
                .map(|row| {
                    let original_source_branch_id = as_text(&row[1]);
                    // Both columns are NOT NULL in one joined parked row.
                    let parked = as_opt_text(&row[4]).zip(as_opt_text(&row[5]));
                    Ok(FlowingCloseUnit {
                        unit_id: as_text(&row[0]),
                        state: classify_unit(
                            source_branch_id,
                            original_source_branch_id.clone(),
                            as_opt_text(&row[2]),
                            as_opt_text(&row[3]),
                            parked,
                        )?,
                        original_source_branch_id,
                    })
                })
                .collect::<StoreResult<Vec<_>>>()?;

            let live_private_pins = self
                .sql
                .query(
                    "SELECT pin_id, twig_branch_id, cut_id, manifest_hash \
                     FROM flowing_private_pins \
                     WHERE released_at IS NULL AND \
                       (twig_branch_id = ?1 OR twig_branch_id IN \
                         (SELECT branch_id FROM branches WHERE parent_branch_id = ?1)) \
                     ORDER BY pin_id",
                    &[text(source_branch_id)],
                )
                .map_err(sql_err)?
                .into_iter()
                .map(|row| FlowingClosePrivatePin {
                    pin_id: as_text(&row[0]),
                    twig_branch_id: as_text(&row[1]),
                    cut_id: as_text(&row[2]),
                    manifest_hash: as_text(&row[3]),
                })
                .collect();
            let mut live_attempts = Vec::new();
            for row in self
                .sql
                .query(
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
                    &[],
                )
                .map_err(sql_err)?
            {
                let attempt = classify_attempt(
                    FlowingAttemptPin {
                        op_id: as_text(&row[0]),
                        witness_digest: as_text(&row[1]),
                        source_cut_id: as_text(&row[2]),
                        candidate_cut_id: as_text(&row[3]),
                        retained_at: as_text(&row[4]),
                        released_at: None,
                    },
                    as_opt_text(&row[5]),
                    as_opt_text(&row[6]),
                    as_opt_text(&row[7]).zip(as_opt_text(&row[8])),
                    as_opt_text(&row[9]),
                )?;
                if attempt.source_branch_id == source_branch_id
                    || members
                        .iter()
                        .any(|member| member.branch_id == attempt.source_branch_id)
                {
                    live_attempts.push(attempt);
                }
            }
            Ok(Some(FlowingCloseRoster {
                source_branch_id: source.branch_id,
                source_fence: fence,
                source_status: source.status,
                source_head_cut_id: source.head_cut_id,
                source_head_manifest_hash: source.head_manifest_hash,
                members,
                units,
                live_private_pins,
                live_attempts,
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::do_store::test_support::RusqliteDoSql;
    use whipplescript_store::branches::flowing_close_roster::FlowingCloseUnitState;
    use whipplescript_store::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource,
    };
    use whipplescript_store::branches::flowing_sources::{
        DeclareContribution, DeclareContributionOutcome, FlowingSources, PinPrivateCut,
        PinPrivateCutOutcome,
    };
    use whipplescript_store::branches::{Branches, CreateBranch, CutRecord, MAINLINE_BRANCH_ID};

    #[test]
    fn hosted_close_roster_retains_member_work_after_disable() {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
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
        sql.execute(
            "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'member'",
            &[text(&serde_json::to_string(&foreign_fence).unwrap())],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_close_roster("branch"),
            Err(StoreError::Conflict(message)) if message.contains("member fence differs")
        ));
        sql.execute(
            "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'member'",
            &[text(&serde_json::to_string(&member_fence).unwrap())],
        )
        .unwrap();
        sql.execute(
            "UPDATE branches SET status = 'unclassified' WHERE branch_id = 'member'",
            &[],
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
        sql.execute(
            "UPDATE branches SET status = 'active' WHERE branch_id = 'member'",
            &[],
        )
        .unwrap();
        let source_fence = store.flowing_source("branch").unwrap().unwrap();
        let mut foreign_source = source_fence.clone();
        foreign_source.source_branch_id = "foreign".into();
        sql.execute(
            "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'branch'",
            &[text(&serde_json::to_string(&foreign_source).unwrap())],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_close_roster("branch"),
            Err(StoreError::Conflict(message)) if message.contains("source fence differs")
        ));
        sql.execute(
            "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'branch'",
            &[text(&serde_json::to_string(&source_fence).unwrap())],
        )
        .unwrap();
        sql.execute("DELETE FROM branches WHERE branch_id = 'branch'", &[])
            .unwrap();
        assert!(matches!(
            store.flowing_close_roster("branch"),
            Err(StoreError::Conflict(message)) if message.contains("source branch is missing")
        ));
    }
}
