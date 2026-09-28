use super::flowing_sources::exact_atomic;
use super::DoBranches;
use crate::do_store::{as_text, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_fence::{
    decide, missing_open_field, missing_transition_field, FlowingFence, FlowingFenceOutcome,
    FlowingFenceReceipt, FlowingFenceRefusal, FlowingFenceState, FlowingFenceTransition,
    FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
};
use whipplescript_store::branches::{BranchStatus, MAINLINE_BRANCH_ID};
use whipplescript_store::StoreResult;

type FenceOutcome = FlowingFenceOutcome;

fn read_state<S: DoSql>(sql: &S, source: &str) -> StoreResult<Option<FlowingFenceState>> {
    sql.query(
        "SELECT state_json FROM flowing_source_fences WHERE source_branch_id = ?1",
        &[text(source)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| serde_json::from_str(&as_text(&row[0])).map_err(Into::into))
    .transpose()
}

fn read_receipt<S: DoSql>(sql: &S, op_id: &str) -> StoreResult<Option<FlowingFenceReceipt>> {
    sql.query(
        "SELECT request_json, state_json FROM flowing_source_fence_ops WHERE op_id = ?1",
        &[text(op_id)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| {
        Ok(FlowingFenceReceipt {
            request: serde_json::from_str(&as_text(&row[0]))?,
            state: serde_json::from_str(&as_text(&row[1]))?,
        })
    })
    .transpose()
}

impl<S: DoSql> FlowingFence for DoBranches<S> {
    fn open_flowing_source(
        &mut self,
        request: &OpenFlowingSource,
    ) -> StoreResult<OpenFlowingSourceOutcome> {
        if let Some(field) = missing_open_field(request) {
            return Ok(OpenFlowingSourceOutcome::Invalid { field });
        }
        if request.source_branch_id == MAINLINE_BRANCH_ID {
            return Ok(OpenFlowingSourceOutcome::Invalid {
                field: "source_branch_id",
            });
        }
        exact_atomic(&self.sql, "flowing source open", || {
            if let Some(existing) = read_state(&self.sql, &request.source_branch_id)? {
                return Ok(
                    if existing.incarnation_id == request.incarnation_id
                        && existing.kind == request.kind
                        && existing.owner == request.owner
                        && existing.opened_at == request.opened_at
                    {
                        OpenFlowingSourceOutcome::Existing(existing)
                    } else {
                        OpenFlowingSourceOutcome::IdentityMismatch
                    },
                );
            }
            let Some(branch) = self.row_by_id(&request.source_branch_id)? else {
                return Ok(OpenFlowingSourceOutcome::BranchMissing);
            };
            if branch.status != BranchStatus::Active {
                return Ok(OpenFlowingSourceOutcome::BranchNotActive);
            }
            if (request.kind == FlowingSourceKind::Branch) != branch.name.is_some() {
                return Ok(OpenFlowingSourceOutcome::InvalidKindName);
            }
            if request.kind == FlowingSourceKind::Branch
                && branch.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID)
            {
                return Ok(OpenFlowingSourceOutcome::InvalidKindParent);
            }
            if request.kind == FlowingSourceKind::Twig
                && branch.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID)
            {
                let parent = match branch.parent_branch_id.as_deref() {
                    Some(id)
                        if self
                            .row_by_id(id)?
                            .is_some_and(|row| row.status == BranchStatus::Active) =>
                    {
                        read_state(&self.sql, id)?
                    }
                    None => None,
                    Some(_) => None,
                };
                if !parent.is_some_and(|state| {
                    state.kind == FlowingSourceKind::Branch && state.admission_enabled
                }) {
                    return Ok(OpenFlowingSourceOutcome::InvalidKindParent);
                }
            }
            if branch.head_cut_id != branch.branch_point_cut_id
                || branch.head_manifest_hash != branch.branch_point_manifest_hash
                || branch.updated_at != branch.created_at
            {
                return Ok(OpenFlowingSourceOutcome::BranchAlreadyMoved);
            }
            let children = self
                .sql
                .query(
                    "SELECT 1 FROM branches WHERE parent_branch_id = ?1 LIMIT 1",
                    &[text(&request.source_branch_id)],
                )
                .map_err(sql_err)?;
            if !children.is_empty() {
                return Ok(OpenFlowingSourceOutcome::BranchAlreadyHasChildren);
            }
            let state = FlowingFenceState {
                source_branch_id: request.source_branch_id.clone(),
                incarnation_id: request.incarnation_id.clone(),
                kind: request.kind.clone(),
                owner: request.owner.clone(),
                owner_epoch: 0,
                eligibility_epoch: 0,
                held: false,
                revision: None,
                admission_enabled: true,
                opened_at: request.opened_at.clone(),
            };
            self.sql
                .execute(
                    "INSERT INTO flowing_source_fences (source_branch_id, state_json) \
                     VALUES (?1, ?2)",
                    &[
                        text(&request.source_branch_id),
                        text(&serde_json::to_string(&state)?),
                    ],
                )
                .map_err(sql_err)?;
            Ok(OpenFlowingSourceOutcome::Opened(state))
        })
    }

    fn flowing_source(&self, source_branch_id: &str) -> StoreResult<Option<FlowingFenceState>> {
        read_state(&self.sql, source_branch_id)
    }

    fn transition_flowing_source(
        &mut self,
        request: &FlowingFenceTransition,
    ) -> StoreResult<FlowingFenceOutcome> {
        if let Some(field) = missing_transition_field(request) {
            return Ok(FlowingFenceOutcome::Refused(FlowingFenceRefusal::Invalid {
                field,
            }));
        }
        exact_atomic(&self.sql, "flowing source transition", || {
            if let Some(existing) = read_receipt(&self.sql, &request.op_id)? {
                if existing.request == *request {
                    return Ok(FlowingFenceOutcome::Existing(existing));
                }
                // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Existing(existing))
                return Ok(FenceOutcome::Refused(FlowingFenceRefusal::IdentityMismatch));
            }
            let Some(state) = read_state(&self.sql, &request.source_branch_id)? else {
                // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt { request: request.clone(), state: FlowingFenceState { source_branch_id: String::new(), incarnation_id: String::new(), kind: FlowingSourceKind::Twig, owner: String::new(), owner_epoch: 0, eligibility_epoch: 0, held: false, revision: None, admission_enabled: false, opened_at: String::new() } }))
                return Ok(FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing));
            };
            let Some(branch) = self.row_by_id(&request.source_branch_id)? else {
                // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt { request: request.clone(), state }))
                return Ok(FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing));
            };
            if branch.status != BranchStatus::Active {
                // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt { request: request.clone(), state }))
                return Ok(FenceOutcome::Refused(FlowingFenceRefusal::BranchNotActive));
            }
            let after = match decide(&state, request, branch.head_cut_id.as_deref()) {
                Ok(after) => after,
                Err(refusal) => return Ok(FlowingFenceOutcome::Refused(refusal)),
            };
            let state_json = serde_json::to_string(&after)?;
            self.sql
                .execute(
                    "UPDATE flowing_source_fences SET state_json = ?2 \
                     WHERE source_branch_id = ?1",
                    &[text(&request.source_branch_id), text(&state_json)],
                )
                .map_err(sql_err)?;
            self.sql
                .execute(
                    "INSERT INTO flowing_source_fence_ops (op_id, request_json, state_json) \
                     VALUES (?1, ?2, ?3)",
                    &[
                        text(&request.op_id),
                        text(&serde_json::to_string(request)?),
                        text(&state_json),
                    ],
                )
                .map_err(sql_err)?;
            Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt {
                request: request.clone(),
                state: after,
            }))
        })
    }

    fn flowing_fence_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingFenceReceipt>> {
        read_receipt(&self.sql, op_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::do_store::test_support::RusqliteDoSql;
    use std::rc::Rc;
    use whipplescript_store::branches::flowing_fence::FlowingFenceAction;
    use whipplescript_store::branches::{BranchStore, Branches, CreateBranch};

    fn exercise<B: Branches + FlowingFence>(mut store: B) -> Vec<FlowingFenceOutcome> {
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
        let opening = OpenFlowingSource {
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            kind: FlowingSourceKind::Branch,
            owner: "coordinator-a".into(),
            opened_at: "t2".into(),
        };
        assert!(matches!(
            store.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        store
            .create_branch(CreateBranch {
                branch_id: "twig",
                name: None,
                parent_branch_id: "branch",
                at_cut: None,
                created_at: "t2",
                idempotency_key: None,
            })
            .unwrap();
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator-a".into(),
                    opened_at: "t2".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        let mut outcomes = Vec::new();
        for (op_id, action) in [
            ("hold", FlowingFenceAction::Hold),
            ("release", FlowingFenceAction::ReleaseHold),
            (
                "begin",
                FlowingFenceAction::BeginRevision {
                    before_cut_id: None,
                    after_cut_id: "c1".into(),
                },
            ),
        ] {
            let state = store.flowing_source("branch").unwrap().unwrap();
            let request = FlowingFenceTransition {
                op_id: op_id.into(),
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                expected_eligibility_epoch: state.eligibility_epoch,
                expected_owner_epoch: state.owner_epoch,
                actor: "mediator".into(),
                action,
                recorded_at: op_id.into(),
            };
            let applied = store.transition_flowing_source(&request).unwrap();
            assert!(matches!(applied, FlowingFenceOutcome::Applied(_)));
            assert!(matches!(
                store.transition_flowing_source(&request).unwrap(),
                FlowingFenceOutcome::Existing(_)
            ));
            let mut reused = request.clone();
            reused.action = FlowingFenceAction::DisableAdmission;
            assert_eq!(
                store.transition_flowing_source(&reused).unwrap(),
                FlowingFenceOutcome::Refused(FlowingFenceRefusal::IdentityMismatch)
            );
            outcomes.push(applied);
        }
        let state = store.flowing_source("branch").unwrap().unwrap();
        let finish = FlowingFenceTransition {
            op_id: "finish".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: state.eligibility_epoch,
            expected_owner_epoch: state.owner_epoch,
            actor: "mediator".into(),
            action: FlowingFenceAction::FinishRevision {
                begin_op_id: "begin".into(),
            },
            recorded_at: "finish".into(),
        };
        outcomes.push(store.transition_flowing_source(&finish).unwrap());
        store
            .advance_head("branch", None, "c1", "manifest-1", "t3")
            .unwrap();
        outcomes.push(store.transition_flowing_source(&finish).unwrap());
        let state = store.flowing_source("branch").unwrap().unwrap();
        assert!(state.revision.is_none());
        assert_eq!(state.eligibility_epoch, 4);
        outcomes
    }

    #[test]
    fn hosted_fence_matches_native_for_hold_revision_and_exact_retries() {
        let native = exercise(BranchStore::open(":memory:").unwrap());
        let hosted =
            exercise(DoBranches::new(Rc::new(RusqliteDoSql::with_runtime_schema())).unwrap());
        assert_eq!(hosted, native);
        assert_eq!(
            hosted[3],
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::HeadMismatch { current: None })
        );
    }

    fn open_after_parent_discard<B: Branches + FlowingFence>(
        mut store: B,
    ) -> OpenFlowingSourceOutcome {
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
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "branch".into(),
                    incarnation_id: "branch-inc".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "coordinator".into(),
                    opened_at: "t2".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        store
            .create_branch(CreateBranch {
                branch_id: "twig",
                name: None,
                parent_branch_id: "branch",
                at_cut: None,
                created_at: "t3",
                idempotency_key: None,
            })
            .unwrap();
        store.discard_branch("branch", "t4").unwrap();
        let result = store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "twig".into(),
                incarnation_id: "twig-inc".into(),
                kind: FlowingSourceKind::Twig,
                owner: "coordinator".into(),
                opened_at: "t5".into(),
            })
            .unwrap();
        assert!(store.flowing_source("twig").unwrap().is_none());
        result
    }

    #[test]
    fn inactive_parent_cannot_open_a_member_twig_in_either_store() {
        assert_eq!(
            open_after_parent_discard(BranchStore::open(":memory:").unwrap()),
            OpenFlowingSourceOutcome::InvalidKindParent
        );
        assert_eq!(
            open_after_parent_discard(
                DoBranches::new(Rc::new(RusqliteDoSql::with_runtime_schema())).unwrap()
            ),
            OpenFlowingSourceOutcome::InvalidKindParent
        );
    }

    #[test]
    fn hosted_failed_receipt_insert_rolls_back_state() {
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
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator-a".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        sql.execute(
            "CREATE TRIGGER fail_fence_op BEFORE INSERT ON flowing_source_fence_ops \
             BEGIN SELECT RAISE(ABORT, 'injected refusal'); END",
            &[],
        )
        .unwrap();
        let hold = FlowingFenceTransition {
            op_id: "hold-fails".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: 0,
            expected_owner_epoch: 0,
            actor: "mediator".into(),
            action: FlowingFenceAction::Hold,
            recorded_at: "t3".into(),
        };
        assert!(store.transition_flowing_source(&hold).is_err());
        let state = store.flowing_source("branch").unwrap().unwrap();
        assert!(!state.held);
        assert_eq!(state.eligibility_epoch, 0);
        assert!(store.flowing_fence_receipt("hold-fails").unwrap().is_none());
    }

    #[test]
    fn hosted_invalid_request_and_inactive_branch_cannot_change_fence_state() {
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
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator-a".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        let request = FlowingFenceTransition {
            op_id: "hold".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: 0,
            expected_owner_epoch: 0,
            actor: "mediator".into(),
            action: FlowingFenceAction::Hold,
            recorded_at: "t3".into(),
        };
        let mut invalid = request.clone();
        invalid.actor.clear();
        assert_eq!(
            store.transition_flowing_source(&invalid).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Invalid { field: "actor" })
        );
        let mut no_state = request.clone();
        no_state.source_branch_id = "never-opened".into();
        no_state.op_id = "no-state".into();
        assert_eq!(
            store.transition_flowing_source(&no_state).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing)
        );
        store.discard_branch("branch", "t3").unwrap();
        assert_eq!(
            store.transition_flowing_source(&request).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::BranchNotActive)
        );
        assert_eq!(
            store
                .flowing_source("branch")
                .unwrap()
                .unwrap()
                .eligibility_epoch,
            0
        );
        sql.execute("DELETE FROM branches WHERE branch_id = 'branch'", &[])
            .unwrap();
        assert_eq!(
            store.transition_flowing_source(&request).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing)
        );
    }

    #[test]
    fn hosted_open_refuses_a_preexisting_member_twig() {
        let mut store = DoBranches::new(Rc::new(RusqliteDoSql::with_runtime_schema())).unwrap();
        store.ensure_mainline("t0").unwrap();
        for (branch_id, parent_branch_id) in
            [("branch", MAINLINE_BRANCH_ID), ("member-twig", "branch")]
        {
            store
                .create_branch(CreateBranch {
                    branch_id,
                    name: (branch_id == "branch").then_some("feature"),
                    parent_branch_id,
                    at_cut: None,
                    created_at: "t1",
                    idempotency_key: None,
                })
                .unwrap();
        }
        assert_eq!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "branch".into(),
                    incarnation_id: "inc-1".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "coordinator-a".into(),
                    opened_at: "t2".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::BranchAlreadyHasChildren
        );
    }
}
