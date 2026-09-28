use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    decide, missing_open_field, missing_transition_field, FlowingFence, FlowingFenceOutcome,
    FlowingFenceReceipt, FlowingFenceRefusal, FlowingFenceState, FlowingFenceTransition,
    FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
};
use crate::branches::{BranchStatus, BranchStore, MAINLINE_BRANCH_ID};
use crate::StoreResult;

type FenceOutcome = FlowingFenceOutcome;

fn read_state(connection: &Connection, source: &str) -> StoreResult<Option<FlowingFenceState>> {
    connection
        .query_row(
            "SELECT state_json FROM flowing_source_fences WHERE source_branch_id = ?1",
            [source],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|json| serde_json::from_str(&json).map_err(Into::into))
        .transpose()
}

fn read_receipt(connection: &Connection, op_id: &str) -> StoreResult<Option<FlowingFenceReceipt>> {
    connection
        .query_row(
            "SELECT request_json, state_json FROM flowing_source_fence_ops WHERE op_id = ?1",
            [op_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(request, state)| {
            Ok(FlowingFenceReceipt {
                request: serde_json::from_str(&request)?,
                state: serde_json::from_str(&state)?,
            })
        })
        .transpose()
}

impl FlowingFence for BranchStore {
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
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_state(&tx, &request.source_branch_id)? {
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
        let Some(branch) = BranchStore::row_by_id(&tx, &request.source_branch_id)? else {
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
                    if BranchStore::row_by_id(&tx, id)?
                        .is_some_and(|row| row.status == BranchStatus::Active) =>
                {
                    read_state(&tx, id)?
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
        let has_children: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM branches WHERE parent_branch_id = ?1)",
            [&request.source_branch_id],
            |row| row.get(0),
        )?;
        if has_children {
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
        tx.execute(
            "INSERT INTO flowing_source_fences (source_branch_id, state_json) VALUES (?1, ?2)",
            params![request.source_branch_id, serde_json::to_string(&state)?],
        )?;
        tx.commit()?;
        Ok(OpenFlowingSourceOutcome::Opened(state))
    }

    fn flowing_source(&self, source_branch_id: &str) -> StoreResult<Option<FlowingFenceState>> {
        read_state(&self.connection, source_branch_id)
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
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_receipt(&tx, &request.op_id)? {
            if existing.request == *request {
                return Ok(FlowingFenceOutcome::Existing(existing));
            }
            // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Existing(existing))
            return Ok(FenceOutcome::Refused(FlowingFenceRefusal::IdentityMismatch));
        }
        let Some(state) = read_state(&tx, &request.source_branch_id)? else {
            // MUTATION-SUCCESS-EXPR: Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt { request: request.clone(), state: FlowingFenceState { source_branch_id: String::new(), incarnation_id: String::new(), kind: FlowingSourceKind::Twig, owner: String::new(), owner_epoch: 0, eligibility_epoch: 0, held: false, revision: None, admission_enabled: false, opened_at: String::new() } }))
            return Ok(FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing));
        };
        let Some(branch) = BranchStore::row_by_id(&tx, &request.source_branch_id)? else {
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
        tx.execute(
            "UPDATE flowing_source_fences SET state_json = ?2 WHERE source_branch_id = ?1",
            params![request.source_branch_id, state_json],
        )?;
        tx.execute(
            "INSERT INTO flowing_source_fence_ops (op_id, request_json, state_json) \
             VALUES (?1, ?2, ?3)",
            params![request.op_id, serde_json::to_string(request)?, state_json,],
        )?;
        tx.commit()?;
        Ok(FlowingFenceOutcome::Applied(FlowingFenceReceipt {
            request: request.clone(),
            state: after,
        }))
    }

    fn flowing_fence_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingFenceReceipt>> {
        read_receipt(&self.connection, op_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_fence::FlowingFenceAction;
    use crate::branches::{AdvanceOutcome, Branches, CreateBranch, CreateBranchOutcome};

    fn source() -> BranchStore {
        let mut store = BranchStore::open_in_memory().unwrap();
        store.ensure_mainline("t0").unwrap();
        assert!(matches!(
            store
                .create_branch(CreateBranch {
                    branch_id: "branch",
                    name: Some("feature"),
                    parent_branch_id: MAINLINE_BRANCH_ID,
                    at_cut: None,
                    created_at: "t1",
                    idempotency_key: None,
                })
                .unwrap(),
            CreateBranchOutcome::Created(_)
        ));
        store
    }

    fn request(
        store: &BranchStore,
        op_id: &str,
        action: FlowingFenceAction,
    ) -> FlowingFenceTransition {
        let state = store.flowing_source("branch").unwrap().unwrap();
        FlowingFenceTransition {
            op_id: op_id.into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: state.eligibility_epoch,
            expected_owner_epoch: state.owner_epoch,
            actor: "mediator".into(),
            action,
            recorded_at: op_id.into(),
        }
    }

    #[test]
    fn source_fence_holds_revision_takeover_and_close_with_exact_retries() {
        let mut store = source();
        let opening = OpenFlowingSource {
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            kind: FlowingSourceKind::Branch,
            owner: "coordinator-a".into(),
            opened_at: "t2".into(),
        };
        let OpenFlowingSourceOutcome::Opened(first) = store.open_flowing_source(&opening).unwrap()
        else {
            panic!("fresh source must open")
        };
        assert_eq!(first.eligibility_epoch, 0);
        assert_eq!(
            store.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::Existing(first)
        );
        for (branch_id, parent_branch_id) in [
            ("member-twig", "branch"),
            ("direct-twig", MAINLINE_BRANCH_ID),
        ] {
            store
                .create_branch(CreateBranch {
                    branch_id,
                    name: None,
                    parent_branch_id,
                    at_cut: None,
                    created_at: "t2",
                    idempotency_key: None,
                })
                .unwrap();
            assert!(matches!(
                store
                    .open_flowing_source(&OpenFlowingSource {
                        source_branch_id: branch_id.into(),
                        incarnation_id: format!("{branch_id}-inc"),
                        kind: FlowingSourceKind::Twig,
                        owner: "coordinator-a".into(),
                        opened_at: "t2".into(),
                    })
                    .unwrap(),
                OpenFlowingSourceOutcome::Opened(_)
            ));
        }
        store
            .create_branch(CreateBranch {
                branch_id: "nested-twig",
                name: None,
                parent_branch_id: "member-twig",
                at_cut: None,
                created_at: "t2",
                idempotency_key: None,
            })
            .unwrap();
        assert_eq!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "nested-twig".into(),
                    incarnation_id: "nested-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator-a".into(),
                    opened_at: "t2".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::InvalidKindParent
        );

        let hold = request(&store, "hold-1", FlowingFenceAction::Hold);
        let FlowingFenceOutcome::Applied(held) = store.transition_flowing_source(&hold).unwrap()
        else {
            panic!("Hold must commit")
        };
        assert!(held.state.held);
        assert_eq!(held.state.eligibility_epoch, 1);
        assert_eq!(
            store.transition_flowing_source(&hold).unwrap(),
            FlowingFenceOutcome::Existing(held.clone())
        );
        let mut reused = hold.clone();
        reused.action = FlowingFenceAction::ReleaseHold;
        assert_eq!(
            store.transition_flowing_source(&reused).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::IdentityMismatch)
        );
        let stale = FlowingFenceTransition {
            op_id: "stale".into(),
            ..hold.clone()
        };
        assert_eq!(
            store.transition_flowing_source(&stale).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::StaleEligibilityEpoch { current: 1 })
        );
        let release = request(&store, "release-1", FlowingFenceAction::ReleaseHold);
        let FlowingFenceOutcome::Applied(released) =
            store.transition_flowing_source(&release).unwrap()
        else {
            panic!("release must commit")
        };
        assert!(!released.state.held);
        assert_eq!(released.state.eligibility_epoch, 2);

        let begin = request(
            &store,
            "begin-1",
            FlowingFenceAction::BeginRevision {
                before_cut_id: None,
                after_cut_id: "branch-cut-1".into(),
            },
        );
        let FlowingFenceOutcome::Applied(pending) =
            store.transition_flowing_source(&begin).unwrap()
        else {
            panic!("revision fence must commit before the head moves")
        };
        assert_eq!(
            pending.state.revision.as_ref().unwrap().begin_op_id,
            "begin-1"
        );
        let finish = request(
            &store,
            "finish-1",
            FlowingFenceAction::FinishRevision {
                begin_op_id: "begin-1".into(),
            },
        );
        assert_eq!(
            store.transition_flowing_source(&finish).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::HeadMismatch { current: None })
        );
        assert!(matches!(
            store
                .advance_head("branch", None, "branch-cut-1", "manifest-1", "t3")
                .unwrap(),
            AdvanceOutcome::Advanced(_)
        ));
        let FlowingFenceOutcome::Applied(finished) =
            store.transition_flowing_source(&finish).unwrap()
        else {
            panic!("the exact moved head closes the pending revision")
        };
        assert!(finished.state.revision.is_none());
        assert_eq!(finished.state.eligibility_epoch, 4);

        let obsolete = request(&store, "obsolete", FlowingFenceAction::Hold);
        let invalidate = request(
            &store,
            "revoke-1",
            FlowingFenceAction::InvalidateEligibility {
                reason: "grant revoked".into(),
            },
        );
        let FlowingFenceOutcome::Applied(invalidated) =
            store.transition_flowing_source(&invalidate).unwrap()
        else {
            panic!("revocation must fence prior candidates")
        };
        assert_eq!(invalidated.state.eligibility_epoch, 5);
        assert_eq!(
            store.transition_flowing_source(&obsolete).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::StaleEligibilityEpoch { current: 5 })
        );

        let begin_aborted = request(
            &store,
            "begin-aborted",
            FlowingFenceAction::BeginRevision {
                before_cut_id: Some("branch-cut-1".into()),
                after_cut_id: "branch-cut-2".into(),
            },
        );
        assert!(matches!(
            store.transition_flowing_source(&begin_aborted).unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        let abort = request(
            &store,
            "abort-1",
            FlowingFenceAction::AbortRevision {
                begin_op_id: "begin-aborted".into(),
            },
        );
        let FlowingFenceOutcome::Applied(aborted) =
            store.transition_flowing_source(&abort).unwrap()
        else {
            panic!("unmoved head may abort the revision")
        };
        assert!(aborted.state.revision.is_none());
        assert_eq!(aborted.state.eligibility_epoch, 7);

        let takeover = request(
            &store,
            "takeover-1",
            FlowingFenceAction::Takeover {
                new_owner: "coordinator-b".into(),
            },
        );
        let FlowingFenceOutcome::Applied(taken) =
            store.transition_flowing_source(&takeover).unwrap()
        else {
            panic!("takeover must commit")
        };
        assert_eq!(taken.state.owner, "coordinator-b");
        assert_eq!(taken.state.owner_epoch, 1);
        assert_eq!(taken.state.eligibility_epoch, 8);
        let disable = request(&store, "close-1", FlowingFenceAction::DisableAdmission);
        let FlowingFenceOutcome::Applied(closed) =
            store.transition_flowing_source(&disable).unwrap()
        else {
            panic!("admission must disable at the ref authority")
        };
        assert!(!closed.state.admission_enabled);
        let later = request(
            &store,
            "late-revision",
            FlowingFenceAction::BeginRevision {
                before_cut_id: Some("branch-cut-1".into()),
                after_cut_id: "branch-cut-2".into(),
            },
        );
        assert_eq!(
            store.transition_flowing_source(&later).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::AdmissionDisabled)
        );
        assert_eq!(store.flowing_fence_receipt("hold-1").unwrap(), Some(held));
        assert!(store.flowing_fence_receipt("stale").unwrap().is_none());
    }

    #[test]
    fn failed_operation_insert_rolls_back_the_fence_change() {
        let mut store = source();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator-a".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_fence_op BEFORE INSERT ON flowing_source_fence_ops \
                 BEGIN SELECT RAISE(ABORT, 'injected refusal'); END;",
            )
            .unwrap();
        let hold = request(&store, "hold-fails", FlowingFenceAction::Hold);
        assert!(store.transition_flowing_source(&hold).is_err());
        let state = store.flowing_source("branch").unwrap().unwrap();
        assert!(!state.held);
        assert_eq!(state.eligibility_epoch, 0);
        assert!(store.flowing_fence_receipt("hold-fails").unwrap().is_none());
    }

    #[test]
    fn invalid_request_and_inactive_branch_cannot_change_fence_state() {
        let mut store = source();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator-a".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        let mut invalid = request(&store, "bad-actor", FlowingFenceAction::Hold);
        invalid.actor.clear();
        assert_eq!(
            store.transition_flowing_source(&invalid).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Invalid { field: "actor" })
        );
        let mut no_state = request(&store, "no-state", FlowingFenceAction::Hold);
        no_state.source_branch_id = "never-opened".into();
        assert_eq!(
            store.transition_flowing_source(&no_state).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing)
        );
        store.discard_branch("branch", "t3").unwrap();
        let hold = request(&store, "closed-branch", FlowingFenceAction::Hold);
        assert_eq!(
            store.transition_flowing_source(&hold).unwrap(),
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
        store
            .connection
            .execute("DELETE FROM branches WHERE branch_id = 'branch'", [])
            .unwrap();
        assert_eq!(
            store.transition_flowing_source(&hold).unwrap(),
            FlowingFenceOutcome::Refused(FlowingFenceRefusal::Missing)
        );
    }

    #[test]
    fn opening_cannot_reinterpret_existing_writes_or_member_twigs() {
        let opening = OpenFlowingSource {
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            kind: FlowingSourceKind::Branch,
            owner: "coordinator-a".into(),
            opened_at: "t2".into(),
        };
        let mut written = source();
        written
            .advance_head("branch", None, "old-cut", "old-manifest", "t2")
            .unwrap();
        assert_eq!(
            written.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::BranchAlreadyMoved
        );

        let mut parent = source();
        parent
            .create_branch(CreateBranch {
                branch_id: "member-twig",
                name: None,
                parent_branch_id: "branch",
                at_cut: None,
                created_at: "t2",
                idempotency_key: None,
            })
            .unwrap();
        assert_eq!(
            parent.open_flowing_source(&opening).unwrap(),
            OpenFlowingSourceOutcome::BranchAlreadyHasChildren
        );
        assert_eq!(
            parent
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "member-twig".into(),
                    incarnation_id: "twig-inc".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "coordinator-a".into(),
                    opened_at: "t3".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::InvalidKindName
        );
        assert_eq!(
            parent
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "member-twig".into(),
                    incarnation_id: "twig-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator-a".into(),
                    opened_at: "t3".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::InvalidKindParent
        );
    }
}
