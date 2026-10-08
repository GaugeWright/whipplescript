use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    missing_field, receipt_matches_keys, FlowingMemberParkOutcome, FlowingMemberParkReceipt,
    FlowingMemberParkRefusal, FlowingMemberParking, ParkFlowingMember,
};
use crate::branches::flowing_fence::{self, FlowingSourceKind};
use crate::branches::{BranchStatus, BranchStore};
use crate::{StoreError, StoreResult};

fn read_receipt(
    connection: &Connection,
    column: &str,
    key: &str,
) -> StoreResult<Option<FlowingMemberParkReceipt>> {
    let query = match column {
        "op_id" => {
            "SELECT member_branch_id, op_id, source_branch_id, holder_id, \
                    retained_head_cut_id, receipt_json FROM flowing_parked_members WHERE op_id = ?1"
        }
        "member_branch_id" => {
            "SELECT member_branch_id, op_id, source_branch_id, holder_id, \
                    retained_head_cut_id, receipt_json FROM flowing_parked_members \
                    WHERE member_branch_id = ?1"
        }
        _ => unreachable!("fixed parked-member lookup"),
    };
    let row: Option<(String, String, String, String, Option<String>, String)> = connection
        .query_row(query, [key], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .optional()?;
    let Some((member_id, op_id, source_id, holder_id, retained_cut, json)) = row else {
        return Ok(None);
    };
    let receipt: FlowingMemberParkReceipt = serde_json::from_str(&json)?;
    if !receipt_matches_keys(
        &receipt,
        &member_id,
        &op_id,
        &source_id,
        &holder_id,
        retained_cut.as_deref(),
    ) {
        return Err(StoreError::Conflict(
            "flowing parked member differs from its ref keys".into(),
        ));
    }
    let member = BranchStore::row_by_id(connection, &member_id)?
        .ok_or_else(|| StoreError::Conflict("flowing parked member row is missing".into()))?;
    if member.status != BranchStatus::Parked
        || member.parent_branch_id.as_deref() != Some(source_id.as_str())
        || member.created_at != receipt.member_created_at
        || member.head_cut_id != receipt.request.expected_member_head_cut_id
        || member.head_manifest_hash != receipt.request.expected_member_head_manifest_hash
    {
        return Err(StoreError::Conflict(
            "flowing parked member changed after disposition".into(),
        ));
    }
    let close = flowing_fence::native::read_close_request(connection, &source_id)?
        .ok_or_else(|| StoreError::Conflict("flowing parked member lost close request".into()))?;
    if close.request.op_id != receipt.source_close_op_id {
        return Err(StoreError::Conflict(
            "flowing parked member names another close request".into(),
        ));
    }
    if let Some(cut_id) = retained_cut.as_deref() {
        let cut = BranchStore::cut_by_id(connection, cut_id)?;
        if !cut.is_some_and(|cut| {
            Some(cut.manifest_hash.as_str())
                == receipt
                    .request
                    .expected_member_head_manifest_hash
                    .as_deref()
        }) {
            return Err(StoreError::Conflict(
                "flowing parked member retained cut is missing or changed".into(),
            ));
        }
    }
    Ok(Some(receipt))
}

pub(crate) fn read_by_member(
    connection: &Connection,
    member_branch_id: &str,
) -> StoreResult<Option<FlowingMemberParkReceipt>> {
    read_receipt(connection, "member_branch_id", member_branch_id)
}

impl FlowingMemberParking for BranchStore {
    fn park_flowing_member(
        &mut self,
        request: &ParkFlowingMember,
    ) -> StoreResult<FlowingMemberParkOutcome> {
        use FlowingMemberParkOutcome::{AlreadyParked, Existing, Parked, Refused};
        use FlowingMemberParkRefusal as R;
        if let Some(field) = missing_field(request) {
            return Ok(Refused(R::Invalid { field }));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_receipt(&tx, "op_id", &request.op_id)? {
            return Ok(if existing.request == *request {
                Existing(existing)
            } else {
                Refused(R::IdentityMismatch)
            });
        }
        if let Some(existing) = read_by_member(&tx, &request.member_branch_id)? {
            return Ok(AlreadyParked(existing));
        }
        let Some(source) = BranchStore::row_by_id(&tx, &request.source_branch_id)? else {
            return Ok(Refused(R::SourceMissing));
        };
        if source.status != BranchStatus::Active {
            return Ok(Refused(R::SourceNotActive));
        }
        let Some(fence) = flowing_fence::native::read_state(&tx, &request.source_branch_id)? else {
            return Ok(Refused(R::SourceMissing));
        };
        if fence.kind != FlowingSourceKind::Branch
            || fence.incarnation_id != request.source_incarnation_id
        {
            return Ok(Refused(R::WrongIncarnation));
        }
        if fence.eligibility_epoch != request.expected_source_eligibility_epoch {
            return Ok(Refused(R::StaleEligibilityEpoch {
                current: fence.eligibility_epoch,
            }));
        }
        if fence.owner_epoch != request.expected_source_owner_epoch {
            return Ok(Refused(R::StaleOwnerEpoch {
                current: fence.owner_epoch,
            }));
        }
        if fence.owner != request.actor {
            return Ok(Refused(R::WrongOwner));
        }
        let Some(close) =
            flowing_fence::native::read_close_request(&tx, &request.source_branch_id)?
        else {
            return Ok(Refused(R::CloseNotRequested));
        };
        if fence.admission_enabled {
            return Ok(Refused(R::AdmissionNotDisabled));
        }
        let Some(member) = BranchStore::row_by_id(&tx, &request.member_branch_id)? else {
            return Ok(Refused(R::MemberMissing));
        };
        if member.status != BranchStatus::Active {
            return Ok(Refused(R::MemberNotActive));
        }
        if member.parent_branch_id.as_deref() != Some(request.source_branch_id.as_str()) {
            return Ok(Refused(R::MemberNotChild));
        }
        let member_fence = flowing_fence::native::read_state(&tx, &request.member_branch_id)?;
        if member_fence
            .as_ref()
            .is_some_and(|fence| fence.kind != FlowingSourceKind::Twig)
        {
            return Ok(Refused(R::MemberIncarnationMismatch));
        }
        if member_fence
            .as_ref()
            .map(|fence| fence.incarnation_id.as_str())
            != request.expected_member_incarnation_id.as_deref()
        {
            return Ok(Refused(R::MemberIncarnationMismatch));
        }
        if member.head_cut_id != request.expected_member_head_cut_id
            || member.head_manifest_hash != request.expected_member_head_manifest_hash
        {
            return Ok(Refused(R::MemberHeadChanged));
        }
        let reserved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM branch_head_reservations WHERE branch_id = ?1)",
            [&request.member_branch_id],
            |row| row.get(0),
        )?;
        if reserved {
            return Ok(Refused(R::MemberReserved));
        }
        let unresolved: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM flowing_contributions AS unit \
             LEFT JOIN flowing_handoffs AS handoff ON handoff.unit_id = unit.unit_id \
             LEFT JOIN flowing_admitted_units AS admitted ON admitted.unit_id = unit.unit_id \
             LEFT JOIN flowing_parked_units AS parked ON parked.unit_id = unit.unit_id \
             WHERE ((unit.source_branch_id = ?1 AND handoff.unit_id IS NULL) \
                    OR handoff.target_branch_id = ?1) \
               AND admitted.unit_id IS NULL AND parked.unit_id IS NULL)",
            [&request.member_branch_id],
            |row| row.get(0),
        )?;
        if unresolved {
            return Ok(Refused(R::UnresolvedUnit));
        }
        let live_private: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM flowing_private_pins \
             WHERE twig_branch_id = ?1 AND released_at IS NULL)",
            [&request.member_branch_id],
            |row| row.get(0),
        )?;
        if live_private {
            return Ok(Refused(R::LivePrivatePin));
        }
        let live_attempt: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM flowing_attempt_pins AS pin \
             LEFT JOIN cuts AS source_cut ON source_cut.cut_id = pin.source_cut_id \
             WHERE pin.released_at IS NULL \
               AND (source_cut.branch_id = ?1 OR source_cut.cut_id IS NULL))",
            [&request.member_branch_id],
            |row| row.get(0),
        )?;
        if live_attempt {
            return Ok(Refused(R::LiveAttempt));
        }
        if let Some(cut_id) = request.expected_member_head_cut_id.as_deref() {
            let cut = BranchStore::cut_by_id(&tx, cut_id)?;
            if !cut.is_some_and(|cut| {
                Some(cut.manifest_hash.as_str())
                    == request.expected_member_head_manifest_hash.as_deref()
            }) {
                return Ok(Refused(R::RetainedCutMissing));
            }
        }
        let receipt = FlowingMemberParkReceipt {
            request: request.clone(),
            source_close_op_id: close.request.op_id,
            member_created_at: member.created_at,
        };
        tx.execute(
            "INSERT INTO flowing_parked_members \
             (member_branch_id, op_id, source_branch_id, holder_id, retained_head_cut_id, receipt_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request.member_branch_id,
                request.op_id,
                request.source_branch_id,
                request.parked_holder_id,
                request.expected_member_head_cut_id,
                serde_json::to_string(&receipt)?,
            ],
        )?;
        tx.execute(
            "UPDATE branches SET status = 'parked', updated_at = ?2 WHERE branch_id = ?1",
            params![request.member_branch_id, request.recorded_at],
        )?;
        tx.commit()?;
        Ok(Parked(receipt))
    }

    fn parked_flowing_member(
        &self,
        member_branch_id: &str,
    ) -> StoreResult<Option<FlowingMemberParkReceipt>> {
        read_by_member(&self.connection, member_branch_id)
    }

    fn flowing_member_park_receipt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingMemberParkReceipt>> {
        read_receipt(&self.connection, "op_id", op_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_close_roster::FlowingCloseRosterReader;
    use crate::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        OpenFlowingSource,
    };
    use crate::branches::flowing_sources::{DeclareContribution, FlowingSources, PinPrivateCut};
    use crate::branches::{AdvanceOutcome, Branches, CreateBranch, CutRecord, MAINLINE_BRANCH_ID};

    fn seed() -> (BranchStore, ParkFlowingMember) {
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
                owner: "coordinator".into(),
                opened_at: "t1".into(),
            })
            .unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "member",
                name: None,
                parent_branch_id: "branch",
                at_cut: None,
                created_at: "t2",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "member".into(),
                incarnation_id: "member-inc".into(),
                kind: FlowingSourceKind::Twig,
                owner: "coordinator".into(),
                opened_at: "t2".into(),
            })
            .unwrap();
        store
            .record_cut(CutRecord {
                cut_id: "member-cut",
                change_id: "member-change",
                branch_id: "member",
                manifest_hash: "member-manifest",
                parent_cut_id: None,
                origin: Some("write:member"),
                actor: Some("author"),
                intent: None,
                recorded_at: "t3",
            })
            .unwrap();
        assert!(matches!(
            store
                .advance_head("member", None, "member-cut", "member-manifest", "t3")
                .unwrap(),
            AdvanceOutcome::Advanced(_)
        ));
        let request = ParkFlowingMember {
            op_id: "park-member".into(),
            source_branch_id: "branch".into(),
            source_incarnation_id: "branch-inc".into(),
            expected_source_eligibility_epoch: 1,
            expected_source_owner_epoch: 0,
            member_branch_id: "member".into(),
            expected_member_incarnation_id: Some("member-inc".into()),
            expected_member_head_cut_id: Some("member-cut".into()),
            expected_member_head_manifest_hash: Some("member-manifest".into()),
            parked_holder_id: "archive-holder".into(),
            actor: "coordinator".into(),
            recorded_at: "t5".into(),
        };
        (store, request)
    }

    fn close_and_disable(store: &mut BranchStore) {
        for (op_id, action) in [
            ("request-close", FlowingFenceAction::RequestClose),
            ("disable", FlowingFenceAction::DisableAdmission),
        ] {
            let fence = store.flowing_source("branch").unwrap().unwrap();
            assert!(matches!(
                store
                    .transition_flowing_source(&FlowingFenceTransition {
                        op_id: op_id.into(),
                        source_branch_id: "branch".into(),
                        incarnation_id: "branch-inc".into(),
                        expected_eligibility_epoch: fence.eligibility_epoch,
                        expected_owner_epoch: fence.owner_epoch,
                        actor: "coordinator".into(),
                        action,
                        recorded_at: "t4".into(),
                    })
                    .unwrap(),
                FlowingFenceOutcome::Applied(_)
            ));
        }
    }

    #[test]
    fn parked_member_retains_exact_head_and_receipt_without_losing_the_roster() {
        let (mut store, request) = seed();
        let mut before_close = request.clone();
        before_close.expected_source_eligibility_epoch = 0;
        assert_eq!(
            store.park_flowing_member(&before_close).unwrap(),
            FlowingMemberParkOutcome::Refused(FlowingMemberParkRefusal::CloseNotRequested)
        );
        let fence = store.flowing_source("branch").unwrap().unwrap();
        store
            .transition_flowing_source(&FlowingFenceTransition {
                op_id: "request-close".into(),
                source_branch_id: "branch".into(),
                incarnation_id: "branch-inc".into(),
                expected_eligibility_epoch: fence.eligibility_epoch,
                expected_owner_epoch: fence.owner_epoch,
                actor: "coordinator".into(),
                action: FlowingFenceAction::RequestClose,
                recorded_at: "t4".into(),
            })
            .unwrap();
        let mut before_disable = request.clone();
        before_disable.expected_source_eligibility_epoch = 0;
        assert_eq!(
            store.park_flowing_member(&before_disable).unwrap(),
            FlowingMemberParkOutcome::Refused(FlowingMemberParkRefusal::AdmissionNotDisabled)
        );
        let fence = store.flowing_source("branch").unwrap().unwrap();
        store
            .transition_flowing_source(&FlowingFenceTransition {
                op_id: "disable".into(),
                source_branch_id: "branch".into(),
                incarnation_id: "branch-inc".into(),
                expected_eligibility_epoch: fence.eligibility_epoch,
                expected_owner_epoch: fence.owner_epoch,
                actor: "coordinator".into(),
                action: FlowingFenceAction::DisableAdmission,
                recorded_at: "t4".into(),
            })
            .unwrap();
        let FlowingMemberParkOutcome::Parked(receipt) =
            store.park_flowing_member(&request).unwrap()
        else {
            panic!("member parks after both fences");
        };
        assert_eq!(receipt.source_close_op_id, "request-close");
        assert_eq!(
            store.park_flowing_member(&request).unwrap(),
            FlowingMemberParkOutcome::Existing(receipt.clone())
        );
        let mut another = request.clone();
        another.op_id = "another-park".into();
        assert_eq!(
            store.park_flowing_member(&another).unwrap(),
            FlowingMemberParkOutcome::AlreadyParked(receipt.clone())
        );
        assert_eq!(
            store.get_branch("member").unwrap().unwrap().status,
            BranchStatus::Parked
        );
        assert!(store.pinned_cuts("t9").unwrap().contains("member-cut"));
        let roster = store.flowing_close_roster("branch").unwrap().unwrap();
        assert_eq!(roster.members.len(), 1);
        assert_eq!(roster.members[0].parked, Some(receipt));
        assert_eq!(
            store
                .advance_head("member", Some("member-cut"), "later", "later-hash", "t6")
                .unwrap(),
            AdvanceOutcome::NotActive {
                status: BranchStatus::Parked
            }
        );
    }

    #[test]
    fn parked_member_receipt_failure_rolls_back_terminal_status() {
        let (mut store, request) = seed();
        close_and_disable(&mut store);
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_park_member BEFORE INSERT ON flowing_parked_members \
                 BEGIN SELECT RAISE(ABORT, 'injected member receipt failure'); END;",
            )
            .unwrap();
        assert!(store.park_flowing_member(&request).is_err());
        assert_eq!(
            store.get_branch("member").unwrap().unwrap().status,
            BranchStatus::Active
        );
        assert!(store.parked_flowing_member("member").unwrap().is_none());
    }

    #[test]
    fn unresolved_work_and_live_pins_refuse_member_parking() {
        let (mut store, request) = seed();
        close_and_disable(&mut store);
        store
            .pin_private_cut(PinPrivateCut {
                pin_id: "private",
                twig_branch_id: "member",
                cut_id: "member-cut",
                manifest_hash: "member-manifest",
                principal: "author",
                retained_at: "t5",
            })
            .unwrap();
        assert_eq!(
            store.park_flowing_member(&request).unwrap(),
            FlowingMemberParkOutcome::Refused(FlowingMemberParkRefusal::LivePrivatePin)
        );
        store
            .declare_contribution(DeclareContribution {
                unit_id: "unit",
                pin_id: "private",
                principal: "author",
                intent: "change",
                read_basis_digest: "read",
                dependency_basis_digest: "dependencies",
                scope_digest: "scope",
                declared_at: "t6",
            })
            .unwrap();
        assert_eq!(
            store.park_flowing_member(&request).unwrap(),
            FlowingMemberParkOutcome::Refused(FlowingMemberParkRefusal::UnresolvedUnit)
        );
        assert_eq!(
            store.get_branch("member").unwrap().unwrap().status,
            BranchStatus::Active
        );
    }

    #[test]
    fn live_attempt_and_lost_retained_cut_refuse_or_invalidate_parking() {
        let (mut store, request) = seed();
        close_and_disable(&mut store);
        store
            .connection
            .execute(
                "INSERT INTO flowing_attempt_pins \
             (op_id, witness_digest, source_cut_id, candidate_cut_id, retained_at) \
             VALUES ('attempt', 'witness', 'member-cut', 'candidate', 't5')",
                [],
            )
            .unwrap();
        assert_eq!(
            store.park_flowing_member(&request).unwrap(),
            FlowingMemberParkOutcome::Refused(FlowingMemberParkRefusal::LiveAttempt)
        );
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_pins SET released_at = 't6' WHERE op_id = 'attempt'",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.park_flowing_member(&request).unwrap(),
            FlowingMemberParkOutcome::Parked(_)
        ));
        store
            .connection
            .execute("DELETE FROM cuts WHERE cut_id = 'member-cut'", [])
            .unwrap();
        assert!(store.parked_flowing_member("member").is_err());
    }

    #[test]
    fn parked_member_receipt_reader_refuses_each_corrupt_authority_fact() {
        let cases = [
            (
                "UPDATE flowing_parked_members SET holder_id = 'different'",
                "flowing parked member differs from its ref keys",
            ),
            (
                "DELETE FROM branches WHERE branch_id = 'member'",
                "flowing parked member row is missing",
            ),
            (
                "UPDATE branches SET status = 'active' WHERE branch_id = 'member'",
                "flowing parked member changed after disposition",
            ),
            (
                "DELETE FROM flowing_source_close_requests WHERE source_branch_id = 'branch'",
                "flowing parked member lost close request",
            ),
            (
                "UPDATE flowing_parked_members SET receipt_json = \
                 json_set(receipt_json, '$.source_close_op_id', 'different')",
                "flowing parked member names another close request",
            ),
            (
                "DELETE FROM cuts WHERE cut_id = 'member-cut'",
                "flowing parked member retained cut is missing or changed",
            ),
        ];
        for (mutation, message) in cases {
            let (mut store, request) = seed();
            close_and_disable(&mut store);
            assert!(matches!(
                store.park_flowing_member(&request).unwrap(),
                FlowingMemberParkOutcome::Parked(_)
            ));
            store.connection.execute(mutation, []).unwrap();
            let error = store.parked_flowing_member("member").unwrap_err();
            assert!(
                format!("{error:?}").contains(message),
                "{mutation}: {error:?}"
            );
        }
    }

    #[test]
    fn incoming_unsettled_handoff_keeps_member_open() {
        let (mut store, request) = seed();
        close_and_disable(&mut store);
        store.connection.execute_batch(
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
             VALUES ('incoming', 'outside-pin', 'outside', 'outside-cut', 'outside-hash', \
                     'author', 'change', 'read', 'dependencies', 'scope', 't4'); \
             INSERT INTO flowing_handoffs \
             (op_id, unit_id, source_branch_id, source_cut_id, source_manifest_hash, \
              source_basis_digest, target_branch_id, target_after_cut_id, target_after_manifest_hash, \
              effects_json, original_principal, actor, recorded_at) \
             VALUES ('handoff', 'incoming', 'outside', 'outside-cut', 'outside-hash', \
                     'basis', 'member', 'member-cut', 'member-manifest', '[]', 'author', 'coordinator', 't4');",
        ).unwrap();
        assert_eq!(
            store.park_flowing_member(&request).unwrap(),
            FlowingMemberParkOutcome::Refused(FlowingMemberParkRefusal::UnresolvedUnit)
        );
        assert_eq!(
            store.get_branch("member").unwrap().unwrap().status,
            BranchStatus::Active
        );
    }
}
