use super::flowing_sources::exact_atomic;
use super::{flowing_fence, DoBranches};
use crate::do_store::{as_opt_text, as_text, opt_text, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_fence::FlowingSourceKind;
use whipplescript_store::branches::flowing_member_parking::{
    missing_field, receipt_matches_keys, FlowingMemberParkOutcome, FlowingMemberParkReceipt,
    FlowingMemberParkRefusal, FlowingMemberParking, ParkFlowingMember,
};
use whipplescript_store::branches::{BranchStatus, Branches};
use whipplescript_store::{StoreError, StoreResult};

fn read_receipt<S: DoSql>(
    store: &DoBranches<S>,
    column: &str,
    key: &str,
) -> StoreResult<Option<FlowingMemberParkReceipt>> {
    let sql = &store.sql;
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
    let rows = sql.query(query, &[text(key)]).map_err(sql_err)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let member_id = as_text(&row[0]);
    let op_id = as_text(&row[1]);
    let source_id = as_text(&row[2]);
    let holder_id = as_text(&row[3]);
    let retained_cut = as_opt_text(&row[4]);
    let receipt: FlowingMemberParkReceipt = serde_json::from_str(&as_text(&row[5]))?;
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
    let member = store
        .row_by_id(&member_id)?
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
    let close = flowing_fence::read_close_request(sql, &source_id)?
        .ok_or_else(|| StoreError::Conflict("flowing parked member lost close request".into()))?;
    if close.request.op_id != receipt.source_close_op_id {
        return Err(StoreError::Conflict(
            "flowing parked member names another close request".into(),
        ));
    }
    if let Some(cut_id) = retained_cut.as_deref() {
        let cut = store.get_cut(cut_id)?;
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

pub(super) fn read_by_member<S: DoSql>(
    store: &DoBranches<S>,
    member_branch_id: &str,
) -> StoreResult<Option<FlowingMemberParkReceipt>> {
    read_receipt(store, "member_branch_id", member_branch_id)
}

impl<S: DoSql> FlowingMemberParking for DoBranches<S> {
    fn park_flowing_member(
        &mut self,
        request: &ParkFlowingMember,
    ) -> StoreResult<FlowingMemberParkOutcome> {
        use FlowingMemberParkOutcome::{AlreadyParked, Existing, Parked, Refused};
        use FlowingMemberParkRefusal as R;
        if let Some(field) = missing_field(request) {
            return Ok(Refused(R::Invalid { field }));
        }
        exact_atomic(&self.sql, "flowing member parking", || {
            if let Some(existing) = read_receipt(self, "op_id", &request.op_id)? {
                return Ok(if existing.request == *request {
                    Existing(existing)
                } else {
                    Refused(R::IdentityMismatch)
                });
            }
            if let Some(existing) = read_by_member(self, &request.member_branch_id)? {
                return Ok(AlreadyParked(existing));
            }
            let Some(source) = self.row_by_id(&request.source_branch_id)? else {
                return Ok(Refused(R::SourceMissing));
            };
            if source.status != BranchStatus::Active {
                return Ok(Refused(R::SourceNotActive));
            }
            let Some(fence) = flowing_fence::read_state(&self.sql, &request.source_branch_id)?
            else {
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
                flowing_fence::read_close_request(&self.sql, &request.source_branch_id)?
            else {
                return Ok(Refused(R::CloseNotRequested));
            };
            if fence.admission_enabled {
                return Ok(Refused(R::AdmissionNotDisabled));
            }
            let Some(member) = self.row_by_id(&request.member_branch_id)? else {
                return Ok(Refused(R::MemberMissing));
            };
            if member.status != BranchStatus::Active {
                return Ok(Refused(R::MemberNotActive));
            }
            if member.parent_branch_id.as_deref() != Some(request.source_branch_id.as_str()) {
                return Ok(Refused(R::MemberNotChild));
            }
            let member_fence = flowing_fence::read_state(&self.sql, &request.member_branch_id)?;
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
            if self.head_reservation(&request.member_branch_id)?.is_some() {
                return Ok(Refused(R::MemberReserved));
            }
            let unresolved = self
                .sql
                .query(
                    "SELECT 1 FROM flowing_contributions AS unit \
                 LEFT JOIN flowing_handoffs AS handoff ON handoff.unit_id = unit.unit_id \
                 LEFT JOIN flowing_admitted_units AS admitted ON admitted.unit_id = unit.unit_id \
                 LEFT JOIN flowing_parked_units AS parked ON parked.unit_id = unit.unit_id \
                 WHERE ((unit.source_branch_id = ?1 AND handoff.unit_id IS NULL) \
                        OR handoff.target_branch_id = ?1) \
                   AND admitted.unit_id IS NULL AND parked.unit_id IS NULL LIMIT 1",
                    &[text(&request.member_branch_id)],
                )
                .map_err(sql_err)?;
            if !unresolved.is_empty() {
                return Ok(Refused(R::UnresolvedUnit));
            }
            let live_private = self
                .sql
                .query(
                    "SELECT 1 FROM flowing_private_pins \
                 WHERE twig_branch_id = ?1 AND released_at IS NULL LIMIT 1",
                    &[text(&request.member_branch_id)],
                )
                .map_err(sql_err)?;
            if !live_private.is_empty() {
                return Ok(Refused(R::LivePrivatePin));
            }
            let live_attempt = self
                .sql
                .query(
                    "SELECT 1 FROM flowing_attempt_pins AS pin \
                 LEFT JOIN cuts AS source_cut ON source_cut.cut_id = pin.source_cut_id \
                 WHERE pin.released_at IS NULL \
                   AND (source_cut.branch_id = ?1 OR source_cut.cut_id IS NULL) LIMIT 1",
                    &[text(&request.member_branch_id)],
                )
                .map_err(sql_err)?;
            if !live_attempt.is_empty() {
                return Ok(Refused(R::LiveAttempt));
            }
            if let Some(cut_id) = request.expected_member_head_cut_id.as_deref() {
                let cut = self.get_cut(cut_id)?;
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
            self.sql.execute(
                "INSERT INTO flowing_parked_members \
                 (member_branch_id, op_id, source_branch_id, holder_id, retained_head_cut_id, receipt_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &[
                    text(&request.member_branch_id),
                    text(&request.op_id),
                    text(&request.source_branch_id),
                    text(&request.parked_holder_id),
                    opt_text(request.expected_member_head_cut_id.as_deref()),
                    text(&serde_json::to_string(&receipt)?),
                ],
            ).map_err(sql_err)?;
            self.sql
                .execute(
                    "UPDATE branches SET status = 'parked', updated_at = ?2 WHERE branch_id = ?1",
                    &[text(&request.member_branch_id), text(&request.recorded_at)],
                )
                .map_err(sql_err)?;
            Ok(Parked(receipt))
        })
    }

    fn parked_flowing_member(
        &self,
        member_branch_id: &str,
    ) -> StoreResult<Option<FlowingMemberParkReceipt>> {
        read_by_member(self, member_branch_id)
    }

    fn flowing_member_park_receipt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingMemberParkReceipt>> {
        read_receipt(self, "op_id", op_id)
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::do_store::test_support::RusqliteDoSql;
    use whipplescript_store::branches::flowing_close_roster::FlowingCloseRosterReader;
    use whipplescript_store::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceTransition, OpenFlowingSource,
    };
    use whipplescript_store::branches::{
        AdvanceOutcome, CreateBranch, CutRecord, MAINLINE_BRANCH_ID,
    };

    fn seed_parkable() -> (
        Rc<RusqliteDoSql>,
        DoBranches<Rc<RusqliteDoSql>>,
        ParkFlowingMember,
    ) {
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
        for (op_id, action) in [
            ("request-close", FlowingFenceAction::RequestClose),
            ("disable", FlowingFenceAction::DisableAdmission),
        ] {
            let fence = store.flowing_source("branch").unwrap().unwrap();
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
                .unwrap();
        }
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
            parked_holder_id: "holder".into(),
            actor: "coordinator".into(),
            recorded_at: "t5".into(),
        };
        (sql, store, request)
    }

    #[test]
    fn hosted_parking_is_exact_and_atomic_with_receipt() {
        let (sql, mut store, request) = seed_parkable();
        sql.execute(
            "CREATE TRIGGER fail_member_park BEFORE INSERT ON flowing_parked_members \
             BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
            &[],
        )
        .unwrap();
        assert!(store.park_flowing_member(&request).is_err());
        assert_eq!(
            store.get_branch("member").unwrap().unwrap().status,
            BranchStatus::Active
        );
        sql.execute("DROP TRIGGER fail_member_park", &[]).unwrap();
        let FlowingMemberParkOutcome::Parked(receipt) =
            store.park_flowing_member(&request).unwrap()
        else {
            panic!("hosted member parks after receipt insert succeeds");
        };
        assert_eq!(
            store.park_flowing_member(&request).unwrap(),
            FlowingMemberParkOutcome::Existing(receipt.clone())
        );
        assert_eq!(
            store
                .flowing_close_roster("branch")
                .unwrap()
                .unwrap()
                .members[0]
                .parked,
            Some(receipt)
        );
        assert_eq!(
            store.get_branch("member").unwrap().unwrap().status,
            BranchStatus::Parked
        );
        assert!(store.pinned_cuts("t9").unwrap().contains("member-cut"));
    }

    #[test]
    fn hosted_parked_member_reader_refuses_each_corrupt_authority_fact() {
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
            let (sql, mut store, request) = seed_parkable();
            assert!(matches!(
                store.park_flowing_member(&request).unwrap(),
                FlowingMemberParkOutcome::Parked(_)
            ));
            sql.execute(mutation, &[]).unwrap();
            let error = store.parked_flowing_member("member").unwrap_err();
            assert!(
                format!("{error:?}").contains(message),
                "{mutation}: {error:?}"
            );
        }
    }

    #[test]
    fn hosted_incoming_unsettled_handoff_keeps_member_open() {
        let (sql, mut store, request) = seed_parkable();
        sql.execute(
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
             VALUES ('incoming', 'outside-pin', 'outside', 'outside-cut', 'outside-hash', \
                     'author', 'change', 'read', 'dependencies', 'scope', 't4')",
            &[],
        ).unwrap();
        sql.execute(
            "INSERT INTO flowing_handoffs \
             (op_id, unit_id, source_branch_id, source_cut_id, source_manifest_hash, \
              source_basis_digest, target_branch_id, target_after_cut_id, target_after_manifest_hash, \
              effects_json, original_principal, actor, recorded_at) \
             VALUES ('handoff', 'incoming', 'outside', 'outside-cut', 'outside-hash', \
                     'basis', 'member', 'member-cut', 'member-manifest', '[]', 'author', 'coordinator', 't4')",
            &[],
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
