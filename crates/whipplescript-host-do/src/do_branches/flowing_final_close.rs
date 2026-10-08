use std::collections::{BTreeMap, BTreeSet};

use super::flowing_sources::exact_atomic;
use super::DoBranches;
use crate::do_store::{as_opt_text, as_text, opt_text, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_admission::FlowingAdmissions;
use whipplescript_store::branches::flowing_close_roster::{
    FlowingCloseRoster, FlowingCloseUnitState,
};
use whipplescript_store::branches::flowing_final_close::{
    cut_in_current_ancestry, missing_field, preflight, receipt_matches_snapshot,
    FinalCloseFlowingSource, FlowingCloseEvidence, FlowingFinalClose, FlowingFinalCloseOutcome,
    FlowingFinalCloseReceipt, FlowingFinalCloseRefusal,
};
use whipplescript_store::branches::flowing_parking::FlowingParking;
use whipplescript_store::branches::flowing_sources::FlowingSources;
use whipplescript_store::branches::{BranchStatus, Branches};
use whipplescript_store::{StoreError, StoreResult};

fn read_receipt<S: DoSql>(
    store: &DoBranches<S>,
    source_branch_id: &str,
) -> StoreResult<Option<FlowingFinalCloseReceipt>> {
    let rows = store
        .sql
        .query(
            "SELECT source_branch_id, op_id, roster_digest, receipt_digest, retained_head_cut_id, receipt_json \
         FROM flowing_final_closes WHERE source_branch_id = ?1",
            &[text(source_branch_id)],
        )
        .map_err(sql_err)?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let source_id = as_text(&row[0]);
    let op_id = as_text(&row[1]);
    let digest = as_text(&row[2]);
    let receipt_digest = as_text(&row[3]);
    let retained_head = as_opt_text(&row[4]);
    let receipt: FlowingFinalCloseReceipt = serde_json::from_str(&as_text(&row[5]))?;
    if receipt.request.source_branch_id != source_id
        || receipt.request.op_id != op_id
        || receipt.request.expected_roster_digest != digest
        || receipt.digest()? != receipt_digest
        || receipt.roster.digest()? != digest
        || receipt.roster.source_branch_id != source_id
        || receipt.roster.source_head_cut_id != retained_head
        || !receipt_matches_snapshot(&receipt)
    {
        return Err(StoreError::Conflict(
            "flowing final close receipt differs from ref keys or roster".into(),
        ));
    }
    let branch = store
        .row_by_id(&source_id)?
        .ok_or_else(|| StoreError::Conflict("flowing final close source row is missing".into()))?;
    if branch.status != BranchStatus::Closed
        || branch.parent_branch_id != receipt.roster.source_parent_branch_id
        || branch.branch_point_cut_id != receipt.roster.source_branch_point_cut_id
        || branch.head_cut_id != receipt.roster.source_head_cut_id
        || branch.head_manifest_hash != receipt.roster.source_head_manifest_hash
    {
        return Err(StoreError::Conflict(
            "flowing final close source changed after disposition".into(),
        ));
    }
    if let Some(head_id) = retained_head.as_deref() {
        let cut = store.get_cut(head_id)?;
        if !cut.is_some_and(|cut| {
            (cut.branch_id == source_id
                || receipt.roster.source_branch_point_cut_id.as_deref() == Some(head_id))
                && Some(cut.manifest_hash.as_str())
                    == receipt.roster.source_head_manifest_hash.as_deref()
        }) {
            return Err(StoreError::Conflict(
                "flowing final close retained head is missing or changed".into(),
            ));
        }
    }
    for member in &receipt.roster.members {
        if super::flowing_member_parking::read_by_member(store, &member.branch_id)? != member.parked
        {
            return Err(StoreError::Conflict(
                "flowing final close lost a member disposition".into(),
            ));
        }
    }
    Ok(Some(receipt))
}

fn verify_units<S: DoSql>(
    store: &DoBranches<S>,
    roster: &FlowingCloseRoster,
) -> StoreResult<Result<FlowingCloseEvidence, FlowingFinalCloseRefusal>> {
    use FlowingCloseUnitState as S;
    use FlowingFinalCloseRefusal as R;
    let mut admissions = BTreeMap::new();
    let mut admitted_unit_ids = BTreeSet::new();
    let mut roster_admitted_unit_ids = BTreeSet::new();
    let mut parked_units = Vec::new();
    let mut handoffs = Vec::new();
    let mut ancestry_checks = BTreeMap::new();
    for unit in &roster.units {
        let missing = || R::UnitReceiptMissing {
            unit_id: unit.unit_id.clone(),
        };
        let mismatch = || R::UnitReceiptMismatch {
            unit_id: unit.unit_id.clone(),
        };
        match &unit.state {
            S::Admitted { op_id } => {
                if !admissions.contains_key(op_id) {
                    let Some(receipt) = store.flowing_admission_receipt(op_id)? else {
                        return Ok(Err(missing()));
                    };
                    if receipt.request.source_branch_id != roster.source_branch_id
                        || receipt.request.source_incarnation_id
                            != roster.source_fence.incarnation_id
                    {
                        return Ok(Err(mismatch()));
                    }
                    for selected in &receipt.request.units {
                        if !admitted_unit_ids.insert((op_id.clone(), selected.unit_id.clone())) {
                            return Ok(Err(R::UnitReceiptMismatch {
                                unit_id: selected.unit_id.clone(),
                            }));
                        }
                    }
                    admissions.insert(op_id.clone(), receipt);
                }
                let key = (op_id.clone(), unit.unit_id.clone());
                if !admitted_unit_ids.contains(&key) || !roster_admitted_unit_ids.insert(key) {
                    return Ok(Err(mismatch()));
                }
            }
            S::Parked { .. } => {
                let Some(receipt) = store.parked_flowing_unit(&unit.unit_id)? else {
                    return Ok(Err(missing()));
                };
                // The parked-unit reader checks the row's operation and
                // holder keys before returning this receipt. The roster read
                // the same row under this transaction.
                parked_units.push(receipt);
            }
            S::Transferred { target_branch_id } => {
                let Some(receipt) = store.contribution_handoff(&unit.unit_id)? else {
                    return Ok(Err(missing()));
                };
                let target = store.row_by_id(target_branch_id)?;
                let cut = store.get_cut(&receipt.target_after_cut_id)?;
                let in_current_ancestry = if let Some(branch) = target.as_ref() {
                    let key = (
                        target_branch_id.clone(),
                        branch.head_cut_id.clone(),
                        receipt.target_after_cut_id.clone(),
                    );
                    if !ancestry_checks.contains_key(&key) {
                        ancestry_checks.insert(
                            key.clone(),
                            cut_in_current_ancestry(
                                target_branch_id,
                                branch.head_cut_id.as_deref(),
                                &receipt.target_after_cut_id,
                                |id| store.get_cut(id),
                            )?,
                        );
                    }
                    ancestry_checks[&key]
                } else {
                    false
                };
                if unit.handoff_op_id.as_deref() != Some(receipt.op_id.as_str())
                    || receipt.unit_id != unit.unit_id
                    || receipt.source_branch_id != unit.original_source_branch_id
                    || receipt.target_branch_id != *target_branch_id
                    || !target.is_some_and(|branch| branch.status == BranchStatus::Active)
                    || !cut.is_some_and(|cut| {
                        cut.branch_id == *target_branch_id
                            && cut.manifest_hash == receipt.target_after_manifest_hash
                    })
                    || !in_current_ancestry
                {
                    return Ok(Err(mismatch()));
                }
                handoffs.push(receipt);
            }
            S::OwedBySource | S::OwedByMember { .. } => {
                return Ok(Err(R::UnitOwed {
                    unit_id: unit.unit_id.clone(),
                }));
            }
        }
    }
    if let Some((_, unit_id)) = admitted_unit_ids
        .difference(&roster_admitted_unit_ids)
        .next()
    {
        return Ok(Err(R::UnitReceiptMismatch {
            unit_id: unit_id.clone(),
        }));
    }
    Ok(Ok(FlowingCloseEvidence {
        admissions: admissions.into_values().collect(),
        parked_units,
        handoffs,
    }))
}

impl<S: DoSql> FlowingFinalClose for DoBranches<S> {
    fn final_close_flowing_source(
        &mut self,
        request: &FinalCloseFlowingSource,
    ) -> StoreResult<FlowingFinalCloseOutcome> {
        use FlowingFinalCloseOutcome::{Closed, Existing, Refused};
        use FlowingFinalCloseRefusal as R;
        if let Some(field) = missing_field(request) {
            return Ok(Refused(R::Invalid { field }));
        }
        exact_atomic(&self.sql, "flowing final close", || {
            if let Some(existing) = read_receipt(self, &request.source_branch_id)? {
                return Ok(if existing.request == *request {
                    Existing(existing)
                } else {
                    Refused(R::AlreadyClosed)
                });
            }
            let conflicting_op = self
                .sql
                .query(
                    "SELECT 1 FROM flowing_final_closes WHERE op_id = ?1 LIMIT 1",
                    &[text(&request.op_id)],
                )
                .map_err(sql_err)?;
            if !conflicting_op.is_empty() {
                return Ok(Refused(R::IdentityMismatch));
            }
            let Some(roster) = self.read_close_roster(&request.source_branch_id)? else {
                return Ok(Refused(R::SourceMissing));
            };
            if let Err(refusal) = preflight(&roster, request) {
                return Ok(Refused(refusal));
            }
            if roster.digest()? != request.expected_roster_digest {
                return Ok(Refused(R::StaleRoster));
            }
            if let Some(head_id) = roster.source_head_cut_id.as_deref() {
                let cut = self.get_cut(head_id)?;
                if !cut.is_some_and(|cut| {
                    (cut.branch_id == request.source_branch_id
                        || roster.source_branch_point_cut_id.as_deref() == Some(head_id))
                        && Some(cut.manifest_hash.as_str())
                            == roster.source_head_manifest_hash.as_deref()
                }) {
                    return Ok(Refused(R::StaleRoster));
                }
            } else if roster.source_head_manifest_hash.is_some() {
                return Ok(Refused(R::StaleRoster));
            }
            let unit_evidence = match verify_units(self, &roster)? {
                Ok(evidence) => evidence,
                Err(refusal) => return Ok(Refused(refusal)),
            };
            let receipt = FlowingFinalCloseReceipt {
                request: request.clone(),
                roster,
                unit_evidence,
            };
            self.sql
                .execute(
                    "INSERT INTO flowing_final_closes \
                 (source_branch_id, op_id, roster_digest, receipt_digest, retained_head_cut_id, receipt_json) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[
                        text(&request.source_branch_id),
                        text(&request.op_id),
                        text(&request.expected_roster_digest),
                        text(&receipt.digest()?),
                        opt_text(receipt.roster.source_head_cut_id.as_deref()),
                        text(&serde_json::to_string(&receipt)?),
                    ],
                )
                .map_err(sql_err)?;
            let changed = self
                .sql
                .execute(
                    "UPDATE branches SET status = 'closed', updated_at = ?2 \
                 WHERE branch_id = ?1 AND status = 'active'",
                    &[text(&request.source_branch_id), text(&request.recorded_at)],
                )
                .map_err(sql_err)?;
            if changed != 1 {
                return Err(StoreError::Conflict(
                    "flowing final close lost active source".into(),
                ));
            }
            Ok(Closed(receipt))
        })
    }

    fn flowing_final_close_receipt(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingFinalCloseReceipt>> {
        read_receipt(self, source_branch_id)
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::do_store::test_support::RusqliteDoSql;
    use whipplescript_store::branches::flowing_close_roster::FlowingCloseRosterReader;
    use whipplescript_store::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceTransition, FlowingSourceKind,
        OpenFlowingSource,
    };
    use whipplescript_store::branches::flowing_holders::FlowingUnitHolder;
    use whipplescript_store::branches::flowing_member_parking::{
        FlowingMemberParking, ParkFlowingMember,
    };
    use whipplescript_store::branches::flowing_parking::{FlowingParkReceipt, ParkFlowingUnit};
    use whipplescript_store::branches::{
        AdvanceOutcome, CreateBranch, CutRecord, MAINLINE_BRANCH_ID,
    };

    fn ready_with_options(
        with_head: bool,
        direct_twig: bool,
    ) -> (
        Rc<RusqliteDoSql>,
        DoBranches<Rc<RusqliteDoSql>>,
        FinalCloseFlowingSource,
    ) {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: (!direct_twig).then_some("feature"),
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
                kind: if direct_twig {
                    FlowingSourceKind::Twig
                } else {
                    FlowingSourceKind::Branch
                },
                owner: "coordinator".into(),
                opened_at: "t1".into(),
            })
            .unwrap();
        if !direct_twig {
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
        }
        if with_head {
            store
                .record_cut(CutRecord {
                    cut_id: "source-cut",
                    change_id: "source-change",
                    branch_id: "branch",
                    manifest_hash: "source-manifest",
                    parent_cut_id: None,
                    origin: Some("write:branch"),
                    actor: Some("coordinator"),
                    intent: None,
                    recorded_at: "t2",
                })
                .unwrap();
            assert!(matches!(
                store
                    .advance_head("branch", None, "source-cut", "source-manifest", "t2")
                    .unwrap(),
                AdvanceOutcome::Advanced(_)
            ));
        }
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
                    recorded_at: "t3".into(),
                })
                .unwrap();
        }
        if !direct_twig {
            store
                .park_flowing_member(&ParkFlowingMember {
                    op_id: "park-member".into(),
                    source_branch_id: "branch".into(),
                    source_incarnation_id: "branch-inc".into(),
                    expected_source_eligibility_epoch: 1,
                    expected_source_owner_epoch: 0,
                    member_branch_id: "member".into(),
                    expected_member_incarnation_id: Some("member-inc".into()),
                    expected_member_head_cut_id: None,
                    expected_member_head_manifest_hash: None,
                    parked_holder_id: "holder".into(),
                    actor: "coordinator".into(),
                    recorded_at: "t4".into(),
                })
                .unwrap();
        }
        let digest = store
            .flowing_close_roster("branch")
            .unwrap()
            .unwrap()
            .digest()
            .unwrap();
        let request = FinalCloseFlowingSource {
            op_id: "final-close".into(),
            source_branch_id: "branch".into(),
            source_incarnation_id: "branch-inc".into(),
            expected_eligibility_epoch: 1,
            expected_owner_epoch: 0,
            expected_roster_digest: digest,
            actor: "coordinator".into(),
            recorded_at: "t5".into(),
        };
        (sql, store, request)
    }

    fn ready_with_head(
        with_head: bool,
    ) -> (
        Rc<RusqliteDoSql>,
        DoBranches<Rc<RusqliteDoSql>>,
        FinalCloseFlowingSource,
    ) {
        ready_with_options(with_head, false)
    }

    fn ready() -> (
        Rc<RusqliteDoSql>,
        DoBranches<Rc<RusqliteDoSql>>,
        FinalCloseFlowingSource,
    ) {
        ready_with_head(false)
    }

    #[test]
    fn hosted_direct_twig_refuses_owed_work_and_closes_resolved_line() {
        let (sql, mut store, mut request) = ready_with_options(true, true);
        let roster = store.flowing_close_roster("branch").unwrap().unwrap();
        assert_eq!(roster.source_fence.kind, FlowingSourceKind::Twig);
        assert_eq!(
            roster.source_parent_branch_id.as_deref(),
            Some(MAINLINE_BRANCH_ID)
        );
        assert!(roster.members.is_empty());
        sql.execute(
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
             VALUES ('owed', 'pin', 'branch', 'source-cut', 'source-manifest', \
                     'author', 'change', 'read', 'deps', 'scope', 't4')",
            &[],
        )
        .unwrap();
        request.expected_roster_digest = store
            .flowing_close_roster("branch")
            .unwrap()
            .unwrap()
            .digest()
            .unwrap();
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitOwed {
                unit_id: "owed".into(),
            })
        );
        let (_, mut store, request) = ready_with_options(true, true);
        let FlowingFinalCloseOutcome::Closed(receipt) =
            store.final_close_flowing_source(&request).unwrap()
        else {
            panic!("resolved hosted direct twig closes");
        };
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Closed
        );
        assert!(store.pinned_cuts("t9").unwrap().contains("source-cut"));
        let host = whipplescript_store::branches::flowing_close_host::read_close_evidence(
            &store, "branch",
        )
        .unwrap()
        .unwrap();
        assert_eq!(host.source_kind, FlowingSourceKind::Twig);
        assert!(host.members.is_empty());
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Existing(receipt)
        );
    }

    #[test]
    fn hosted_final_close_is_atomic_and_retry_safe() {
        let (sql, mut store, request) = ready();
        sql.execute(
            "CREATE TRIGGER fail_final_close BEFORE INSERT ON flowing_final_closes \
             BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END",
            &[],
        )
        .unwrap();
        assert!(store.final_close_flowing_source(&request).is_err());
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Active
        );
        drop(store);
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
        assert!(store
            .flowing_final_close_receipt("branch")
            .unwrap()
            .is_none());
        sql.execute("DROP TRIGGER fail_final_close", &[]).unwrap();
        let FlowingFinalCloseOutcome::Closed(receipt) =
            store.final_close_flowing_source(&request).unwrap()
        else {
            panic!("hosted resolved roster closes");
        };
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Closed
        );
        drop(store);
        let mut store = DoBranches::new(Rc::clone(&sql)).unwrap();
        assert_eq!(
            store.flowing_final_close_receipt("branch").unwrap(),
            Some(receipt.clone())
        );
        let host = whipplescript_store::branches::flowing_close_host::read_close_evidence(
            &store, "branch",
        )
        .unwrap()
        .unwrap();
        assert_eq!(host.source_kind, FlowingSourceKind::Branch);
        assert_eq!(host.members.len(), 1);
        assert_eq!(host.members[0].park_operation_id, "park-member");
        assert_eq!(
            store.flowing_member_park_receipt("park-member").unwrap(),
            receipt.roster.members[0].parked
        );
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Existing(receipt)
        );
    }

    #[test]
    fn hosted_final_close_cannot_acknowledge_without_status_change() {
        let (sql, mut store, request) = ready();
        sql.execute(
            "CREATE TRIGGER skip_final_status BEFORE UPDATE OF status ON branches \
             WHEN NEW.branch_id = 'branch' BEGIN SELECT RAISE(IGNORE); END",
            &[],
        )
        .unwrap();
        let error = store.final_close_flowing_source(&request).unwrap_err();
        assert!(format!("{error:?}").contains("flowing final close lost active source"));
        assert!(store
            .flowing_final_close_receipt("branch")
            .unwrap()
            .is_none());
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Active
        );
    }

    #[test]
    fn hosted_final_close_rechecks_exact_roster() {
        let (_, mut store, mut request) = ready();
        request.expected_roster_digest = "sha256:old".into();
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::StaleRoster)
        );
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Active
        );
    }

    #[test]
    fn hosted_final_close_retains_and_validates_exact_source_head() {
        let (sql, mut store, request) = ready_with_head(true);
        assert!(matches!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Closed(_)
        ));
        assert!(store.pinned_cuts("t9").unwrap().contains("source-cut"));
        sql.execute("DELETE FROM cuts WHERE cut_id = 'source-cut'", &[])
            .unwrap();
        let error = store.flowing_final_close_receipt("branch").unwrap_err();
        assert!(format!("{error:?}")
            .contains("flowing final close retained head is missing or changed"));
    }

    #[test]
    fn hosted_final_close_refuses_owed_unit_and_live_private_pin() {
        let (sql, mut store, request) = ready();
        sql.execute(
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
             VALUES ('owed', 'pin', 'branch', 'cut', 'manifest', \
                     'author', 'change', 'read', 'deps', 'scope', 't4')",
            &[],
        )
        .unwrap();
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitOwed {
                unit_id: "owed".into()
            })
        );
        sql.execute(
            "DELETE FROM flowing_contributions WHERE unit_id = 'owed'",
            &[],
        )
        .unwrap();
        sql.execute(
            "INSERT INTO flowing_private_pins \
             (pin_id, twig_branch_id, cut_id, manifest_hash, principal, retained_at) \
             VALUES ('pin', 'member', 'cut', 'manifest', 'author', 't4')",
            &[],
        )
        .unwrap();
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::PrivatePinLive)
        );
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Active
        );
    }

    #[test]
    fn hosted_final_close_receipt_reader_refuses_corrupt_keys_and_lost_members() {
        let cases = [
            (
                "UPDATE flowing_final_closes SET roster_digest = 'different'",
                "flowing final close receipt differs from ref keys or roster",
            ),
            (
                "UPDATE flowing_final_closes SET receipt_json = REPLACE(receipt_json, '\"recorded_at\":\"t5\"', '\"recorded_at\":\"altered\"')",
                "flowing final close receipt differs from ref keys or roster",
            ),
            (
                "DELETE FROM branches WHERE branch_id = 'branch'",
                "flowing final close source row is missing",
            ),
            (
                "UPDATE branches SET status = 'active' WHERE branch_id = 'branch'",
                "flowing final close source changed after disposition",
            ),
            (
                "UPDATE branches SET parent_branch_id = 'member' WHERE branch_id = 'branch'",
                "flowing final close source changed after disposition",
            ),
            (
                "DELETE FROM flowing_parked_members WHERE member_branch_id = 'member'",
                "flowing final close lost a member disposition",
            ),
        ];
        for (mutation, message) in cases {
            let (sql, mut store, request) = ready();
            assert!(matches!(
                store.final_close_flowing_source(&request).unwrap(),
                FlowingFinalCloseOutcome::Closed(_)
            ));
            sql.execute(mutation, &[]).unwrap();
            let error = store.flowing_final_close_receipt("branch").unwrap_err();
            assert!(
                format!("{error:?}").contains(message),
                "{mutation}: {error:?}"
            );
        }
    }

    #[test]
    fn hosted_final_close_embeds_a_multi_unit_admission_once() {
        for direct_twig in [false, true] {
            let (sql, mut store, mut request) = ready_with_options(true, direct_twig);
            let admission = serde_json::json!({
                "request": {
                    "op_id": "admit-both",
                    "certificate_handle": "certificate",
                    "candidate_witness_digest": "witness",
                    "contribution_id": "contribution",
                    "revision_sequence": 1,
                    "source_branch_id": "branch",
                    "source_incarnation_id": "branch-inc",
                    "source_cut_id": "source-cut",
                    "source_manifest_hash": "source-manifest",
                    "expected_eligibility_epoch": 0,
                    "expected_owner_epoch": 0,
                    "coordinator": "coordinator",
                    "expected_trunk_cut_id": null,
                    "candidate_cut_id": "candidate",
                    "candidate_manifest_hash": "candidate-manifest",
                    "units": [
                        {"unit_id": "unit-a", "basis_digest": "basis", "principal": "author", "intent": "change", "outcome": "applied"},
                        {"unit_id": "unit-b", "basis_digest": "basis", "principal": "author", "intent": "change", "outcome": "applied"}
                    ],
                    "recorded_at": "t3"
                }
            });
            sql.execute(
                "INSERT INTO flowing_admissions (op_id, receipt_json) VALUES ('admit-both', ?1)",
                &[text(&admission.to_string())],
            )
            .unwrap();
            for unit_id in ["unit-a", "unit-b"] {
                sql.execute(
                "INSERT INTO flowing_contributions \
                 (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
                  principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
                 VALUES (?1, 'pin', 'branch', 'source-cut', 'source-manifest', \
                         'author', 'change', 'read', 'deps', 'scope', 't2')",
                &[text(unit_id)],
            )
            .unwrap();
                sql.execute(
                    "INSERT INTO flowing_admitted_units (unit_id, op_id) VALUES (?1, 'admit-both')",
                    &[text(unit_id)],
                )
                .unwrap();
            }
            request.expected_roster_digest = store
                .flowing_close_roster("branch")
                .unwrap()
                .unwrap()
                .digest()
                .unwrap();
            let mut incomplete = admission.clone();
            incomplete["request"]["units"].as_array_mut().unwrap().pop();
            sql.execute(
                "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admit-both'",
                &[text(&incomplete.to_string())],
            )
            .unwrap();
            assert_eq!(
                store.final_close_flowing_source(&request).unwrap(),
                FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                    unit_id: "unit-b".into()
                })
            );
            let mut extra = admission.clone();
            extra["request"]["units"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "unit_id": "unit-c", "basis_digest": "basis", "principal": "author",
                    "intent": "change", "outcome": "applied"
                }));
            sql.execute(
                "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admit-both'",
                &[text(&extra.to_string())],
            )
            .unwrap();
            assert_eq!(
                store.final_close_flowing_source(&request).unwrap(),
                FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                    unit_id: "unit-c".into()
                })
            );
            let mut duplicate = admission.clone();
            let first = duplicate["request"]["units"][0].clone();
            duplicate["request"]["units"]
                .as_array_mut()
                .unwrap()
                .push(first);
            sql.execute(
                "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admit-both'",
                &[text(&duplicate.to_string())],
            )
            .unwrap();
            assert_eq!(
                store.final_close_flowing_source(&request).unwrap(),
                FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                    unit_id: "unit-a".into()
                })
            );
            let mut wrong_source = admission.clone();
            wrong_source["request"]["source_branch_id"] = "another-branch".into();
            sql.execute(
                "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admit-both'",
                &[text(&wrong_source.to_string())],
            )
            .unwrap();
            assert!(matches!(
                store.final_close_flowing_source(&request).unwrap(),
                FlowingFinalCloseOutcome::Refused(
                    FlowingFinalCloseRefusal::UnitReceiptMismatch { .. }
                )
            ));
            sql.execute(
                "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admit-both'",
                &[text(&admission.to_string())],
            )
            .unwrap();
            let FlowingFinalCloseOutcome::Closed(receipt) =
                store.final_close_flowing_source(&request).unwrap()
            else {
                panic!("both hosted admitted units close");
            };
            assert_eq!(receipt.roster.units.len(), 2);
            assert_eq!(receipt.unit_evidence.admissions.len(), 1);
            let host = whipplescript_store::branches::flowing_close_host::read_close_evidence(
                &store, "branch",
            )
            .unwrap()
            .unwrap();
            assert_eq!(host.units.len(), 2);
            assert!(host.units.iter().all(|unit| matches!(
            unit.disposition,
            whipplescript_store::branches::flowing_close_host::FlowingHostCloseDispositionV1::Admitted {
                outcome: whipplescript_store::branches::flowing_admission::FlowingUnitOutcome::Applied,
                ..
            }
        )));
            assert_eq!(receipt.unit_evidence.admissions[0].request.units.len(), 2);
            assert_eq!(
                store.flowing_admission_receipt("admit-both").unwrap(),
                receipt.unit_evidence.admissions.first().cloned()
            );
            assert_eq!(
                store.flowing_final_close_receipt("branch").unwrap(),
                Some(receipt)
            );
        }
    }

    #[test]
    fn hosted_final_close_preserves_a_parked_unit_receipt() {
        let (sql, mut store, mut request) = ready_with_head(true);
        let mut fence_after = store.flowing_source("branch").unwrap().unwrap();
        fence_after.eligibility_epoch += 1;
        let park = FlowingParkReceipt {
            request: ParkFlowingUnit {
                op_id: "park-unit".into(),
                unit_id: "parked-unit".into(),
                source_branch_id: "branch".into(),
                source_incarnation_id: "branch-inc".into(),
                source_cut_id: "source-cut".into(),
                source_manifest_hash: "source-manifest".into(),
                basis_digest: "basis".into(),
                principal: "author".into(),
                intent: "change".into(),
                expected_eligibility_epoch: 1,
                expected_owner_epoch: 0,
                parked_holder_id: "holder".into(),
                actor: "coordinator".into(),
                recorded_at: "t4".into(),
            },
            former_holder: FlowingUnitHolder {
                unit_id: "parked-unit".into(),
                holder_branch_id: "branch".into(),
                holder_cut_id: "source-cut".into(),
                holder_manifest_hash: "source-manifest".into(),
                handoff_op_id: None,
                proof_digest: "holder-proof".into(),
            },
            source_fence_after: fence_after,
        };
        sql.execute(
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
             VALUES ('parked-unit', 'pin', 'branch', 'source-cut', 'source-manifest', \
                     'author', 'change', 'read', 'deps', 'scope', 't3')",
            &[],
        )
        .unwrap();
        sql.execute(
            "INSERT INTO flowing_parked_units (unit_id, op_id, holder_id, receipt_json) \
             VALUES ('parked-unit', 'park-unit', 'holder', ?1)",
            &[text(&serde_json::to_string(&park).unwrap())],
        )
        .unwrap();
        request.expected_roster_digest = store
            .flowing_close_roster("branch")
            .unwrap()
            .unwrap()
            .digest()
            .unwrap();
        let FlowingFinalCloseOutcome::Closed(receipt) =
            store.final_close_flowing_source(&request).unwrap()
        else {
            panic!("hosted parked unit permits close");
        };
        assert_eq!(receipt.unit_evidence.parked_units, vec![park.clone()]);
        assert_eq!(store.flowing_park_receipt("park-unit").unwrap(), Some(park));
    }

    #[test]
    fn hosted_final_close_requires_a_transferred_unit_in_the_receiving_head() {
        let (sql, mut store, mut request) = ready_with_head(true);
        store
            .create_branch(CreateBranch {
                branch_id: "recipient",
                name: Some("recipient"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t3",
                idempotency_key: None,
            })
            .unwrap();
        for (cut_id, manifest_hash) in [
            ("received-cut", "received-manifest"),
            ("orphan", "orphan-manifest"),
        ] {
            store
                .record_cut(CutRecord {
                    cut_id,
                    change_id: cut_id,
                    branch_id: "recipient",
                    manifest_hash,
                    parent_cut_id: None,
                    origin: Some("handoff"),
                    actor: Some("coordinator"),
                    intent: None,
                    recorded_at: "t3",
                })
                .unwrap();
        }
        store
            .advance_head("recipient", None, "received-cut", "received-manifest", "t3")
            .unwrap();
        sql.execute(
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
             VALUES ('transferred', 'pin', 'branch', 'source-cut', 'source-manifest', \
                     'author', 'change', 'read', 'deps', 'scope', 't3')",
            &[],
        )
        .unwrap();
        sql.execute(
            "INSERT INTO flowing_handoffs \
             (op_id, unit_id, source_branch_id, source_cut_id, source_manifest_hash, \
              source_basis_digest, target_branch_id, target_before_cut_id, \
              target_after_cut_id, target_after_manifest_hash, effects_json, \
              original_principal, actor, recorded_at) \
             VALUES ('handoff', 'transferred', 'branch', 'source-cut', 'source-manifest', \
                     'basis', 'recipient', NULL, 'received-cut', 'received-manifest', '[]', \
                     'author', 'coordinator', 't3')",
            &[],
        )
        .unwrap();
        request.expected_roster_digest = store
            .flowing_close_roster("branch")
            .unwrap()
            .unwrap()
            .digest()
            .unwrap();
        sql.execute(
            "UPDATE branches SET head_cut_id = 'orphan', head_manifest_hash = 'orphan-manifest' \
             WHERE branch_id = 'recipient'",
            &[],
        )
        .unwrap();
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                unit_id: "transferred".into()
            })
        );
        sql.execute(
            "UPDATE branches SET head_cut_id = 'received-cut', head_manifest_hash = 'received-manifest' \
             WHERE branch_id = 'recipient'",
            &[],
        )
        .unwrap();
        let FlowingFinalCloseOutcome::Closed(receipt) =
            store.final_close_flowing_source(&request).unwrap()
        else {
            panic!("retained recipient cut permits hosted transfer disposition");
        };
        assert_eq!(receipt.unit_evidence.handoffs.len(), 1);
        assert_eq!(receipt.unit_evidence.handoffs[0].unit_id, "transferred");
    }
}
