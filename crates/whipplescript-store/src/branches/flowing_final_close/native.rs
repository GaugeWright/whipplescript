use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    cut_in_current_ancestry, missing_field, preflight, receipt_matches_snapshot,
    FinalCloseFlowingSource, FlowingCloseEvidence, FlowingFinalClose, FlowingFinalCloseOutcome,
    FlowingFinalCloseReceipt, FlowingFinalCloseRefusal,
};
use crate::branches::flowing_close_roster::{self, FlowingCloseUnitState};
use crate::branches::{
    flowing_abandonment, flowing_admission, flowing_member_parking, flowing_parking,
    flowing_sources, BranchStatus, BranchStore,
};
use crate::{StoreError, StoreResult};
use flowing_abandonment::native::read_receipt as read_abandonment_receipt;

fn read_receipt(
    connection: &Connection,
    source_branch_id: &str,
) -> StoreResult<Option<FlowingFinalCloseReceipt>> {
    let row: Option<(String, String, String, String, Option<String>, String)> = connection
        .query_row(
            "SELECT source_branch_id, op_id, roster_digest, receipt_digest, retained_head_cut_id, receipt_json \
             FROM flowing_final_closes WHERE source_branch_id = ?1",
            [source_branch_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((source_id, op_id, digest, receipt_digest, retained_head, json)) = row else {
        return Ok(None);
    };
    let receipt: FlowingFinalCloseReceipt = serde_json::from_str(&json)?;
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
    let branch = BranchStore::row_by_id(connection, &source_id)?
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
        let cut = BranchStore::cut_by_id(connection, head_id)?;
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
        if flowing_member_parking::native::read_by_member(connection, &member.branch_id)?
            != member.parked
        {
            return Err(StoreError::Conflict(
                "flowing final close lost a member disposition".into(),
            ));
        }
    }
    Ok(Some(receipt))
}

fn verify_units(
    connection: &Connection,
    roster: &flowing_close_roster::FlowingCloseRoster,
) -> StoreResult<Result<FlowingCloseEvidence, FlowingFinalCloseRefusal>> {
    use FlowingCloseUnitState as S;
    use FlowingFinalCloseRefusal as R;
    let mut admissions = BTreeMap::new();
    let mut abandonments = BTreeMap::new();
    let mut admitted_unit_ids = BTreeSet::new();
    let mut roster_admitted_unit_ids = BTreeSet::new();
    let mut abandoned_unit_ids = BTreeSet::new();
    let mut roster_abandoned_unit_ids = BTreeSet::new();
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
                    let Some(receipt) = flowing_admission::native::read_receipt(connection, op_id)?
                    else {
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
            S::Abandoned { op_id } => {
                if !abandonments.contains_key(op_id) {
                    let receipt = read_abandonment_receipt(connection, "op_id", op_id)?;
                    let Some(receipt) = receipt else {
                        return Ok(Err(missing()));
                    };
                    if receipt.source_branch_id != roster.source_branch_id
                        || receipt.source_incarnation_id != roster.source_fence.incarnation_id
                    {
                        return Ok(Err(mismatch()));
                    }
                    for selected in &receipt.units {
                        abandoned_unit_ids.insert((op_id.clone(), selected.unit_id().to_owned()));
                    }
                    abandonments.insert(op_id.clone(), receipt);
                }
                let key = (op_id.clone(), unit.unit_id.clone());
                if !abandoned_unit_ids.contains(&key) || !roster_abandoned_unit_ids.insert(key) {
                    return Ok(Err(mismatch()));
                }
            }
            S::Parked { .. } => {
                let Some(receipt) =
                    flowing_parking::native::read_by_unit(connection, &unit.unit_id)?
                else {
                    return Ok(Err(missing()));
                };
                // The parked-unit reader checks the row's operation and
                // holder keys before returning this receipt. The roster read
                // the same row under this transaction.
                parked_units.push(receipt);
            }
            S::Transferred { target_branch_id } => {
                let Some(receipt) =
                    flowing_sources::native::holder_handoff(connection, &unit.unit_id)?
                else {
                    return Ok(Err(missing()));
                };
                let target = BranchStore::row_by_id(connection, target_branch_id)?;
                let cut = BranchStore::cut_by_id(connection, &receipt.target_after_cut_id)?;
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
                                |id| BranchStore::cut_by_id(connection, id),
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
    if let Some((_, unit_id)) = abandoned_unit_ids
        .difference(&roster_abandoned_unit_ids)
        .next()
    {
        return Ok(Err(R::UnitReceiptMismatch {
            unit_id: unit_id.clone(),
        }));
    }
    Ok(Ok(FlowingCloseEvidence {
        admissions: admissions.into_values().collect(),
        abandonments: abandonments.into_values().collect(),
        parked_units,
        handoffs,
    }))
}

impl FlowingFinalClose for BranchStore {
    fn final_close_flowing_source(
        &mut self,
        request: &FinalCloseFlowingSource,
    ) -> StoreResult<FlowingFinalCloseOutcome> {
        use FlowingFinalCloseOutcome::{Closed, Existing, Refused};
        use FlowingFinalCloseRefusal as R;
        if let Some(field) = missing_field(request) {
            return Ok(Refused(R::Invalid { field }));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_receipt(&tx, &request.source_branch_id)? {
            return Ok(if existing.request == *request {
                Existing(existing)
            } else {
                Refused(R::AlreadyClosed)
            });
        }
        let conflicting_op: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM flowing_final_closes WHERE op_id = ?1)",
            [&request.op_id],
            |row| row.get(0),
        )?;
        if conflicting_op {
            return Ok(Refused(R::IdentityMismatch));
        }
        let Some(roster) =
            flowing_close_roster::native::read_roster(&tx, &request.source_branch_id)?
        else {
            return Ok(Refused(R::SourceMissing));
        };
        if let Err(refusal) = preflight(&roster, request) {
            return Ok(Refused(refusal));
        }
        if roster.digest()? != request.expected_roster_digest {
            return Ok(Refused(R::StaleRoster));
        }
        if let Some(head_id) = roster.source_head_cut_id.as_deref() {
            let cut = BranchStore::cut_by_id(&tx, head_id)?;
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
        let unit_evidence = match verify_units(&tx, &roster)? {
            Ok(evidence) => evidence,
            Err(refusal) => return Ok(Refused(refusal)),
        };
        let receipt = FlowingFinalCloseReceipt {
            request: request.clone(),
            roster,
            unit_evidence,
        };
        tx.execute(
            "INSERT INTO flowing_final_closes \
             (source_branch_id, op_id, roster_digest, receipt_digest, retained_head_cut_id, receipt_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request.source_branch_id,
                request.op_id,
                request.expected_roster_digest,
                receipt.digest()?,
                receipt.roster.source_head_cut_id,
                serde_json::to_string(&receipt)?,
            ],
        )?;
        let changed = tx.execute(
            "UPDATE branches SET status = 'closed', updated_at = ?2 \
             WHERE branch_id = ?1 AND status = 'active'",
            params![request.source_branch_id, request.recorded_at],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict(
                "flowing final close lost active source".into(),
            ));
        }
        tx.commit()?;
        Ok(Closed(receipt))
    }

    fn flowing_final_close_receipt(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingFinalCloseReceipt>> {
        read_receipt(&self.connection, source_branch_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_admission::{
        FlowingAdmissionRequest, FlowingAdmissions, FlowingSelectedUnit, FlowingUnitOutcome,
    };
    use crate::branches::flowing_close_roster::FlowingCloseRosterReader;
    use crate::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceTransition, FlowingSourceKind,
        OpenFlowingSource,
    };
    use crate::branches::flowing_holders::FlowingUnitHolder;
    use crate::branches::flowing_member_parking::{FlowingMemberParking, ParkFlowingMember};
    use crate::branches::flowing_parking::{FlowingParkReceipt, FlowingParking, ParkFlowingUnit};
    use crate::branches::{AdvanceOutcome, Branches, CreateBranch, CutRecord, MAINLINE_BRANCH_ID};

    fn ready_with_options(
        with_head: bool,
        direct_twig: bool,
    ) -> (BranchStore, FinalCloseFlowingSource) {
        ready_with_store(
            BranchStore::open_in_memory().unwrap(),
            with_head,
            direct_twig,
        )
    }

    fn ready_with_store(
        mut store: BranchStore,
        with_head: bool,
        direct_twig: bool,
    ) -> (BranchStore, FinalCloseFlowingSource) {
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
        (store, request)
    }

    fn ready_with_head(with_head: bool) -> (BranchStore, FinalCloseFlowingSource) {
        ready_with_options(with_head, false)
    }

    fn ready() -> (BranchStore, FinalCloseFlowingSource) {
        ready_with_head(false)
    }

    #[test]
    fn direct_twig_refuses_owed_work_and_closes_resolved_line() {
        let (mut store, mut request) = ready_with_options(true, true);
        let roster = store.flowing_close_roster("branch").unwrap().unwrap();
        assert_eq!(roster.source_fence.kind, FlowingSourceKind::Twig);
        assert_eq!(
            roster.source_parent_branch_id.as_deref(),
            Some(MAINLINE_BRANCH_ID)
        );
        assert!(roster.members.is_empty());
        store
            .connection
            .execute(
                "INSERT INTO flowing_contributions \
                 (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
                  principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
                 VALUES ('owed', 'pin', 'branch', 'source-cut', 'source-manifest', \
                         'author', 'change', 'read', 'deps', 'scope', 't4')",
                [],
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
        let (mut store, request) = ready_with_options(true, true);
        let FlowingFinalCloseOutcome::Closed(receipt) =
            store.final_close_flowing_source(&request).unwrap()
        else {
            panic!("resolved direct twig closes");
        };
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Closed
        );
        assert!(store.pinned_cuts("t9").unwrap().contains("source-cut"));
        let host = crate::branches::flowing_close_host::read_close_evidence(&store, "branch")
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
    fn final_close_records_exact_roster_and_is_retry_safe() {
        let (mut store, request) = ready();
        assert!(
            crate::branches::flowing_close_host::read_close_evidence(&store, "branch")
                .unwrap()
                .is_none()
        );
        assert!(crate::branches::flowing_close_host::read_close_evidence(&store, " ").is_err());
        let FlowingFinalCloseOutcome::Closed(receipt) =
            store.final_close_flowing_source(&request).unwrap()
        else {
            panic!("resolved roster closes");
        };
        assert_eq!(receipt.roster.members.len(), 1);
        assert!(receipt.roster.members[0].parked.is_some());
        assert!(receipt.unit_evidence.admissions.is_empty());
        assert!(receipt.unit_evidence.parked_units.is_empty());
        assert!(receipt.unit_evidence.handoffs.is_empty());
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Closed
        );
        assert_eq!(
            store.flowing_final_close_receipt("branch").unwrap(),
            Some(receipt.clone())
        );
        let host = crate::branches::flowing_close_host::read_close_evidence(&store, "branch")
            .unwrap()
            .unwrap();
        assert_eq!(host.source_kind, FlowingSourceKind::Branch);
        assert_eq!(host.members.len(), 1);
        assert_eq!(host.members[0].park_operation_id, "park-member");
        let mut changed = receipt.clone();
        changed.request.expected_roster_digest = format!("sha256:{}", "0".repeat(32));
        assert!(format!(
            "{:?}",
            crate::branches::flowing_close_host::FlowingHostCloseEvidenceV1::from_retained(
                &changed
            )
            .unwrap_err()
        )
        .contains("close receipt has an unresolved or changed roster"));
        struct WrongSource(FlowingFinalCloseReceipt);
        impl FlowingFinalClose for WrongSource {
            fn final_close_flowing_source(
                &mut self,
                _: &FinalCloseFlowingSource,
            ) -> StoreResult<FlowingFinalCloseOutcome> {
                unreachable!("reader fixture never closes")
            }

            fn flowing_final_close_receipt(
                &self,
                _: &str,
            ) -> StoreResult<Option<FlowingFinalCloseReceipt>> {
                Ok(Some(self.0.clone()))
            }
        }
        assert!(crate::branches::flowing_close_host::read_close_evidence(
            &WrongSource(receipt.clone()),
            "other-source"
        )
        .is_err());
        assert_eq!(
            store.flowing_member_park_receipt("park-member").unwrap(),
            receipt.roster.members[0].parked
        );
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Existing(receipt)
        );
        let mut different = request;
        different.op_id = "another-close".into();
        assert_eq!(
            store.final_close_flowing_source(&different).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::AlreadyClosed)
        );
    }

    #[test]
    fn final_close_survives_writer_restart_with_receipt_and_retained_head() {
        let dir = crate::scratch::path("flowing-final-close-reopen");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("branches.sqlite");
        let (mut store, request) = ready_with_store(BranchStore::open(&path).unwrap(), true, false);
        let FlowingFinalCloseOutcome::Closed(receipt) =
            store.final_close_flowing_source(&request).unwrap()
        else {
            panic!("resolved source closes before restart");
        };
        drop(store);

        let mut recovered = BranchStore::open(&path).unwrap();
        assert_eq!(
            recovered.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Closed
        );
        assert_eq!(
            recovered.flowing_final_close_receipt("branch").unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            recovered
                .flowing_member_park_receipt("park-member")
                .unwrap(),
            receipt.roster.members[0].parked
        );
        assert!(recovered.pinned_cuts("t9").unwrap().contains("source-cut"));
        assert_eq!(
            recovered.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Existing(receipt)
        );
        drop(recovered);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_final_close_recovers_before_boundary_and_can_retry() {
        let dir = crate::scratch::path("flowing-final-close-before-boundary");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("branches.sqlite");
        let (mut store, request) = ready_with_store(BranchStore::open(&path).unwrap(), true, false);
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_final_close BEFORE INSERT ON flowing_final_closes \
                 BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;",
            )
            .unwrap();
        assert!(store.final_close_flowing_source(&request).is_err());
        drop(store);

        let mut recovered = BranchStore::open(&path).unwrap();
        assert_eq!(
            recovered.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Active
        );
        assert!(recovered
            .flowing_final_close_receipt("branch")
            .unwrap()
            .is_none());
        recovered
            .connection
            .execute_batch("DROP TRIGGER fail_final_close")
            .unwrap();
        assert!(matches!(
            recovered.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Closed(_)
        ));
        drop(recovered);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn final_close_receipt_failure_preserves_active_source() {
        let (mut store, request) = ready();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_final_close BEFORE INSERT ON flowing_final_closes \
             BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;",
            )
            .unwrap();
        assert!(store.final_close_flowing_source(&request).is_err());
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Active
        );
        assert!(store
            .flowing_final_close_receipt("branch")
            .unwrap()
            .is_none());
    }

    #[test]
    fn final_close_rechecks_exact_roster_and_member_receipt() {
        let (mut store, mut request) = ready();
        request.expected_roster_digest = "sha256:old".into();
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::StaleRoster)
        );
        let (mut store, request) = ready();
        store
            .connection
            .execute(
                "DELETE FROM flowing_parked_members WHERE member_branch_id = 'member'",
                [],
            )
            .unwrap();
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::MemberUnresolved {
                branch_id: "member".into()
            })
        );
        assert_eq!(
            store.get_branch("branch").unwrap().unwrap().status,
            BranchStatus::Active
        );
    }

    #[test]
    fn final_close_refuses_abandoned_unit_without_exact_receipt() {
        let (mut store, _) = ready_with_head(true);
        let mut roster = store.flowing_close_roster("branch").unwrap().unwrap();
        roster.units.push(flowing_close_roster::FlowingCloseUnit {
            unit_id: "missing-abandon".into(),
            original_source_branch_id: "branch".into(),
            handoff_op_id: None,
            state: FlowingCloseUnitState::Abandoned {
                op_id: "abandon-missing".into(),
            },
        });
        assert_eq!(
            verify_units(&store.connection, &roster).unwrap(),
            Err(FlowingFinalCloseRefusal::UnitReceiptMissing {
                unit_id: "missing-abandon".into(),
            })
        );
    }

    #[test]
    fn final_close_retains_and_validates_exact_source_head() {
        let (mut store, request) = ready_with_head(true);
        assert!(matches!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Closed(_)
        ));
        assert!(store.pinned_cuts("t9").unwrap().contains("source-cut"));
        store
            .connection
            .execute("DELETE FROM cuts WHERE cut_id = 'source-cut'", [])
            .unwrap();
        let error = store.flowing_final_close_receipt("branch").unwrap_err();
        assert!(format!("{error:?}")
            .contains("flowing final close retained head is missing or changed"));
    }

    #[test]
    fn final_close_refuses_owed_unit_and_live_private_pin() {
        let (mut store, request) = ready();
        store.connection.execute(
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
             VALUES ('owed', 'pin', 'branch', 'cut', 'manifest', \
                     'author', 'change', 'read', 'deps', 'scope', 't4')",
            [],
        ).unwrap();
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitOwed {
                unit_id: "owed".into()
            })
        );
        store
            .connection
            .execute(
                "DELETE FROM flowing_contributions WHERE unit_id = 'owed'",
                [],
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO flowing_private_pins \
             (pin_id, twig_branch_id, cut_id, manifest_hash, principal, retained_at) \
             VALUES ('pin', 'member', 'cut', 'manifest', 'author', 't4')",
                [],
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
    fn final_close_receipt_reader_refuses_corrupt_keys_and_lost_members() {
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
            let (mut store, request) = ready();
            assert!(matches!(
                store.final_close_flowing_source(&request).unwrap(),
                FlowingFinalCloseOutcome::Closed(_)
            ));
            store.connection.execute(mutation, []).unwrap();
            let error = store.flowing_final_close_receipt("branch").unwrap_err();
            assert!(
                format!("{error:?}").contains(message),
                "{mutation}: {error:?}"
            );
        }
    }

    #[test]
    fn final_close_cannot_acknowledge_without_status_change() {
        let (mut store, request) = ready();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER skip_final_status BEFORE UPDATE OF status ON branches \
             WHEN NEW.branch_id = 'branch' BEGIN SELECT RAISE(IGNORE); END;",
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
    fn final_close_embeds_a_multi_unit_admission_once() {
        for direct_twig in [false, true] {
            let (mut store, mut request) = ready_with_options(true, direct_twig);
            let admission = flowing_admission::FlowingAdmissionReceipt {
                request: FlowingAdmissionRequest {
                    op_id: "admit-both".into(),
                    certificate_handle: "certificate".into(),
                    candidate_witness_digest: "witness".into(),
                    contribution_id: "contribution".into(),
                    revision_sequence: 1,
                    source_branch_id: "branch".into(),
                    source_incarnation_id: "branch-inc".into(),
                    source_cut_id: "source-cut".into(),
                    source_manifest_hash: "source-manifest".into(),
                    expected_eligibility_epoch: 0,
                    expected_owner_epoch: 0,
                    coordinator: "coordinator".into(),
                    expected_trunk_cut_id: None,
                    candidate_cut_id: "candidate".into(),
                    candidate_manifest_hash: "candidate-manifest".into(),
                    units: ["unit-a", "unit-b"]
                        .into_iter()
                        .map(|unit_id| FlowingSelectedUnit {
                            unit_id: unit_id.into(),
                            basis_digest: "basis".into(),
                            principal: "author".into(),
                            intent: "change".into(),
                            outcome: FlowingUnitOutcome::Applied,
                        })
                        .collect(),
                    recorded_at: "t3".into(),
                },
            };
            store
                .connection
                .execute(
                    "INSERT INTO flowing_admissions (op_id, receipt_json) VALUES (?1, ?2)",
                    params!["admit-both", serde_json::to_string(&admission).unwrap()],
                )
                .unwrap();
            for unit_id in ["unit-a", "unit-b"] {
                store
                .connection
                .execute(
                    "INSERT INTO flowing_contributions \
                     (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
                      principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
                     VALUES (?1, 'pin', 'branch', 'source-cut', 'source-manifest', \
                             'author', 'change', 'read', 'deps', 'scope', 't2')",
                    [unit_id],
                )
                .unwrap();
                store
                .connection
                .execute(
                    "INSERT INTO flowing_admitted_units (unit_id, op_id) VALUES (?1, 'admit-both')",
                    [unit_id],
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
            incomplete.request.units.pop();
            store
                .connection
                .execute(
                    "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admit-both'",
                    [serde_json::to_string(&incomplete).unwrap()],
                )
                .unwrap();
            assert_eq!(
                store.final_close_flowing_source(&request).unwrap(),
                FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                    unit_id: "unit-b".into()
                })
            );
            let mut extra = admission.clone();
            extra.request.units.push(FlowingSelectedUnit {
                unit_id: "unit-c".into(),
                basis_digest: "basis".into(),
                principal: "author".into(),
                intent: "change".into(),
                outcome: FlowingUnitOutcome::Applied,
            });
            store
                .connection
                .execute(
                    "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admit-both'",
                    [serde_json::to_string(&extra).unwrap()],
                )
                .unwrap();
            assert_eq!(
                store.final_close_flowing_source(&request).unwrap(),
                FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                    unit_id: "unit-c".into()
                })
            );
            let mut duplicate = admission.clone();
            duplicate
                .request
                .units
                .push(duplicate.request.units[0].clone());
            store
                .connection
                .execute(
                    "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admit-both'",
                    [serde_json::to_string(&duplicate).unwrap()],
                )
                .unwrap();
            assert_eq!(
                store.final_close_flowing_source(&request).unwrap(),
                FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                    unit_id: "unit-a".into()
                })
            );
            let mut wrong_source = admission.clone();
            wrong_source.request.source_branch_id = "another-branch".into();
            store
                .connection
                .execute(
                    "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admit-both'",
                    [serde_json::to_string(&wrong_source).unwrap()],
                )
                .unwrap();
            assert!(matches!(
                store.final_close_flowing_source(&request).unwrap(),
                FlowingFinalCloseOutcome::Refused(
                    FlowingFinalCloseRefusal::UnitReceiptMismatch { .. }
                )
            ));
            store
                .connection
                .execute(
                    "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admit-both'",
                    [serde_json::to_string(&admission).unwrap()],
                )
                .unwrap();
            let FlowingFinalCloseOutcome::Closed(receipt) =
                store.final_close_flowing_source(&request).unwrap()
            else {
                panic!("both admitted units close");
            };
            assert_eq!(receipt.roster.units.len(), 2);
            assert_eq!(receipt.unit_evidence.admissions, vec![admission]);
            assert_eq!(
                store.flowing_admission_receipt("admit-both").unwrap(),
                receipt.unit_evidence.admissions.first().cloned()
            );
            let mut receipt_with_extra = receipt.clone();
            receipt_with_extra.unit_evidence.admissions[0]
                .request
                .units
                .push(FlowingSelectedUnit {
                    unit_id: "unit-c".into(),
                    basis_digest: "basis".into(),
                    principal: "author".into(),
                    intent: "change".into(),
                    outcome: FlowingUnitOutcome::Applied,
                });
            assert!(!receipt_matches_snapshot(&receipt_with_extra));
            let mut receipt_with_duplicate = receipt.clone();
            let first = receipt_with_duplicate.unit_evidence.admissions[0]
                .request
                .units[0]
                .clone();
            receipt_with_duplicate.unit_evidence.admissions[0]
                .request
                .units
                .push(first);
            assert!(!receipt_matches_snapshot(&receipt_with_duplicate));
            let host = crate::branches::flowing_close_host::read_close_evidence(&store, "branch")
                .unwrap()
                .unwrap();
            assert_eq!(host.units.len(), 2);
            assert!(host.units.iter().all(|unit| matches!(
                unit.disposition,
                crate::branches::flowing_close_host::FlowingHostCloseDispositionV1::Admitted {
                    outcome: FlowingUnitOutcome::Applied,
                    ..
                }
            )));
            assert!(receipt.unit_evidence.parked_units.is_empty());
            assert!(receipt.unit_evidence.handoffs.is_empty());
            assert_eq!(
                store.flowing_final_close_receipt("branch").unwrap(),
                Some(receipt)
            );
        }
    }

    #[test]
    fn final_close_preserves_a_parked_unit_receipt() {
        let (mut store, mut request) = ready_with_head(true);
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
        store
            .connection
            .execute_batch(
                "INSERT INTO flowing_contributions \
                 (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
                  principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
                 VALUES ('parked-unit', 'pin', 'branch', 'source-cut', 'source-manifest', \
                         'author', 'change', 'read', 'deps', 'scope', 't3')",
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO flowing_parked_units (unit_id, op_id, holder_id, receipt_json) \
                 VALUES ('parked-unit', 'park-unit', 'holder', ?1)",
                [serde_json::to_string(&park).unwrap()],
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
            panic!("parked unit permits close");
        };
        assert_eq!(receipt.unit_evidence.parked_units, vec![park.clone()]);
        assert_eq!(store.flowing_park_receipt("park-unit").unwrap(), Some(park));
    }

    #[test]
    fn final_close_requires_a_transferred_unit_in_the_receiving_head() {
        let (mut store, mut request) = ready_with_head(true);
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
        store
            .connection
            .execute_batch(
                "INSERT INTO flowing_contributions \
                 (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
                  principal, intent, read_basis_digest, dependency_basis_digest, scope_digest, declared_at) \
                 VALUES ('transferred', 'pin', 'branch', 'source-cut', 'source-manifest', \
                         'author', 'change', 'read', 'deps', 'scope', 't3');
                 INSERT INTO flowing_handoffs \
                 (op_id, unit_id, source_branch_id, source_cut_id, source_manifest_hash, \
                  source_basis_digest, target_branch_id, target_before_cut_id, \
                  target_after_cut_id, target_after_manifest_hash, effects_json, \
                  original_principal, actor, recorded_at) \
                 VALUES ('handoff', 'transferred', 'branch', 'source-cut', 'source-manifest', \
                         'basis', 'recipient', NULL, 'received-cut', 'received-manifest', '[]', \
                         'author', 'coordinator', 't3');",
            )
            .unwrap();
        request.expected_roster_digest = store
            .flowing_close_roster("branch")
            .unwrap()
            .unwrap()
            .digest()
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE branches SET head_cut_id = 'orphan', head_manifest_hash = 'orphan-manifest' \
                 WHERE branch_id = 'recipient'",
                [],
            )
            .unwrap();
        assert_eq!(
            store.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                unit_id: "transferred".into()
            })
        );
        store
            .connection
            .execute(
                "UPDATE branches SET head_cut_id = 'received-cut', head_manifest_hash = 'received-manifest' \
                 WHERE branch_id = 'recipient'",
                [],
            )
            .unwrap();
        let FlowingFinalCloseOutcome::Closed(receipt) =
            store.final_close_flowing_source(&request).unwrap()
        else {
            panic!("retained recipient cut permits transfer disposition");
        };
        assert_eq!(receipt.unit_evidence.handoffs.len(), 1);
        assert_eq!(receipt.unit_evidence.handoffs[0].unit_id, "transferred");
    }
}
