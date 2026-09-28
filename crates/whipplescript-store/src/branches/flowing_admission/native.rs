use std::collections::BTreeSet;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    check_fence, validate_cancel_request, validate_request, FlowingAdmissionOutcome,
    FlowingAdmissionReceipt, FlowingAdmissionRefusal, FlowingAdmissionRequest, FlowingAdmissions,
    FlowingCancelOutcome, FlowingCancelReceipt, FlowingCancelRefusal, FlowingCancelRequest,
    FlowingUnitOutcome,
};
use crate::branches::flowing_fence;
use crate::branches::flowing_fence::FlowingSourceKind;
use crate::branches::{BranchStatus, BranchStore, MAINLINE_BRANCH_ID, MAINLINE_GATE_LEASE};
use crate::{StoreError, StoreResult};

fn read_receipt(
    connection: &Connection,
    op_id: &str,
) -> StoreResult<Option<FlowingAdmissionReceipt>> {
    let row: Option<(String, String)> = connection
        .query_row(
            "SELECT op_id, receipt_json FROM flowing_admissions WHERE op_id = ?1",
            [op_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(stored_op_id, json)| {
        let receipt: FlowingAdmissionReceipt = serde_json::from_str(&json)?;
        if receipt.request.op_id != stored_op_id {
            return Err(StoreError::Conflict(
                "flowing admission receipt differs from its operation key".into(),
            ));
        }
        Ok(receipt)
    })
    .transpose()
}

fn read_cancellation(
    connection: &Connection,
    column: &str,
    op_id: &str,
) -> StoreResult<Option<FlowingCancelReceipt>> {
    let query = match column {
        "admission_op_id" => {
            "SELECT admission_op_id, cancel_op_id, request_json \
             FROM flowing_admission_cancellations WHERE admission_op_id = ?1"
        }
        "cancel_op_id" => {
            "SELECT admission_op_id, cancel_op_id, request_json \
             FROM flowing_admission_cancellations WHERE cancel_op_id = ?1"
        }
        _ => unreachable!("the cancellation lookup column is fixed by this module"),
    };
    let row: Option<(String, String, String)> = connection
        .query_row(query, [op_id], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .optional()?;
    row.map(|(admission_op_id, cancel_op_id, json)| {
        let receipt = FlowingCancelReceipt {
            request: serde_json::from_str(&json)?,
        };
        if receipt.request.admission_op_id != admission_op_id
            || receipt.request.cancel_op_id != cancel_op_id
        {
            return Err(StoreError::Conflict(
                "flowing cancellation receipt differs from its operation keys".into(),
            ));
        }
        Ok(receipt)
    })
    .transpose()
}

/// All accepted source heads have append ancestry until a controlled
/// revision fences the old certificate. A missing or cyclic cut chain never
/// establishes that an older selected cut remains in the current line.
fn ancestor(connection: &Connection, older: &str, newer: &str) -> StoreResult<bool> {
    let mut cursor = Some(newer.to_owned());
    let mut visited = BTreeSet::new();
    while let Some(id) = cursor {
        if !visited.insert(id.clone()) {
            return Ok(false);
        }
        if id == older {
            return Ok(true);
        }
        cursor = BranchStore::cut_by_id(connection, &id)?.and_then(|cut| cut.parent_cut_id);
    }
    Ok(false)
}

impl FlowingAdmissions for BranchStore {
    fn admit_flowing_prefix(
        &mut self,
        request: &FlowingAdmissionRequest,
    ) -> StoreResult<FlowingAdmissionOutcome> {
        use FlowingAdmissionOutcome::{Admitted, Existing, Refused};
        use FlowingAdmissionRefusal as R;

        if let Err(refusal) = validate_request(request) {
            return Ok(Refused(refusal));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_receipt(&tx, &request.op_id)? {
            return Ok(if existing.request == *request {
                Existing(existing)
            } else {
                Refused(R::IdentityMismatch)
            });
        }
        if let Some(cancelled) = read_cancellation(&tx, "admission_op_id", &request.op_id)? {
            return Ok(Refused(R::AttemptCancelled {
                cancel_op_id: cancelled.request.cancel_op_id,
            }));
        }

        let Some(source) = BranchStore::row_by_id(&tx, &request.source_branch_id)? else {
            return Ok(Refused(R::SourceMissing));
        };
        if source.status != BranchStatus::Active {
            return Ok(Refused(R::SourceNotActive));
        }
        if source.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID) {
            return Ok(Refused(R::SourceNotTrunkChild));
        }
        let Some(fence) = flowing_fence::native::read_state(&tx, &request.source_branch_id)? else {
            return Ok(Refused(R::SourceMissing));
        };
        if fence.kind != FlowingSourceKind::Twig {
            return Ok(Refused(R::SourceNotDirectTwig));
        }
        if let Err(refusal) = check_fence(&fence, request) {
            return Ok(Refused(refusal));
        }
        let Some(selected_cut) = BranchStore::cut_by_id(&tx, &request.source_cut_id)? else {
            return Ok(Refused(R::SourceCutMissing));
        };
        if selected_cut.branch_id != request.source_branch_id
            || selected_cut.manifest_hash != request.source_manifest_hash
        {
            return Ok(Refused(R::SourceCutMismatch));
        }
        let Some(source_head) = source.head_cut_id.as_deref() else {
            return Ok(Refused(R::SourceCutNotRetained));
        };
        if !ancestor(&tx, &request.source_cut_id, source_head)? {
            return Ok(Refused(R::SourceCutNotRetained));
        }

        let Some(trunk) = BranchStore::row_by_id(&tx, MAINLINE_BRANCH_ID)? else {
            return Ok(Refused(R::TrunkMissing));
        };
        if trunk.status != BranchStatus::Active {
            return Ok(Refused(R::TrunkNotActive));
        }
        let reservation: Option<String> = tx
            .query_row(
                "SELECT reservation_id FROM branch_head_reservations WHERE branch_id = ?1",
                [MAINLINE_BRANCH_ID],
                |row| row.get(0),
            )
            .optional()?;
        if reservation
            .as_deref()
            .is_some_and(|holder| holder != MAINLINE_GATE_LEASE)
        {
            return Ok(Refused(R::TrunkReserved));
        }
        if trunk.head_cut_id != request.expected_trunk_cut_id {
            return Ok(Refused(R::TrunkStale {
                current: trunk.head_cut_id,
            }));
        }
        let Some(candidate) = BranchStore::cut_by_id(&tx, &request.candidate_cut_id)? else {
            return Ok(Refused(R::CandidateMissing));
        };
        let same_cut =
            request.expected_trunk_cut_id.as_deref() == Some(request.candidate_cut_id.as_str());
        let has_applied = request
            .units
            .iter()
            .any(|unit| unit.outcome == FlowingUnitOutcome::Applied);
        let expected_origin = format!("transport:{}", request.source_branch_id);
        if candidate.branch_id != MAINLINE_BRANCH_ID
            || candidate.manifest_hash != request.candidate_manifest_hash
            || (!same_cut
                && candidate.parent_cut_id.as_deref() != request.expected_trunk_cut_id.as_deref())
            || (!same_cut
                && (candidate.origin.as_deref() != Some(expected_origin.as_str())
                    || candidate.actor.as_deref() != Some(request.coordinator.as_str())))
            || same_cut == has_applied
        {
            return Ok(Refused(R::CandidateMismatch));
        }

        for unit in &request.units {
            let declaration: Option<(String, String, String, String, String)> = tx
                .query_row(
                    "SELECT pin_id, source_branch_id, source_cut_id, principal, intent \
                     FROM flowing_contributions WHERE unit_id = ?1",
                    [&unit.unit_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .optional()?;
            let Some((pin_id, declared_branch, declared_cut, principal, intent)) = declaration
            else {
                return Ok(Refused(R::UnitMissing {
                    unit_id: unit.unit_id.clone(),
                }));
            };
            let basis: Option<String> = tx
                .query_row(
                    "SELECT basis_digest FROM flowing_contribution_basis WHERE unit_id = ?1",
                    [&unit.unit_id],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(basis) = basis else {
                return Ok(Refused(R::UnitBasisMissing {
                    unit_id: unit.unit_id.clone(),
                }));
            };
            if basis != unit.basis_digest || principal != unit.principal || intent != unit.intent {
                return Ok(Refused(R::UnitBasisMismatch {
                    unit_id: unit.unit_id.clone(),
                }));
            }
            let handoff: Option<(String, String)> = tx
                .query_row(
                    "SELECT target_branch_id, target_after_cut_id \
                     FROM flowing_handoffs WHERE unit_id = ?1",
                    [&unit.unit_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            if handoff.is_some() {
                return Ok(Refused(R::UnverifiedLineage {
                    unit_id: unit.unit_id.clone(),
                }));
            }
            let (holder, holder_cut) = handoff.as_ref().map_or(
                (declared_branch.as_str(), declared_cut.as_str()),
                |(branch, cut)| (branch.as_str(), cut.as_str()),
            );
            if handoff.is_none() {
                let pin: Option<Option<String>> = tx
                    .query_row(
                        "SELECT released_at FROM flowing_private_pins WHERE pin_id = ?1",
                        [&pin_id],
                        |row| row.get(0),
                    )
                    .optional()?;
                match pin {
                    None => {
                        return Ok(Refused(R::UnitPinMissing {
                            unit_id: unit.unit_id.clone(),
                        }));
                    }
                    Some(Some(_)) => {
                        return Ok(Refused(R::UnitPinReleased {
                            unit_id: unit.unit_id.clone(),
                        }));
                    }
                    Some(None) => {}
                }
            }
            if holder != request.source_branch_id
                || !ancestor(&tx, holder_cut, &request.source_cut_id)?
            {
                return Ok(Refused(R::UnitNotHeldBySource {
                    unit_id: unit.unit_id.clone(),
                }));
            }
            let already: Option<String> = tx
                .query_row(
                    "SELECT op_id FROM flowing_admitted_units WHERE unit_id = ?1",
                    [&unit.unit_id],
                    |row| row.get(0),
                )
                .optional()?;
            if already.is_some() {
                return Ok(Refused(R::UnitAlreadyAdmitted {
                    unit_id: unit.unit_id.clone(),
                }));
            }
        }

        let receipt = FlowingAdmissionReceipt {
            request: request.clone(),
        };
        tx.execute(
            "INSERT INTO flowing_admissions (op_id, receipt_json) VALUES (?1, ?2)",
            params![&request.op_id, serde_json::to_string(&receipt)?],
        )?;
        for unit in &request.units {
            tx.execute(
                "INSERT INTO flowing_admitted_units (unit_id, op_id) VALUES (?1, ?2)",
                params![&unit.unit_id, &request.op_id],
            )?;
        }
        if !same_cut {
            tx.execute(
                "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, \
                 updated_at = ?4 WHERE branch_id = ?1",
                params![
                    MAINLINE_BRANCH_ID,
                    &request.candidate_cut_id,
                    &request.candidate_manifest_hash,
                    &request.recorded_at,
                ],
            )?;
        }
        tx.commit()?;
        Ok(Admitted(receipt))
    }

    fn flowing_admission_receipt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingAdmissionReceipt>> {
        read_receipt(&self.connection, op_id)
    }

    fn cancel_flowing_attempt(
        &mut self,
        request: &FlowingCancelRequest,
    ) -> StoreResult<FlowingCancelOutcome> {
        use FlowingCancelOutcome::{
            AlreadyAdmitted, AlreadyCancelled, Cancelled, Existing, Refused,
        };
        use FlowingCancelRefusal as R;

        if let Err(refusal) = validate_cancel_request(request) {
            return Ok(Refused(refusal));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_cancellation(&tx, "cancel_op_id", &request.cancel_op_id)? {
            return Ok(if existing.request == *request {
                Existing(existing)
            } else {
                Refused(R::IdentityMismatch)
            });
        }
        if let Some(existing) = read_cancellation(&tx, "admission_op_id", &request.admission_op_id)?
        {
            return Ok(
                if existing.request.source_branch_id == request.source_branch_id
                    && existing.request.source_incarnation_id == request.source_incarnation_id
                {
                    AlreadyCancelled(existing)
                } else {
                    Refused(R::IdentityMismatch)
                },
            );
        }
        if let Some(admitted) = read_receipt(&tx, &request.admission_op_id)? {
            return Ok(
                if admitted.request.source_branch_id == request.source_branch_id
                    && admitted.request.source_incarnation_id == request.source_incarnation_id
                {
                    AlreadyAdmitted(admitted)
                } else {
                    Refused(R::IdentityMismatch)
                },
            );
        }
        let Some(state) = flowing_fence::native::read_state(&tx, &request.source_branch_id)? else {
            return Ok(Refused(R::SourceMissing));
        };
        if state.incarnation_id != request.source_incarnation_id {
            return Ok(Refused(R::WrongIncarnation));
        }
        if state.owner_epoch != request.expected_owner_epoch {
            return Ok(Refused(R::StaleOwnerEpoch {
                current: state.owner_epoch,
            }));
        }
        if state.owner != request.coordinator {
            return Ok(Refused(R::WrongOwner));
        }
        tx.execute(
            "INSERT INTO flowing_admission_cancellations \
             (admission_op_id, cancel_op_id, request_json) VALUES (?1, ?2, ?3)",
            params![
                &request.admission_op_id,
                &request.cancel_op_id,
                serde_json::to_string(request)?,
            ],
        )?;
        tx.commit()?;
        Ok(Cancelled(FlowingCancelReceipt {
            request: request.clone(),
        }))
    }

    fn flowing_cancellation_for_attempt(
        &self,
        admission_op_id: &str,
    ) -> StoreResult<Option<FlowingCancelReceipt>> {
        read_cancellation(&self.connection, "admission_op_id", admission_op_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
    };
    use crate::branches::{Branches, CreateBranch, CutRecord};

    fn fixture() -> BranchStore {
        let mut store = BranchStore::open_in_memory().unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "twig",
                name: None,
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t1".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        store
            .record_cut(CutRecord {
                cut_id: "source",
                change_id: "change",
                branch_id: "twig",
                manifest_hash: "source-manifest",
                parent_cut_id: None,
                origin: None,
                actor: Some("author"),
                intent: Some("change"),
                recorded_at: "t2",
            })
            .unwrap();
        store
            .advance_head("twig", None, "source", "source-manifest", "t2")
            .unwrap();
        store
            .record_cut(CutRecord {
                cut_id: "candidate",
                change_id: "integrated",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: "candidate-manifest",
                parent_cut_id: None,
                origin: Some("transport:twig"),
                actor: Some("coordinator"),
                intent: Some("change"),
                recorded_at: "t3",
            })
            .unwrap();
        store
            .connection
            .execute_batch(
                "INSERT INTO flowing_private_pins \
             (pin_id, twig_branch_id, cut_id, manifest_hash, principal, retained_at) \
             VALUES ('pin', 'twig', 'source', 'source-manifest', 'author', 't2');
             INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, \
              scope_digest, declared_at) \
             VALUES ('unit-a', 'pin', 'twig', 'source', 'source-manifest', \
                     'author', 'change', 'reads', 'deps', 'scope', 't2'),
                    ('unit-b', 'pin', 'twig', 'source', 'source-manifest', \
                     'author', 'change', 'reads', 'deps', 'scope', 't2');
             INSERT INTO flowing_contribution_basis (unit_id, basis_digest, atoms_json, bound_at) \
             VALUES ('unit-a', 'basis-a', '[]', 't2'),
                    ('unit-b', 'basis-b', '[]', 't2');",
            )
            .unwrap();
        store
    }

    fn request(unit_id: &str, op_id: &str) -> FlowingAdmissionRequest {
        FlowingAdmissionRequest {
            op_id: op_id.into(),
            certificate_handle: "certificate-a".into(),
            source_branch_id: "twig".into(),
            source_incarnation_id: "inc".into(),
            source_cut_id: "source".into(),
            source_manifest_hash: "source-manifest".into(),
            expected_eligibility_epoch: 0,
            expected_owner_epoch: 0,
            coordinator: "coordinator".into(),
            expected_trunk_cut_id: None,
            candidate_cut_id: "candidate".into(),
            candidate_manifest_hash: "candidate-manifest".into(),
            units: vec![super::super::FlowingSelectedUnit {
                unit_id: unit_id.into(),
                basis_digest: format!("basis-{}", unit_id.strip_prefix("unit-").unwrap()),
                principal: "author".into(),
                intent: "change".into(),
                outcome: FlowingUnitOutcome::Applied,
            }],
            recorded_at: "t4".into(),
        }
    }

    fn cancel(admission_op_id: &str, cancel_op_id: &str) -> FlowingCancelRequest {
        FlowingCancelRequest {
            cancel_op_id: cancel_op_id.into(),
            admission_op_id: admission_op_id.into(),
            source_branch_id: "twig".into(),
            source_incarnation_id: "inc".into(),
            expected_owner_epoch: 0,
            coordinator: "coordinator".into(),
            recorded_at: "t4".into(),
        }
    }

    #[test]
    fn cancellation_wins_before_cas_without_disposing_the_unit() {
        let mut store = fixture();
        let cancellation = cancel("admission-a", "cancel-a");
        let receipt = FlowingCancelReceipt {
            request: cancellation.clone(),
        };
        assert_eq!(
            store.cancel_flowing_attempt(&cancellation).unwrap(),
            FlowingCancelOutcome::Cancelled(receipt.clone())
        );
        assert_eq!(
            store
                .flowing_cancellation_for_attempt("admission-a")
                .unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            store.cancel_flowing_attempt(&cancellation).unwrap(),
            FlowingCancelOutcome::Existing(receipt.clone())
        );
        assert_eq!(
            store
                .cancel_flowing_attempt(&cancel("admission-a", "cancel-b"))
                .unwrap(),
            FlowingCancelOutcome::AlreadyCancelled(receipt)
        );
        let mut reused_cancel_id = cancellation.clone();
        reused_cancel_id.admission_op_id = "admission-b".into();
        assert_eq!(
            store.cancel_flowing_attempt(&reused_cancel_id).unwrap(),
            FlowingCancelOutcome::Refused(FlowingCancelRefusal::IdentityMismatch)
        );
        assert_eq!(
            store
                .admit_flowing_prefix(&request("unit-a", "admission-a"))
                .unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::AttemptCancelled {
                cancel_op_id: "cancel-a".into()
            })
        );
        assert!(store
            .flowing_admission_receipt("admission-a")
            .unwrap()
            .is_none());
        assert!(store
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
        assert!(matches!(
            store
                .admit_flowing_prefix(&request("unit-a", "admission-b"))
                .unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
    }

    #[test]
    fn cancellation_after_cas_reports_the_landed_receipt() {
        let mut store = fixture();
        let admission = request("unit-a", "admission-a");
        let admitted = store.admit_flowing_prefix(&admission).unwrap();
        let FlowingAdmissionOutcome::Admitted(receipt) = admitted else {
            panic!("admission should land")
        };
        assert_eq!(
            store
                .cancel_flowing_attempt(&cancel("admission-a", "cancel-a"))
                .unwrap(),
            FlowingCancelOutcome::AlreadyAdmitted(receipt)
        );
        assert!(store
            .flowing_cancellation_for_attempt("admission-a")
            .unwrap()
            .is_none());
    }

    #[test]
    fn cancellation_owner_fence_and_failed_write_leave_admission_order_intact() {
        let mut store = fixture();
        let mut cancellation = cancel("admission-a", "cancel-a");
        cancellation.expected_owner_epoch = 1;
        assert_eq!(
            store.cancel_flowing_attempt(&cancellation).unwrap(),
            FlowingCancelOutcome::Refused(FlowingCancelRefusal::StaleOwnerEpoch { current: 0 })
        );
        cancellation.expected_owner_epoch = 0;
        cancellation.coordinator = "other".into();
        assert_eq!(
            store.cancel_flowing_attempt(&cancellation).unwrap(),
            FlowingCancelOutcome::Refused(FlowingCancelRefusal::WrongOwner)
        );
        cancellation.coordinator = "coordinator".into();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER reject_cancel BEFORE INSERT ON flowing_admission_cancellations \
                 BEGIN SELECT RAISE(ABORT, 'injected cancellation failure'); END;",
            )
            .unwrap();
        assert!(store.cancel_flowing_attempt(&cancellation).is_err());
        assert!(store
            .flowing_cancellation_for_attempt("admission-a")
            .unwrap()
            .is_none());
        store
            .connection
            .execute_batch("DROP TRIGGER reject_cancel")
            .unwrap();
        assert!(matches!(
            store
                .admit_flowing_prefix(&request("unit-a", "admission-a"))
                .unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
    }

    #[test]
    fn corrupt_operation_receipts_are_indeterminate() {
        let mut store = fixture();
        let cancellation = cancel("admission-a", "cancel-a");
        store.cancel_flowing_attempt(&cancellation).unwrap();
        let mut altered = cancellation.clone();
        altered.admission_op_id = "another-attempt".into();
        store
            .connection
            .execute(
                "UPDATE flowing_admission_cancellations SET request_json = ?1 \
                 WHERE admission_op_id = 'admission-a'",
                [serde_json::to_string(&altered).unwrap()],
            )
            .unwrap();
        assert!(matches!(
            store.flowing_cancellation_for_attempt("admission-a"),
            Err(StoreError::Conflict(message)) if message.contains("operation keys")
        ));
        assert!(store
            .admit_flowing_prefix(&request("unit-a", "admission-a"))
            .is_err());

        let mut admitted_store = fixture();
        admitted_store
            .admit_flowing_prefix(&request("unit-a", "admission-b"))
            .unwrap();
        let mut altered_receipt = request("unit-a", "another-admission");
        altered_receipt.op_id = "another-admission".into();
        admitted_store
            .connection
            .execute(
                "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admission-b'",
                [serde_json::to_string(&FlowingAdmissionReceipt {
                    request: altered_receipt,
                })
                .unwrap()],
            )
            .unwrap();
        assert!(matches!(
            admitted_store.flowing_admission_receipt("admission-b"),
            Err(StoreError::Conflict(message)) if message.contains("operation key")
        ));
    }

    #[test]
    fn trunk_cas_and_unit_accounting_share_one_ref_entry() {
        let mut store = fixture();
        let first = request("unit-a", "admission-a");
        let FlowingAdmissionOutcome::Admitted(receipt) =
            store.admit_flowing_prefix(&first).unwrap()
        else {
            panic!("first prefix should admit")
        };
        assert_eq!(receipt.request, first);
        assert_eq!(
            store
                .get_branch(MAINLINE_BRANCH_ID)
                .unwrap()
                .unwrap()
                .head_cut_id,
            Some("candidate".into())
        );
        assert_eq!(
            store.flowing_admission_receipt("admission-a").unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            store.admit_flowing_prefix(&first).unwrap(),
            FlowingAdmissionOutcome::Existing(receipt)
        );
        let mut changed = first.clone();
        changed.certificate_handle = "another-certificate".into();
        assert_eq!(
            store.admit_flowing_prefix(&changed).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::IdentityMismatch)
        );
        let mut competing = request("unit-a", "admission-b");
        competing.expected_trunk_cut_id = Some("candidate".into());
        competing.candidate_cut_id = "candidate".into();
        competing.units[0].outcome = FlowingUnitOutcome::Equivalent;
        assert!(matches!(
            store.admit_flowing_prefix(&competing).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::UnitAlreadyAdmitted { .. })
        ));
        let mut no_op = request("unit-b", "admission-c");
        no_op.expected_trunk_cut_id = Some("candidate".into());
        no_op.candidate_cut_id = "candidate".into();
        no_op.units[0].outcome = FlowingUnitOutcome::Equivalent;
        store
            .record_cut(CutRecord {
                cut_id: "spurious-cut",
                change_id: "spurious",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: "spurious-manifest",
                parent_cut_id: Some("candidate"),
                origin: Some("transport:twig"),
                actor: Some("coordinator"),
                intent: Some("change"),
                recorded_at: "t5",
            })
            .unwrap();
        let mut spurious = no_op.clone();
        spurious.candidate_cut_id = "spurious-cut".into();
        spurious.candidate_manifest_hash = "spurious-manifest".into();
        assert_eq!(
            store.admit_flowing_prefix(&spurious).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CandidateMismatch)
        );
        assert!(matches!(
            store.admit_flowing_prefix(&no_op).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        assert_eq!(
            store
                .get_branch(MAINLINE_BRANCH_ID)
                .unwrap()
                .unwrap()
                .head_cut_id,
            Some("candidate".into()),
            "metadata-only accounting keeps the same trunk cut"
        );
    }

    #[test]
    fn hold_and_failed_receipt_write_never_acknowledge_an_admission() {
        let mut store = fixture();
        let hold = FlowingFenceTransition {
            op_id: "hold".into(),
            source_branch_id: "twig".into(),
            incarnation_id: "inc".into(),
            expected_eligibility_epoch: 0,
            expected_owner_epoch: 0,
            actor: "coordinator".into(),
            action: FlowingFenceAction::Hold,
            recorded_at: "t3".into(),
        };
        assert!(matches!(
            store.transition_flowing_source(&hold).unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        let mut request = request("unit-a", "admission-a");
        request.expected_eligibility_epoch = 1;
        assert_eq!(
            store.admit_flowing_prefix(&request).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::Held)
        );
        let release = FlowingFenceTransition {
            op_id: "release".into(),
            expected_eligibility_epoch: 1,
            action: FlowingFenceAction::ReleaseHold,
            ..hold
        };
        store.transition_flowing_source(&release).unwrap();
        request.expected_eligibility_epoch = 2;
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER reject_admitted_unit BEFORE INSERT ON flowing_admitted_units \
             BEGIN SELECT RAISE(ABORT, 'injected refusal'); END;",
            )
            .unwrap();
        assert!(store.admit_flowing_prefix(&request).is_err());
        assert!(store
            .flowing_admission_receipt("admission-a")
            .unwrap()
            .is_none());
        assert!(store
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
        store
            .connection
            .execute_batch("DROP TRIGGER reject_admitted_unit")
            .unwrap();
        assert!(matches!(
            store.admit_flowing_prefix(&request).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
    }

    #[test]
    fn handed_units_and_named_branches_wait_for_transitive_lineage_fencing() {
        let mut store = fixture();
        store
            .connection
            .execute_batch(
                "INSERT INTO flowing_handoffs \
             (op_id, unit_id, source_branch_id, source_cut_id, source_manifest_hash, \
              source_basis_digest, target_branch_id, target_after_cut_id, \
              target_after_manifest_hash, effects_json, original_principal, actor, recorded_at) \
             VALUES ('handoff', 'unit-a', 'twig', 'source', 'source-manifest', \
                     'basis-a', 'branch', 'branch-cut', 'branch-manifest', '[]', \
                     'author', 'coordinator', 't3')",
            )
            .unwrap();
        assert!(matches!(
            store
                .admit_flowing_prefix(&request("unit-a", "admission-a"))
                .unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::UnverifiedLineage { .. })
        ));
        store
            .create_branch(CreateBranch {
                branch_id: "branch",
                name: Some("feature"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t3",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "branch-inc".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator".into(),
                opened_at: "t3".into(),
            })
            .unwrap();
        let mut branch_request = request("unit-b", "admission-b");
        branch_request.source_branch_id = "branch".into();
        branch_request.source_incarnation_id = "branch-inc".into();
        assert_eq!(
            store.admit_flowing_prefix(&branch_request).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::SourceNotDirectTwig)
        );
        assert!(store
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
    }
}
