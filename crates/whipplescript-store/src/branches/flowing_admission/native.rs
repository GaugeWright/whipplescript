use std::collections::BTreeSet;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    check_fence, validate_cancel_request, validate_request, FlowingAdmissionOutcome,
    FlowingAdmissionReceipt, FlowingAdmissionRefusal, FlowingAdmissionRequest, FlowingAdmissions,
    FlowingCancelOutcome, FlowingCancelReceipt, FlowingCancelRefusal, FlowingCancelRequest,
    FlowingCandidateWitness, FlowingGateCertificate, FlowingUnitOutcome,
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

fn read_witness(
    connection: &Connection,
    digest: &str,
) -> StoreResult<Option<FlowingCandidateWitness>> {
    let json: Option<String> = connection
        .query_row(
            "SELECT witness_json FROM flowing_candidate_witnesses WHERE digest = ?1",
            [digest],
            |row| row.get(0),
        )
        .optional()?;
    json.map(|json| {
        let witness: FlowingCandidateWitness = serde_json::from_str(&json)?;
        if witness.digest()? != digest {
            return Err(StoreError::Conflict(
                "flowing candidate witness differs from its digest key".into(),
            ));
        }
        Ok(witness)
    })
    .transpose()
}

fn read_gate_certificate(
    connection: &Connection,
    handle: &str,
) -> StoreResult<Option<FlowingGateCertificate>> {
    let json: Option<String> = connection
        .query_row(
            "SELECT certificate_json FROM flowing_gate_certificates WHERE handle = ?1",
            [handle],
            |row| row.get(0),
        )
        .optional()?;
    json.map(|json| {
        let certificate: FlowingGateCertificate = serde_json::from_str(&json)?;
        if certificate.handle()? != handle {
            return Err(StoreError::Conflict(
                "flowing gate certificate differs from its handle".into(),
            ));
        }
        Ok(certificate)
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
    fn admitted_unit_operation(&self, unit_id: &str) -> StoreResult<Option<String>> {
        self.connection
            .query_row(
                "SELECT op_id FROM flowing_admitted_units WHERE unit_id = ?1",
                [unit_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn record_candidate_witness(
        &mut self,
        witness: &FlowingCandidateWitness,
    ) -> StoreResult<String> {
        let digest = witness.digest()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO flowing_candidate_witnesses (digest, witness_json) VALUES (?1, ?2)",
            params![&digest, serde_json::to_string(witness)?],
        )?;
        let _ = read_witness(&tx, &digest)?;
        tx.commit()?;
        Ok(digest)
    }

    fn candidate_witness(&self, digest: &str) -> StoreResult<Option<FlowingCandidateWitness>> {
        read_witness(&self.connection, digest)
    }

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

        let Some(witness) = read_witness(&tx, &request.candidate_witness_digest)? else {
            return Ok(Refused(R::CandidateWitnessMissing));
        };
        if !witness.matches_request(request) {
            return Ok(Refused(R::CandidateWitnessMismatch));
        }
        let Some(certificate) = read_gate_certificate(&tx, &request.certificate_handle)? else {
            return Ok(Refused(R::GateCertificateMissing));
        };
        if !certificate.matches_request(request) {
            return Ok(Refused(R::GateCertificateMismatch));
        }
        if let Some(refusal) = certificate.admission_refusal() {
            return Ok(Refused(refusal));
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
                    AlreadyAdmitted(Box::new(admitted))
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
    use crate::branches::flowing_admission::{FlowingGateCheck, FlowingGateVerdict};
    use crate::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
    };
    use crate::branches::{Branches, CreateBranch, CutRecord};
    use crate::source_review::{ReviewError, ReviewStore, SourceKind};
    use crate::source_review_native::{NativeRevision, NativeUpload};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_REVIEW_FILE: AtomicU64 = AtomicU64::new(0);

    fn native_request<'a>(
        upload_id: &'a str,
        source_cut_id: &'a str,
        unit_ids: &'a [&'a str],
    ) -> NativeUpload<'a> {
        NativeUpload {
            contribution_id: "review-a",
            upload_id,
            actor: "author",
            source_branch_id: "twig",
            source_cut_id,
            unit_ids,
        }
    }

    fn upload(
        reviews: &mut ReviewStore,
        source: &BranchStore,
        upload_id: &str,
        source_cut_id: &str,
        unit_ids: &[&str],
    ) -> Result<NativeRevision, ReviewError> {
        reviews.upload_native_revision(source, native_request(upload_id, source_cut_id, unit_ids))
    }

    fn expect_invalid(result: Result<NativeRevision, ReviewError>, expected: &str) {
        match result {
            Err(ReviewError::Invalid(message)) => assert_eq!(message, expected),
            other => panic!("expected invalid native review: {expected}; found {other:?}"),
        }
    }

    fn expect_missing(result: Result<NativeRevision, ReviewError>, expected: &str) {
        match result {
            Err(ReviewError::Missing(message)) => assert_eq!(message, expected),
            other => panic!("expected missing native source: {expected}; found {other:?}"),
        }
    }

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
        for unit_id in ["unit-a", "unit-b"] {
            let attempt = request(unit_id, "fixture");
            store
                .record_candidate_witness(&witness_for(&attempt))
                .unwrap();
            record_gate_certificate(&store, &attempt);
        }
        store
    }

    fn certificate_for(request: &FlowingAdmissionRequest) -> FlowingGateCertificate {
        FlowingGateCertificate {
            candidate_witness_digest: request.candidate_witness_digest.clone(),
            expected_trunk_cut_id: request.expected_trunk_cut_id.clone(),
            candidate_cut_id: request.candidate_cut_id.clone(),
            candidate_manifest_hash: request.candidate_manifest_hash.clone(),
            source_eligibility_epoch: request.expected_eligibility_epoch,
            source_owner_epoch: request.expected_owner_epoch,
            coordinator: request.coordinator.clone(),
            policy_digest: "sha256:fixture-policy".into(),
            rules_digest: "sha256:fixture-rules".into(),
            graph_coverage_digest: "sha256:fixture-coverage".into(),
            required_checks: vec!["full-workspace-bar".into()],
            checks: vec![FlowingGateCheck {
                check_id: "full-workspace-bar".into(),
                input_digest: "sha256:fixture-input".into(),
                evidence_digest: "sha256:fixture-evidence".into(),
                verdict: FlowingGateVerdict::Passed,
            }],
        }
    }

    fn record_gate_certificate(store: &BranchStore, request: &FlowingAdmissionRequest) {
        insert_gate_certificate(store, &certificate_for(request));
    }

    fn insert_gate_certificate(store: &BranchStore, certificate: &FlowingGateCertificate) {
        store
            .connection
            .execute(
                "INSERT OR IGNORE INTO flowing_gate_certificates (handle, certificate_json) VALUES (?1, ?2)",
                params![
                    certificate.handle().unwrap(),
                    serde_json::to_string(certificate).unwrap()
                ],
            )
            .unwrap();
    }

    fn witness_for(request: &FlowingAdmissionRequest) -> FlowingCandidateWitness {
        FlowingCandidateWitness {
            contribution_id: request.contribution_id.clone(),
            revision_sequence: request.revision_sequence,
            source_branch_id: request.source_branch_id.clone(),
            source_incarnation_id: request.source_incarnation_id.clone(),
            source_cut_id: request.source_cut_id.clone(),
            source_manifest_hash: request.source_manifest_hash.clone(),
            expected_trunk_cut_id: request.expected_trunk_cut_id.clone(),
            candidate_cut_id: request.candidate_cut_id.clone(),
            candidate_manifest_hash: request.candidate_manifest_hash.clone(),
            source_atoms_digest: "sha256:fixture-source-atoms".into(),
            units: request.units.clone(),
        }
    }

    fn request(unit_id: &str, op_id: &str) -> FlowingAdmissionRequest {
        let mut request = FlowingAdmissionRequest {
            op_id: op_id.into(),
            certificate_handle: String::new(),
            candidate_witness_digest: String::new(),
            contribution_id: "review-a".into(),
            revision_sequence: 1,
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
        };
        request.candidate_witness_digest = witness_for(&request).digest().unwrap();
        request.certificate_handle = certificate_for(&request).handle().unwrap();
        request
    }

    #[test]
    fn native_ref_requires_the_recorded_complete_candidate_witness() {
        let mut store = fixture();
        let mut attempt = request("unit-a", "admission-witness");
        attempt.candidate_witness_digest = "sha256:missing".into();
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CandidateWitnessMissing)
        );

        let mut complete = request("unit-a", "complete");
        complete
            .units
            .push(request("unit-b", "second").units[0].clone());
        let complete_digest = store
            .record_candidate_witness(&witness_for(&complete))
            .unwrap();
        attempt.candidate_witness_digest = complete_digest;
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CandidateWitnessMismatch),
            "an omitted unit cannot use the complete prefix's witness"
        );
        attempt = request("unit-a", "admission-witness");
        attempt.revision_sequence += 1;
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CandidateWitnessMismatch)
        );
        assert!(store
            .flowing_admission_receipt("admission-witness")
            .unwrap()
            .is_none());
        assert!(store
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
    }

    #[test]
    fn native_ref_requires_a_matching_passing_gate_certificate() {
        let mut store = fixture();
        let mut attempt = request("unit-a", "admission-gate");
        attempt.certificate_handle = "sha256:missing".into();
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::GateCertificateMissing)
        );

        let mut foreign = certificate_for(&attempt);
        foreign.candidate_witness_digest = "sha256:other-candidate".into();
        insert_gate_certificate(&store, &foreign);
        attempt.certificate_handle = foreign.handle().unwrap();
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::GateCertificateMismatch)
        );

        for (verdict, refusal) in [
            (
                FlowingGateVerdict::Failed,
                FlowingAdmissionRefusal::GateFailed,
            ),
            (
                FlowingGateVerdict::Unrun,
                FlowingAdmissionRefusal::GateUnrun,
            ),
        ] {
            let mut certificate = certificate_for(&attempt);
            certificate.checks[0].verdict = verdict;
            insert_gate_certificate(&store, &certificate);
            attempt.certificate_handle = certificate.handle().unwrap();
            assert_eq!(
                store.admit_flowing_prefix(&attempt).unwrap(),
                FlowingAdmissionOutcome::Refused(refusal)
            );
        }
        let mut incomplete = certificate_for(&attempt);
        incomplete.checks.clear();
        insert_gate_certificate(&store, &incomplete);
        attempt.certificate_handle = incomplete.handle().unwrap();
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::GatePlanIncomplete)
        );
        assert!(store
            .flowing_admission_receipt(&attempt.op_id)
            .unwrap()
            .is_none());
        assert!(store
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
    }

    #[test]
    fn native_ref_treats_changed_gate_certificate_as_indeterminate() {
        let mut store = fixture();
        let attempt = request("unit-a", "admission-gate");
        let mut changed = certificate_for(&attempt);
        changed.rules_digest = "sha256:different-rules".into();
        store
            .connection
            .execute(
                "UPDATE flowing_gate_certificates SET certificate_json = ?1 WHERE handle = ?2",
                params![
                    serde_json::to_string(&changed).unwrap(),
                    &attempt.certificate_handle
                ],
            )
            .unwrap();
        assert!(matches!(
            store.admit_flowing_prefix(&attempt),
            Err(StoreError::Conflict(message)) if message.contains("certificate differs")
        ));
        assert!(store
            .flowing_admission_receipt(&attempt.op_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn native_ref_treats_a_changed_stored_witness_as_indeterminate() {
        let mut store = fixture();
        let attempt = request("unit-a", "admission-witness");
        let mut changed = witness_for(&attempt);
        changed.revision_sequence += 1;
        store
            .connection
            .execute(
                "UPDATE flowing_candidate_witnesses SET witness_json = ?1 WHERE digest = ?2",
                params![
                    serde_json::to_string(&changed).unwrap(),
                    &attempt.candidate_witness_digest
                ],
            )
            .unwrap();
        assert!(matches!(
            store.admit_flowing_prefix(&attempt),
            Err(StoreError::Conflict(message)) if message.contains("digest key")
        ));
        assert!(store
            .flowing_admission_receipt(&attempt.op_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn native_review_revision_keeps_the_selected_cut_after_a_source_tail() {
        let mut source = fixture();
        let root = std::env::temp_dir().join(format!(
            "whipplescript-native-review-{}-{}",
            std::process::id(),
            NEXT_REVIEW_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let review_path = root.join("review.sqlite");
        let mut reviews = ReviewStore::open(&review_path).unwrap();
        let contribution = reviews
            .create_native_contribution("review-a", "author", "change", MAINLINE_BRANCH_ID, &[])
            .unwrap();
        assert_eq!(contribution.source_kind, SourceKind::Native);
        assert_eq!(contribution.target_scope, MAINLINE_BRANCH_ID);
        let first = upload(&mut reviews, &source, "upload-a", "source", &["unit-a"]).unwrap();
        assert_eq!(first.source_incarnation_id, "inc");
        assert_eq!(first.source_cut_id, "source");
        assert_eq!(first.units[0].basis_digest, "basis-a");
        assert_eq!(first.units[0].principal, "author");
        assert_eq!(first.units[0].intent, "change");
        drop(reviews);
        let mut reviews = ReviewStore::open(&review_path).unwrap();

        source
            .record_cut(CutRecord {
                cut_id: "tail",
                change_id: "later-change",
                branch_id: "twig",
                manifest_hash: "tail-manifest",
                parent_cut_id: Some("source"),
                origin: Some("write:later"),
                actor: Some("author"),
                intent: Some("later"),
                recorded_at: "t4",
            })
            .unwrap();
        source
            .advance_head("twig", Some("source"), "tail", "tail-manifest", "t4")
            .unwrap();
        assert_eq!(reviews.native_revision("review-a", 1).unwrap(), first);
        assert_eq!(
            upload(&mut reviews, &source, "upload-a", "source", &["unit-a"]).unwrap(),
            first
        );
        assert!(matches!(
            upload(&mut reviews, &source, "upload-a", "tail", &["unit-a"]),
            Err(ReviewError::Conflict(_))
        ));
        assert!(matches!(
            upload(&mut reviews, &source, "upload-tail", "tail", &["unit-a"]),
            Err(ReviewError::Invalid(_))
        ));
        drop(reviews);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_review_refuses_unbound_duplicate_and_lost_source_units() {
        let source = fixture();
        let mut reviews = ReviewStore::open(":memory:").unwrap();
        reviews
            .create_native_contribution("review-a", "author", "change", MAINLINE_BRANCH_ID, &[])
            .unwrap();
        assert!(matches!(
            upload(
                &mut reviews,
                &source,
                "duplicate",
                "source",
                &["unit-a", "unit-a"]
            ),
            Err(ReviewError::Invalid(_))
        ));
        assert!(matches!(
            upload(&mut reviews, &source, "missing", "source", &["unknown"]),
            Err(ReviewError::Missing(_))
        ));
        source
            .connection
            .execute(
                "UPDATE flowing_private_pins SET released_at='t5' WHERE pin_id='pin'",
                [],
            )
            .unwrap();
        assert!(matches!(
            upload(&mut reviews, &source, "released", "source", &["unit-a"]),
            Err(ReviewError::Invalid(_))
        ));
    }

    #[test]
    fn native_review_refuses_invalid_upload_identity_and_kind() {
        let source = fixture();
        let mut reviews = ReviewStore::open(":memory:").unwrap();
        reviews
            .create_native_contribution("review-a", "author", "change", MAINLINE_BRANCH_ID, &[])
            .unwrap();
        expect_invalid(
            upload(&mut reviews, &source, "", "source", &["unit-a"]),
            "invalid upload id",
        );
        let mut request = native_request("empty-actor", "source", &["unit-a"]);
        request.actor = "";
        expect_invalid(
            reviews.upload_native_revision(&source, request),
            "actor and selected units are required",
        );
        expect_invalid(
            upload(&mut reviews, &source, "empty-units", "source", &[]),
            "actor and selected units are required",
        );
        request = native_request("wrong-author", "source", &["unit-a"]);
        request.actor = "intruder";
        expect_invalid(
            reviews.upload_native_revision(&source, request),
            "only the author may upload",
        );
        reviews
            .create_contribution("git-review", "author", "change", "refs/heads/main", &[])
            .unwrap();
        request = native_request("wrong-kind", "source", &["unit-a"]);
        request.contribution_id = "git-review";
        expect_invalid(
            reviews.upload_native_revision(&source, request),
            "native revision needs a native contribution",
        );
    }

    #[test]
    fn native_review_refuses_missing_or_ineligible_source_line() {
        let source = fixture();
        let mut reviews = ReviewStore::open(":memory:").unwrap();
        reviews
            .create_native_contribution("review-a", "author", "change", MAINLINE_BRANCH_ID, &[])
            .unwrap();
        let mut request = native_request("missing-source", "source", &["unit-a"]);
        request.source_branch_id = "missing";
        expect_missing(
            reviews.upload_native_revision(&source, request),
            "source branch missing",
        );
        reviews
            .create_native_contribution("missing-target", "author", "change", "missing", &[])
            .unwrap();
        request = native_request("missing-target", "source", &["unit-a"]);
        request.contribution_id = "missing-target";
        expect_missing(
            reviews.upload_native_revision(&source, request),
            "target branch missing",
        );

        let inactive = fixture();
        inactive
            .connection
            .execute(
                "UPDATE branches SET status='discarded' WHERE branch_id='twig'",
                [],
            )
            .unwrap();
        expect_invalid(
            upload(&mut reviews, &inactive, "inactive", "source", &["unit-a"]),
            "source must be an active child of the target",
        );
        let unfenced = fixture();
        unfenced
            .connection
            .execute(
                "DELETE FROM flowing_source_fences WHERE source_branch_id='twig'",
                [],
            )
            .unwrap();
        expect_missing(
            upload(&mut reviews, &unfenced, "unfenced", "source", &["unit-a"]),
            "flowing source twig",
        );
        let disabled = fixture();
        let mut state = disabled.flowing_source("twig").unwrap().unwrap();
        state.admission_enabled = false;
        disabled
            .connection
            .execute(
                "UPDATE flowing_source_fences SET state_json=?1 WHERE source_branch_id='twig'",
                [serde_json::to_string(&state).unwrap()],
            )
            .unwrap();
        expect_invalid(
            upload(&mut reviews, &disabled, "disabled", "source", &["unit-a"]),
            "source needs an eligible settled twig",
        );
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
            FlowingCancelOutcome::AlreadyAdmitted(Box::new(receipt))
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
        no_op.candidate_witness_digest = store
            .record_candidate_witness(&witness_for(&no_op))
            .unwrap();
        no_op.certificate_handle = certificate_for(&no_op).handle().unwrap();
        assert_eq!(
            store.admit_flowing_prefix(&no_op).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::GateCertificateMissing),
            "metadata-only admission still needs the exact gate"
        );
        record_gate_certificate(&store, &no_op);
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
        request.certificate_handle = certificate_for(&request).handle().unwrap();
        record_gate_certificate(&store, &request);
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
