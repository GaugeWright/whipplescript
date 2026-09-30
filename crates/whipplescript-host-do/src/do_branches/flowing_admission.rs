use std::collections::BTreeSet;

use super::flowing_fence;
use super::flowing_sources::exact_atomic;
use super::DoBranches;
use crate::do_store::{as_text, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_admission::{
    check_fence, validate_cancel_request, validate_request, FlowingAdmissionOutcome,
    FlowingAdmissionReceipt, FlowingAdmissionRefusal, FlowingAdmissionRequest, FlowingAdmissions,
    FlowingCancelOutcome, FlowingCancelReceipt, FlowingCancelRefusal, FlowingCancelRequest,
    FlowingCandidateWitness, FlowingGateCertificate, FlowingUnitOutcome,
};
use whipplescript_store::branches::flowing_fence::FlowingSourceKind;
use whipplescript_store::branches::{
    BranchStatus, Branches, MAINLINE_BRANCH_ID, MAINLINE_GATE_LEASE,
};
use whipplescript_store::{StoreError, StoreResult};

fn read_receipt<S: DoSql>(sql: &S, op_id: &str) -> StoreResult<Option<FlowingAdmissionReceipt>> {
    sql.query(
        "SELECT op_id, receipt_json FROM flowing_admissions WHERE op_id = ?1",
        &[text(op_id)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| {
        let receipt: FlowingAdmissionReceipt = serde_json::from_str(&as_text(&row[1]))?;
        if receipt.request.op_id != as_text(&row[0]) {
            return Err(StoreError::Conflict(
                "flowing admission receipt differs from its operation key".into(),
            ));
        }
        Ok(receipt)
    })
    .transpose()
}

fn read_witness<S: DoSql>(sql: &S, digest: &str) -> StoreResult<Option<FlowingCandidateWitness>> {
    sql.query(
        "SELECT witness_json FROM flowing_candidate_witnesses WHERE digest = ?1",
        &[text(digest)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| {
        let witness: FlowingCandidateWitness = serde_json::from_str(&as_text(&row[0]))?;
        if witness.digest()? != digest {
            return Err(StoreError::Conflict(
                "flowing candidate witness differs from its digest key".into(),
            ));
        }
        Ok(witness)
    })
    .transpose()
}

fn read_gate_certificate<S: DoSql>(
    sql: &S,
    handle: &str,
) -> StoreResult<Option<FlowingGateCertificate>> {
    sql.query(
        "SELECT certificate_json FROM flowing_gate_certificates WHERE handle = ?1",
        &[text(handle)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| {
        let certificate: FlowingGateCertificate = serde_json::from_str(&as_text(&row[0]))?;
        if certificate.handle()? != handle {
            return Err(StoreError::Conflict(
                "flowing gate certificate differs from its handle".into(),
            ));
        }
        Ok(certificate)
    })
    .transpose()
}

fn read_cancellation<S: DoSql>(
    sql: &S,
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
    sql.query(query, &[text(op_id)])
        .map_err(sql_err)?
        .first()
        .map(|row| {
            let receipt = FlowingCancelReceipt {
                request: serde_json::from_str(&as_text(&row[2]))?,
            };
            if receipt.request.admission_op_id != as_text(&row[0])
                || receipt.request.cancel_op_id != as_text(&row[1])
            {
                return Err(StoreError::Conflict(
                    "flowing cancellation receipt differs from its operation keys".into(),
                ));
            }
            Ok(receipt)
        })
        .transpose()
}

impl<S: DoSql> DoBranches<S> {
    fn flowing_ancestor(&self, older: &str, newer: &str) -> StoreResult<bool> {
        let mut cursor = Some(newer.to_owned());
        let mut visited = BTreeSet::new();
        while let Some(id) = cursor {
            if !visited.insert(id.clone()) {
                return Ok(false);
            }
            if id == older {
                return Ok(true);
            }
            cursor = self.get_cut(&id)?.and_then(|cut| cut.parent_cut_id);
        }
        Ok(false)
    }
}

impl<S: DoSql> FlowingAdmissions for DoBranches<S> {
    fn admitted_unit_operation(&self, unit_id: &str) -> StoreResult<Option<String>> {
        Ok(self
            .sql
            .query(
                "SELECT op_id FROM flowing_admitted_units WHERE unit_id = ?1",
                &[text(unit_id)],
            )
            .map_err(sql_err)?
            .first()
            .map(|row| as_text(&row[0])))
    }

    fn record_candidate_witness(
        &mut self,
        witness: &FlowingCandidateWitness,
    ) -> StoreResult<String> {
        let digest = witness.digest()?;
        exact_atomic(&self.sql, "flowing candidate witness", || {
            self.sql
                .execute(
                    "INSERT OR IGNORE INTO flowing_candidate_witnesses (digest, witness_json) VALUES (?1, ?2)",
                    &[text(&digest), text(&serde_json::to_string(witness)?)],
                )
                .map_err(sql_err)?;
            let _ = read_witness(&self.sql, &digest)?;
            Ok(digest.clone())
        })
    }

    fn candidate_witness(&self, digest: &str) -> StoreResult<Option<FlowingCandidateWitness>> {
        read_witness(&self.sql, digest)
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
        exact_atomic(&self.sql, "flowing trunk admission", || {
            if let Some(existing) = read_receipt(&self.sql, &request.op_id)? {
                return Ok(if existing.request == *request {
                    Existing(existing)
                } else {
                    Refused(R::IdentityMismatch)
                });
            }
            if let Some(cancelled) =
                read_cancellation(&self.sql, "admission_op_id", &request.op_id)?
            {
                return Ok(Refused(R::AttemptCancelled {
                    cancel_op_id: cancelled.request.cancel_op_id,
                }));
            }
            let Some(source) = self.row_by_id(&request.source_branch_id)? else {
                return Ok(Refused(R::SourceMissing));
            };
            if source.status != BranchStatus::Active {
                return Ok(Refused(R::SourceNotActive));
            }
            if source.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID) {
                return Ok(Refused(R::SourceNotTrunkChild));
            }
            let Some(fence) = flowing_fence::read_state(&self.sql, &request.source_branch_id)?
            else {
                return Ok(Refused(R::SourceMissing));
            };
            if fence.kind != FlowingSourceKind::Twig {
                return Ok(Refused(R::SourceNotDirectTwig));
            }
            if let Err(refusal) = check_fence(&fence, request) {
                return Ok(Refused(refusal));
            }
            let Some(selected_cut) = self.get_cut(&request.source_cut_id)? else {
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
            if !self.flowing_ancestor(&request.source_cut_id, source_head)? {
                return Ok(Refused(R::SourceCutNotRetained));
            }

            let Some(trunk) = self.row_by_id(MAINLINE_BRANCH_ID)? else {
                return Ok(Refused(R::TrunkMissing));
            };
            if trunk.status != BranchStatus::Active {
                return Ok(Refused(R::TrunkNotActive));
            }
            let reservation = self.head_reservation(MAINLINE_BRANCH_ID)?;
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
            let Some(candidate) = self.get_cut(&request.candidate_cut_id)? else {
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
                    && candidate.parent_cut_id.as_deref()
                        != request.expected_trunk_cut_id.as_deref())
                || (!same_cut
                    && (candidate.origin.as_deref() != Some(expected_origin.as_str())
                        || candidate.actor.as_deref() != Some(request.coordinator.as_str())))
                || same_cut == has_applied
            {
                return Ok(Refused(R::CandidateMismatch));
            }

            for unit in &request.units {
                let declarations = self
                    .sql
                    .query(
                        "SELECT pin_id, source_branch_id, source_cut_id, principal, intent \
                         FROM flowing_contributions WHERE unit_id = ?1",
                        &[text(&unit.unit_id)],
                    )
                    .map_err(sql_err)?;
                let Some(declaration) = declarations.first() else {
                    return Ok(Refused(R::UnitMissing {
                        unit_id: unit.unit_id.clone(),
                    }));
                };
                let pin_id = as_text(&declaration[0]);
                let declared_branch = as_text(&declaration[1]);
                let declared_cut = as_text(&declaration[2]);
                let principal = as_text(&declaration[3]);
                let intent = as_text(&declaration[4]);
                let bases = self
                    .sql
                    .query(
                        "SELECT basis_digest FROM flowing_contribution_basis WHERE unit_id = ?1",
                        &[text(&unit.unit_id)],
                    )
                    .map_err(sql_err)?;
                let Some(basis) = bases.first() else {
                    return Ok(Refused(R::UnitBasisMissing {
                        unit_id: unit.unit_id.clone(),
                    }));
                };
                if as_text(&basis[0]) != unit.basis_digest
                    || principal != unit.principal
                    || intent != unit.intent
                {
                    return Ok(Refused(R::UnitBasisMismatch {
                        unit_id: unit.unit_id.clone(),
                    }));
                }
                let handoffs = self
                    .sql
                    .query(
                        "SELECT target_branch_id, target_after_cut_id \
                         FROM flowing_handoffs WHERE unit_id = ?1",
                        &[text(&unit.unit_id)],
                    )
                    .map_err(sql_err)?;
                if !handoffs.is_empty() {
                    return Ok(Refused(R::UnverifiedLineage {
                        unit_id: unit.unit_id.clone(),
                    }));
                }
                let (holder, holder_cut) = handoffs.first().map_or_else(
                    || (declared_branch, declared_cut),
                    |handoff| (as_text(&handoff[0]), as_text(&handoff[1])),
                );
                if handoffs.is_empty() {
                    let pins = self
                        .sql
                        .query(
                            "SELECT released_at FROM flowing_private_pins WHERE pin_id = ?1",
                            &[text(&pin_id)],
                        )
                        .map_err(sql_err)?;
                    let Some(pin) = pins.first() else {
                        return Ok(Refused(R::UnitPinMissing {
                            unit_id: unit.unit_id.clone(),
                        }));
                    };
                    if !matches!(pin[0], crate::do_store::SqlValue::Null) {
                        return Ok(Refused(R::UnitPinReleased {
                            unit_id: unit.unit_id.clone(),
                        }));
                    }
                }
                if holder != request.source_branch_id
                    || !self.flowing_ancestor(&holder_cut, &request.source_cut_id)?
                {
                    return Ok(Refused(R::UnitNotHeldBySource {
                        unit_id: unit.unit_id.clone(),
                    }));
                }
                if !self
                    .sql
                    .query(
                        "SELECT op_id FROM flowing_admitted_units WHERE unit_id = ?1",
                        &[text(&unit.unit_id)],
                    )
                    .map_err(sql_err)?
                    .is_empty()
                {
                    return Ok(Refused(R::UnitAlreadyAdmitted {
                        unit_id: unit.unit_id.clone(),
                    }));
                }
            }

            let Some(witness) = read_witness(&self.sql, &request.candidate_witness_digest)? else {
                return Ok(Refused(R::CandidateWitnessMissing));
            };
            if !witness.matches_request(request) {
                return Ok(Refused(R::CandidateWitnessMismatch));
            }
            let Some(certificate) = read_gate_certificate(&self.sql, &request.certificate_handle)?
            else {
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
            self.sql
                .execute(
                    "INSERT INTO flowing_admissions (op_id, receipt_json) VALUES (?1, ?2)",
                    &[
                        text(&request.op_id),
                        text(&serde_json::to_string(&receipt)?),
                    ],
                )
                .map_err(sql_err)?;
            for unit in &request.units {
                self.sql
                    .execute(
                        "INSERT INTO flowing_admitted_units (unit_id, op_id) VALUES (?1, ?2)",
                        &[text(&unit.unit_id), text(&request.op_id)],
                    )
                    .map_err(sql_err)?;
            }
            if !same_cut {
                self.sql
                    .execute(
                        "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, \
                         updated_at = ?4 WHERE branch_id = ?1",
                        &[
                            text(MAINLINE_BRANCH_ID),
                            text(&request.candidate_cut_id),
                            text(&request.candidate_manifest_hash),
                            text(&request.recorded_at),
                        ],
                    )
                    .map_err(sql_err)?;
            }
            Ok(Admitted(receipt))
        })
    }

    fn flowing_admission_receipt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingAdmissionReceipt>> {
        read_receipt(&self.sql, op_id)
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
        exact_atomic(&self.sql, "flowing admission cancellation", || {
            if let Some(existing) =
                read_cancellation(&self.sql, "cancel_op_id", &request.cancel_op_id)?
            {
                return Ok(if existing.request == *request {
                    Existing(existing)
                } else {
                    Refused(R::IdentityMismatch)
                });
            }
            if let Some(existing) =
                read_cancellation(&self.sql, "admission_op_id", &request.admission_op_id)?
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
            if let Some(admitted) = read_receipt(&self.sql, &request.admission_op_id)? {
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
            let Some(state) = flowing_fence::read_state(&self.sql, &request.source_branch_id)?
            else {
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
            self.sql
                .execute(
                    "INSERT INTO flowing_admission_cancellations \
                     (admission_op_id, cancel_op_id, request_json) VALUES (?1, ?2, ?3)",
                    &[
                        text(&request.admission_op_id),
                        text(&request.cancel_op_id),
                        text(&serde_json::to_string(request)?),
                    ],
                )
                .map_err(sql_err)?;
            Ok(Cancelled(FlowingCancelReceipt {
                request: request.clone(),
            }))
        })
    }

    fn flowing_cancellation_for_attempt(
        &self,
        admission_op_id: &str,
    ) -> StoreResult<Option<FlowingCancelReceipt>> {
        read_cancellation(&self.sql, "admission_op_id", admission_op_id)
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::do_store::test_support::RusqliteDoSql;
    use whipplescript_store::branches::flowing_admission::{
        FlowingGateCheck, FlowingGateVerdict, FlowingSelectedUnit,
    };
    use whipplescript_store::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
    };
    use whipplescript_store::branches::{CreateBranch, CutRecord};

    type Sql = Rc<RusqliteDoSql>;

    fn fixture() -> (Sql, DoBranches<Sql>) {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(sql.clone()).unwrap();
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
        for statement in [
            "INSERT INTO flowing_private_pins \
             (pin_id, twig_branch_id, cut_id, manifest_hash, principal, retained_at) \
             VALUES ('pin', 'twig', 'source', 'source-manifest', 'author', 't2')",
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, \
              scope_digest, declared_at) \
             VALUES ('unit-a', 'pin', 'twig', 'source', 'source-manifest', \
                     'author', 'change', 'reads', 'deps', 'scope', 't2')",
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, \
              scope_digest, declared_at) \
             VALUES ('unit-b', 'pin', 'twig', 'source', 'source-manifest', \
                     'author', 'change', 'reads', 'deps', 'scope', 't2')",
            "INSERT INTO flowing_contribution_basis (unit_id, basis_digest, atoms_json, bound_at) \
             VALUES ('unit-a', 'basis-a', '[]', 't2')",
            "INSERT INTO flowing_contribution_basis (unit_id, basis_digest, atoms_json, bound_at) \
             VALUES ('unit-b', 'basis-b', '[]', 't2')",
        ] {
            sql.execute(statement, &[]).unwrap();
        }
        for unit_id in ["unit-a", "unit-b"] {
            let attempt = request(unit_id, "fixture");
            store
                .record_candidate_witness(&witness_for(&attempt))
                .unwrap();
            record_gate_certificate(&sql, &attempt);
        }
        (sql, store)
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

    fn record_gate_certificate(sql: &Sql, request: &FlowingAdmissionRequest) {
        insert_gate_certificate(sql, &certificate_for(request));
    }

    fn insert_gate_certificate(sql: &Sql, certificate: &FlowingGateCertificate) {
        sql.execute(
            "INSERT OR IGNORE INTO flowing_gate_certificates (handle, certificate_json) VALUES (?1, ?2)",
            &[
                text(&certificate.handle().unwrap()),
                text(&serde_json::to_string(certificate).unwrap()),
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
            units: vec![FlowingSelectedUnit {
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
    fn hosted_ref_requires_the_recorded_complete_candidate_witness() {
        let (_, mut store) = fixture();
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
        attempt.candidate_witness_digest = store
            .record_candidate_witness(&witness_for(&complete))
            .unwrap();
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CandidateWitnessMismatch)
        );
        attempt = request("unit-a", "admission-witness");
        attempt.contribution_id = "another-review".into();
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
    fn hosted_ref_requires_a_matching_passing_gate_certificate() {
        let (sql, mut store) = fixture();
        let mut attempt = request("unit-a", "admission-gate");
        attempt.certificate_handle = "sha256:missing".into();
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::GateCertificateMissing)
        );

        let mut foreign = certificate_for(&attempt);
        foreign.candidate_witness_digest = "sha256:other-candidate".into();
        insert_gate_certificate(&sql, &foreign);
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
            insert_gate_certificate(&sql, &certificate);
            attempt.certificate_handle = certificate.handle().unwrap();
            assert_eq!(
                store.admit_flowing_prefix(&attempt).unwrap(),
                FlowingAdmissionOutcome::Refused(refusal)
            );
        }
        let mut incomplete = certificate_for(&attempt);
        incomplete.checks.clear();
        insert_gate_certificate(&sql, &incomplete);
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
    fn hosted_ref_treats_changed_gate_certificate_as_indeterminate() {
        let (sql, mut store) = fixture();
        let attempt = request("unit-a", "admission-gate");
        let mut changed = certificate_for(&attempt);
        changed.rules_digest = "sha256:different-rules".into();
        sql.execute(
            "UPDATE flowing_gate_certificates SET certificate_json = ?1 WHERE handle = ?2",
            &[
                text(&serde_json::to_string(&changed).unwrap()),
                text(&attempt.certificate_handle),
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
    fn hosted_ref_treats_a_changed_stored_witness_as_indeterminate() {
        let (sql, mut store) = fixture();
        let attempt = request("unit-a", "admission-witness");
        let mut changed = witness_for(&attempt);
        changed.revision_sequence += 1;
        sql.execute(
            "UPDATE flowing_candidate_witnesses SET witness_json = ?1 WHERE digest = ?2",
            &[
                text(&serde_json::to_string(&changed).unwrap()),
                text(&attempt.candidate_witness_digest),
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
    fn hosted_cancellation_before_cas_fences_only_the_attempt() {
        let (_, mut store) = fixture();
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
        assert_eq!(
            store
                .admit_flowing_prefix(&request("unit-a", "admission-a"))
                .unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::AttemptCancelled {
                cancel_op_id: "cancel-a".into()
            })
        );
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
    fn hosted_cancellation_after_cas_reports_admission_without_reversing_it() {
        let (_, mut store) = fixture();
        let FlowingAdmissionOutcome::Admitted(receipt) = store
            .admit_flowing_prefix(&request("unit-a", "admission-a"))
            .unwrap()
        else {
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
    fn hosted_failed_cancellation_write_cannot_fence_an_attempt() {
        let (sql, mut store) = fixture();
        sql.execute(
            "CREATE TRIGGER reject_cancel BEFORE INSERT ON flowing_admission_cancellations \
             BEGIN SELECT RAISE(ABORT, 'injected cancellation failure'); END",
            &[],
        )
        .unwrap();
        assert!(store
            .cancel_flowing_attempt(&cancel("admission-a", "cancel-a"))
            .is_err());
        assert!(store
            .flowing_cancellation_for_attempt("admission-a")
            .unwrap()
            .is_none());
        sql.execute("DROP TRIGGER reject_cancel", &[]).unwrap();
        assert!(matches!(
            store
                .admit_flowing_prefix(&request("unit-a", "admission-a"))
                .unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
    }

    #[test]
    fn hosted_corrupt_operation_receipts_are_indeterminate() {
        let (sql, mut store) = fixture();
        let cancellation = cancel("admission-a", "cancel-a");
        store.cancel_flowing_attempt(&cancellation).unwrap();
        let mut altered = cancellation;
        altered.admission_op_id = "another-attempt".into();
        sql.execute(
            "UPDATE flowing_admission_cancellations SET request_json = ?1 \
             WHERE admission_op_id = 'admission-a'",
            &[text(&serde_json::to_string(&altered).unwrap())],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_cancellation_for_attempt("admission-a"),
            Err(StoreError::Conflict(message)) if message.contains("operation keys")
        ));
        assert!(store
            .admit_flowing_prefix(&request("unit-a", "admission-a"))
            .is_err());

        let (sql, mut store) = fixture();
        store
            .admit_flowing_prefix(&request("unit-a", "admission-b"))
            .unwrap();
        let altered = FlowingAdmissionReceipt {
            request: request("unit-a", "another-admission"),
        };
        sql.execute(
            "UPDATE flowing_admissions SET receipt_json = ?1 WHERE op_id = 'admission-b'",
            &[text(&serde_json::to_string(&altered).unwrap())],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_admission_receipt("admission-b"),
            Err(StoreError::Conflict(message)) if message.contains("operation key")
        ));
    }

    #[test]
    fn hosted_ref_entry_orders_hold_cas_noop_and_duplicate_unit() {
        let (_, mut store) = fixture();
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
        let mut first = request("unit-a", "admission-a");
        first.expected_eligibility_epoch = 1;
        assert_eq!(
            store.admit_flowing_prefix(&first).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::Held)
        );
        store
            .transition_flowing_source(&FlowingFenceTransition {
                op_id: "release".into(),
                expected_eligibility_epoch: 1,
                action: FlowingFenceAction::ReleaseHold,
                ..hold
            })
            .unwrap();
        first.expected_eligibility_epoch = 2;
        first.certificate_handle = certificate_for(&first).handle().unwrap();
        record_gate_certificate(&store.sql, &first);
        let FlowingAdmissionOutcome::Admitted(receipt) =
            store.admit_flowing_prefix(&first).unwrap()
        else {
            panic!("hosted prefix should admit")
        };
        assert_eq!(
            store
                .admitted_unit_operation("unit-a")
                .expect("admission index"),
            Some("admission-a".into())
        );
        assert_eq!(
            store.admit_flowing_prefix(&first).unwrap(),
            FlowingAdmissionOutcome::Existing(receipt.clone())
        );
        assert_eq!(
            store.flowing_admission_receipt("admission-a").unwrap(),
            Some(receipt)
        );
        let mut competing = first.clone();
        competing.op_id = "admission-b".into();
        competing.expected_trunk_cut_id = Some("candidate".into());
        competing.units[0].outcome = FlowingUnitOutcome::Equivalent;
        assert!(matches!(
            store.admit_flowing_prefix(&competing).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::UnitAlreadyAdmitted { .. })
        ));
        let mut no_op = request("unit-b", "admission-c");
        no_op.expected_eligibility_epoch = 2;
        no_op.expected_trunk_cut_id = Some("candidate".into());
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
        record_gate_certificate(&store.sql, &no_op);
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
            Some("candidate".into())
        );
    }

    #[test]
    fn hosted_failed_unit_write_rolls_back_trunk_and_receipt() {
        let (sql, mut store) = fixture();
        sql.execute(
            "CREATE TRIGGER reject_admitted_unit BEFORE INSERT ON flowing_admitted_units \
             BEGIN SELECT RAISE(ABORT, 'injected refusal'); END",
            &[],
        )
        .unwrap();
        assert!(store
            .admit_flowing_prefix(&request("unit-a", "admission-a"))
            .is_err());
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
    }

    #[test]
    fn hosted_handoff_is_not_admitted_without_lineage_policy() {
        let (sql, mut store) = fixture();
        sql.execute(
            "INSERT INTO flowing_handoffs \
             (op_id, unit_id, source_branch_id, source_cut_id, source_manifest_hash, \
              source_basis_digest, target_branch_id, target_after_cut_id, \
              target_after_manifest_hash, effects_json, original_principal, actor, recorded_at) \
             VALUES ('handoff', 'unit-a', 'twig', 'source', 'source-manifest', \
                     'basis-a', 'branch', 'branch-cut', 'branch-manifest', '[]', \
                     'author', 'coordinator', 't3')",
            &[],
        )
        .unwrap();
        assert!(matches!(
            store
                .admit_flowing_prefix(&request("unit-a", "admission-a"))
                .unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::UnverifiedLineage { .. })
        ));
        assert!(store
            .flowing_admission_receipt("admission-a")
            .unwrap()
            .is_none());
    }
}
