use std::collections::BTreeSet;

use super::flowing_fence;
use super::flowing_sources::exact_atomic;
use super::DoBranches;
use crate::do_store::{as_opt_text, as_text, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_admission::{
    check_fence, validate_cancel_request, validate_request, FlowingAdmissionOutcome,
    FlowingAdmissionReceipt, FlowingAdmissionRefusal, FlowingAdmissionRequest, FlowingAdmissions,
    FlowingAttemptFinishOutcome, FlowingAttemptFinishReceipt, FlowingAttemptFinishRefusal,
    FlowingAttemptPin, FlowingCancelOutcome, FlowingCancelReceipt, FlowingCancelRefusal,
    FlowingCancelRequest, FlowingCandidateWitness, FlowingGateCertificate, FlowingGateVerdict,
    FlowingUnitOutcome, ReleaseFlowingAttemptOutcome, RetainFlowingAttemptOutcome,
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

fn read_finish<S: DoSql>(sql: &S, op_id: &str) -> StoreResult<Option<FlowingAttemptFinishReceipt>> {
    sql.query(
        "SELECT op_id, receipt_json FROM flowing_attempt_finishes WHERE op_id = ?1",
        &[text(op_id)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| {
        let receipt: FlowingAttemptFinishReceipt = serde_json::from_str(&as_text(&row[1]))?;
        if receipt.request.op_id != as_text(&row[0])
            || !matches!(
                receipt.verdict,
                FlowingGateVerdict::Failed | FlowingGateVerdict::Unrun
            )
        {
            return Err(StoreError::Conflict(
                "flowing attempt finish differs from its operation key or terminal verdict".into(),
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

fn read_attempt_pin<S: DoSql>(sql: &S, op_id: &str) -> StoreResult<Option<FlowingAttemptPin>> {
    Ok(sql
        .query(
            "SELECT op_id, witness_digest, source_cut_id, candidate_cut_id, \
             retained_at, released_at FROM flowing_attempt_pins WHERE op_id = ?1",
            &[text(op_id)],
        )
        .map_err(sql_err)?
        .first()
        .map(|row| FlowingAttemptPin {
            op_id: as_text(&row[0]),
            witness_digest: as_text(&row[1]),
            source_cut_id: as_text(&row[2]),
            candidate_cut_id: as_text(&row[3]),
            retained_at: as_text(&row[4]),
            released_at: as_opt_text(&row[5]),
        }))
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

    fn missing_attempt_unit_holder(
        &self,
        witness: &FlowingCandidateWitness,
    ) -> StoreResult<Option<String>> {
        for unit in &witness.units {
            let handoffs = self
                .sql
                .query(
                    "SELECT target_branch_id, target_after_cut_id, target_after_manifest_hash, \
                 source_branch_id, source_cut_id, source_manifest_hash, \
                 source_basis_digest, original_principal \
                 FROM flowing_handoffs WHERE unit_id = ?1",
                    &[text(&unit.unit_id)],
                )
                .map_err(sql_err)?;
            if let Some(handoff) = handoffs.first() {
                let target_branch = as_text(&handoff[0]);
                let target_cut = as_text(&handoff[1]);
                let target_manifest = as_text(&handoff[2]);
                let source_branch = as_text(&handoff[3]);
                let source_cut = as_text(&handoff[4]);
                let source_manifest = as_text(&handoff[5]);
                let source_basis = as_text(&handoff[6]);
                let original_principal = as_text(&handoff[7]);
                let declarations = self
                    .sql
                    .query(
                        "SELECT c.source_branch_id, c.source_cut_id, c.source_manifest_hash, \
                     c.principal, c.intent, b.basis_digest \
                     FROM flowing_contributions c \
                     JOIN flowing_contribution_basis b ON b.unit_id = c.unit_id \
                     WHERE c.unit_id = ?1",
                        &[text(&unit.unit_id)],
                    )
                    .map_err(sql_err)?;
                let Some(declared) = declarations.first() else {
                    return Ok(Some(unit.unit_id.clone()));
                };
                let source_row = self.get_branch(&source_branch)?;
                let Some(target_row) = self.get_branch(&target_branch)? else {
                    return Ok(Some(unit.unit_id.clone()));
                };
                let Some(target_head) = target_row.head_cut_id.as_deref() else {
                    return Ok(Some(unit.unit_id.clone()));
                };
                let source_cut_row = self.get_cut(&source_cut)?;
                let target_cut_row = self.get_cut(&target_cut)?;
                let held = target_branch == witness.source_branch_id
                    && source_branch == as_text(&declared[0])
                    && source_cut == as_text(&declared[1])
                    && source_manifest == as_text(&declared[2])
                    && source_basis == as_text(&declared[5])
                    && source_basis == unit.basis_digest
                    && original_principal == as_text(&declared[3])
                    && original_principal == unit.principal
                    && as_text(&declared[4]) == unit.intent
                    && source_row.as_ref().is_some_and(|row| {
                        row.name.is_none()
                            && row.parent_branch_id.as_deref() == Some(target_branch.as_str())
                    })
                    && target_row.status == BranchStatus::Active
                    && target_row.name.is_some()
                    && source_cut_row.as_ref().is_some_and(|cut| {
                        cut.branch_id == source_branch && cut.manifest_hash == source_manifest
                    })
                    && target_cut_row.as_ref().is_some_and(|cut| {
                        cut.branch_id == target_branch && cut.manifest_hash == target_manifest
                    })
                    && self.flowing_ancestor(&target_cut, &witness.source_cut_id)?
                    && self.flowing_ancestor(&witness.source_cut_id, target_head)?;
                if !held {
                    return Ok(Some(unit.unit_id.clone()));
                }
                continue;
            }
            let rows = self
                .sql
                .query(
                    "SELECT c.source_cut_id \
                     FROM flowing_contributions c \
                     JOIN flowing_contribution_basis b ON b.unit_id = c.unit_id \
                     JOIN flowing_private_pins p ON p.pin_id = c.pin_id \
                     WHERE c.unit_id = ?1 AND c.source_branch_id = ?2 \
                     AND c.principal = ?3 AND c.intent = ?4 \
                     AND b.basis_digest = ?5 \
                     AND p.twig_branch_id = c.source_branch_id \
                     AND p.cut_id = c.source_cut_id \
                     AND p.manifest_hash = c.source_manifest_hash \
                     AND p.released_at IS NULL",
                    &[
                        text(&unit.unit_id),
                        text(&witness.source_branch_id),
                        text(&unit.principal),
                        text(&unit.intent),
                        text(&unit.basis_digest),
                    ],
                )
                .map_err(sql_err)?;
            let Some(row) = rows.first() else {
                return Ok(Some(unit.unit_id.clone()));
            };
            if !self.flowing_ancestor(&as_text(&row[0]), &witness.source_cut_id)? {
                return Ok(Some(unit.unit_id.clone()));
            }
        }
        Ok(None)
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

    fn retain_flowing_attempt(
        &mut self,
        op_id: &str,
        witness_digest: &str,
        retained_at: &str,
    ) -> StoreResult<RetainFlowingAttemptOutcome> {
        use RetainFlowingAttemptOutcome as O;
        for (field, value) in [
            ("op_id", op_id),
            ("witness_digest", witness_digest),
            ("retained_at", retained_at),
        ] {
            if value.trim().is_empty() {
                return Ok(O::Invalid { field });
            }
        }
        exact_atomic(&self.sql, "flowing attempt retention", || {
            if let Some(pin) = read_attempt_pin(&self.sql, op_id)? {
                return Ok(
                    if pin.witness_digest != witness_digest || pin.retained_at != retained_at {
                        O::IdentityMismatch
                    } else if pin.released_at.is_some() {
                        O::Released
                    } else {
                        O::Existing(pin)
                    },
                );
            }
            if read_receipt(&self.sql, op_id)?.is_some()
                || read_cancellation(&self.sql, "admission_op_id", op_id)?.is_some()
                || read_finish(&self.sql, op_id)?.is_some()
            {
                return Ok(O::AttemptTerminal);
            }
            let Some(witness) = read_witness(&self.sql, witness_digest)? else {
                return Ok(O::WitnessMissing);
            };
            if witness.units.is_empty() {
                return Ok(O::Invalid { field: "units" });
            }
            let Some(source) = self.get_cut(&witness.source_cut_id)? else {
                return Ok(O::SourceCutMissing);
            };
            if source.branch_id != witness.source_branch_id
                || source.manifest_hash != witness.source_manifest_hash
            {
                return Ok(O::SourceCutMismatch);
            }
            let Some(candidate) = self.get_cut(&witness.candidate_cut_id)? else {
                return Ok(O::CandidateCutMissing);
            };
            if candidate.branch_id != MAINLINE_BRANCH_ID
                || candidate.manifest_hash != witness.candidate_manifest_hash
            {
                return Ok(O::CandidateCutMismatch);
            }
            if let Some(unit_id) = self.missing_attempt_unit_holder(&witness)? {
                return Ok(O::UnitHolderMissing { unit_id });
            }
            self.sql
                .execute(
                    "INSERT INTO flowing_attempt_pins \
                     (op_id, witness_digest, source_cut_id, candidate_cut_id, retained_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    &[
                        text(op_id),
                        text(witness_digest),
                        text(&witness.source_cut_id),
                        text(&witness.candidate_cut_id),
                        text(retained_at),
                    ],
                )
                .map_err(sql_err)?;
            Ok(O::Retained(
                read_attempt_pin(&self.sql, op_id)?.expect("inserted attempt pin"),
            ))
        })
    }

    fn flowing_attempt_pin(&self, op_id: &str) -> StoreResult<Option<FlowingAttemptPin>> {
        read_attempt_pin(&self.sql, op_id)
    }

    fn release_terminal_flowing_attempt(
        &mut self,
        op_id: &str,
        released_at: &str,
    ) -> StoreResult<ReleaseFlowingAttemptOutcome> {
        use ReleaseFlowingAttemptOutcome as O;
        for (field, value) in [("op_id", op_id), ("released_at", released_at)] {
            if value.trim().is_empty() {
                return Ok(O::Invalid { field });
            }
        }
        exact_atomic(&self.sql, "flowing attempt pin release", || {
            let Some(pin) = read_attempt_pin(&self.sql, op_id)? else {
                return Ok(O::Missing);
            };
            if pin.released_at.is_some() {
                return Ok(O::AlreadyReleased);
            }
            if read_receipt(&self.sql, op_id)?.is_some() {
                return Ok(O::Admitted);
            }
            let cancelled = read_cancellation(&self.sql, "admission_op_id", op_id)?;
            let finished = read_finish(&self.sql, op_id)?;
            if cancelled.is_none() && finished.is_none() {
                return Ok(O::NotTerminal);
            }
            if cancelled.is_some() && finished.is_some() {
                return Err(StoreError::Conflict(
                    "flowing attempt has conflicting terminal receipts".into(),
                ));
            }
            let Some(witness) = read_witness(&self.sql, &pin.witness_digest)? else {
                return Err(StoreError::Conflict(
                    "retained flowing attempt lost its witness".into(),
                ));
            };
            if witness.source_cut_id != pin.source_cut_id
                || witness.candidate_cut_id != pin.candidate_cut_id
            {
                return Err(StoreError::Conflict(
                    "retained flowing attempt differs from its witness".into(),
                ));
            }
            if let Some(finished) = finished {
                if finished.request.candidate_witness_digest != pin.witness_digest
                    || finished.request.source_cut_id != pin.source_cut_id
                    || finished.request.candidate_cut_id != pin.candidate_cut_id
                    || !witness.matches_request(&finished.request)
                {
                    return Err(StoreError::Conflict(
                        "flowing attempt finish differs from its retained witness".into(),
                    ));
                }
            }
            if let Some(unit_id) = self.missing_attempt_unit_holder(&witness)? {
                return Ok(O::UnitHolderMissing { unit_id });
            }
            self.sql
                .execute(
                    "UPDATE flowing_attempt_pins SET released_at = ?2 WHERE op_id = ?1",
                    &[text(op_id), text(released_at)],
                )
                .map_err(sql_err)?;
            Ok(O::Released)
        })
    }

    fn finish_flowing_attempt(
        &mut self,
        request: &FlowingAdmissionRequest,
    ) -> StoreResult<FlowingAttemptFinishOutcome> {
        use FlowingAttemptFinishOutcome as O;
        use FlowingAttemptFinishRefusal as R;
        if let Err(refusal) = validate_request(request) {
            return Ok(O::Refused(R::InvalidRequest(refusal)));
        }
        exact_atomic(&self.sql, "flowing attempt finish", || {
            if let Some(existing) = read_finish(&self.sql, &request.op_id)? {
                if existing.request != *request {
                    return Ok(O::Refused(R::IdentityMismatch));
                }
                return Ok(O::Existing(existing));
            }
            if let Some(admitted) = read_receipt(&self.sql, &request.op_id)? {
                if admitted.request != *request {
                    return Ok(O::Refused(R::IdentityMismatch));
                }
                return Ok(O::AlreadyAdmitted(Box::new(admitted)));
            }
            if let Some(cancelled) =
                read_cancellation(&self.sql, "admission_op_id", &request.op_id)?
            {
                if cancelled.request.source_branch_id != request.source_branch_id
                    || cancelled.request.source_incarnation_id != request.source_incarnation_id
                {
                    return Ok(O::Refused(R::IdentityMismatch));
                }
                return Ok(O::AlreadyCancelled(cancelled));
            }
            let Some(pin) = read_attempt_pin(&self.sql, &request.op_id)? else {
                // MUTATION-SUCCESS-EXPR: Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
                return Ok(O::Refused(R::AttemptPinMissing));
            };
            if pin.witness_digest != request.candidate_witness_digest
                || pin.source_cut_id != request.source_cut_id
                || pin.candidate_cut_id != request.candidate_cut_id
            {
                return Ok(O::Refused(R::AttemptPinMismatch));
            }
            if pin.released_at.is_some() {
                return Ok(O::Refused(R::AttemptPinReleased));
            }
            let Some(witness) = read_witness(&self.sql, &request.candidate_witness_digest)? else {
                // MUTATION-SUCCESS-EXPR: Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
                return Ok(O::Refused(R::CandidateWitnessMissing));
            };
            if !witness.matches_request(request) {
                return Ok(O::Refused(R::CandidateWitnessMismatch));
            }
            let Some(certificate) = read_gate_certificate(&self.sql, &request.certificate_handle)?
            else {
                // MUTATION-SUCCESS-EXPR: Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
                return Ok(O::Refused(R::GateCertificateMissing));
            };
            if !certificate.matches_request(request) {
                return Ok(O::Refused(R::GateCertificateMismatch));
            }
            let verdict = match certificate.admission_refusal() {
                Some(FlowingAdmissionRefusal::GateFailed) => FlowingGateVerdict::Failed,
                Some(FlowingAdmissionRefusal::GateUnrun) => FlowingGateVerdict::Unrun,
                // MUTATION-SUCCESS-EXPR: return Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
                Some(_) => return Ok(O::Refused(R::GatePlanIncomplete)),
                // MUTATION-SUCCESS-EXPR: return Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
                None => return Ok(O::Refused(R::GatePassed)),
            };
            let receipt = FlowingAttemptFinishReceipt {
                request: request.clone(),
                verdict,
            };
            self.sql
                .execute(
                    "INSERT INTO flowing_attempt_finishes (op_id, receipt_json) VALUES (?1, ?2)",
                    &[
                        text(&request.op_id),
                        text(&serde_json::to_string(&receipt)?),
                    ],
                )
                .map_err(sql_err)?;
            Ok(O::Finished(receipt))
        })
    }

    fn flowing_finish_for_attempt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingAttemptFinishReceipt>> {
        read_finish(&self.sql, op_id)
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
            if let Some(finished) = read_finish(&self.sql, &request.op_id)? {
                return Ok(if finished.request == *request {
                    Refused(match finished.verdict {
                        FlowingGateVerdict::Failed => R::GateFailed,
                        FlowingGateVerdict::Unrun => R::GateUnrun,
                        FlowingGateVerdict::Passed => unreachable!("validated terminal receipt"),
                    })
                } else {
                    Refused(R::IdentityMismatch)
                });
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
            let Some(lineage) =
                whipplescript_store::branches::flowing_lineage::capture(self, &witness)?
            else {
                // MUTATION-SUCCESS-EXPR: Ok(Refused(R::LineageChanged))
                return Ok(Refused(R::LineageUnavailable));
            };
            if !whipplescript_store::branches::flowing_lineage::matches_certificate(
                &lineage,
                &certificate,
                &request.source_branch_id,
            ) {
                return Ok(Refused(R::LineageChanged));
            }
            let Some(holders) =
                whipplescript_store::branches::flowing_holders::capture(self, &witness)?
            else {
                // MUTATION-SUCCESS-EXPR: Ok(Refused(R::HolderChanged))
                return Ok(Refused(R::HolderUnavailable));
            };
            if !whipplescript_store::branches::flowing_holders::matches_certificate(
                &holders,
                &certificate,
            ) {
                return Ok(Refused(R::HolderChanged));
            }
            let Some(pin) = read_attempt_pin(&self.sql, &request.op_id)? else {
                return Ok(Refused(R::AttemptPinMissing));
            };
            if pin.witness_digest != request.candidate_witness_digest
                || pin.source_cut_id != request.source_cut_id
                || pin.candidate_cut_id != request.candidate_cut_id
            {
                return Ok(Refused(R::AttemptPinMismatch));
            }
            if pin.released_at.is_some() {
                return Ok(Refused(R::AttemptPinReleased));
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
            AlreadyAdmitted, AlreadyCancelled, AlreadyFinished, Cancelled, Existing, Refused,
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
            if let Some(finished) = read_finish(&self.sql, &request.admission_op_id)? {
                return Ok(
                    if finished.request.source_branch_id == request.source_branch_id
                        && finished.request.source_incarnation_id == request.source_incarnation_id
                    {
                        AlreadyFinished(Box::new(finished))
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
             VALUES ('unit-a', 'basis-a', '[{\"cut_id\":\"source\",\"change_id\":\"change\",\"path\":\"a\",\"before\":null,\"after\":\"a\"}]', 't2')",
            "INSERT INTO flowing_contribution_basis (unit_id, basis_digest, atoms_json, bound_at) \
             VALUES ('unit-b', 'basis-b', '[{\"cut_id\":\"source\",\"change_id\":\"change\",\"path\":\"b\",\"before\":null,\"after\":\"b\"}]', 't2')",
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
            unit_holders: Vec::new(),
            lineage_fences: Vec::new(),
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

    fn named_origin(sql: &Sql, store: &mut DoBranches<Sql>) {
        store
            .create_branch(CreateBranch {
                branch_id: "origin",
                name: Some("Origin"),
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        store
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "origin".into(),
                incarnation_id: "origin-inc".into(),
                kind: FlowingSourceKind::Branch,
                owner: "origin-owner".into(),
                opened_at: "t1".into(),
            })
            .unwrap();
        store
            .record_cut(CutRecord {
                cut_id: "origin-cut",
                change_id: "origin-change",
                branch_id: "origin",
                manifest_hash: "origin-manifest",
                parent_cut_id: None,
                origin: None,
                actor: Some("author"),
                intent: Some("change"),
                recorded_at: "t2",
            })
            .unwrap();
        // The trusted fixture supplies a retained cross-origin atom. Content
        // derivation remains a separate prerequisite tested by candidate builders.
        sql.execute(
            "UPDATE flowing_contribution_basis SET atoms_json = ?1 WHERE unit_id = 'unit-a'",
            &[text(r#"[{"cut_id":"origin-cut","change_id":"origin-change","path":"a","before":null,"after":"a"}]"#)],
        ).unwrap();
    }

    #[test]
    fn hosted_lineage_hold_release_invalidates_an_earlier_certificate() {
        let (sql, mut store) = fixture();
        named_origin(&sql, &mut store);
        let mut attempt = request("unit-a", "lineage-attempt");
        pin_attempt(&mut store, &attempt);
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::LineageChanged)
        );
        let mut certificate = certificate_for(&attempt);
        certificate.lineage_fences =
            whipplescript_store::branches::flowing_lineage::capture(&store, &witness_for(&attempt))
                .unwrap()
                .unwrap();
        assert_eq!(
            certificate
                .lineage_fences
                .iter()
                .map(|f| f.source_branch_id.as_str())
                .collect::<Vec<_>>(),
            ["origin", "twig"]
        );
        attempt.certificate_handle = certificate.handle().unwrap();
        insert_gate_certificate(&sql, &certificate);
        for (epoch, action, refusal) in [
            (
                0,
                FlowingFenceAction::Hold,
                FlowingAdmissionRefusal::LineageUnavailable,
            ),
            (
                1,
                FlowingFenceAction::ReleaseHold,
                FlowingAdmissionRefusal::LineageChanged,
            ),
        ] {
            assert!(matches!(
                store
                    .transition_flowing_source(&FlowingFenceTransition {
                        op_id: format!("origin-transition-{epoch}"),
                        source_branch_id: "origin".into(),
                        incarnation_id: "origin-inc".into(),
                        expected_eligibility_epoch: epoch,
                        expected_owner_epoch: 0,
                        actor: "origin-owner".into(),
                        action,
                        recorded_at: "t4".into(),
                    })
                    .unwrap(),
                FlowingFenceOutcome::Applied(_)
            ));
            assert_eq!(
                store.admit_flowing_prefix(&attempt).unwrap(),
                FlowingAdmissionOutcome::Refused(refusal)
            );
        }
        assert!(store
            .flowing_admission_receipt(&attempt.op_id)
            .unwrap()
            .is_none());
        assert!(store.admitted_unit_operation("unit-a").unwrap().is_none());
        assert!(store
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
        certificate.lineage_fences =
            whipplescript_store::branches::flowing_lineage::capture(&store, &witness_for(&attempt))
                .unwrap()
                .unwrap();
        attempt.certificate_handle = certificate.handle().unwrap();
        insert_gate_certificate(&sql, &certificate);
        assert!(matches!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
    }

    #[test]
    fn hosted_source_subject_reads_current_lineage_and_holder_evidence() {
        let (sql, mut store) = fixture();
        named_origin(&sql, &mut store);
        let attempt = request("unit-a", "subject-attempt");
        pin_attempt(&mut store, &attempt);
        let vcs = crate::do_branches::observe_vcs(&sql);
        let captured = vcs
            .capture_gate_subject(&attempt.candidate_witness_digest, &attempt.op_id)
            .unwrap();
        assert_eq!(
            captured
                .lineage_fences()
                .iter()
                .map(|f| f.source_branch_id.as_str())
                .collect::<Vec<_>>(),
            ["origin", "twig"]
        );
        assert_eq!(captured.unit_holders().len(), 1);
        assert_eq!(captured.unit_holders()[0].unit_id, "unit-a");
        let transition = FlowingFenceTransition {
            op_id: "origin-hold-subject".into(),
            source_branch_id: "origin".into(),
            incarnation_id: "origin-inc".into(),
            expected_owner_epoch: 0,
            expected_eligibility_epoch: 0,
            actor: "origin-owner".into(),
            action: FlowingFenceAction::Hold,
            recorded_at: "t4".into(),
        };
        store.transition_flowing_source(&transition).unwrap();
        assert!(format!(
            "{:?}",
            vcs.capture_gate_subject(&attempt.candidate_witness_digest, &attempt.op_id)
                .unwrap_err()
        )
        .contains("source lineage is unknown or ineligible"));
        store
            .transition_flowing_source(&FlowingFenceTransition {
                op_id: "origin-release-subject".into(),
                expected_eligibility_epoch: 1,
                action: FlowingFenceAction::ReleaseHold,
                ..transition
            })
            .unwrap();
        let released = vcs
            .capture_gate_subject(&attempt.candidate_witness_digest, &attempt.op_id)
            .unwrap();
        assert_eq!(captured.fence(), released.fence());
        assert_ne!(captured, released);
        sql.execute(
            "UPDATE flowing_private_pins SET principal = 'foreign' WHERE pin_id = 'pin'",
            &[],
        )
        .unwrap();
        assert!(format!(
            "{:?}",
            vcs.capture_gate_subject(&attempt.candidate_witness_digest, &attempt.op_id)
                .unwrap_err()
        )
        .contains("unit holder is unknown or changed"));
        sql.execute(
            "UPDATE flowing_private_pins SET principal = 'author' WHERE pin_id = 'pin'",
            &[],
        )
        .unwrap();
        sql.execute(
            "UPDATE flowing_contribution_basis SET atoms_json = '[]' WHERE unit_id = 'unit-a'",
            &[],
        )
        .unwrap();
        assert!(format!(
            "{:?}",
            vcs.capture_gate_subject(&attempt.candidate_witness_digest, &attempt.op_id)
                .unwrap_err()
        )
        .contains("source lineage is unknown or ineligible"));
        assert!(store
            .flowing_admission_receipt(&attempt.op_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn hosted_holder_evidence_is_rechecked_inside_admission() {
        for (sql_text, refusal) in [
            ("UPDATE flowing_private_pins SET principal = 'foreign' WHERE pin_id = 'pin'", FlowingAdmissionRefusal::HolderUnavailable),
            ("UPDATE flowing_private_pins SET manifest_hash = 'wrong' WHERE pin_id = 'pin'", FlowingAdmissionRefusal::HolderUnavailable),
            ("UPDATE flowing_contributions SET scope_digest = 'changed' WHERE unit_id = 'unit-a'", FlowingAdmissionRefusal::HolderChanged),
            ("UPDATE flowing_private_pins SET retained_at = 'changed' WHERE pin_id = 'pin'", FlowingAdmissionRefusal::HolderChanged),
        ] {
            let (sql, mut store) = fixture();
            let mut attempt = request("unit-a", "holder-attempt");
            pin_attempt(&mut store, &attempt);
            let mut certificate = certificate_for(&attempt);
            certificate.lineage_fences = whipplescript_store::branches::flowing_lineage::capture(&store, &witness_for(&attempt)).unwrap().unwrap();
            certificate.unit_holders = whipplescript_store::branches::flowing_holders::capture(&store, &witness_for(&attempt)).unwrap().unwrap();
            attempt.certificate_handle = certificate.handle().unwrap();
            insert_gate_certificate(&sql, &certificate);
            sql.execute(sql_text, &[]).unwrap();
            assert_eq!(store.admit_flowing_prefix(&attempt).unwrap(), FlowingAdmissionOutcome::Refused(refusal));
            assert!(store.admitted_unit_operation("unit-a").unwrap().is_none());
            assert!(store.flowing_admission_receipt(&attempt.op_id).unwrap().is_none());
            assert!(store.get_branch(MAINLINE_BRANCH_ID).unwrap().unwrap().head_cut_id.is_none());
            assert!(store.flowing_attempt_pin(&attempt.op_id).unwrap().unwrap().released_at.is_none());
        }
        let (sql, mut store) = fixture();
        let mut attempt = request("unit-a", "current-holder");
        pin_attempt(&mut store, &attempt);
        let mut certificate = certificate_for(&attempt);
        certificate.lineage_fences =
            whipplescript_store::branches::flowing_lineage::capture(&store, &witness_for(&attempt))
                .unwrap()
                .unwrap();
        certificate.unit_holders =
            whipplescript_store::branches::flowing_holders::capture(&store, &witness_for(&attempt))
                .unwrap()
                .unwrap();
        attempt.certificate_handle = certificate.handle().unwrap();
        insert_gate_certificate(&sql, &certificate);
        assert!(matches!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        // Legacy certificates keep their identity, but require a real matching pin.
        let (sql, mut store) = fixture();
        let attempt = request("unit-a", "legacy-holder");
        pin_attempt(&mut store, &attempt);
        let sql_text = "UPDATE flowing_private_pins SET cut_id = 'candidate' WHERE pin_id = 'pin'";
        sql.execute(sql_text, &[]).unwrap();
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::HolderUnavailable)
        );
    }

    #[test]
    fn hosted_lineage_missing_facts_and_cycles_cannot_authorize_cas() {
        for statement in [
            "DELETE FROM flowing_contribution_basis WHERE unit_id = 'unit-a'",
            "UPDATE flowing_contribution_basis SET atoms_json = '[]' WHERE unit_id = 'unit-a'",
            "UPDATE branches SET parent_branch_id = 'missing' WHERE branch_id = 'origin'",
            "UPDATE branches SET parent_branch_id = 'origin' WHERE branch_id = 'origin'",
            "DELETE FROM cuts WHERE cut_id = 'origin-cut'",
            "DELETE FROM flowing_source_fences WHERE source_branch_id = 'origin'",
        ] {
            let (sql, mut store) = fixture();
            named_origin(&sql, &mut store);
            let attempt = request("unit-a", "unknown-lineage");
            pin_attempt(&mut store, &attempt);
            DoSql::execute(&*sql, statement, &[]).unwrap();
            assert!(
                whipplescript_store::branches::flowing_lineage::capture(
                    &store,
                    &witness_for(&attempt)
                )
                .unwrap()
                .is_none(),
                "{statement}"
            );
            let expected = if statement.starts_with("DELETE FROM flowing_contribution_basis") {
                FlowingAdmissionRefusal::UnitBasisMissing {
                    unit_id: "unit-a".into(),
                }
            } else {
                FlowingAdmissionRefusal::LineageUnavailable
            };
            assert_eq!(
                store.admit_flowing_prefix(&attempt).unwrap(),
                FlowingAdmissionOutcome::Refused(expected),
                "{statement}"
            );
            assert!(store
                .flowing_admission_receipt(&attempt.op_id)
                .unwrap()
                .is_none());
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

    fn pin_attempt(store: &mut DoBranches<Sql>, request: &FlowingAdmissionRequest) {
        assert!(matches!(
            store
                .retain_flowing_attempt(&request.op_id, &request.candidate_witness_digest, "t3")
                .unwrap(),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
    }

    fn terminal_request(
        sql: &Sql,
        op_id: &str,
        verdict: FlowingGateVerdict,
    ) -> FlowingAdmissionRequest {
        let mut attempt = request("unit-a", op_id);
        let mut certificate = certificate_for(&attempt);
        certificate.checks[0].verdict = verdict;
        attempt.certificate_handle = certificate.handle().unwrap();
        insert_gate_certificate(sql, &certificate);
        attempt
    }

    #[test]
    fn hosted_failed_and_unrun_attempts_finish_before_their_roots_are_released() {
        for verdict in [FlowingGateVerdict::Failed, FlowingGateVerdict::Unrun] {
            let (sql, mut store) = fixture();
            let request = terminal_request(&sql, "terminal", verdict);
            pin_attempt(&mut store, &request);
            assert_eq!(
                store
                    .release_terminal_flowing_attempt(&request.op_id, "t4")
                    .unwrap(),
                ReleaseFlowingAttemptOutcome::NotTerminal
            );
            let receipt = FlowingAttemptFinishReceipt {
                request: request.clone(),
                verdict,
            };
            assert_eq!(
                store.finish_flowing_attempt(&request).unwrap(),
                FlowingAttemptFinishOutcome::Finished(receipt.clone())
            );
            assert_eq!(
                store.finish_flowing_attempt(&request).unwrap(),
                FlowingAttemptFinishOutcome::Existing(receipt.clone())
            );
            assert_eq!(
                store.flowing_finish_for_attempt(&request.op_id).unwrap(),
                Some(receipt.clone())
            );
            let mut changed = request.clone();
            changed.recorded_at = "changed".into();
            assert_eq!(
                store.finish_flowing_attempt(&changed).unwrap(),
                FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::IdentityMismatch)
            );
            assert_eq!(
                store.admit_flowing_prefix(&request).unwrap(),
                FlowingAdmissionOutcome::Refused(match verdict {
                    FlowingGateVerdict::Failed => FlowingAdmissionRefusal::GateFailed,
                    FlowingGateVerdict::Unrun => FlowingAdmissionRefusal::GateUnrun,
                    FlowingGateVerdict::Passed => unreachable!(),
                })
            );
            assert_eq!(
                store
                    .cancel_flowing_attempt(&cancel(&request.op_id, "cancel-terminal"))
                    .unwrap(),
                FlowingCancelOutcome::AlreadyFinished(Box::new(receipt))
            );
            assert_eq!(
                store
                    .release_terminal_flowing_attempt(&request.op_id, "t5")
                    .unwrap(),
                ReleaseFlowingAttemptOutcome::Released
            );
            assert!(store.pinned_cuts("t5").unwrap().contains("source"));
            assert!(!store.pinned_cuts("t5").unwrap().contains("candidate"));
            assert_eq!(
                store
                    .retain_flowing_attempt(&request.op_id, &request.candidate_witness_digest, "t3")
                    .unwrap(),
                RetainFlowingAttemptOutcome::Released
            );
        }
    }

    #[test]
    fn hosted_failed_finish_refuses_passed_or_incomplete_evidence_and_write_failure() {
        let (sql, mut store) = fixture();
        let passed = request("unit-a", "passed");
        pin_attempt(&mut store, &passed);
        assert_eq!(
            store.finish_flowing_attempt(&passed).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::GatePassed)
        );
        let mut incomplete = request("unit-a", "incomplete");
        let mut certificate = certificate_for(&incomplete);
        certificate.checks.clear();
        incomplete.certificate_handle = certificate.handle().unwrap();
        insert_gate_certificate(&sql, &certificate);
        pin_attempt(&mut store, &incomplete);
        assert_eq!(
            store.finish_flowing_attempt(&incomplete).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::GatePlanIncomplete)
        );

        let failed = terminal_request(&sql, "failed-write", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &failed);
        sql.execute(
            "CREATE TRIGGER reject_finish BEFORE INSERT ON flowing_attempt_finishes \
             BEGIN SELECT RAISE(ABORT, 'injected finish failure'); END",
            &[],
        )
        .unwrap();
        assert!(store.finish_flowing_attempt(&failed).is_err());
        assert!(store
            .flowing_finish_for_attempt(&failed.op_id)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .release_terminal_flowing_attempt(&failed.op_id, "t5")
                .unwrap(),
            ReleaseFlowingAttemptOutcome::NotTerminal
        );
        sql.execute("DROP TRIGGER reject_finish", &[]).unwrap();
        assert!(matches!(
            store.finish_flowing_attempt(&failed).unwrap(),
            FlowingAttemptFinishOutcome::Finished(_)
        ));
        sql.execute(
            "UPDATE flowing_private_pins SET released_at = 't4' WHERE pin_id = 'pin'",
            &[],
        )
        .unwrap();
        assert_eq!(
            store
                .release_terminal_flowing_attempt(&failed.op_id, "t5")
                .unwrap(),
            ReleaseFlowingAttemptOutcome::UnitHolderMissing {
                unit_id: "unit-a".into()
            }
        );
        assert!(store
            .flowing_attempt_pin(&failed.op_id)
            .unwrap()
            .unwrap()
            .released_at
            .is_none());
    }

    #[test]
    fn hosted_changed_terminal_receipt_cannot_release_a_different_pinned_witness() {
        let (sql, mut store) = fixture();
        let request = terminal_request(&sql, "changed-finish", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &request);
        store.finish_flowing_attempt(&request).unwrap();
        let mut altered = FlowingAttemptFinishReceipt {
            request: request.clone(),
            verdict: FlowingGateVerdict::Failed,
        };
        altered.request.candidate_witness_digest = "sha256:other".into();
        sql.execute(
            "UPDATE flowing_attempt_finishes SET receipt_json = ?1 WHERE op_id = ?2",
            &[
                text(&serde_json::to_string(&altered).unwrap()),
                text(&request.op_id),
            ],
        )
        .unwrap();
        assert!(matches!(
            store.release_terminal_flowing_attempt(&request.op_id, "t5"),
            Err(StoreError::Conflict(message)) if message.contains("differs from its retained witness")
        ));
        assert!(store
            .flowing_attempt_pin(&request.op_id)
            .unwrap()
            .unwrap()
            .released_at
            .is_none());
    }

    #[test]
    fn hosted_terminal_receipt_key_verdict_and_exclusivity_guard_release() {
        let (sql, mut store) = fixture();
        let request = terminal_request(&sql, "receipt-guard", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &request);
        store.finish_flowing_attempt(&request).unwrap();
        let mut altered = FlowingAttemptFinishReceipt {
            request: request.clone(),
            verdict: FlowingGateVerdict::Failed,
        };
        altered.request.op_id = "other".into();
        sql.execute(
            "UPDATE flowing_attempt_finishes SET receipt_json=?1 WHERE op_id=?2",
            &[
                text(&serde_json::to_string(&altered).unwrap()),
                text(&request.op_id),
            ],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_finish_for_attempt(&request.op_id),
            Err(StoreError::Conflict(message)) if message.contains("operation key or terminal verdict")
        ));
        altered.request.op_id = request.op_id.clone();
        altered.verdict = FlowingGateVerdict::Passed;
        sql.execute(
            "UPDATE flowing_attempt_finishes SET receipt_json=?1 WHERE op_id=?2",
            &[
                text(&serde_json::to_string(&altered).unwrap()),
                text(&request.op_id),
            ],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_finish_for_attempt(&request.op_id),
            Err(StoreError::Conflict(message)) if message.contains("operation key or terminal verdict")
        ));
        altered.verdict = FlowingGateVerdict::Failed;
        sql.execute(
            "UPDATE flowing_attempt_finishes SET receipt_json=?1 WHERE op_id=?2",
            &[
                text(&serde_json::to_string(&altered).unwrap()),
                text(&request.op_id),
            ],
        )
        .unwrap();
        let cancellation = cancel(&request.op_id, "conflicting-cancel");
        sql.execute(
            "INSERT INTO flowing_admission_cancellations \
             (admission_op_id, cancel_op_id, request_json) VALUES (?1, ?2, ?3)",
            &[
                text(&request.op_id),
                text(&cancellation.cancel_op_id),
                text(&serde_json::to_string(&cancellation).unwrap()),
            ],
        )
        .unwrap();
        assert!(matches!(
            store.release_terminal_flowing_attempt(&request.op_id, "t5"),
            Err(StoreError::Conflict(message)) if message.contains("conflicting terminal receipts")
        ));
    }

    #[test]
    fn hosted_finish_checks_pin_witness_and_certificate_before_terminal_receipt() {
        let (_, mut store) = fixture();
        let mut invalid = request("unit-a", "invalid");
        invalid.op_id.clear();
        assert_eq!(
            store.finish_flowing_attempt(&invalid).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::InvalidRequest(
                FlowingAdmissionRefusal::Invalid { field: "op_id" }
            ))
        );

        let (sql, mut store) = fixture();
        let missing = terminal_request(&sql, "missing-pin", FlowingGateVerdict::Failed);
        assert_eq!(
            store.finish_flowing_attempt(&missing).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::AttemptPinMissing)
        );

        let (sql, mut store) = fixture();
        let changed = terminal_request(&sql, "changed-pin", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &changed);
        sql.execute(
            "UPDATE flowing_attempt_pins SET witness_digest='sha256:other' WHERE op_id=?1",
            &[text(&changed.op_id)],
        )
        .unwrap();
        assert_eq!(
            store.finish_flowing_attempt(&changed).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::AttemptPinMismatch)
        );

        let (sql, mut store) = fixture();
        let released = terminal_request(&sql, "released-pin", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &released);
        sql.execute(
            "UPDATE flowing_attempt_pins SET released_at='t4' WHERE op_id=?1",
            &[text(&released.op_id)],
        )
        .unwrap();
        assert_eq!(
            store.finish_flowing_attempt(&released).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::AttemptPinReleased)
        );

        let (sql, mut store) = fixture();
        let mut changed_witness =
            terminal_request(&sql, "changed-witness", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &changed_witness);
        changed_witness.contribution_id = "other".into();
        assert_eq!(
            store.finish_flowing_attempt(&changed_witness).unwrap(),
            FlowingAttemptFinishOutcome::Refused(
                FlowingAttemptFinishRefusal::CandidateWitnessMismatch
            )
        );

        let (sql, mut store) = fixture();
        let mut changed_certificate =
            terminal_request(&sql, "changed-certificate", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &changed_certificate);
        changed_certificate.coordinator = "other".into();
        assert_eq!(
            store.finish_flowing_attempt(&changed_certificate).unwrap(),
            FlowingAttemptFinishOutcome::Refused(
                FlowingAttemptFinishRefusal::GateCertificateMismatch
            )
        );

        let (sql, mut store) = fixture();
        let missing_witness = terminal_request(&sql, "missing-witness", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &missing_witness);
        sql.execute(
            "DELETE FROM flowing_candidate_witnesses WHERE digest=?1",
            &[text(&missing_witness.candidate_witness_digest)],
        )
        .unwrap();
        assert_eq!(
            store.finish_flowing_attempt(&missing_witness).unwrap(),
            FlowingAttemptFinishOutcome::Refused(
                FlowingAttemptFinishRefusal::CandidateWitnessMissing
            )
        );

        let (sql, mut store) = fixture();
        let missing_certificate =
            terminal_request(&sql, "missing-certificate", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &missing_certificate);
        sql.execute(
            "DELETE FROM flowing_gate_certificates WHERE handle=?1",
            &[text(&missing_certificate.certificate_handle)],
        )
        .unwrap();
        assert_eq!(
            store.finish_flowing_attempt(&missing_certificate).unwrap(),
            FlowingAttemptFinishOutcome::Refused(
                FlowingAttemptFinishRefusal::GateCertificateMissing
            )
        );
    }

    #[test]
    fn hosted_finish_reads_the_winning_admission_or_cancellation() {
        let (_, mut store) = fixture();
        let admitted = request("unit-a", "already-admitted");
        pin_attempt(&mut store, &admitted);
        let FlowingAdmissionOutcome::Admitted(receipt) =
            store.admit_flowing_prefix(&admitted).unwrap()
        else {
            panic!("admission should land");
        };
        assert_eq!(
            store.finish_flowing_attempt(&admitted).unwrap(),
            FlowingAttemptFinishOutcome::AlreadyAdmitted(Box::new(receipt))
        );
        let mut changed = admitted.clone();
        changed.recorded_at = "different".into();
        assert_eq!(
            store.finish_flowing_attempt(&changed).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::IdentityMismatch)
        );

        let (sql, mut store) = fixture();
        let failed = terminal_request(&sql, "already-cancelled", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &failed);
        let FlowingCancelOutcome::Cancelled(receipt) = store
            .cancel_flowing_attempt(&cancel(&failed.op_id, "cancel-first"))
            .unwrap()
        else {
            panic!("cancellation should land");
        };
        assert_eq!(
            store.finish_flowing_attempt(&failed).unwrap(),
            FlowingAttemptFinishOutcome::AlreadyCancelled(receipt)
        );
        let mut changed = failed.clone();
        changed.source_incarnation_id = "other".into();
        assert_eq!(
            store.finish_flowing_attempt(&changed).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::IdentityMismatch)
        );
        assert!(store
            .flowing_finish_for_attempt(&failed.op_id)
            .unwrap()
            .is_none());
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
    fn hosted_attempt_retains_a_handed_unit_after_private_pin_release() {
        let (sql, mut store) = fixture();
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
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "branch".into(),
                    incarnation_id: "branch-inc".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "coordinator".into(),
                    opened_at: "t3".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        sql.execute(
            "UPDATE branches SET parent_branch_id = 'branch' WHERE branch_id = 'twig'",
            &[],
        )
        .unwrap();
        store
            .record_cut(CutRecord {
                cut_id: "branch-cut",
                change_id: "handoff",
                branch_id: "branch",
                manifest_hash: "branch-manifest",
                parent_cut_id: None,
                origin: Some("transport:twig"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t4",
            })
            .unwrap();
        store
            .advance_head("branch", None, "branch-cut", "branch-manifest", "t4")
            .unwrap();
        sql.execute(
            "INSERT INTO flowing_handoffs \
             (op_id, unit_id, source_branch_id, source_cut_id, source_manifest_hash, \
              source_basis_digest, target_branch_id, target_before_cut_id, \
              target_after_cut_id, target_after_manifest_hash, effects_json, \
              original_principal, actor, recorded_at) VALUES \
             ('handoff', 'unit-a', 'twig', 'source', 'source-manifest', \
              'basis-a', 'branch', NULL, 'branch-cut', 'branch-manifest', '[]', \
              'author', 'mediator', 't4')",
            &[],
        )
        .unwrap();
        sql.execute(
            "UPDATE flowing_private_pins SET released_at = 't5' WHERE pin_id = 'pin'",
            &[],
        )
        .unwrap();
        let mut witness = witness_for(&request("unit-a", "fixture"));
        witness.source_branch_id = "branch".into();
        witness.source_incarnation_id = "branch-inc".into();
        witness.source_cut_id = "branch-cut".into();
        witness.source_manifest_hash = "branch-manifest".into();
        let holders = whipplescript_store::branches::flowing_holders::capture(&store, &witness)
            .unwrap()
            .unwrap();
        assert_eq!(holders[0].holder_branch_id, "branch");
        assert_eq!(holders[0].handoff_op_id.as_deref(), Some("handoff"));
        let digest = store.record_candidate_witness(&witness).unwrap();
        assert!(matches!(
            store
                .retain_flowing_attempt("branch-attempt", &digest, "t6")
                .unwrap(),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        assert!(matches!(
            store
                .cancel_flowing_attempt(&FlowingCancelRequest {
                    cancel_op_id: "cancel-branch".into(),
                    admission_op_id: "branch-attempt".into(),
                    source_branch_id: "branch".into(),
                    source_incarnation_id: "branch-inc".into(),
                    expected_owner_epoch: 0,
                    coordinator: "coordinator".into(),
                    recorded_at: "t7".into(),
                })
                .unwrap(),
            FlowingCancelOutcome::Cancelled(_)
        ));
        assert_eq!(
            store
                .release_terminal_flowing_attempt("branch-attempt", "t8")
                .unwrap(),
            ReleaseFlowingAttemptOutcome::Released
        );
        assert!(store.pinned_cuts("t8").unwrap().contains("source"));
        sql.execute(
            "UPDATE flowing_handoffs SET target_after_manifest_hash = 'wrong' \
             WHERE unit_id = 'unit-a'",
            &[],
        )
        .unwrap();
        assert!(
            whipplescript_store::branches::flowing_holders::capture(&store, &witness)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .retain_flowing_attempt("changed-handoff", &digest, "t7")
                .unwrap(),
            RetainFlowingAttemptOutcome::UnitHolderMissing {
                unit_id: "unit-a".into()
            }
        );
    }

    #[test]
    fn hosted_cancelled_attempt_roots_survive_reopen_and_release_independently() {
        let (sql, mut store) = fixture();
        let witness = request("unit-a", "fixture").candidate_witness_digest;
        assert!(matches!(
            store
                .retain_flowing_attempt("attempt-a", &witness, "t3")
                .unwrap(),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        assert!(matches!(
            store
                .retain_flowing_attempt("attempt-b", &witness, "t3")
                .unwrap(),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        drop(store);
        let mut store = DoBranches::new(sql).unwrap();
        assert!(store.flowing_attempt_pin("attempt-a").unwrap().is_some());
        assert!(store.pinned_cuts("t4").unwrap().contains("candidate"));
        assert_eq!(
            store
                .release_terminal_flowing_attempt("attempt-a", "t5")
                .unwrap(),
            ReleaseFlowingAttemptOutcome::NotTerminal
        );
        store
            .cancel_flowing_attempt(&cancel("attempt-a", "cancel-a"))
            .unwrap();
        assert_eq!(
            store
                .release_terminal_flowing_attempt("attempt-a", "t5")
                .unwrap(),
            ReleaseFlowingAttemptOutcome::Released
        );
        assert!(store.pinned_cuts("t5").unwrap().contains("candidate"));
        assert_eq!(
            store
                .retain_flowing_attempt("attempt-a", &witness, "t3")
                .unwrap(),
            RetainFlowingAttemptOutcome::Released
        );
        store
            .cancel_flowing_attempt(&cancel("attempt-b", "cancel-b"))
            .unwrap();
        assert_eq!(
            store
                .release_terminal_flowing_attempt("attempt-b", "t6")
                .unwrap(),
            ReleaseFlowingAttemptOutcome::Released
        );
        let roots = store.pinned_cuts("t6").unwrap();
        assert!(roots.contains("source"));
        assert!(!roots.contains("candidate"));
    }

    #[test]
    fn hosted_cancelled_attempt_keeps_its_roots_when_source_holder_is_lost() {
        let (sql, mut store) = fixture();
        let witness = request("unit-a", "fixture").candidate_witness_digest;
        store
            .retain_flowing_attempt("attempt-a", &witness, "t3")
            .unwrap();
        store
            .cancel_flowing_attempt(&cancel("attempt-a", "cancel-a"))
            .unwrap();
        sql.execute(
            "UPDATE flowing_private_pins SET released_at = 't4' WHERE pin_id = 'pin'",
            &[],
        )
        .unwrap();
        assert_eq!(
            store
                .release_terminal_flowing_attempt("attempt-a", "t5")
                .unwrap(),
            ReleaseFlowingAttemptOutcome::UnitHolderMissing {
                unit_id: "unit-a".into()
            }
        );
        assert!(store
            .flowing_attempt_pin("attempt-a")
            .unwrap()
            .unwrap()
            .released_at
            .is_none());
        assert!(store.pinned_cuts("t5").unwrap().contains("candidate"));
    }

    #[test]
    fn hosted_cancelled_attempt_cannot_release_a_lost_or_changed_witness() {
        let (sql, mut store) = fixture();
        let witness = request("unit-a", "fixture").candidate_witness_digest;
        store
            .retain_flowing_attempt("attempt-a", &witness, "t3")
            .unwrap();
        store
            .cancel_flowing_attempt(&cancel("attempt-a", "cancel-a"))
            .unwrap();
        sql.execute(
            "DELETE FROM flowing_candidate_witnesses WHERE digest = ?1",
            &[text(&witness)],
        )
        .unwrap();
        assert!(matches!(
            store.release_terminal_flowing_attempt("attempt-a", "t5"),
            Err(StoreError::Conflict(message)) if message.contains("lost its witness")
        ));
        assert!(store
            .flowing_attempt_pin("attempt-a")
            .unwrap()
            .unwrap()
            .released_at
            .is_none());
        store
            .record_candidate_witness(&witness_for(&request("unit-a", "fixture")))
            .unwrap();
        sql.execute(
            "UPDATE flowing_attempt_pins SET source_cut_id = 'other' WHERE op_id = 'attempt-a'",
            &[],
        )
        .unwrap();
        assert!(matches!(
            store.release_terminal_flowing_attempt("attempt-a", "t6"),
            Err(StoreError::Conflict(message)) if message.contains("differs from its witness")
        ));
        assert!(store
            .flowing_attempt_pin("attempt-a")
            .unwrap()
            .unwrap()
            .released_at
            .is_none());
    }

    #[test]
    fn hosted_admitted_attempt_cannot_release_before_receipt_reconciliation() {
        let (_sql, mut store) = fixture();
        let request = request("unit-a", "fixture");
        store
            .retain_flowing_attempt(&request.op_id, &request.candidate_witness_digest, "t3")
            .unwrap();
        assert!(matches!(
            store.admit_flowing_prefix(&request).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        assert_eq!(
            store
                .release_terminal_flowing_attempt(&request.op_id, "t5")
                .unwrap(),
            ReleaseFlowingAttemptOutcome::Admitted
        );
        assert!(store
            .flowing_attempt_pin(&request.op_id)
            .unwrap()
            .unwrap()
            .released_at
            .is_none());
        assert!(store.pinned_cuts("t5").unwrap().contains("candidate"));
    }

    #[test]
    fn hosted_cas_requires_the_live_pin_for_its_exact_attempt_and_witness() {
        let (sql, mut store) = fixture();
        let request = request("unit-a", "fixture");
        assert_eq!(
            store.admit_flowing_prefix(&request).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::AttemptPinMissing)
        );
        pin_attempt(&mut store, &request);
        sql.execute(
            "UPDATE flowing_attempt_pins SET witness_digest = 'different' WHERE op_id = ?1",
            &[text(&request.op_id)],
        )
        .unwrap();
        assert_eq!(
            store.admit_flowing_prefix(&request).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::AttemptPinMismatch)
        );
        sql.execute(
            "UPDATE flowing_attempt_pins SET witness_digest = ?2, released_at = 't4' WHERE op_id = ?1",
            &[text(&request.op_id), text(&request.candidate_witness_digest)],
        )
        .unwrap();
        assert_eq!(
            store.admit_flowing_prefix(&request).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::AttemptPinReleased)
        );
        assert!(store
            .flowing_admission_receipt(&request.op_id)
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
    fn hosted_attempt_retention_refuses_missing_or_changed_witness_bases() {
        let (_sql, mut store) = fixture();
        let request = request("unit-a", "fixture");
        assert_eq!(
            store
                .retain_flowing_attempt("attempt", "missing", "t3")
                .unwrap(),
            RetainFlowingAttemptOutcome::WitnessMissing
        );
        assert_eq!(
            store
                .retain_flowing_attempt("", &request.candidate_witness_digest, "t3")
                .unwrap(),
            RetainFlowingAttemptOutcome::Invalid { field: "op_id" }
        );
        for (change, expected) in [
            (
                "source_missing",
                RetainFlowingAttemptOutcome::SourceCutMissing,
            ),
            (
                "source_mismatch",
                RetainFlowingAttemptOutcome::SourceCutMismatch,
            ),
            (
                "candidate_missing",
                RetainFlowingAttemptOutcome::CandidateCutMissing,
            ),
            (
                "candidate_mismatch",
                RetainFlowingAttemptOutcome::CandidateCutMismatch,
            ),
            (
                "holder",
                RetainFlowingAttemptOutcome::UnitHolderMissing {
                    unit_id: "unit-a".into(),
                },
            ),
            (
                "empty",
                RetainFlowingAttemptOutcome::Invalid { field: "units" },
            ),
        ] {
            let mut witness = witness_for(&request);
            match change {
                "source_missing" => witness.source_cut_id = "missing".into(),
                "source_mismatch" => witness.source_manifest_hash = "wrong".into(),
                "candidate_missing" => witness.candidate_cut_id = "missing".into(),
                "candidate_mismatch" => witness.candidate_manifest_hash = "wrong".into(),
                "holder" => witness.units[0].basis_digest = "wrong".into(),
                "empty" => witness.units.clear(),
                _ => unreachable!(),
            }
            let digest = store.record_candidate_witness(&witness).unwrap();
            assert_eq!(
                store
                    .retain_flowing_attempt(&format!("attempt-{change}"), &digest, "t3")
                    .unwrap(),
                expected,
                "{change}"
            );
        }
        store
            .cancel_flowing_attempt(&cancel("terminal", "cancel-terminal"))
            .unwrap();
        assert_eq!(
            store
                .retain_flowing_attempt("terminal", &request.candidate_witness_digest, "t3")
                .unwrap(),
            RetainFlowingAttemptOutcome::AttemptTerminal
        );
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
        pin_attempt(&mut store, &request("unit-a", "admission-b"));
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
        pin_attempt(&mut store, &request("unit-a", "admission-a"));
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
        pin_attempt(&mut store, &request("unit-a", "admission-a"));
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
        pin_attempt(&mut store, &request("unit-a", "admission-b"));
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
        pin_attempt(&mut store, &first);
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
        pin_attempt(&mut store, &no_op);
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
        pin_attempt(&mut store, &request("unit-a", "admission-a"));
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
