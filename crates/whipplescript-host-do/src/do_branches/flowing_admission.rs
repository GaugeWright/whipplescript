use std::collections::BTreeSet;

use super::flowing_fence;
use super::flowing_sources::exact_atomic;
use super::DoBranches;
use crate::do_store::{as_i64, as_opt_text, as_text, int, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_admission::{
    check_fence, configure_issuer_outcome, validate_cancel_request, validate_issuer_signature,
    validate_request, validate_trusted_issuer, verify_issued, ConfigureFlowingGateIssuerOutcome,
    FlowingGateIssuerRefusal, FlowingGateIssuerSignature, FlowingGateTrustedIssuer,
    RecordFlowingGateSignatureOutcome,
};
use whipplescript_store::branches::flowing_admission::{
    FlowingAdmissionOutcome, FlowingAdmissionReceipt, FlowingAdmissionRefusal,
    FlowingAdmissionRequest, FlowingAdmissions, FlowingAttemptFinishOutcome,
    FlowingAttemptFinishReceipt, FlowingAttemptFinishRefusal, FlowingAttemptPin,
    FlowingCancelOutcome, FlowingCancelReceipt, FlowingCancelRefusal, FlowingCancelRequest,
    FlowingCandidateWitness, FlowingGateCertificate, FlowingGateVerdict, FlowingUnitOutcome,
    ReleaseFlowingAttemptOutcome, RetainFlowingAttemptOutcome,
};
use whipplescript_store::branches::flowing_coverage::{
    FlowingCoveragePremises, RecordCoveragePremisesOutcome, HOME_COVERAGE_DOMAIN,
};
use whipplescript_store::branches::flowing_fence::FlowingSourceKind;
use whipplescript_store::branches::flowing_parking::FlowingParking;
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

fn read_coverage_premises<S: DoSql>(sql: &S) -> StoreResult<Option<FlowingCoveragePremises>> {
    sql.query(
        "SELECT premises_json FROM flowing_coverage_premises WHERE domain = ?1",
        &[text(HOME_COVERAGE_DOMAIN)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| {
        let premises: FlowingCoveragePremises = serde_json::from_str(&as_text(&row[0]))?;
        if premises.invalid_field().is_some() {
            return Err(StoreError::Conflict(
                "flowing coverage premises are malformed".into(),
            ));
        }
        Ok(premises)
    })
    .transpose()
}

fn read_trusted_issuers<S: DoSql>(sql: &S) -> StoreResult<Vec<FlowingGateTrustedIssuer>> {
    sql.query(
        "SELECT issuer_id, issuer_json FROM flowing_gate_trusted_issuers ORDER BY issuer_id",
        &[],
    )
    .map_err(sql_err)?
    .iter()
    .map(|row| {
        let issuer: FlowingGateTrustedIssuer = serde_json::from_str(&as_text(&row[1]))?;
        if issuer.issuer_id != as_text(&row[0]) || validate_trusted_issuer(&issuer).is_err() {
            return Err(StoreError::Conflict(
                "flowing gate trusted issuer differs from its key".into(),
            ));
        }
        Ok(issuer)
    })
    .collect()
}

fn read_signatures<S: DoSql>(
    sql: &S,
    handle: &str,
) -> StoreResult<Vec<FlowingGateIssuerSignature>> {
    sql.query(
        "SELECT handle, issuer_id, issuer_epoch, signature_json \
         FROM flowing_gate_certificate_signatures WHERE handle = ?1 \
         ORDER BY issuer_id, issuer_epoch",
        &[text(handle)],
    )
    .map_err(sql_err)?
    .iter()
    .map(|row| {
        let signature: FlowingGateIssuerSignature = serde_json::from_str(&as_text(&row[3]))?;
        if signature.certificate_handle != as_text(&row[0])
            || signature.issuer_id != as_text(&row[1])
            || signature.issuer_epoch != as_i64(&row[2])
        {
            return Err(StoreError::Conflict(
                "flowing gate signature differs from its key".into(),
            ));
        }
        Ok(signature)
    })
    .collect()
}

/// The hosted ref CAS's issuer check, read inside the same atomic step.
fn issuer_refusal<S: DoSql>(
    sql: &S,
    handle: &str,
) -> StoreResult<Option<FlowingGateIssuerRefusal>> {
    Ok(verify_issued(
        handle,
        &read_trusted_issuers(sql)?,
        &read_signatures(sql, handle)?,
    )
    .err())
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
            if let Some(refusal) = issuer_refusal(&self.sql, &request.certificate_handle)? {
                // MUTATION-SUCCESS-EXPR: Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
                return Ok(O::Refused(R::GateIssuer(refusal)));
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
                if let Some(parked) = self.parked_flowing_unit(&unit.unit_id)? {
                    return Ok(Refused(R::UnitParked {
                        unit_id: unit.unit_id.clone(),
                        park_op_id: parked.request.op_id,
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
            if let Some(refusal) = issuer_refusal(&self.sql, &request.certificate_handle)? {
                return Ok(Refused(R::GateIssuer(refusal)));
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
            if let Err(refusal) = whipplescript_store::branches::flowing_coverage::check(
                certificate.coverage.as_ref(),
                read_coverage_premises(&self.sql)?.as_ref(),
                &request.candidate_manifest_hash,
            )? {
                return Ok(Refused(refusal));
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

    fn record_flowing_coverage_premises(
        &mut self,
        premises: &FlowingCoveragePremises,
    ) -> StoreResult<RecordCoveragePremisesOutcome> {
        exact_atomic(&self.sql, "flowing coverage premises", || {
            let existing = read_coverage_premises(&self.sql)?;
            let outcome = whipplescript_store::branches::flowing_coverage::record_outcome(
                existing.as_ref(),
                premises,
            );
            if let RecordCoveragePremisesOutcome::Recorded(next) = &outcome {
                self.sql
                    .execute(
                        "INSERT INTO flowing_coverage_premises (domain, premises_json) \
                         VALUES (?1, ?2) ON CONFLICT(domain) DO UPDATE SET \
                         premises_json = excluded.premises_json",
                        &[
                            text(HOME_COVERAGE_DOMAIN),
                            text(&serde_json::to_string(next)?),
                        ],
                    )
                    .map_err(sql_err)?;
            }
            Ok(outcome)
        })
    }

    fn configure_flowing_gate_issuer(
        &mut self,
        issuer: &FlowingGateTrustedIssuer,
    ) -> StoreResult<ConfigureFlowingGateIssuerOutcome> {
        exact_atomic(&self.sql, "flowing gate issuer configuration", || {
            let current = read_trusted_issuers(&self.sql)?
                .into_iter()
                .find(|current| current.issuer_id == issuer.issuer_id);
            let outcome = configure_issuer_outcome(current, issuer);
            if let ConfigureFlowingGateIssuerOutcome::Configured(configured) = &outcome {
                self.sql
                    .execute(
                        "INSERT INTO flowing_gate_trusted_issuers (issuer_id, issuer_json) \
                         VALUES (?1, ?2) ON CONFLICT(issuer_id) DO UPDATE SET issuer_json = ?2",
                        &[
                            text(&configured.issuer_id),
                            text(&serde_json::to_string(configured)?),
                        ],
                    )
                    .map_err(sql_err)?;
            }
            Ok(outcome)
        })
    }

    fn flowing_coverage_premises(&self) -> StoreResult<Option<FlowingCoveragePremises>> {
        read_coverage_premises(&self.sql)
    }

    fn flowing_gate_trusted_issuers(&self) -> StoreResult<Vec<FlowingGateTrustedIssuer>> {
        read_trusted_issuers(&self.sql)
    }

    fn record_flowing_gate_signature(
        &mut self,
        signature: &FlowingGateIssuerSignature,
    ) -> StoreResult<RecordFlowingGateSignatureOutcome> {
        use RecordFlowingGateSignatureOutcome as O;
        if let Err(field) = validate_issuer_signature(signature) {
            return Ok(O::Invalid { field });
        }
        exact_atomic(&self.sql, "flowing gate signature", || {
            if read_gate_certificate(&self.sql, &signature.certificate_handle)?.is_none() {
                return Ok(O::CertificateMissing);
            }
            if let Some(existing) = read_signatures(&self.sql, &signature.certificate_handle)?
                .into_iter()
                .find(|existing| {
                    existing.issuer_id == signature.issuer_id
                        && existing.issuer_epoch == signature.issuer_epoch
                })
            {
                if existing != *signature {
                    return Err(StoreError::Conflict(
                        "flowing gate signature differs from the one already retained".into(),
                    ));
                }
                return Ok(O::Existing(existing));
            }
            if let Err(refusal) = verify_issued(
                &signature.certificate_handle,
                &read_trusted_issuers(&self.sql)?,
                std::slice::from_ref(signature),
            ) {
                return Ok(O::Refused(refusal));
            }
            self.sql
                .execute(
                    "INSERT INTO flowing_gate_certificate_signatures \
                     (handle, issuer_id, issuer_epoch, signature_json) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        text(&signature.certificate_handle),
                        text(&signature.issuer_id),
                        int(signature.issuer_epoch),
                        text(&serde_json::to_string(signature)?),
                    ],
                )
                .map_err(sql_err)?;
            Ok(O::Recorded(signature.clone()))
        })
    }

    fn flowing_gate_signatures(
        &self,
        certificate_handle: &str,
    ) -> StoreResult<Vec<FlowingGateIssuerSignature>> {
        read_signatures(&self.sql, certificate_handle)
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
    use whipplescript_store::branches::flowing_close_roster::{
        FlowingCloseAttemptState, FlowingCloseRosterReader,
    };
    use whipplescript_store::branches::flowing_coverage::{
        FlowingCoverageBasis, FlowingCoverageClaim, FlowingCoverageUniverse,
        FlowingOwnerValidation, FlowingRequiredScope, FlowingScopeCoverage,
    };
    use whipplescript_store::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
    };
    use whipplescript_store::branches::flowing_parking::{
        FlowingParkOutcome, FlowingParkRefusal, ParkFlowingUnit,
    };
    use whipplescript_store::branches::flowing_sources::{
        FlowingSources, ReleasePrivateCut, ReleasePrivateCutOutcome,
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
        assert!(matches!(
            store
                .record_flowing_coverage_premises(&coverage_premises())
                .unwrap(),
            RecordCoveragePremisesOutcome::Recorded(_)
        ));
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
            coverage: Some(coverage_for(
                &coverage_premises(),
                &request.candidate_manifest_hash,
            )),
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
    fn hosted_malformed_coverage_premises_are_never_read_as_current() {
        let (sql, store) = fixture();
        let mut malformed = coverage_premises();
        malformed.registry_digest = " ".into();
        sql.execute(
            "UPDATE flowing_coverage_premises SET premises_json = ?1",
            &[text(&serde_json::to_string(&malformed).unwrap())],
        )
        .unwrap();
        let error = store.flowing_coverage_premises().unwrap_err();
        assert!(format!("{error:?}").contains("flowing coverage premises are malformed"));
    }

    #[test]
    fn hosted_ref_rechecks_coverage_premises_inside_the_trunk_cas() {
        let (sql, mut store) = fixture();
        let mut attempt = request("unit-a", "coverage-attempt");
        pin_attempt(&mut store, &attempt);
        let mut admit_with = |store: &mut DoBranches<Sql>,
                              coverage: Option<FlowingCoverageBasis>| {
            let mut certificate = certificate_for(&attempt);
            certificate.coverage = coverage;
            insert_gate_certificate(&sql, &certificate);
            attempt.certificate_handle = certificate.handle().unwrap();
            store.admit_flowing_prefix(&attempt).unwrap()
        };
        assert_eq!(
            admit_with(&mut store, None),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CoverageUnavailable)
        );

        let answered = coverage_premises();
        let captured = coverage_for(&answered, "candidate-manifest");
        let mut moved = answered.clone();
        moved.graph_epoch += 1;
        assert!(matches!(
            store.record_flowing_coverage_premises(&moved).unwrap(),
            RecordCoveragePremisesOutcome::Recorded(_)
        ));
        assert_eq!(
            admit_with(&mut store, Some(captured.clone())),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CoverageStale {
                premise: "graph"
            })
        );
        assert_eq!(
            store.record_flowing_coverage_premises(&answered).unwrap(),
            RecordCoveragePremisesOutcome::Regressed { premise: "graph" }
        );
        let mut recaptured = FlowingCoverageBasis::under(&moved).unwrap();
        recaptured.scopes = captured.scopes.clone();
        assert_eq!(
            admit_with(&mut store, Some(recaptured)),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CoverageOwnerUnvalidated {
                scope_id: "norm-relations@home".into(),
                owner: "owner-a".into(),
            })
        );

        let mut unowned = moved.clone();
        unowned.roster_digest = "sha256:roster-unowned".into();
        unowned.required_scopes[1].owners.clear();
        assert!(matches!(
            store.record_flowing_coverage_premises(&unowned).unwrap(),
            RecordCoveragePremisesOutcome::Recorded(_)
        ));
        let mut empty_query = coverage_for(&unowned, "candidate-manifest");
        empty_query.scopes[1].claim = FlowingCoverageClaim::Complete {
            examined_digest: "sha256:what-the-query-saw".into(),
            edge_digest: "sha256:no-edges".into(),
        };
        assert_eq!(
            admit_with(&mut store, Some(empty_query)),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CoverageScopeUnknown {
                scope_id: "norm-relations@home".into()
            })
        );
        assert!(store
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());

        let mut owned = unowned.clone();
        owned.roster_digest = "sha256:roster-owned".into();
        owned.required_scopes[1].owners = vec!["owner-a".into()];
        assert!(matches!(
            store.record_flowing_coverage_premises(&owned).unwrap(),
            RecordCoveragePremisesOutcome::Recorded(_)
        ));
        assert!(matches!(
            admit_with(&mut store, Some(coverage_for(&owned, "candidate-manifest"))),
            FlowingAdmissionOutcome::Admitted(_)
        ));
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
    fn hosted_retained_candidate_verification_reuses_real_content_and_complete_prefix() {
        use whipplescript_store::branches::flowing_sources::{
            DeclareContribution, FlowingSources, PinPrivateCut, ReleasePrivateCut,
            ReleasePrivateCutOutcome,
        };
        use whipplescript_store::source_review_types::{NativeRevision, NativeUnitRef};
        use whipplescript_store::vcs::{
            native_dependency_basis_digest, native_read_basis_digest, FlowingSelectionOutcome,
            FlowingTargetEffectsOutcome, NativeCandidateOutcome,
        };
        for named in [false, true] {
            for no_op in [false, true] {
                let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
                let mut vcs = crate::do_branches::compose_vcs_shared(&sql).unwrap();
                let mut refs = DoBranches::observe(sql.clone());
                vcs.init("t0").unwrap();
                vcs.write(MAINLINE_BRANCH_ID, "base.txt", Some("base"), "base", "t1")
                    .unwrap();
                let base = refs.get_cut("base").unwrap().unwrap();
                if named {
                    vcs.create_branch("branch", Some("feature"), MAINLINE_BRANCH_ID, "t2")
                        .unwrap();
                    refs.open_flowing_source(&OpenFlowingSource {
                        source_branch_id: "branch".into(),
                        incarnation_id: "branch-inc".into(),
                        kind: FlowingSourceKind::Branch,
                        owner: "coordinator".into(),
                        opened_at: "t2".into(),
                    })
                    .unwrap();
                }
                vcs.create_branch(
                    "twig",
                    None,
                    if named { "branch" } else { MAINLINE_BRANCH_ID },
                    "t2",
                )
                .unwrap();
                refs.open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t2".into(),
                })
                .unwrap();
                vcs.write("twig", "a.txt", Some("A"), "source-a", "t3")
                    .unwrap();
                if no_op {
                    vcs.write("twig", "a.txt", None, "source-undo", "t4")
                        .unwrap();
                }
                let source = refs.get_branch("twig").unwrap().unwrap();
                let source_id = source.head_cut_id.as_deref().unwrap();
                let source_manifest = source.head_manifest_hash.as_deref().unwrap();
                refs.pin_private_cut(PinPrivateCut {
                    pin_id: "pin",
                    twig_branch_id: "twig",
                    cut_id: source_id,
                    manifest_hash: source_manifest,
                    principal: "author",
                    retained_at: "t5",
                })
                .unwrap();
                refs.declare_contribution(DeclareContribution {
                    unit_id: "unit",
                    pin_id: "pin",
                    principal: "author",
                    intent: "change",
                    read_basis_digest: &native_read_basis_digest(
                        Some("base"),
                        Some(&base.manifest_hash),
                    ),
                    dependency_basis_digest: &native_dependency_basis_digest(&[]),
                    scope_digest: "scope",
                    declared_at: "t5",
                })
                .unwrap();
                let FlowingSelectionOutcome::Selected(selected) = vcs
                    .select_private_changes(
                        "pin",
                        &whipplescript_store::selection::parse("path(a.txt)").unwrap(),
                    )
                    .unwrap()
                else {
                    panic!("source atoms")
                };
                vcs.bind_private_selection("unit", &selected, "t6").unwrap();
                if named {
                    let target_id = "target";
                    let FlowingTargetEffectsOutcome::Verified(target) = vcs
                        .prepare_private_handoff_target("unit", target_id, "coordinator", "t7")
                        .unwrap()
                    else {
                        panic!("actual target content")
                    };
                    vcs.handoff_private_selection("handoff", &target, "coordinator", "t8")
                        .unwrap();
                    assert_eq!(
                        refs.release_private_cut(ReleasePrivateCut {
                            pin_id: "pin",
                            released_by: "coordinator",
                            reason: "handed",
                            released_at: "t9",
                        })
                        .unwrap(),
                        ReleasePrivateCutOutcome::Released
                    );
                }
                let source_branch = if named { "branch" } else { "twig" };
                let current = refs.get_branch(source_branch).unwrap().unwrap();
                let basis = refs.contribution_basis("unit").unwrap().unwrap();
                let revision = NativeRevision {
                    contribution_id: "review".into(),
                    sequence: 1,
                    upload_id: "upload".into(),
                    actor: "author".into(),
                    source_branch_id: source_branch.into(),
                    source_incarnation_id: if named { "branch-inc" } else { "twig-inc" }.into(),
                    source_cut_id: current.head_cut_id.unwrap(),
                    source_manifest_hash: current.head_manifest_hash.unwrap(),
                    units: vec![NativeUnitRef {
                        unit_id: "unit".into(),
                        source_cut_id: source_id.into(),
                        pin_id: "pin".into(),
                        basis_digest: basis.basis_digest,
                        principal: "author".into(),
                        intent: "change".into(),
                    }],
                };
                let candidate_id = if no_op { "base" } else { "candidate" };
                let prepared = if named {
                    vcs.prepare_named_branch_candidate(
                        &revision,
                        Some("base"),
                        candidate_id,
                        "coordinator",
                        "t10",
                    )
                } else {
                    vcs.prepare_native_review_candidate(
                        &revision,
                        Some("base"),
                        candidate_id,
                        "coordinator",
                        "t10",
                    )
                }
                .unwrap();
                let NativeCandidateOutcome::Prepared(candidate) = prepared else {
                    panic!("{prepared:?}")
                };
                vcs.retain_review_attempt(
                    "verify-attempt",
                    &candidate.candidate_witness_digest,
                    "t11",
                )
                .unwrap();
                let before = sql.query("SELECT total_changes()", &[]).unwrap();
                let observer = crate::do_branches::observe_vcs(&sql);
                let verified = observer
                    .verify_retained_native_candidate(
                        &revision,
                        &candidate.candidate_witness_digest,
                        "verify-attempt",
                    )
                    .unwrap();
                assert_eq!(
                    verified.subject().witness().units[0].outcome,
                    if no_op {
                        FlowingUnitOutcome::Neutralized
                    } else {
                        FlowingUnitOutcome::Applied
                    }
                );
                assert_eq!(sql.query("SELECT total_changes()", &[]).unwrap(), before);
                assert_eq!(
                    refs.get_branch(MAINLINE_BRANCH_ID)
                        .unwrap()
                        .unwrap()
                        .head_cut_id
                        .as_deref(),
                    Some("base")
                );
                let mut substituted = revision.clone();
                substituted.upload_id = "another-upload".into();
                assert!(observer
                    .verify_retained_native_candidate(
                        &substituted,
                        &candidate.candidate_witness_digest,
                        "verify-attempt"
                    )
                    .is_err());
                if !no_op {
                    let mismatch = if named {
                        vcs.prepare_named_branch_candidate(
                            &revision,
                            Some("base"),
                            "base",
                            "coordinator",
                            "t10",
                        )
                    } else {
                        vcs.prepare_native_review_candidate(
                            &revision,
                            Some("base"),
                            "base",
                            "coordinator",
                            "t10",
                        )
                    }
                    .unwrap();
                    assert_eq!(mismatch, NativeCandidateOutcome::CandidateMismatch);
                }
            }
        }
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

    fn coverage_premises() -> FlowingCoveragePremises {
        FlowingCoveragePremises {
            registry_digest: "sha256:registry-1".into(),
            roster_digest: "sha256:roster-1".into(),
            source_epoch: 1,
            lock_epoch: 1,
            graph_epoch: 1,
            required_scopes: vec![
                FlowingRequiredScope {
                    scope_id: "imports@home".into(),
                    universe: FlowingCoverageUniverse::Closed {
                        members_digest: "sha256:programs".into(),
                    },
                    owners: vec!["owner-a".into()],
                },
                FlowingRequiredScope {
                    scope_id: "norm-relations@home".into(),
                    universe: FlowingCoverageUniverse::Open,
                    owners: vec!["owner-a".into()],
                },
            ],
        }
    }

    fn coverage_for(premises: &FlowingCoveragePremises, candidate: &str) -> FlowingCoverageBasis {
        let mut basis = FlowingCoverageBasis::under(premises).unwrap();
        basis.scopes = vec![
            FlowingScopeCoverage {
                scope_id: "imports@home".into(),
                claim: FlowingCoverageClaim::Complete {
                    examined_digest: "sha256:programs".into(),
                    edge_digest: "sha256:edges".into(),
                },
                owner_validations: Vec::new(),
            },
            FlowingScopeCoverage {
                scope_id: "norm-relations@home".into(),
                claim: FlowingCoverageClaim::Unknown,
                owner_validations: vec![FlowingOwnerValidation {
                    owner: "owner-a".into(),
                    candidate_manifest_hash: candidate.into(),
                    graph_epoch: premises.graph_epoch,
                    evidence_digest: "sha256:owner-a-answer".into(),
                }],
            },
        ];
        basis
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
        let handle = certificate.handle().unwrap();
        insert_trusted_issuer(sql, &trusted_issuer(ISSUER, 1, 7));
        insert_signature(sql, &issuer_sign(&handle, ISSUER, 1, 7));
    }

    const ISSUER: &str = "fleet-gate";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn trusted_issuer(issuer_id: &str, epoch: i64, seed: u8) -> FlowingGateTrustedIssuer {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        FlowingGateTrustedIssuer {
            issuer_id: issuer_id.into(),
            epoch,
            public_key: hex(key.verifying_key().as_bytes()),
            configured_at: format!("epoch-{epoch}"),
        }
    }

    fn issuer_sign(
        handle: &str,
        issuer_id: &str,
        epoch: i64,
        seed: u8,
    ) -> FlowingGateIssuerSignature {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let message = whipplescript_store::branches::flowing_admission::issuer_signing_bytes(
            handle, issuer_id, epoch,
        )
        .unwrap();
        FlowingGateIssuerSignature {
            certificate_handle: handle.into(),
            issuer_id: issuer_id.into(),
            issuer_epoch: epoch,
            signature: hex(&key.sign(&message).to_bytes()),
        }
    }

    fn insert_trusted_issuer(sql: &Sql, issuer: &FlowingGateTrustedIssuer) {
        sql.execute(
            "INSERT OR IGNORE INTO flowing_gate_trusted_issuers (issuer_id, issuer_json) \
             VALUES (?1, ?2)",
            &[
                text(&issuer.issuer_id),
                text(&serde_json::to_string(issuer).unwrap()),
            ],
        )
        .unwrap();
    }

    /// Raw row write: models a writer that bypasses the recording API, so the
    /// hosted ref CAS is the check under test.
    fn insert_signature(sql: &Sql, signature: &FlowingGateIssuerSignature) {
        sql.execute(
            "INSERT OR IGNORE INTO flowing_gate_certificate_signatures \
             (handle, issuer_id, issuer_epoch, signature_json) VALUES (?1, ?2, ?3, ?4)",
            &[
                text(&signature.certificate_handle),
                text(&signature.issuer_id),
                int(signature.issuer_epoch),
                text(&serde_json::to_string(signature).unwrap()),
            ],
        )
        .unwrap();
    }

    fn clear_signatures(sql: &Sql) {
        sql.execute("DELETE FROM flowing_gate_certificate_signatures", &[])
            .unwrap();
    }

    fn assert_hosted_trunk_unmoved(store: &DoBranches<Sql>, attempt: &FlowingAdmissionRequest) {
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
    fn hosted_ref_requires_a_current_trusted_issuer_signature() {
        use FlowingGateIssuerRefusal as I;
        let (sql, mut store) = fixture();
        let attempt = request("unit-a", "issued");
        let handle = attempt.certificate_handle.clone();
        pin_attempt(&mut store, &attempt);
        let refused = |store: &mut DoBranches<Sql>, issuer: I| {
            assert_eq!(
                store.admit_flowing_prefix(&attempt).unwrap(),
                FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::GateIssuer(issuer))
            );
            assert_hosted_trunk_unmoved(store, &attempt);
        };

        sql.execute("DELETE FROM flowing_gate_trusted_issuers", &[])
            .unwrap();
        refused(&mut store, I::TrustRootMissing);

        insert_trusted_issuer(&sql, &trusted_issuer(ISSUER, 1, 7));
        clear_signatures(&sql);
        refused(&mut store, I::Unsigned);

        // Forged issuer: the trusted name over the exact handle, wrong key.
        insert_signature(&sql, &issuer_sign(&handle, ISSUER, 1, 9));
        refused(
            &mut store,
            I::BadSignature {
                issuer_id: ISSUER.into(),
            },
        );

        // Swapped digest: a genuine signature over another certificate.
        clear_signatures(&sql);
        let mut swapped = issuer_sign("sha256:other-certificate", ISSUER, 1, 7);
        swapped.certificate_handle = handle.clone();
        insert_signature(&sql, &swapped);
        refused(
            &mut store,
            I::BadSignature {
                issuer_id: ISSUER.into(),
            },
        );

        clear_signatures(&sql);
        insert_signature(&sql, &issuer_sign(&handle, "elsewhere", 1, 7));
        refused(&mut store, I::ForeignIssuer);

        // Old-epoch issuer: genuine at epoch 1, retired by a rotation.
        insert_signature(&sql, &issuer_sign(&handle, ISSUER, 1, 7));
        let rotated = trusted_issuer(ISSUER, 2, 8);
        assert_eq!(
            store.configure_flowing_gate_issuer(&rotated).unwrap(),
            ConfigureFlowingGateIssuerOutcome::Configured(rotated.clone())
        );
        assert_eq!(
            store
                .configure_flowing_gate_issuer(&trusted_issuer(ISSUER, 1, 7))
                .unwrap(),
            ConfigureFlowingGateIssuerOutcome::EpochNotAdvanced { current: 2 }
        );
        refused(
            &mut store,
            I::IssuerEpochMismatch {
                issuer_id: ISSUER.into(),
                signed: 1,
                current: 2,
            },
        );
        assert_eq!(
            store
                .record_flowing_gate_signature(&issuer_sign(&handle, ISSUER, 1, 7))
                .unwrap(),
            RecordFlowingGateSignatureOutcome::Existing(issuer_sign(&handle, ISSUER, 1, 7))
        );
        assert_eq!(
            store
                .record_flowing_gate_signature(&issuer_sign(&handle, ISSUER, 2, 7))
                .unwrap(),
            RecordFlowingGateSignatureOutcome::Refused(I::BadSignature {
                issuer_id: ISSUER.into()
            })
        );
        assert_eq!(
            store
                .record_flowing_gate_signature(&issuer_sign("sha256:absent", ISSUER, 2, 8))
                .unwrap(),
            RecordFlowingGateSignatureOutcome::CertificateMissing
        );

        let current = issuer_sign(&handle, ISSUER, 2, 8);
        assert_eq!(
            store.record_flowing_gate_signature(&current).unwrap(),
            RecordFlowingGateSignatureOutcome::Recorded(current)
        );
        let FlowingAdmissionOutcome::Admitted(receipt) =
            store.admit_flowing_prefix(&attempt).unwrap()
        else {
            panic!("a current issuer's signature admits");
        };

        // Restart after the CAS: a new authority over the same durable rows
        // returns the receipt, even once this issuer has rotated again.
        drop(store);
        let mut restarted = DoBranches::new(sql.clone()).unwrap();
        let again = trusted_issuer(ISSUER, 3, 9);
        assert_eq!(
            restarted.configure_flowing_gate_issuer(&again).unwrap(),
            ConfigureFlowingGateIssuerOutcome::Configured(again)
        );
        assert_eq!(
            restarted.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Existing(receipt)
        );
        assert_eq!(
            restarted
                .get_branch(MAINLINE_BRANCH_ID)
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some(attempt.candidate_cut_id.as_str())
        );
    }

    /// A trust-root or signature row whose JSON disagrees with its primary
    /// key is indeterminate: the hosted CAS and both read APIs refuse it.
    #[test]
    fn hosted_issuance_rows_that_differ_from_their_key_are_indeterminate() {
        let (sql, mut store) = fixture();
        let attempt = request("unit-a", "tampered-issuance");
        let handle = attempt.certificate_handle.clone();
        pin_attempt(&mut store, &attempt);
        let indeterminate = |store: &mut DoBranches<Sql>, what: &str| {
            assert!(
                matches!(
                    store.admit_flowing_prefix(&attempt),
                    Err(StoreError::Conflict(message)) if message.contains(what)
                ),
                "the hosted CAS refuses a {what} row"
            );
            assert_hosted_trunk_unmoved(store, &attempt);
        };
        let set_issuer_json = |issuer: &FlowingGateTrustedIssuer| {
            sql.execute(
                "UPDATE flowing_gate_trusted_issuers SET issuer_json = ?1 WHERE issuer_id = ?2",
                &[text(&serde_json::to_string(issuer).unwrap()), text(ISSUER)],
            )
            .unwrap();
        };
        let set_signature_json = |signature: &FlowingGateIssuerSignature| {
            sql.execute(
                "UPDATE flowing_gate_certificate_signatures SET signature_json = ?1 \
                 WHERE handle = ?2 AND issuer_id = ?3 AND issuer_epoch = 1",
                &[
                    text(&serde_json::to_string(signature).unwrap()),
                    text(&handle),
                    text(ISSUER),
                ],
            )
            .unwrap();
        };
        let trusted = trusted_issuer(ISSUER, 1, 7);
        let signed = issuer_sign(&handle, ISSUER, 1, 7);

        // Trust root: the row names another issuer, then carries an invalid key.
        let issuer_differs = "trusted issuer differs from its key";
        let mut renamed = trusted.clone();
        renamed.issuer_id = "elsewhere".into();
        let mut unkeyed = trusted.clone();
        unkeyed.public_key = "zz".into();
        for tampered in [renamed, unkeyed] {
            set_issuer_json(&tampered);
            indeterminate(&mut store, issuer_differs);
            assert!(matches!(
                store.flowing_gate_trusted_issuers(),
                Err(StoreError::Conflict(message)) if message.contains(issuer_differs)
            ));
        }
        set_issuer_json(&trusted);

        // Signature: the row's handle, issuer or epoch disagrees with its key.
        let signature_differs = "signature differs from its key";
        let mut rehandled = signed.clone();
        rehandled.certificate_handle = "sha256:other-certificate".into();
        let mut reissued = signed.clone();
        reissued.issuer_id = "elsewhere".into();
        let mut reepoched = signed.clone();
        reepoched.issuer_epoch = 2;
        for tampered in [rehandled, reissued, reepoched] {
            set_signature_json(&tampered);
            indeterminate(&mut store, signature_differs);
            assert!(matches!(
                store.flowing_gate_signatures(&handle),
                Err(StoreError::Conflict(message)) if message.contains(signature_differs)
            ));
        }
        set_signature_json(&signed);
        assert_eq!(store.flowing_gate_trusted_issuers().unwrap(), vec![trusted]);
        assert_eq!(
            store.flowing_gate_signatures(&handle).unwrap(),
            vec![signed.clone()]
        );

        // A different row already under the key is not silently kept or replaced.
        clear_signatures(&sql);
        insert_signature(&sql, &issuer_sign(&handle, ISSUER, 1, 9));
        assert!(matches!(
            store.record_flowing_gate_signature(&signed),
            Err(StoreError::Conflict(message)) if message.contains("already retained")
        ));
        clear_signatures(&sql);
        insert_signature(&sql, &signed);
        assert!(matches!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
    }

    #[test]
    fn hosted_finish_requires_an_issued_certificate() {
        let (sql, mut store) = fixture();
        let attempt = terminal_request(&sql, "unsigned-finish", FlowingGateVerdict::Unrun);
        pin_attempt(&mut store, &attempt);
        clear_signatures(&sql);
        assert_eq!(
            store.finish_flowing_attempt(&attempt).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::GateIssuer(
                FlowingGateIssuerRefusal::Unsigned
            ))
        );
        assert!(store
            .flowing_finish_for_attempt(&attempt.op_id)
            .unwrap()
            .is_none());
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

    fn park_request(op_id: &str, unit_id: &str) -> ParkFlowingUnit {
        ParkFlowingUnit {
            op_id: op_id.into(),
            unit_id: unit_id.into(),
            source_branch_id: "twig".into(),
            source_incarnation_id: "inc".into(),
            source_cut_id: "source".into(),
            source_manifest_hash: "source-manifest".into(),
            basis_digest: format!("basis-{}", unit_id.strip_prefix("unit-").unwrap()),
            principal: "author".into(),
            intent: "change".into(),
            expected_eligibility_epoch: 0,
            expected_owner_epoch: 0,
            parked_holder_id: "park:repair-owner".into(),
            actor: "coordinator".into(),
            recorded_at: "t4".into(),
        }
    }

    #[test]
    fn park_first_retains_exact_holder_and_fences_hosted_trunk_cas() {
        let (sql, mut store) = fixture();
        let attempt = request("unit-a", "admission-a");
        pin_attempt(&mut store, &attempt);
        let park = park_request("park-a", "unit-a");
        let FlowingParkOutcome::Parked(receipt) = store.park_flowing_unit(&park).unwrap() else {
            panic!("expected parked receipt");
        };
        let evidence = whipplescript_store::branches::flowing_parking_host::read_parking_evidence(
            &store, "park-a",
        )
        .unwrap()
        .unwrap();
        assert_eq!(evidence.unit_id, "unit-a");
        assert_eq!(evidence.parked_holder_id, "park:repair-owner");
        assert_eq!(evidence.resulting_eligibility_epoch, 1);
        assert_eq!(receipt.former_holder.holder_cut_id, "source");
        assert_eq!(receipt.source_fence_after.eligibility_epoch, 1);
        assert_eq!(
            store.parked_flowing_unit("unit-a").unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            store.parked_holder_units("park:repair-owner").unwrap(),
            vec![receipt.clone()]
        );
        assert!(store.parked_holder_units("park:other").unwrap().is_empty());
        assert!(matches!(
            store.park_flowing_unit(&park).unwrap(),
            FlowingParkOutcome::Existing(existing) if existing == receipt
        ));
        assert!(matches!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::StaleEligibilityEpoch {
                current: 1
            })
        ));
        let mut fresh = request("unit-a", "admission-fresh");
        fresh.expected_eligibility_epoch = 1;
        assert_eq!(
            store.admit_flowing_prefix(&fresh).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::UnitParked {
                unit_id: "unit-a".into(),
                park_op_id: "park-a".into(),
            })
        );
        assert!(whipplescript_store::branches::flowing_holders::capture(
            &store,
            &witness_for(&attempt)
        )
        .unwrap()
        .is_none());
        assert!(store.admitted_unit_operation("unit-a").unwrap().is_none());
        assert_eq!(
            store
                .flowing_fence_receipt("park-a")
                .unwrap()
                .unwrap()
                .state,
            receipt.source_fence_after
        );
        assert_eq!(
            store
                .park_flowing_unit(&park_request("other-park", "unit-a"))
                .unwrap(),
            FlowingParkOutcome::AlreadyParked(receipt)
        );
        let reopened = DoBranches::new(sql).unwrap();
        assert_eq!(
            reopened
                .parked_flowing_unit("unit-a")
                .unwrap()
                .unwrap()
                .request
                .op_id,
            "park-a"
        );
        assert_eq!(
            reopened
                .parked_holder_units("park:repair-owner")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn terminal_parking_keeps_the_hosted_source_cut_after_private_pin_release() {
        let (sql, mut store) = fixture();
        assert!(matches!(
            store
                .park_flowing_unit(&park_request("park-a", "unit-a"))
                .unwrap(),
            FlowingParkOutcome::Parked(_)
        ));
        let release = ReleasePrivateCut {
            pin_id: "pin",
            released_by: "author",
            reason: "all declared work transferred to parked holders",
            released_at: "t5",
        };
        assert_eq!(
            store.release_private_cut(release).unwrap(),
            ReleasePrivateCutOutcome::HasDeclaredUnit
        );
        let mut park_b = park_request("park-b", "unit-b");
        park_b.expected_eligibility_epoch = store
            .flowing_source("twig")
            .unwrap()
            .unwrap()
            .eligibility_epoch;
        assert!(matches!(
            store.park_flowing_unit(&park_b).unwrap(),
            FlowingParkOutcome::Parked(_)
        ));
        assert_eq!(
            store.release_private_cut(release).unwrap(),
            ReleasePrivateCutOutcome::Released
        );
        let reopened = DoBranches::new(sql).unwrap();
        assert_eq!(
            reopened
                .private_cut_pin("pin")
                .unwrap()
                .unwrap()
                .released_at
                .as_deref(),
            Some("t5")
        );
        assert!(reopened
            .pinned_cuts("year-3000")
            .unwrap()
            .contains("source"));
    }

    #[test]
    fn admitted_unit_keeps_the_hosted_source_cut_after_private_and_attempt_pin_release() {
        let (sql, mut store) = fixture();
        sql.execute(
            "DELETE FROM flowing_contribution_basis WHERE unit_id = 'unit-b'",
            &[],
        )
        .unwrap();
        sql.execute(
            "DELETE FROM flowing_contributions WHERE unit_id = 'unit-b'",
            &[],
        )
        .unwrap();
        let attempt = request("unit-a", "fixture");
        pin_attempt(&mut store, &attempt);
        assert!(matches!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        assert_eq!(
            store
                .release_private_cut(ReleasePrivateCut {
                    pin_id: "pin",
                    released_by: "author",
                    reason: "declared unit admitted",
                    released_at: "t5",
                })
                .unwrap(),
            ReleasePrivateCutOutcome::Released
        );
        // Model the later receipt reconciliation that releases the attempt pin.
        sql.execute(
            "UPDATE flowing_attempt_pins SET released_at = 't6' WHERE op_id = 'fixture'",
            &[],
        )
        .unwrap();
        assert!(store.pinned_cuts("year-3000").unwrap().contains("source"));
    }

    #[test]
    fn hosted_close_roster_keeps_pending_and_admitted_attempts() {
        let (sql, mut store) = fixture();
        let attempt = request("unit-a", "fixture");
        assert!(store
            .flowing_close_roster("twig")
            .unwrap()
            .unwrap()
            .live_attempts
            .is_empty());
        pin_attempt(&mut store, &attempt);
        let pending = store.flowing_close_roster("twig").unwrap().unwrap();
        assert_eq!(pending.live_attempts.len(), 1);
        assert_eq!(
            pending.live_attempts[0].state,
            FlowingCloseAttemptState::Pending
        );
        assert_eq!(pending.live_attempts[0].unit_ids, ["unit-a"]);
        assert!(matches!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        let admitted = store.flowing_close_roster("twig").unwrap().unwrap();
        assert_eq!(
            admitted.live_attempts[0].state,
            FlowingCloseAttemptState::Admitted
        );
        sql.execute(
            "UPDATE flowing_attempt_pins SET witness_digest = 'missing' WHERE op_id = 'fixture'",
            &[],
        )
        .unwrap();
        assert!(matches!(
            store.flowing_close_roster("twig"),
            Err(StoreError::Conflict(message)) if message.contains("lost its candidate witness")
        ));
    }

    #[test]
    fn trunk_cas_first_returns_exact_admission_to_hosted_parking() {
        let (sql, mut store) = fixture();
        let attempt = request("unit-a", "admission-a");
        pin_attempt(&mut store, &attempt);
        record_gate_certificate(&sql, &attempt);
        let FlowingAdmissionOutcome::Admitted(admitted) =
            store.admit_flowing_prefix(&attempt).unwrap()
        else {
            panic!("expected admission");
        };
        assert_eq!(
            store
                .park_flowing_unit(&park_request("park-a", "unit-a"))
                .unwrap(),
            FlowingParkOutcome::AlreadyAdmitted(admitted)
        );
        assert!(store.parked_flowing_unit("unit-a").unwrap().is_none());
        assert!(store.flowing_fence_receipt("park-a").unwrap().is_none());
    }

    #[test]
    fn hosted_parking_rejects_corrupt_ref_receipts_and_missing_retained_cut() {
        for statement in [
            "UPDATE flowing_parked_units SET holder_id = 'wrong' WHERE unit_id = 'unit-a'",
            "DELETE FROM cuts WHERE cut_id = 'source'",
        ] {
            let (sql, mut store) = fixture();
            assert!(matches!(
                store
                    .park_flowing_unit(&park_request("park-a", "unit-a"))
                    .unwrap(),
                FlowingParkOutcome::Parked(_)
            ));
            sql.execute(statement, &[]).unwrap();
            let error = store.parked_flowing_unit("unit-a").unwrap_err();
            let expected = if statement.starts_with("UPDATE") {
                "flowing park receipt differs from its ref keys"
            } else {
                "flowing parked holder lost its retained cut"
            };
            assert!(format!("{error:?}").contains(expected));
        }
    }

    #[test]
    fn hosted_parking_refuses_dangling_admission_index() {
        let (sql, mut store) = fixture();
        sql.execute("PRAGMA foreign_keys = OFF", &[]).unwrap();
        sql.execute(
            "INSERT INTO flowing_admitted_units (unit_id, op_id) VALUES ('unit-a', 'missing')",
            &[],
        )
        .unwrap();
        sql.execute("PRAGMA foreign_keys = ON", &[]).unwrap();
        let error = store
            .park_flowing_unit(&park_request("park-a", "unit-a"))
            .unwrap_err();
        assert!(format!("{error:?}").contains("admitted flowing unit lost its receipt"));
        assert!(store.parked_flowing_unit("unit-a").unwrap().is_none());
    }

    #[test]
    fn hosted_parking_refuses_changed_owner_epoch_and_bad_basis() {
        let (_sql, mut store) = fixture();
        let mut bad_basis = park_request("park-a", "unit-a");
        bad_basis.basis_digest = "wrong".into();
        assert_eq!(
            store.park_flowing_unit(&bad_basis).unwrap(),
            FlowingParkOutcome::Refused(FlowingParkRefusal::UnitHolderUnavailable)
        );
        let mut stale = park_request("park-b", "unit-a");
        stale.expected_owner_epoch = 1;
        assert_eq!(
            store.park_flowing_unit(&stale).unwrap(),
            FlowingParkOutcome::Refused(FlowingParkRefusal::StaleOwnerEpoch { current: 0 })
        );
        let mut wrong_owner = park_request("park-c", "unit-a");
        wrong_owner.actor = "other".into();
        assert_eq!(
            store.park_flowing_unit(&wrong_owner).unwrap(),
            FlowingParkOutcome::Refused(FlowingParkRefusal::WrongOwner)
        );
        assert!(store.parked_flowing_unit("unit-a").unwrap().is_none());
    }

    #[test]
    fn hosted_park_receipt_and_fence_roll_back_together() {
        let (sql, mut store) = fixture();
        sql.execute(
            "CREATE TRIGGER fail_park_fence BEFORE INSERT ON flowing_source_fence_ops \
             WHEN NEW.op_id = 'park-a' BEGIN SELECT RAISE(ABORT, 'fence write failed'); END",
            &[],
        )
        .unwrap();
        assert!(store
            .park_flowing_unit(&park_request("park-a", "unit-a"))
            .is_err());
        assert!(store.parked_flowing_unit("unit-a").unwrap().is_none());
        assert!(store.flowing_fence_receipt("park-a").unwrap().is_none());
        assert_eq!(
            store
                .flowing_source("twig")
                .unwrap()
                .unwrap()
                .eligibility_epoch,
            0
        );
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
    fn hosted_close_roster_distinguishes_cancelled_failed_and_unrun_attempts() {
        for (verdict, expected) in [
            (FlowingGateVerdict::Failed, FlowingCloseAttemptState::Failed),
            (FlowingGateVerdict::Unrun, FlowingCloseAttemptState::Unrun),
        ] {
            let (sql, mut store) = fixture();
            let attempt = terminal_request(&sql, "terminal", verdict);
            pin_attempt(&mut store, &attempt);
            assert!(matches!(
                store.finish_flowing_attempt(&attempt).unwrap(),
                FlowingAttemptFinishOutcome::Finished(_)
            ));
            assert_eq!(
                store
                    .flowing_close_roster("twig")
                    .unwrap()
                    .unwrap()
                    .live_attempts[0]
                    .state,
                expected
            );
        }
        let (_sql, mut store) = fixture();
        let attempt = request("unit-a", "fixture");
        pin_attempt(&mut store, &attempt);
        assert!(matches!(
            store
                .cancel_flowing_attempt(&cancel("fixture", "cancel-a"))
                .unwrap(),
            FlowingCancelOutcome::Cancelled(_)
        ));
        assert_eq!(
            store
                .flowing_close_roster("twig")
                .unwrap()
                .unwrap()
                .live_attempts[0]
                .state,
            FlowingCloseAttemptState::Cancelled {
                cancel_op_id: "cancel-a".into()
            }
        );
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
        let host_evidence = whipplescript_store::branches::flowing_host::read_admission_evidence(
            &store,
            "admission-a",
        )
        .unwrap()
        .expect("landed hosted ref operation has host evidence");
        assert_eq!(host_evidence.operation_id, receipt.request.op_id);
        assert_eq!(
            host_evidence.resulting_trunk_cut_id,
            receipt.request.candidate_cut_id
        );
        assert_eq!(host_evidence.units.len(), receipt.request.units.len());
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
    fn hosted_host_evidence_refuses_an_admitted_ref_with_a_missing_candidate_witness() {
        let (sql, mut store) = fixture();
        let admission = request("unit-a", "admission-a");
        pin_attempt(&mut store, &admission);
        assert!(matches!(
            store.admit_flowing_prefix(&admission).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        sql.execute(
            "DELETE FROM flowing_candidate_witnesses WHERE digest = ?1",
            &[text(&admission.candidate_witness_digest)],
        )
        .unwrap();
        assert!(
            whipplescript_store::branches::flowing_host::read_admission_evidence(
                &store,
                "admission-a"
            )
            .is_err()
        );
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
