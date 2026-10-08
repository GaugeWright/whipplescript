use std::collections::BTreeSet;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    check_fence, validate_cancel_request, validate_request, FlowingAdmissionOutcome,
    FlowingAdmissionReceipt, FlowingAdmissionRefusal, FlowingAdmissionRequest, FlowingAdmissions,
    FlowingAttemptFinishOutcome, FlowingAttemptFinishReceipt, FlowingAttemptFinishRefusal,
    FlowingAttemptPin, FlowingCancelOutcome, FlowingCancelReceipt, FlowingCancelRefusal,
    FlowingCancelRequest, FlowingCandidateWitness, FlowingGateCertificate, FlowingGateEvidence,
    FlowingGateIssuerRefusal, FlowingGateIssuerSignature, FlowingGateTrustedIssuer,
    FlowingGateVerdict, FlowingUnitOutcome, ReleaseFlowingAttemptOutcome,
    RetainFlowingAttemptOutcome,
};
use super::{ConfigureFlowingGateIssuerOutcome, RecordFlowingGateSignatureOutcome};
use crate::branches::flowing_coverage::{
    FlowingCoveragePremises, RecordCoveragePremisesOutcome, HOME_COVERAGE_DOMAIN,
};
use crate::branches::flowing_fence;
use crate::branches::flowing_fence::FlowingSourceKind;
use crate::branches::{BranchStatus, BranchStore, MAINLINE_BRANCH_ID, MAINLINE_GATE_LEASE};
use crate::{StoreError, StoreResult};

pub(crate) fn read_receipt(
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

fn read_finish(
    connection: &Connection,
    op_id: &str,
) -> StoreResult<Option<FlowingAttemptFinishReceipt>> {
    let row: Option<(String, String)> = connection
        .query_row(
            "SELECT op_id, receipt_json FROM flowing_attempt_finishes WHERE op_id = ?1",
            [op_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(stored_op_id, json)| {
        let receipt: FlowingAttemptFinishReceipt = serde_json::from_str(&json)?;
        if receipt.request.op_id != stored_op_id
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

fn read_attempt_pin(
    connection: &Connection,
    op_id: &str,
) -> StoreResult<Option<FlowingAttemptPin>> {
    connection
        .query_row(
            "SELECT op_id, witness_digest, source_cut_id, candidate_cut_id, \
             retained_at, released_at FROM flowing_attempt_pins WHERE op_id = ?1",
            [op_id],
            |row| {
                Ok(FlowingAttemptPin {
                    op_id: row.get(0)?,
                    witness_digest: row.get(1)?,
                    source_cut_id: row.get(2)?,
                    candidate_cut_id: row.get(3)?,
                    retained_at: row.get(4)?,
                    released_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

struct HandoffHolder {
    target_branch: String,
    target_cut: String,
    target_manifest: String,
    source_branch: String,
    source_cut: String,
    source_manifest: String,
    source_basis: String,
    original_principal: String,
}

fn missing_unit_holder(
    connection: &Connection,
    witness: &FlowingCandidateWitness,
) -> StoreResult<Option<String>> {
    for unit in &witness.units {
        let handoff: Option<HandoffHolder> = connection
            .query_row(
                "SELECT target_branch_id, target_after_cut_id, target_after_manifest_hash, \
                     source_branch_id, source_cut_id, source_manifest_hash, \
                     source_basis_digest, original_principal \
                     FROM flowing_handoffs WHERE unit_id = ?1",
                [&unit.unit_id],
                |row| {
                    Ok(HandoffHolder {
                        target_branch: row.get(0)?,
                        target_cut: row.get(1)?,
                        target_manifest: row.get(2)?,
                        source_branch: row.get(3)?,
                        source_cut: row.get(4)?,
                        source_manifest: row.get(5)?,
                        source_basis: row.get(6)?,
                        original_principal: row.get(7)?,
                    })
                },
            )
            .optional()?;
        if let Some(handoff) = handoff {
            let declaration: Option<(String, String, String, String, String, String)> = connection
                .query_row(
                    "SELECT c.source_branch_id, c.source_cut_id, c.source_manifest_hash, \
                     c.principal, c.intent, b.basis_digest \
                     FROM flowing_contributions c \
                     JOIN flowing_contribution_basis b ON b.unit_id = c.unit_id \
                     WHERE c.unit_id = ?1",
                    [&unit.unit_id],
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
            let Some((declared_branch, declared_cut, declared_manifest, principal, intent, basis)) =
                declaration
            else {
                return Ok(Some(unit.unit_id.clone()));
            };
            let source_row = BranchStore::row_by_id(connection, &handoff.source_branch)?;
            let Some(target_row) = BranchStore::row_by_id(connection, &handoff.target_branch)?
            else {
                return Ok(Some(unit.unit_id.clone()));
            };
            let Some(target_head) = target_row.head_cut_id.as_deref() else {
                return Ok(Some(unit.unit_id.clone()));
            };
            let source_cut_row = BranchStore::cut_by_id(connection, &handoff.source_cut)?;
            let target_cut_row = BranchStore::cut_by_id(connection, &handoff.target_cut)?;
            let held = handoff.target_branch == witness.source_branch_id
                && handoff.source_branch == declared_branch
                && handoff.source_cut == declared_cut
                && handoff.source_manifest == declared_manifest
                && handoff.source_basis == basis
                && handoff.source_basis == unit.basis_digest
                && handoff.original_principal == principal
                && principal == unit.principal
                && intent == unit.intent
                && source_row.as_ref().is_some_and(|row| {
                    row.name.is_none()
                        && row.parent_branch_id.as_deref() == Some(handoff.target_branch.as_str())
                })
                && target_row.status == BranchStatus::Active
                && target_row.name.is_some()
                && source_cut_row.as_ref().is_some_and(|cut| {
                    cut.branch_id == handoff.source_branch
                        && cut.manifest_hash == handoff.source_manifest
                })
                && target_cut_row.as_ref().is_some_and(|cut| {
                    cut.branch_id == handoff.target_branch
                        && cut.manifest_hash == handoff.target_manifest
                })
                && ancestor(connection, &handoff.target_cut, &witness.source_cut_id)?
                && ancestor(connection, &witness.source_cut_id, target_head)?;
            if !held {
                return Ok(Some(unit.unit_id.clone()));
            }
            continue;
        }
        let cut: Option<String> = connection
            .query_row(
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
                params![
                    &unit.unit_id,
                    &witness.source_branch_id,
                    &unit.principal,
                    &unit.intent,
                    &unit.basis_digest
                ],
                |row| row.get(0),
            )
            .optional()?;
        let Some(cut) = cut else {
            return Ok(Some(unit.unit_id.clone()));
        };
        if !ancestor(connection, &cut, &witness.source_cut_id)? {
            return Ok(Some(unit.unit_id.clone()));
        }
    }
    Ok(None)
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

fn read_trusted_issuers(connection: &Connection) -> StoreResult<Vec<FlowingGateTrustedIssuer>> {
    let mut statement = connection.prepare(
        "SELECT issuer_id, issuer_json FROM flowing_gate_trusted_issuers ORDER BY issuer_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut issuers = Vec::new();
    for row in rows {
        let (issuer_id, json) = row?;
        let issuer: FlowingGateTrustedIssuer = serde_json::from_str(&json)?;
        if issuer.issuer_id != issuer_id || super::validate_trusted_issuer(&issuer).is_err() {
            return Err(StoreError::Conflict(
                "flowing gate trusted issuer differs from its key".into(),
            ));
        }
        issuers.push(issuer);
    }
    Ok(issuers)
}

fn read_signatures(
    connection: &Connection,
    handle: &str,
) -> StoreResult<Vec<FlowingGateIssuerSignature>> {
    let mut statement = connection.prepare(
        "SELECT handle, issuer_id, issuer_epoch, signature_json \
         FROM flowing_gate_certificate_signatures WHERE handle = ?1 \
         ORDER BY issuer_id, issuer_epoch",
    )?;
    let rows = statement.query_map([handle], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    let mut signatures = Vec::new();
    for row in rows {
        let (stored_handle, issuer_id, epoch, json) = row?;
        let signature: FlowingGateIssuerSignature = serde_json::from_str(&json)?;
        if signature.certificate_handle != stored_handle
            || signature.issuer_id != issuer_id
            || signature.issuer_epoch != epoch
        {
            return Err(StoreError::Conflict(
                "flowing gate signature differs from its key".into(),
            ));
        }
        signatures.push(signature);
    }
    Ok(signatures)
}

/// The ref CAS's issuer check: the exact handle must carry a signature from an
/// issuer the trust root holds now, read inside the same transaction.
fn issuer_refusal(
    connection: &Connection,
    handle: &str,
) -> StoreResult<Option<FlowingGateIssuerRefusal>> {
    Ok(super::verify_issued(
        handle,
        &read_trusted_issuers(connection)?,
        &read_signatures(connection, handle)?,
    )
    .err())
}

impl BranchStore {
    /// Trusted native gate writer. The certificate and every raw result are
    /// committed together; a retry may reuse the same handle but cannot
    /// replace bytes under an existing digest.
    pub(crate) fn record_native_gate_certificate(
        &mut self,
        certificate: &FlowingGateCertificate,
        evidence: &[FlowingGateEvidence],
    ) -> StoreResult<String> {
        if certificate.required_checks.len() != evidence.len()
            || certificate.admission_refusal() == Some(FlowingAdmissionRefusal::GatePlanIncomplete)
        {
            return Err(StoreError::Conflict(
                "native gate plan is incomplete".into(),
            ));
        }
        for (check, result) in certificate.checks.iter().zip(evidence) {
            if check.check_id != result.check_id
                || check.input_digest != result.input_digest
                || check.evidence_digest != result.digest()?
                || check.verdict != result.verdict()
                || result.started == result.run_error.is_some()
                || (!result.started
                    && (result.exit_code.is_some()
                        || !result.stdout.is_empty()
                        || !result.stderr.is_empty()
                        || result.run_error.as_deref().is_none_or(str::is_empty)))
            {
                return Err(StoreError::Conflict(
                    "native gate result differs from its evidence".into(),
                ));
            }
        }
        let handle = certificate.handle()?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for result in evidence {
            let digest = result.digest()?;
            tx.execute(
                "INSERT OR IGNORE INTO flowing_gate_evidence (digest, evidence_json) VALUES (?1, ?2)",
                params![&digest, serde_json::to_string(result)?],
            )?;
            let stored: String = tx.query_row(
                "SELECT evidence_json FROM flowing_gate_evidence WHERE digest = ?1",
                [&digest],
                |row| row.get(0),
            )?;
            let stored: FlowingGateEvidence = serde_json::from_str(&stored)?;
            if stored != *result || stored.digest()? != digest {
                return Err(StoreError::Conflict(
                    "native gate evidence differs from its digest key".into(),
                ));
            }
        }
        tx.execute(
            "INSERT OR IGNORE INTO flowing_gate_certificates (handle, certificate_json) VALUES (?1, ?2)",
            params![&handle, serde_json::to_string(certificate)?],
        )?;
        if read_gate_certificate(&tx, &handle)?.as_ref() != Some(certificate) {
            return Err(StoreError::Conflict(
                "native gate certificate differs from its handle".into(),
            ));
        }
        tx.commit()?;
        Ok(handle)
    }

    pub fn native_gate_certificate(
        &self,
        handle: &str,
    ) -> StoreResult<Option<FlowingGateCertificate>> {
        read_gate_certificate(&self.connection, handle)
    }

    pub fn native_gate_evidence(&self, digest: &str) -> StoreResult<Option<FlowingGateEvidence>> {
        let json: Option<String> = self
            .connection
            .query_row(
                "SELECT evidence_json FROM flowing_gate_evidence WHERE digest = ?1",
                [digest],
                |row| row.get(0),
            )
            .optional()?;
        json.map(|json| {
            let result: FlowingGateEvidence = serde_json::from_str(&json)?;
            if result.digest()? != digest {
                return Err(StoreError::Conflict(
                    "native gate evidence differs from its digest key".into(),
                ));
            }
            Ok(result)
        })
        .transpose()
    }
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

pub(crate) fn read_coverage_premises(
    connection: &Connection,
) -> StoreResult<Option<FlowingCoveragePremises>> {
    let json: Option<String> = connection
        .query_row(
            "SELECT premises_json FROM flowing_coverage_premises WHERE domain = ?1",
            [HOME_COVERAGE_DOMAIN],
            |row| row.get(0),
        )
        .optional()?;
    json.map(|json| {
        let premises: FlowingCoveragePremises = serde_json::from_str(&json)?;
        if premises.invalid_field().is_some() {
            return Err(StoreError::Conflict(
                "flowing coverage premises are malformed".into(),
            ));
        }
        Ok(premises)
    })
    .transpose()
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
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(pin) = read_attempt_pin(&tx, op_id)? {
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
        if read_receipt(&tx, op_id)?.is_some()
            || read_cancellation(&tx, "admission_op_id", op_id)?.is_some()
            || read_finish(&tx, op_id)?.is_some()
        {
            return Ok(O::AttemptTerminal);
        }
        let Some(witness) = read_witness(&tx, witness_digest)? else {
            return Ok(O::WitnessMissing);
        };
        if witness.units.is_empty() {
            return Ok(O::Invalid { field: "units" });
        }
        let Some(source) = BranchStore::cut_by_id(&tx, &witness.source_cut_id)? else {
            return Ok(O::SourceCutMissing);
        };
        if source.branch_id != witness.source_branch_id
            || source.manifest_hash != witness.source_manifest_hash
        {
            return Ok(O::SourceCutMismatch);
        }
        let Some(candidate) = BranchStore::cut_by_id(&tx, &witness.candidate_cut_id)? else {
            return Ok(O::CandidateCutMissing);
        };
        if candidate.branch_id != MAINLINE_BRANCH_ID
            || candidate.manifest_hash != witness.candidate_manifest_hash
        {
            return Ok(O::CandidateCutMismatch);
        }
        if let Some(unit_id) = missing_unit_holder(&tx, &witness)? {
            return Ok(O::UnitHolderMissing { unit_id });
        }
        tx.execute(
            "INSERT INTO flowing_attempt_pins \
             (op_id, witness_digest, source_cut_id, candidate_cut_id, retained_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                op_id,
                witness_digest,
                &witness.source_cut_id,
                &witness.candidate_cut_id,
                retained_at
            ],
        )?;
        let pin = read_attempt_pin(&tx, op_id)?.expect("inserted attempt pin");
        tx.commit()?;
        Ok(O::Retained(pin))
    }

    fn flowing_attempt_pin(&self, op_id: &str) -> StoreResult<Option<FlowingAttemptPin>> {
        read_attempt_pin(&self.connection, op_id)
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
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(pin) = read_attempt_pin(&tx, op_id)? else {
            return Ok(O::Missing);
        };
        if pin.released_at.is_some() {
            return Ok(O::AlreadyReleased);
        }
        if read_receipt(&tx, op_id)?.is_some() {
            return Ok(O::Admitted);
        }
        let cancelled = read_cancellation(&tx, "admission_op_id", op_id)?;
        let finished = read_finish(&tx, op_id)?;
        if cancelled.is_none() && finished.is_none() {
            return Ok(O::NotTerminal);
        }
        if cancelled.is_some() && finished.is_some() {
            return Err(StoreError::Conflict(
                "flowing attempt has conflicting terminal receipts".into(),
            ));
        }
        let Some(witness) = read_witness(&tx, &pin.witness_digest)? else {
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
        if let Some(unit_id) = missing_unit_holder(&tx, &witness)? {
            return Ok(O::UnitHolderMissing { unit_id });
        }
        tx.execute(
            "UPDATE flowing_attempt_pins SET released_at = ?2 WHERE op_id = ?1",
            params![op_id, released_at],
        )?;
        tx.commit()?;
        Ok(O::Released)
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
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_finish(&tx, &request.op_id)? {
            if existing.request != *request {
                return Ok(O::Refused(R::IdentityMismatch));
            }
            return Ok(O::Existing(existing));
        }
        if let Some(admitted) = read_receipt(&tx, &request.op_id)? {
            if admitted.request != *request {
                return Ok(O::Refused(R::IdentityMismatch));
            }
            return Ok(O::AlreadyAdmitted(Box::new(admitted)));
        }
        if let Some(cancelled) = read_cancellation(&tx, "admission_op_id", &request.op_id)? {
            if cancelled.request.source_branch_id != request.source_branch_id
                || cancelled.request.source_incarnation_id != request.source_incarnation_id
            {
                return Ok(O::Refused(R::IdentityMismatch));
            }
            return Ok(O::AlreadyCancelled(cancelled));
        }
        let Some(pin) = read_attempt_pin(&tx, &request.op_id)? else {
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
        let Some(witness) = read_witness(&tx, &request.candidate_witness_digest)? else {
            // MUTATION-SUCCESS-EXPR: Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
            return Ok(O::Refused(R::CandidateWitnessMissing));
        };
        if !witness.matches_request(request) {
            return Ok(O::Refused(R::CandidateWitnessMismatch));
        }
        let Some(certificate) = read_gate_certificate(&tx, &request.certificate_handle)? else {
            // MUTATION-SUCCESS-EXPR: Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
            return Ok(O::Refused(R::GateCertificateMissing));
        };
        if !certificate.matches_request(request) {
            return Ok(O::Refused(R::GateCertificateMismatch));
        }
        if let Some(refusal) = issuer_refusal(&tx, &request.certificate_handle)? {
            // MUTATION-SUCCESS-EXPR: Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
            return Ok(O::Refused(R::GateIssuer(refusal)));
        }
        let verdict = match certificate.admission_refusal() {
            Some(super::FlowingAdmissionRefusal::GateFailed) => FlowingGateVerdict::Failed,
            Some(super::FlowingAdmissionRefusal::GateUnrun) => FlowingGateVerdict::Unrun,
            // MUTATION-SUCCESS-EXPR: return Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
            Some(_) => return Ok(O::Refused(R::GatePlanIncomplete)),
            // MUTATION-SUCCESS-EXPR: return Ok(O::Finished(FlowingAttemptFinishReceipt { request: request.clone(), verdict: FlowingGateVerdict::Failed }))
            None => return Ok(O::Refused(R::GatePassed)),
        };
        let receipt = FlowingAttemptFinishReceipt {
            request: request.clone(),
            verdict,
        };
        tx.execute(
            "INSERT INTO flowing_attempt_finishes (op_id, receipt_json) VALUES (?1, ?2)",
            params![&request.op_id, serde_json::to_string(&receipt)?],
        )?;
        tx.commit()?;
        Ok(O::Finished(receipt))
    }

    fn flowing_finish_for_attempt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingAttemptFinishReceipt>> {
        read_finish(&self.connection, op_id)
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
        if let Some(finished) = read_finish(&tx, &request.op_id)? {
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
        let expected_kind = if source.name.is_some() {
            FlowingSourceKind::Branch
        } else {
            FlowingSourceKind::Twig
        };
        if fence.kind != expected_kind {
            return Ok(Refused(R::SourceKindMismatch));
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
            if handoff.is_some() && source.name.is_none() {
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
            if let Some(parked) =
                crate::branches::flowing_parking::native::read_by_unit(&tx, &unit.unit_id)?
            {
                return Ok(Refused(R::UnitParked {
                    unit_id: unit.unit_id.clone(),
                    park_op_id: parked.request.op_id,
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
        if let Some(refusal) = issuer_refusal(&tx, &request.certificate_handle)? {
            return Ok(Refused(R::GateIssuer(refusal)));
        }
        if let Some(refusal) = certificate.admission_refusal() {
            return Ok(Refused(refusal));
        }
        let Some(lineage) = crate::branches::flowing_lineage::native_capture(&tx, &witness)? else {
            // MUTATION-SUCCESS-EXPR: Ok(Refused(R::LineageChanged))
            return Ok(Refused(R::LineageUnavailable));
        };
        if !crate::branches::flowing_lineage::matches_certificate(
            &lineage,
            &certificate,
            &request.source_branch_id,
        ) {
            return Ok(Refused(R::LineageChanged));
        }
        let Some(holders) = crate::branches::flowing_holders::native_capture(&tx, &witness)? else {
            // MUTATION-SUCCESS-EXPR: Ok(Refused(R::HolderChanged))
            return Ok(Refused(R::HolderUnavailable));
        };
        if !crate::branches::flowing_holders::matches_certificate(&holders, &certificate) {
            return Ok(Refused(R::HolderChanged));
        }
        if let Err(refusal) = crate::branches::flowing_coverage::check(
            certificate.coverage.as_ref(),
            read_coverage_premises(&tx)?.as_ref(),
            &request.candidate_manifest_hash,
        )? {
            return Ok(Refused(refusal));
        }
        let Some(pin) = read_attempt_pin(&tx, &request.op_id)? else {
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
            AlreadyAdmitted, AlreadyCancelled, AlreadyFinished, Cancelled, Existing, Refused,
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
        if let Some(finished) = read_finish(&tx, &request.admission_op_id)? {
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

    fn record_flowing_coverage_premises(
        &mut self,
        premises: &FlowingCoveragePremises,
    ) -> StoreResult<RecordCoveragePremisesOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = read_coverage_premises(&tx)?;
        let outcome =
            crate::branches::flowing_coverage::record_outcome(existing.as_ref(), premises);
        if let RecordCoveragePremisesOutcome::Recorded(next) = &outcome {
            tx.execute(
                "INSERT INTO flowing_coverage_premises (domain, premises_json) VALUES (?1, ?2) \
                 ON CONFLICT(domain) DO UPDATE SET premises_json = excluded.premises_json",
                params![HOME_COVERAGE_DOMAIN, serde_json::to_string(next)?],
            )?;
            tx.commit()?;
        }
        Ok(outcome)
    }

    fn configure_flowing_gate_issuer(
        &mut self,
        issuer: &FlowingGateTrustedIssuer,
    ) -> StoreResult<ConfigureFlowingGateIssuerOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = read_trusted_issuers(&tx)?
            .into_iter()
            .find(|current| current.issuer_id == issuer.issuer_id);
        let outcome = super::configure_issuer_outcome(current, issuer);
        if let ConfigureFlowingGateIssuerOutcome::Configured(configured) = &outcome {
            tx.execute(
                "INSERT INTO flowing_gate_trusted_issuers (issuer_id, issuer_json) \
                 VALUES (?1, ?2) ON CONFLICT(issuer_id) DO UPDATE SET issuer_json = ?2",
                params![&configured.issuer_id, serde_json::to_string(configured)?],
            )?;
            tx.commit()?;
        }
        Ok(outcome)
    }

    fn flowing_coverage_premises(&self) -> StoreResult<Option<FlowingCoveragePremises>> {
        read_coverage_premises(&self.connection)
    }

    fn flowing_gate_trusted_issuers(&self) -> StoreResult<Vec<FlowingGateTrustedIssuer>> {
        read_trusted_issuers(&self.connection)
    }

    fn record_flowing_gate_signature(
        &mut self,
        signature: &FlowingGateIssuerSignature,
    ) -> StoreResult<RecordFlowingGateSignatureOutcome> {
        use RecordFlowingGateSignatureOutcome as O;
        if let Err(field) = super::validate_issuer_signature(signature) {
            return Ok(O::Invalid { field });
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if read_gate_certificate(&tx, &signature.certificate_handle)?.is_none() {
            return Ok(O::CertificateMissing);
        }
        if let Some(existing) = read_signatures(&tx, &signature.certificate_handle)?
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
        if let Err(refusal) = super::verify_issued(
            &signature.certificate_handle,
            &read_trusted_issuers(&tx)?,
            std::slice::from_ref(signature),
        ) {
            return Ok(O::Refused(refusal));
        }
        tx.execute(
            "INSERT INTO flowing_gate_certificate_signatures \
             (handle, issuer_id, issuer_epoch, signature_json) VALUES (?1, ?2, ?3, ?4)",
            params![
                &signature.certificate_handle,
                &signature.issuer_id,
                signature.issuer_epoch,
                serde_json::to_string(signature)?
            ],
        )?;
        tx.commit()?;
        Ok(O::Recorded(signature.clone()))
    }

    fn flowing_gate_signatures(
        &self,
        certificate_handle: &str,
    ) -> StoreResult<Vec<FlowingGateIssuerSignature>> {
        read_signatures(&self.connection, certificate_handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_admission::{test_issuer, FlowingGateCheck, FlowingGateVerdict};
    use crate::branches::flowing_close_roster::{
        FlowingCloseAttemptState, FlowingCloseRosterReader,
    };
    use crate::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
    };
    use crate::branches::flowing_parking::{
        FlowingParkOutcome, FlowingParkRefusal, FlowingParking, ParkFlowingUnit,
    };
    use crate::branches::flowing_sources::{
        FlowingSources, ReleasePrivateCut, ReleasePrivateCutOutcome,
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
             VALUES ('unit-a', 'basis-a', '[{\"cut_id\":\"source\",\"change_id\":\"change\",\"path\":\"a\",\"before\":null,\"after\":\"a\"}]', 't2'),
                    ('unit-b', 'basis-b', '[{\"cut_id\":\"source\",\"change_id\":\"change\",\"path\":\"b\",\"before\":null,\"after\":\"b\"}]', 't2');",
            )
            .unwrap();
        assert!(matches!(
            store
                .record_flowing_coverage_premises(
                    &crate::branches::flowing_coverage::tests::premises()
                )
                .unwrap(),
            crate::branches::flowing_coverage::RecordCoveragePremisesOutcome::Recorded(_)
        ));
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
            unit_holders: Vec::new(),
            lineage_fences: Vec::new(),
            source_eligibility_epoch: request.expected_eligibility_epoch,
            source_owner_epoch: request.expected_owner_epoch,
            coordinator: request.coordinator.clone(),
            policy_digest: "sha256:fixture-policy".into(),
            rules_digest: "sha256:fixture-rules".into(),
            graph_coverage_digest: "sha256:fixture-coverage".into(),
            coverage: Some(crate::branches::flowing_coverage::tests::basis_for(
                &crate::branches::flowing_coverage::tests::premises(),
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

    fn named_origin(store: &mut BranchStore) {
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
        store.connection.execute(
            "UPDATE flowing_contribution_basis SET atoms_json = ?1 WHERE unit_id = 'unit-a'",
            [r#"[{"cut_id":"origin-cut","change_id":"origin-change","path":"a","before":null,"after":"a"}]"#],
        ).unwrap();
    }

    #[test]
    fn native_lineage_hold_release_invalidates_an_earlier_certificate() {
        let mut store = fixture();
        named_origin(&mut store);
        let mut attempt = request("unit-a", "lineage-attempt");
        pin_attempt(&mut store, &attempt);
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::LineageChanged)
        );
        let mut certificate = certificate_for(&attempt);
        certificate.lineage_fences =
            crate::branches::flowing_lineage::capture(&store, &witness_for(&attempt))
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
        insert_gate_certificate(&store, &certificate);
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
            crate::branches::flowing_lineage::capture(&store, &witness_for(&attempt))
                .unwrap()
                .unwrap();
        attempt.certificate_handle = certificate.handle().unwrap();
        insert_gate_certificate(&store, &certificate);
        assert!(matches!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
    }

    #[test]
    fn native_holder_evidence_is_rechecked_inside_admission() {
        for (sql_text, refusal) in [
            ("UPDATE flowing_private_pins SET principal = 'foreign' WHERE pin_id = 'pin'", FlowingAdmissionRefusal::HolderUnavailable),
            ("UPDATE flowing_private_pins SET manifest_hash = 'wrong' WHERE pin_id = 'pin'", FlowingAdmissionRefusal::HolderUnavailable),
            ("UPDATE flowing_contributions SET scope_digest = 'changed' WHERE unit_id = 'unit-a'", FlowingAdmissionRefusal::HolderChanged),
            ("UPDATE flowing_private_pins SET retained_at = 'changed' WHERE pin_id = 'pin'", FlowingAdmissionRefusal::HolderChanged),
        ] {
            let mut store = fixture();
            let mut attempt = request("unit-a", "holder-attempt");
            pin_attempt(&mut store, &attempt);
            let mut certificate = certificate_for(&attempt);
            certificate.lineage_fences = crate::branches::flowing_lineage::capture(&store, &witness_for(&attempt)).unwrap().unwrap();
            certificate.unit_holders = crate::branches::flowing_holders::capture(&store, &witness_for(&attempt)).unwrap().unwrap();
            attempt.certificate_handle = certificate.handle().unwrap();
            insert_gate_certificate(&store, &certificate);
            store.connection.execute(sql_text, []).unwrap();
            assert_eq!(store.admit_flowing_prefix(&attempt).unwrap(), FlowingAdmissionOutcome::Refused(refusal));
            assert!(store.admitted_unit_operation("unit-a").unwrap().is_none());
            assert!(store.flowing_admission_receipt(&attempt.op_id).unwrap().is_none());
            assert!(store.get_branch(MAINLINE_BRANCH_ID).unwrap().unwrap().head_cut_id.is_none());
            assert!(store.flowing_attempt_pin(&attempt.op_id).unwrap().unwrap().released_at.is_none());
        }
        let mut store = fixture();
        let mut attempt = request("unit-a", "current-holder");
        pin_attempt(&mut store, &attempt);
        let mut certificate = certificate_for(&attempt);
        certificate.lineage_fences =
            crate::branches::flowing_lineage::capture(&store, &witness_for(&attempt))
                .unwrap()
                .unwrap();
        certificate.unit_holders =
            crate::branches::flowing_holders::capture(&store, &witness_for(&attempt))
                .unwrap()
                .unwrap();
        attempt.certificate_handle = certificate.handle().unwrap();
        insert_gate_certificate(&store, &certificate);
        assert!(matches!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        // Legacy certificates keep their identity, but require a real matching pin.
        let mut store = fixture();
        let attempt = request("unit-a", "legacy-holder");
        pin_attempt(&mut store, &attempt);
        let sql_text = "UPDATE flowing_private_pins SET cut_id = 'candidate' WHERE pin_id = 'pin'";
        store.connection.execute(sql_text, []).unwrap();
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::HolderUnavailable)
        );
    }

    #[test]
    fn native_lineage_missing_facts_and_cycles_cannot_authorize_cas() {
        for sql in [
            "DELETE FROM flowing_contribution_basis WHERE unit_id = 'unit-a'",
            "UPDATE flowing_contribution_basis SET atoms_json = '[]' WHERE unit_id = 'unit-a'",
            "UPDATE branches SET parent_branch_id = 'missing' WHERE branch_id = 'origin'",
            "UPDATE branches SET parent_branch_id = 'origin' WHERE branch_id = 'origin'",
            "DELETE FROM cuts WHERE cut_id = 'origin-cut'",
            "DELETE FROM flowing_source_fences WHERE source_branch_id = 'origin'",
        ] {
            let mut store = fixture();
            named_origin(&mut store);
            let attempt = request("unit-a", "unknown-lineage");
            pin_attempt(&mut store, &attempt);
            store.connection.execute_batch(sql).unwrap();
            assert!(
                crate::branches::flowing_lineage::capture(&store, &witness_for(&attempt))
                    .unwrap()
                    .is_none(),
                "{sql}"
            );
            let expected = if sql.starts_with("DELETE FROM flowing_contribution_basis") {
                FlowingAdmissionRefusal::UnitBasisMissing {
                    unit_id: "unit-a".into(),
                }
            } else {
                FlowingAdmissionRefusal::LineageUnavailable
            };
            assert_eq!(
                store.admit_flowing_prefix(&attempt).unwrap(),
                FlowingAdmissionOutcome::Refused(expected),
                "{sql}"
            );
            assert!(store
                .flowing_admission_receipt(&attempt.op_id)
                .unwrap()
                .is_none());
        }
    }

    fn issued_gate_fixture() -> (FlowingGateCertificate, FlowingGateEvidence) {
        let mut certificate = certificate_for(&request("unit-a", "gate-op"));
        let evidence = FlowingGateEvidence {
            attempt_op_id: "gate-op".into(),
            check_id: "full-workspace-bar".into(),
            input_digest: "sha256:fixture-input".into(),
            program: "sh".into(),
            args: vec!["-c".into(), "true".into()],
            exit_code: Some(0),
            started: true,
            stdout: b"passed\n".to_vec(),
            stderr: Vec::new(),
            run_error: None,
        };
        certificate.checks[0].evidence_digest = evidence.digest().unwrap();
        (certificate, evidence)
    }

    #[test]
    fn native_gate_writer_refuses_incomplete_mismatched_and_corrupt_evidence() {
        let (certificate, evidence) = issued_gate_fixture();
        let mut store = BranchStore::open_in_memory().unwrap();
        let mut incomplete = certificate.clone();
        incomplete.required_checks.clear();
        assert!(store
            .record_native_gate_certificate(&incomplete, std::slice::from_ref(&evidence))
            .is_err());
        assert!(store
            .native_gate_certificate(&incomplete.handle().unwrap())
            .unwrap()
            .is_none());

        let mut mismatch = evidence.clone();
        mismatch.stdout = b"different\n".to_vec();
        assert!(store
            .record_native_gate_certificate(&certificate, &[mismatch])
            .is_err());
        assert!(store
            .native_gate_certificate(&certificate.handle().unwrap())
            .unwrap()
            .is_none());

        let handle = store
            .record_native_gate_certificate(&certificate, std::slice::from_ref(&evidence))
            .expect("record exact result");
        assert_eq!(
            store.native_gate_certificate(&handle).unwrap(),
            Some(certificate.clone())
        );
        assert_eq!(
            store
                .native_gate_evidence(&evidence.digest().unwrap())
                .unwrap(),
            Some(evidence.clone())
        );

        let mut corrupt = evidence.clone();
        corrupt.stdout = b"changed after record\n".to_vec();
        store
            .connection
            .execute(
                "UPDATE flowing_gate_evidence SET evidence_json = ?1 WHERE digest = ?2",
                params![
                    serde_json::to_string(&corrupt).unwrap(),
                    evidence.digest().unwrap()
                ],
            )
            .unwrap();
        assert!(store
            .native_gate_evidence(&evidence.digest().unwrap())
            .is_err());
        assert!(store
            .record_native_gate_certificate(&certificate, std::slice::from_ref(&evidence))
            .is_err());

        store
            .connection
            .execute(
                "UPDATE flowing_gate_evidence SET evidence_json = ?1 WHERE digest = ?2",
                params![
                    serde_json::to_string(&evidence).unwrap(),
                    evidence.digest().unwrap()
                ],
            )
            .unwrap();
        let mut foreign = certificate.clone();
        foreign.policy_digest = "sha256:foreign-policy".into();
        store
            .connection
            .execute(
                "UPDATE flowing_gate_certificates SET certificate_json = ?1 WHERE handle = ?2",
                params![serde_json::to_string(&foreign).unwrap(), &handle],
            )
            .unwrap();
        assert!(store
            .record_native_gate_certificate(&certificate, &[evidence])
            .is_err());
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
        sign_gate_certificate(store, &certificate.handle().unwrap());
    }

    /// Trust the fixture issuer at epoch 1 and retain its signature over the
    /// handle, as a fleet issuer would after a run.
    fn sign_gate_certificate(store: &BranchStore, handle: &str) {
        insert_trusted_issuer(store, &test_issuer::trusted(test_issuer::ISSUER, 1, 7));
        insert_signature(store, &test_issuer::sign(handle, test_issuer::ISSUER, 1, 7));
    }

    fn insert_trusted_issuer(store: &BranchStore, issuer: &FlowingGateTrustedIssuer) {
        store
            .connection
            .execute(
                "INSERT OR IGNORE INTO flowing_gate_trusted_issuers (issuer_id, issuer_json) \
                 VALUES (?1, ?2)",
                params![&issuer.issuer_id, serde_json::to_string(issuer).unwrap()],
            )
            .unwrap();
    }

    /// Raw row write: models a writer that bypasses the recording API, so the
    /// ref CAS is the check under test.
    fn insert_signature(store: &BranchStore, signature: &FlowingGateIssuerSignature) {
        store
            .connection
            .execute(
                "INSERT OR IGNORE INTO flowing_gate_certificate_signatures \
                 (handle, issuer_id, issuer_epoch, signature_json) VALUES (?1, ?2, ?3, ?4)",
                params![
                    &signature.certificate_handle,
                    &signature.issuer_id,
                    signature.issuer_epoch,
                    serde_json::to_string(signature).unwrap()
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

    fn pin_attempt(store: &mut BranchStore, request: &FlowingAdmissionRequest) {
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
    fn park_first_retains_exact_holder_and_fences_native_trunk_cas() {
        let mut store = fixture();
        let attempt = request("unit-a", "admission-a");
        pin_attempt(&mut store, &attempt);
        record_gate_certificate(&store, &attempt);
        let park = park_request("park-a", "unit-a");
        let FlowingParkOutcome::Parked(receipt) = store.park_flowing_unit(&park).unwrap() else {
            panic!("expected parked receipt");
        };
        let evidence =
            crate::branches::flowing_parking_host::read_parking_evidence(&store, "park-a")
                .unwrap()
                .unwrap();
        assert_eq!(evidence.unit_id, "unit-a");
        assert_eq!(evidence.parked_holder_id, "park:repair-owner");
        assert_eq!(evidence.resulting_eligibility_epoch, 1);
        let wire = serde_json::to_vec(&evidence).unwrap();
        assert!(!String::from_utf8_lossy(&wire).contains("\"intent\""));
        assert!(!String::from_utf8_lossy(&wire).contains("\"principal\""));
        assert_eq!(
            crate::branches::flowing_parking_host::FlowingHostParkingEvidenceV1::decode(&wire)
                .unwrap(),
            evidence
        );
        let mut unknown: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        unknown["new_claim"] = serde_json::json!(true);
        assert!(
            crate::branches::flowing_parking_host::FlowingHostParkingEvidenceV1::decode(
                &serde_json::to_vec(&unknown).unwrap()
            )
            .is_err()
        );
        let mut missing: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        missing
            .as_object_mut()
            .unwrap()
            .remove("former_holder_digest");
        assert!(
            crate::branches::flowing_parking_host::FlowingHostParkingEvidenceV1::decode(
                &serde_json::to_vec(&missing).unwrap()
            )
            .is_err()
        );
        let mut stale: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        stale["resulting_eligibility_epoch"] = serde_json::json!(0);
        let stale_error =
            crate::branches::flowing_parking_host::FlowingHostParkingEvidenceV1::decode(
                &serde_json::to_vec(&stale).unwrap(),
            )
            .unwrap_err();
        assert!(format!("{stale_error:?}").contains("parking evidence shape is invalid"));
        let mut bad_digest: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        bad_digest["request_digest"] = serde_json::json!("sha256:bad");
        assert!(
            crate::branches::flowing_parking_host::FlowingHostParkingEvidenceV1::decode(
                &serde_json::to_vec(&bad_digest).unwrap()
            )
            .is_err()
        );
        assert!(crate::branches::flowing_parking_host::read_parking_evidence(&store, "").is_err());
        assert!(
            crate::branches::flowing_parking_host::read_parking_evidence(&store, "missing")
                .unwrap()
                .is_none()
        );
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
        assert!(
            crate::branches::flowing_holders::capture(&store, &witness_for(&attempt))
                .unwrap()
                .is_none()
        );
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
    }

    #[test]
    fn terminal_parking_keeps_the_source_cut_after_explicit_private_pin_release() {
        let mut store = fixture();
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
        assert_eq!(
            store
                .private_cut_pin("pin")
                .unwrap()
                .unwrap()
                .released_at
                .as_deref(),
            Some("t5")
        );
        assert!(store.pinned_cuts("year-3000").unwrap().contains("source"));
    }

    #[test]
    fn admitted_unit_keeps_its_source_cut_after_private_and_attempt_pin_release() {
        let mut store = fixture();
        // Isolate one unit so admission is the only durable source-cut root.
        store
            .connection
            .execute(
                "DELETE FROM flowing_contribution_basis WHERE unit_id = 'unit-b'",
                [],
            )
            .unwrap();
        store
            .connection
            .execute(
                "DELETE FROM flowing_contributions WHERE unit_id = 'unit-b'",
                [],
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
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_pins SET released_at = 't6' WHERE op_id = 'fixture'",
                [],
            )
            .unwrap();
        assert!(store.pinned_cuts("year-3000").unwrap().contains("source"));
    }

    #[test]
    fn close_roster_keeps_pending_and_admitted_attempts_under_one_source() {
        let mut store = fixture();
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
        store.connection.execute("UPDATE flowing_attempt_pins SET witness_digest = 'missing' WHERE op_id = 'fixture'", []).unwrap();
        assert!(matches!(
            store.flowing_close_roster("twig"),
            Err(StoreError::Conflict(message)) if message.contains("lost its candidate witness")
        ));
    }

    #[test]
    fn trunk_cas_first_returns_exact_admission_to_native_parking() {
        let mut store = fixture();
        let attempt = request("unit-a", "admission-a");
        pin_attempt(&mut store, &attempt);
        record_gate_certificate(&store, &attempt);
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
    fn native_parking_rejects_corrupt_ref_receipts_and_missing_retained_cut() {
        for statement in [
            "UPDATE flowing_parked_units SET holder_id = 'wrong' WHERE unit_id = 'unit-a'",
            "DELETE FROM cuts WHERE cut_id = 'source'",
        ] {
            let mut store = fixture();
            assert!(matches!(
                store
                    .park_flowing_unit(&park_request("park-a", "unit-a"))
                    .unwrap(),
                FlowingParkOutcome::Parked(_)
            ));
            store.connection.execute(statement, []).unwrap();
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
    fn native_parking_refuses_dangling_admission_index() {
        let mut store = fixture();
        store
            .connection
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 INSERT INTO flowing_admitted_units (unit_id, op_id) VALUES ('unit-a', 'missing');
                 PRAGMA foreign_keys = ON;",
            )
            .unwrap();
        let error = store
            .park_flowing_unit(&park_request("park-a", "unit-a"))
            .unwrap_err();
        assert!(format!("{error:?}").contains("admitted flowing unit lost its receipt"));
        assert!(store.parked_flowing_unit("unit-a").unwrap().is_none());
    }

    #[test]
    fn native_parking_refuses_changed_owner_epoch_and_bad_basis() {
        let mut store = fixture();
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
    fn native_park_receipt_and_fence_roll_back_together() {
        let mut store = fixture();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail_park_fence BEFORE INSERT ON flowing_source_fence_ops \
             WHEN NEW.op_id = 'park-a' BEGIN SELECT RAISE(ABORT, 'fence write failed'); END;",
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
        store: &BranchStore,
        op_id: &str,
        verdict: FlowingGateVerdict,
    ) -> FlowingAdmissionRequest {
        let mut attempt = request("unit-a", op_id);
        let mut certificate = certificate_for(&attempt);
        certificate.checks[0].verdict = verdict;
        attempt.certificate_handle = certificate.handle().unwrap();
        insert_gate_certificate(store, &certificate);
        attempt
    }

    #[test]
    fn close_roster_distinguishes_cancelled_failed_and_unrun_attempts() {
        for (verdict, expected) in [
            (FlowingGateVerdict::Failed, FlowingCloseAttemptState::Failed),
            (FlowingGateVerdict::Unrun, FlowingCloseAttemptState::Unrun),
        ] {
            let mut store = fixture();
            let attempt = terminal_request(&store, "terminal", verdict);
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
        let mut store = fixture();
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
        let witness = store
            .candidate_witness(&attempt.candidate_witness_digest)
            .unwrap()
            .unwrap();
        let pin = store.flowing_attempt_pin("fixture").unwrap().unwrap();
        assert!(matches!(
            crate::branches::flowing_close_roster::classify_attempt(
                pin,
                Some(serde_json::to_string(&witness).unwrap()),
                Some(serde_json::to_string(&FlowingAdmissionReceipt { request: attempt }).unwrap()),
                Some("cancel-a".into()),
                Some(serde_json::to_string(&cancel("fixture", "cancel-a")).unwrap()),
                None,
            ),
            Err(StoreError::Conflict(message)) if message.contains("conflicting terminal results")
        ));
    }

    #[test]
    fn close_attempt_classifier_refuses_changed_witness_and_terminal_rows() {
        use crate::branches::flowing_close_roster::classify_attempt;

        let mut store = fixture();
        let attempt = request("unit-a", "fixture");
        pin_attempt(&mut store, &attempt);
        let pin = store.flowing_attempt_pin("fixture").unwrap().unwrap();
        let witness = store
            .candidate_witness(&pin.witness_digest)
            .unwrap()
            .unwrap();
        let witness_json = serde_json::to_string(&witness).unwrap();

        let mut changed_pin = pin.clone();
        changed_pin.source_cut_id = "other-cut".into();
        assert!(matches!(
            classify_attempt(changed_pin, Some(witness_json.clone()), None, None, None, None),
            Err(StoreError::Conflict(message)) if message.contains("differs from its witness")
        ));

        let mut changed_request = attempt.clone();
        changed_request.op_id = "other-op".into();
        let changed_admission = serde_json::to_string(&FlowingAdmissionReceipt {
            request: changed_request.clone(),
        })
        .unwrap();
        assert!(matches!(
            classify_attempt(pin.clone(), Some(witness_json.clone()), Some(changed_admission), None, None, None),
            Err(StoreError::Conflict(message)) if message.contains("admission differs")
        ));

        let cancellation = serde_json::to_string(&cancel("fixture", "cancel-a")).unwrap();
        assert!(matches!(
            classify_attempt(pin.clone(), Some(witness_json.clone()), None, Some("changed-key".into()), Some(cancellation), None),
            Err(StoreError::Conflict(message)) if message.contains("cancellation differs")
        ));

        for (finish, expected) in [
            (
                FlowingAttemptFinishReceipt {
                    request: changed_request,
                    verdict: FlowingGateVerdict::Failed,
                },
                "finish differs",
            ),
            (
                FlowingAttemptFinishReceipt {
                    request: attempt,
                    verdict: FlowingGateVerdict::Passed,
                },
                "passed gate",
            ),
        ] {
            assert!(matches!(
                classify_attempt(pin.clone(), Some(witness_json.clone()), None, None, None, Some(serde_json::to_string(&finish).unwrap())),
                Err(StoreError::Conflict(message)) if message.contains(expected)
            ));
        }
    }

    #[test]
    fn failed_and_unrun_attempts_finish_before_their_roots_are_released() {
        for verdict in [FlowingGateVerdict::Failed, FlowingGateVerdict::Unrun] {
            let mut store = fixture();
            let request = terminal_request(&store, "terminal", verdict);
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
    fn failed_attempt_finish_refuses_passed_or_incomplete_evidence_and_rolls_back_write_failure() {
        let mut store = fixture();
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
        insert_gate_certificate(&store, &certificate);
        pin_attempt(&mut store, &incomplete);
        assert_eq!(
            store.finish_flowing_attempt(&incomplete).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::GatePlanIncomplete)
        );

        let failed = terminal_request(&store, "failed-write", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &failed);
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER reject_finish BEFORE INSERT ON flowing_attempt_finishes \
             BEGIN SELECT RAISE(ABORT, 'injected finish failure'); END",
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
        store
            .connection
            .execute_batch("DROP TRIGGER reject_finish")
            .unwrap();
        assert!(matches!(
            store.finish_flowing_attempt(&failed).unwrap(),
            FlowingAttemptFinishOutcome::Finished(_)
        ));
        store
            .connection
            .execute(
                "UPDATE flowing_private_pins SET released_at = 't4' WHERE pin_id = 'pin'",
                [],
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
    fn changed_terminal_receipt_cannot_release_a_different_pinned_witness() {
        let mut store = fixture();
        let request = terminal_request(&store, "changed-finish", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &request);
        store.finish_flowing_attempt(&request).unwrap();
        let mut altered = FlowingAttemptFinishReceipt {
            request: request.clone(),
            verdict: FlowingGateVerdict::Failed,
        };
        altered.request.candidate_witness_digest = "sha256:other".into();
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_finishes SET receipt_json = ?1 WHERE op_id = ?2",
                params![serde_json::to_string(&altered).unwrap(), &request.op_id],
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
    fn terminal_receipt_key_verdict_and_exclusivity_are_checked_before_release() {
        let mut store = fixture();
        let request = terminal_request(&store, "receipt-guard", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &request);
        store.finish_flowing_attempt(&request).unwrap();
        let mut altered = FlowingAttemptFinishReceipt {
            request: request.clone(),
            verdict: FlowingGateVerdict::Failed,
        };
        altered.request.op_id = "other".into();
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_finishes SET receipt_json=?1 WHERE op_id=?2",
                params![serde_json::to_string(&altered).unwrap(), &request.op_id],
            )
            .unwrap();
        assert!(matches!(
            store.flowing_finish_for_attempt(&request.op_id),
            Err(StoreError::Conflict(message)) if message.contains("operation key or terminal verdict")
        ));
        altered.request.op_id = request.op_id.clone();
        altered.verdict = FlowingGateVerdict::Passed;
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_finishes SET receipt_json=?1 WHERE op_id=?2",
                params![serde_json::to_string(&altered).unwrap(), &request.op_id],
            )
            .unwrap();
        assert!(matches!(
            store.flowing_finish_for_attempt(&request.op_id),
            Err(StoreError::Conflict(message)) if message.contains("operation key or terminal verdict")
        ));
        altered.verdict = FlowingGateVerdict::Failed;
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_finishes SET receipt_json=?1 WHERE op_id=?2",
                params![serde_json::to_string(&altered).unwrap(), &request.op_id],
            )
            .unwrap();
        let cancellation = cancel(&request.op_id, "conflicting-cancel");
        store
            .connection
            .execute(
                "INSERT INTO flowing_admission_cancellations \
             (admission_op_id, cancel_op_id, request_json) VALUES (?1, ?2, ?3)",
                params![
                    &request.op_id,
                    &cancellation.cancel_op_id,
                    serde_json::to_string(&cancellation).unwrap()
                ],
            )
            .unwrap();
        assert!(matches!(
            store.release_terminal_flowing_attempt(&request.op_id, "t5"),
            Err(StoreError::Conflict(message)) if message.contains("conflicting terminal receipts")
        ));
    }

    #[test]
    fn finish_checks_pin_witness_and_certificate_before_terminal_receipt() {
        let mut store = fixture();
        let mut invalid = request("unit-a", "invalid");
        invalid.op_id.clear();
        assert_eq!(
            store.finish_flowing_attempt(&invalid).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::InvalidRequest(
                FlowingAdmissionRefusal::Invalid { field: "op_id" }
            ))
        );

        let mut store = fixture();
        let missing = terminal_request(&store, "missing-pin", FlowingGateVerdict::Failed);
        assert_eq!(
            store.finish_flowing_attempt(&missing).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::AttemptPinMissing)
        );

        let mut store = fixture();
        let changed = terminal_request(&store, "changed-pin", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &changed);
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_pins SET witness_digest='sha256:other' WHERE op_id=?1",
                [&changed.op_id],
            )
            .unwrap();
        assert_eq!(
            store.finish_flowing_attempt(&changed).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::AttemptPinMismatch)
        );

        let mut store = fixture();
        let released = terminal_request(&store, "released-pin", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &released);
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_pins SET released_at='t4' WHERE op_id=?1",
                [&released.op_id],
            )
            .unwrap();
        assert_eq!(
            store.finish_flowing_attempt(&released).unwrap(),
            FlowingAttemptFinishOutcome::Refused(FlowingAttemptFinishRefusal::AttemptPinReleased)
        );

        let mut store = fixture();
        let mut changed_witness =
            terminal_request(&store, "changed-witness", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &changed_witness);
        changed_witness.contribution_id = "other".into();
        assert_eq!(
            store.finish_flowing_attempt(&changed_witness).unwrap(),
            FlowingAttemptFinishOutcome::Refused(
                FlowingAttemptFinishRefusal::CandidateWitnessMismatch
            )
        );

        let mut store = fixture();
        let mut changed_certificate =
            terminal_request(&store, "changed-certificate", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &changed_certificate);
        changed_certificate.coordinator = "other".into();
        assert_eq!(
            store.finish_flowing_attempt(&changed_certificate).unwrap(),
            FlowingAttemptFinishOutcome::Refused(
                FlowingAttemptFinishRefusal::GateCertificateMismatch
            )
        );

        let mut store = fixture();
        let missing_witness =
            terminal_request(&store, "missing-witness", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &missing_witness);
        store
            .connection
            .execute(
                "DELETE FROM flowing_candidate_witnesses WHERE digest=?1",
                [&missing_witness.candidate_witness_digest],
            )
            .unwrap();
        assert_eq!(
            store.finish_flowing_attempt(&missing_witness).unwrap(),
            FlowingAttemptFinishOutcome::Refused(
                FlowingAttemptFinishRefusal::CandidateWitnessMissing
            )
        );

        let mut store = fixture();
        let missing_certificate =
            terminal_request(&store, "missing-certificate", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &missing_certificate);
        store
            .connection
            .execute(
                "DELETE FROM flowing_gate_certificates WHERE handle=?1",
                [&missing_certificate.certificate_handle],
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
    fn finish_reads_the_winning_admission_or_cancellation() {
        let mut store = fixture();
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

        let mut store = fixture();
        let failed = terminal_request(&store, "already-cancelled", FlowingGateVerdict::Failed);
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
    fn native_ref_rechecks_coverage_premises_inside_the_trunk_cas() {
        use crate::branches::flowing_coverage::tests::{basis_for, premises};
        use crate::branches::flowing_coverage::{
            FlowingCoverageBasis, FlowingCoverageClaim, RecordCoveragePremisesOutcome,
        };

        let mut store = fixture();
        let mut attempt = request("unit-a", "coverage-attempt");
        pin_attempt(&mut store, &attempt);
        let admit_with = |store: &mut BranchStore,
                          attempt: &mut FlowingAdmissionRequest,
                          coverage: Option<FlowingCoverageBasis>| {
            let mut certificate = certificate_for(attempt);
            certificate.coverage = coverage;
            insert_gate_certificate(store, &certificate);
            attempt.certificate_handle = certificate.handle().unwrap();
            store.admit_flowing_prefix(attempt).unwrap()
        };

        // A certificate issued before coverage was bound cannot admit.
        assert_eq!(
            admit_with(&mut store, &mut attempt, None),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CoverageUnavailable)
        );

        // Stale capture: the graph moved after the owner answered.
        let answered = premises();
        let captured = basis_for(&answered, &attempt.candidate_manifest_hash);
        let mut moved = answered.clone();
        moved.graph_epoch += 1;
        assert!(matches!(
            store.record_flowing_coverage_premises(&moved).unwrap(),
            RecordCoveragePremisesOutcome::Recorded(_)
        ));
        assert_eq!(
            admit_with(&mut store, &mut attempt, Some(captured.clone())),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CoverageStale {
                premise: "graph"
            })
        );
        assert_eq!(
            store.record_flowing_coverage_premises(&answered).unwrap(),
            RecordCoveragePremisesOutcome::Regressed { premise: "graph" }
        );
        // Recapturing the premises does not carry the earlier answer forward.
        let mut recaptured = FlowingCoverageBasis::under(&moved).unwrap();
        recaptured.scopes = captured.scopes.clone();
        assert_eq!(
            admit_with(&mut store, &mut attempt, Some(recaptured)),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CoverageOwnerUnvalidated {
                scope_id: "norm-relations@home".into(),
                owner: "owner-a".into(),
            })
        );

        // A no-edge query over an open roster with no identifiable owner.
        let mut unowned = moved.clone();
        unowned.roster_digest = "sha256:roster-unowned".into();
        unowned.required_scopes[1].owners.clear();
        assert!(matches!(
            store.record_flowing_coverage_premises(&unowned).unwrap(),
            RecordCoveragePremisesOutcome::Recorded(_)
        ));
        let mut empty_query = basis_for(&unowned, &attempt.candidate_manifest_hash);
        empty_query.scopes[1].claim = FlowingCoverageClaim::Complete {
            examined_digest: "sha256:what-the-query-saw".into(),
            edge_digest: "sha256:no-edges".into(),
        };
        assert_eq!(
            admit_with(&mut store, &mut attempt, Some(empty_query)),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::CoverageScopeUnknown {
                scope_id: "norm-relations@home".into()
            })
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

        // Current premises with every owner's answer at this graph admit.
        let mut owned = unowned.clone();
        owned.roster_digest = "sha256:roster-owned".into();
        owned.required_scopes[1].owners = vec!["owner-a".into()];
        assert!(matches!(
            store.record_flowing_coverage_premises(&owned).unwrap(),
            RecordCoveragePremisesOutcome::Recorded(_)
        ));
        let current = basis_for(&owned, &attempt.candidate_manifest_hash);
        assert!(matches!(
            admit_with(&mut store, &mut attempt, Some(current)),
            FlowingAdmissionOutcome::Admitted(_)
        ));
    }

    #[test]
    fn native_malformed_coverage_premises_are_never_read_as_current() {
        let store = fixture();
        let mut malformed = crate::branches::flowing_coverage::tests::premises();
        malformed.registry_digest = " ".into();
        store
            .connection
            .execute(
                "UPDATE flowing_coverage_premises SET premises_json = ?1",
                params![serde_json::to_string(&malformed).unwrap()],
            )
            .unwrap();
        let error = store.flowing_coverage_premises().unwrap_err();
        assert!(format!("{error:?}").contains("flowing coverage premises are malformed"));
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

    fn clear_issuance(store: &BranchStore) {
        store
            .connection
            .execute_batch(
                "DELETE FROM flowing_gate_certificate_signatures; \
                 DELETE FROM flowing_gate_trusted_issuers;",
            )
            .unwrap();
    }

    fn assert_trunk_unmoved(store: &BranchStore, attempt: &FlowingAdmissionRequest) {
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
    fn native_ref_requires_a_current_trusted_issuer_signature() {
        use FlowingGateIssuerRefusal as I;
        let mut store = fixture();
        let attempt = request("unit-a", "issued");
        let handle = attempt.certificate_handle.clone();
        pin_attempt(&mut store, &attempt);
        let refused = |store: &mut BranchStore, issuer: I| {
            assert_eq!(
                store.admit_flowing_prefix(&attempt).unwrap(),
                FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::GateIssuer(issuer))
            );
            assert_trunk_unmoved(store, &attempt);
        };

        clear_issuance(&store);
        insert_signature(
            &store,
            &test_issuer::sign(&handle, test_issuer::ISSUER, 1, 7),
        );
        refused(&mut store, I::TrustRootMissing);

        clear_issuance(&store);
        insert_trusted_issuer(&store, &test_issuer::trusted(test_issuer::ISSUER, 1, 7));
        refused(&mut store, I::Unsigned);

        // Forged issuer: the trusted name over the exact handle, wrong key.
        insert_signature(
            &store,
            &test_issuer::sign(&handle, test_issuer::ISSUER, 1, 9),
        );
        refused(
            &mut store,
            I::BadSignature {
                issuer_id: test_issuer::ISSUER.into(),
            },
        );

        // Swapped digest: a genuine signature over another certificate,
        // relabelled onto this handle.
        store
            .connection
            .execute("DELETE FROM flowing_gate_certificate_signatures", [])
            .unwrap();
        let mut swapped = test_issuer::sign("sha256:other-certificate", test_issuer::ISSUER, 1, 7);
        swapped.certificate_handle = handle.clone();
        insert_signature(&store, &swapped);
        refused(
            &mut store,
            I::BadSignature {
                issuer_id: test_issuer::ISSUER.into(),
            },
        );

        store
            .connection
            .execute("DELETE FROM flowing_gate_certificate_signatures", [])
            .unwrap();
        insert_signature(&store, &test_issuer::sign(&handle, "elsewhere", 1, 7));
        refused(&mut store, I::ForeignIssuer);

        // Old-epoch issuer: genuine at epoch 1, retired by a rotation.
        insert_signature(
            &store,
            &test_issuer::sign(&handle, test_issuer::ISSUER, 1, 7),
        );
        let rotated = test_issuer::trusted(test_issuer::ISSUER, 2, 8);
        assert_eq!(
            store.configure_flowing_gate_issuer(&rotated).unwrap(),
            ConfigureFlowingGateIssuerOutcome::Configured(rotated.clone())
        );
        refused(
            &mut store,
            I::IssuerEpochMismatch {
                issuer_id: test_issuer::ISSUER.into(),
                signed: 1,
                current: 2,
            },
        );

        let current = test_issuer::sign(&handle, test_issuer::ISSUER, 2, 8);
        assert_eq!(
            store.record_flowing_gate_signature(&current).unwrap(),
            RecordFlowingGateSignatureOutcome::Recorded(current)
        );
        assert!(matches!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        assert_eq!(
            store
                .get_branch(MAINLINE_BRANCH_ID)
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some(attempt.candidate_cut_id.as_str())
        );
    }

    #[test]
    fn native_finish_requires_an_issued_certificate() {
        let mut store = fixture();
        let attempt = terminal_request(&store, "unsigned-finish", FlowingGateVerdict::Failed);
        pin_attempt(&mut store, &attempt);
        store
            .connection
            .execute("DELETE FROM flowing_gate_certificate_signatures", [])
            .unwrap();
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

    /// A trust-root or signature row whose JSON disagrees with its primary
    /// key is indeterminate: the CAS and both read APIs refuse it rather than
    /// trusting either half.
    #[test]
    fn native_issuance_rows_that_differ_from_their_key_are_indeterminate() {
        let mut store = fixture();
        let attempt = request("unit-a", "tampered-issuance");
        let handle = attempt.certificate_handle.clone();
        pin_attempt(&mut store, &attempt);
        let indeterminate = |store: &mut BranchStore, what: &str| {
            assert!(
                matches!(
                    store.admit_flowing_prefix(&attempt),
                    Err(StoreError::Conflict(message)) if message.contains(what)
                ),
                "the CAS refuses a {what} row"
            );
            assert_trunk_unmoved(store, &attempt);
        };
        let set_issuer_json = |store: &BranchStore, issuer: &FlowingGateTrustedIssuer| {
            store
                .connection
                .execute(
                    "UPDATE flowing_gate_trusted_issuers SET issuer_json = ?1 WHERE issuer_id = ?2",
                    params![serde_json::to_string(issuer).unwrap(), test_issuer::ISSUER],
                )
                .unwrap();
        };
        let set_signature_json = |store: &BranchStore, signature: &FlowingGateIssuerSignature| {
            store
                .connection
                .execute(
                    "UPDATE flowing_gate_certificate_signatures SET signature_json = ?1 \
                     WHERE handle = ?2 AND issuer_id = ?3 AND issuer_epoch = 1",
                    params![
                        serde_json::to_string(signature).unwrap(),
                        &handle,
                        test_issuer::ISSUER
                    ],
                )
                .unwrap();
        };
        let trusted = test_issuer::trusted(test_issuer::ISSUER, 1, 7);
        let signed = test_issuer::sign(&handle, test_issuer::ISSUER, 1, 7);

        // Trust root: the row names another issuer, then carries an invalid key.
        let issuer_differs = "trusted issuer differs from its key";
        let mut renamed = trusted.clone();
        renamed.issuer_id = "elsewhere".into();
        let mut unkeyed = trusted.clone();
        unkeyed.public_key = "zz".into();
        for tampered in [renamed, unkeyed] {
            set_issuer_json(&store, &tampered);
            indeterminate(&mut store, issuer_differs);
            assert!(matches!(
                store.flowing_gate_trusted_issuers(),
                Err(StoreError::Conflict(message)) if message.contains(issuer_differs)
            ));
        }
        set_issuer_json(&store, &trusted);

        // Signature: the row's handle, issuer or epoch disagrees with its key.
        let signature_differs = "signature differs from its key";
        let mut rehandled = signed.clone();
        rehandled.certificate_handle = "sha256:other-certificate".into();
        let mut reissued = signed.clone();
        reissued.issuer_id = "elsewhere".into();
        let mut reepoched = signed.clone();
        reepoched.issuer_epoch = 2;
        for tampered in [rehandled, reissued, reepoched] {
            set_signature_json(&store, &tampered);
            indeterminate(&mut store, signature_differs);
            assert!(matches!(
                store.flowing_gate_signatures(&handle),
                Err(StoreError::Conflict(message)) if message.contains(signature_differs)
            ));
        }
        set_signature_json(&store, &signed);

        assert_eq!(store.flowing_gate_trusted_issuers().unwrap(), vec![trusted]);
        assert_eq!(
            store.flowing_gate_signatures(&handle).unwrap(),
            vec![signed]
        );
        assert!(matches!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
    }

    #[test]
    fn native_signature_recording_and_issuer_configuration_refuse_early() {
        use RecordFlowingGateSignatureOutcome as O;
        let mut store = fixture();
        let handle = request("unit-a", "record").certificate_handle;
        clear_issuance(&store);
        let issuer = test_issuer::trusted(test_issuer::ISSUER, 1, 7);
        assert_eq!(
            store.configure_flowing_gate_issuer(&issuer).unwrap(),
            ConfigureFlowingGateIssuerOutcome::Configured(issuer.clone())
        );
        assert_eq!(
            store.configure_flowing_gate_issuer(&issuer).unwrap(),
            ConfigureFlowingGateIssuerOutcome::Existing(issuer.clone())
        );
        assert_eq!(
            store
                .configure_flowing_gate_issuer(&test_issuer::trusted(test_issuer::ISSUER, 1, 8))
                .unwrap(),
            ConfigureFlowingGateIssuerOutcome::EpochNotAdvanced { current: 1 }
        );
        assert_eq!(store.flowing_gate_trusted_issuers().unwrap(), vec![issuer]);

        let mut invalid = test_issuer::sign(&handle, test_issuer::ISSUER, 1, 7);
        invalid.signature = "00".into();
        assert_eq!(
            store.record_flowing_gate_signature(&invalid).unwrap(),
            O::Invalid { field: "signature" }
        );
        assert_eq!(
            store
                .record_flowing_gate_signature(&test_issuer::sign(
                    "sha256:no-such-certificate",
                    test_issuer::ISSUER,
                    1,
                    7
                ))
                .unwrap(),
            O::CertificateMissing
        );
        assert_eq!(
            store
                .record_flowing_gate_signature(&test_issuer::sign(&handle, "elsewhere", 1, 7))
                .unwrap(),
            O::Refused(FlowingGateIssuerRefusal::ForeignIssuer)
        );
        assert_eq!(
            store
                .record_flowing_gate_signature(&test_issuer::sign(
                    &handle,
                    test_issuer::ISSUER,
                    1,
                    9
                ))
                .unwrap(),
            O::Refused(FlowingGateIssuerRefusal::BadSignature {
                issuer_id: test_issuer::ISSUER.into()
            })
        );
        assert!(store.flowing_gate_signatures(&handle).unwrap().is_empty());
        let good = test_issuer::sign(&handle, test_issuer::ISSUER, 1, 7);
        assert_eq!(
            store.record_flowing_gate_signature(&good).unwrap(),
            O::Recorded(good.clone())
        );
        assert_eq!(
            store.record_flowing_gate_signature(&good).unwrap(),
            O::Existing(good.clone())
        );
        assert_eq!(store.flowing_gate_signatures(&handle).unwrap(), vec![good]);

        // A different row already under the key is not silently kept or replaced.
        store
            .connection
            .execute("DELETE FROM flowing_gate_certificate_signatures", [])
            .unwrap();
        insert_signature(
            &store,
            &test_issuer::sign(&handle, test_issuer::ISSUER, 1, 9),
        );
        let error = store
            .record_flowing_gate_signature(&test_issuer::sign(&handle, test_issuer::ISSUER, 1, 7))
            .unwrap_err();
        assert!(format!("{error:?}").contains("differs from the one already retained"));
    }

    #[test]
    fn native_admission_survives_a_crash_after_cas_and_a_later_rotation() {
        let root = std::env::temp_dir().join(format!(
            "whipplescript-issued-cas-{}-{}",
            std::process::id(),
            NEXT_REVIEW_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("branches.sqlite");
        let attempt = request("unit-a", "crash-after-cas");
        {
            let mut store = fixture();
            pin_attempt(&mut store, &attempt);
            store
                .connection
                .execute("VACUUM INTO ?1", [path.to_str().unwrap()])
                .unwrap();
        }
        let receipt = {
            let mut store = BranchStore::open(&path).unwrap();
            let FlowingAdmissionOutcome::Admitted(receipt) =
                store.admit_flowing_prefix(&attempt).unwrap()
            else {
                panic!("an issued certificate admits");
            };
            receipt
            // The coordinator dies here, after the CAS committed and before it
            // learned the outcome.
        };
        let mut store = BranchStore::open(&path).unwrap();
        // The issuer rotates before the retry. The durable receipt answers the
        // retry; the retired signature cannot reopen or repeat the CAS.
        let rotated = test_issuer::trusted(test_issuer::ISSUER, 2, 8);
        assert_eq!(
            store.configure_flowing_gate_issuer(&rotated).unwrap(),
            ConfigureFlowingGateIssuerOutcome::Configured(rotated)
        );
        assert_eq!(
            store.admit_flowing_prefix(&attempt).unwrap(),
            FlowingAdmissionOutcome::Existing(receipt)
        );
        let admissions: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM flowing_admissions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(admissions, 1);
        assert_eq!(
            store
                .get_branch(MAINLINE_BRANCH_ID)
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some(attempt.candidate_cut_id.as_str())
        );
        let mut competing = request("unit-a", "competing-after-crash");
        competing.recorded_at = "t9".into();
        assert_eq!(
            store.admit_flowing_prefix(&competing).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::TrunkStale {
                current: Some(attempt.candidate_cut_id.clone())
            })
        );
        drop(store);
        std::fs::remove_dir_all(&root).unwrap();
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
    fn cancelled_attempt_releases_only_its_own_cut_roots() {
        let mut store = fixture();
        let witness = request("unit-a", "fixture").candidate_witness_digest;
        let first = store
            .retain_flowing_attempt("attempt-a", &witness, "t3")
            .unwrap();
        assert!(matches!(first, RetainFlowingAttemptOutcome::Retained(_)));
        assert!(matches!(
            store
                .retain_flowing_attempt("attempt-a", &witness, "t3")
                .unwrap(),
            RetainFlowingAttemptOutcome::Existing(_)
        ));
        assert_eq!(
            store
                .retain_flowing_attempt("attempt-a", &witness, "changed")
                .unwrap(),
            RetainFlowingAttemptOutcome::IdentityMismatch
        );
        assert!(matches!(
            store
                .retain_flowing_attempt("attempt-b", &witness, "t3")
                .unwrap(),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
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
                .release_terminal_flowing_attempt("attempt-a", "t6")
                .unwrap(),
            ReleaseFlowingAttemptOutcome::AlreadyReleased
        );
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
        assert!(
            roots.contains("source"),
            "the private unit still owns its cut"
        );
        assert!(
            !roots.contains("candidate"),
            "both attempt pins were released"
        );
        assert_eq!(store.admitted_unit_operation("unit-a").unwrap(), None);
    }

    #[test]
    fn cancelled_attempt_cannot_release_a_lost_source_holder() {
        let mut store = fixture();
        let witness = request("unit-a", "fixture").candidate_witness_digest;
        store
            .retain_flowing_attempt("attempt-a", &witness, "t3")
            .unwrap();
        store
            .cancel_flowing_attempt(&cancel("attempt-a", "cancel-a"))
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE flowing_private_pins SET released_at = 't4' WHERE pin_id = 'pin'",
                [],
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
    fn cancelled_attempt_cannot_release_a_lost_or_changed_witness() {
        let mut store = fixture();
        let witness = request("unit-a", "fixture").candidate_witness_digest;
        store
            .retain_flowing_attempt("attempt-a", &witness, "t3")
            .unwrap();
        store
            .cancel_flowing_attempt(&cancel("attempt-a", "cancel-a"))
            .unwrap();
        store
            .connection
            .execute(
                "DELETE FROM flowing_candidate_witnesses WHERE digest = ?1",
                [&witness],
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
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_pins SET source_cut_id = 'other' WHERE op_id = 'attempt-a'",
                [],
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
    fn admitted_attempt_keeps_its_roots_until_receipt_reconciliation() {
        let mut store = fixture();
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
    fn native_cas_requires_the_live_pin_for_its_exact_attempt_and_witness() {
        let mut store = fixture();
        let request = request("unit-a", "fixture");
        assert_eq!(
            store.admit_flowing_prefix(&request).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::AttemptPinMissing)
        );
        pin_attempt(&mut store, &request);
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_pins SET witness_digest = 'different' WHERE op_id = ?1",
                [&request.op_id],
            )
            .unwrap();
        assert_eq!(
            store.admit_flowing_prefix(&request).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::AttemptPinMismatch)
        );
        store
            .connection
            .execute(
                "UPDATE flowing_attempt_pins SET witness_digest = ?2, released_at = 't4' WHERE op_id = ?1",
                [&request.op_id, &request.candidate_witness_digest],
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
    fn native_attempt_retention_refuses_missing_or_changed_witness_bases() {
        let mut store = fixture();
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
        pin_attempt(&mut store, &request("unit-a", "admission-b"));
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
        pin_attempt(&mut store, &admission);
        let admitted = store.admit_flowing_prefix(&admission).unwrap();
        let FlowingAdmissionOutcome::Admitted(receipt) = admitted else {
            panic!("admission should land")
        };
        let host_evidence =
            crate::branches::flowing_host::read_admission_evidence(&store, "admission-a")
                .unwrap()
                .expect("landed ref operation has host evidence");
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
    fn host_evidence_refuses_an_admitted_ref_with_a_missing_candidate_witness() {
        let mut store = fixture();
        let admission = request("unit-a", "admission-a");
        pin_attempt(&mut store, &admission);
        assert!(matches!(
            store.admit_flowing_prefix(&admission).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        store
            .connection
            .execute(
                "DELETE FROM flowing_candidate_witnesses WHERE digest = ?1",
                [&admission.candidate_witness_digest],
            )
            .unwrap();
        assert!(
            crate::branches::flowing_host::read_admission_evidence(&store, "admission-a").is_err()
        );
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
        pin_attempt(&mut store, &request("unit-a", "admission-a"));
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
        pin_attempt(&mut admitted_store, &request("unit-a", "admission-b"));
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
        pin_attempt(&mut store, &first);
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
        pin_attempt(&mut store, &no_op);
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
        pin_attempt(&mut store, &request);
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
    fn malformed_handoff_and_unrelated_named_source_cannot_admit() {
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
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::SourceCutMismatch)
        );
        assert!(store
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
    }

    #[test]
    fn source_kind_mismatch_refuses_before_trunk_admission() {
        let mut store = fixture();
        let mut state = store.flowing_source("twig").unwrap().unwrap();
        state.kind = FlowingSourceKind::Branch;
        store
            .connection
            .execute(
                "UPDATE flowing_source_fences SET state_json = ?1 WHERE source_branch_id = 'twig'",
                [serde_json::to_string(&state).unwrap()],
            )
            .unwrap();
        assert_eq!(
            store
                .admit_flowing_prefix(&request("unit-a", "admission-a"))
                .unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::SourceKindMismatch)
        );
        assert!(store
            .flowing_admission_receipt("admission-a")
            .unwrap()
            .is_none());
    }
}
