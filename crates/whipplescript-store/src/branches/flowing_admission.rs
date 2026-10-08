//! Atomic ref entries for gated flowing-source admission (DR-0130, FB-3).
//!
//! A gate attempt is disposable; an accepted unit is not. The ref entry and
//! per-unit uniqueness index must commit with the trunk CAS so a second
//! coordinator cannot admit a still-visible source prefix after a crash.
//! This first store slice accepts only a direct twig: member-twig handoffs
//! and named branches need transitive Hold/lineage checks. No host exposes
//! this operation until candidate construction, gate certification and
//! recovery are wired.

mod issuer;
#[cfg(feature = "native")]
pub(crate) mod native;

#[cfg(test)]
pub(crate) use issuer::test_issuer;
pub use issuer::{
    configure_outcome as configure_issuer_outcome, signing_bytes as issuer_signing_bytes,
    validate_issuer as validate_trusted_issuer, validate_signature as validate_issuer_signature,
    verify_issued, ConfigureFlowingGateIssuerOutcome, FlowingGateIssuerRefusal,
    FlowingGateIssuerSignature, FlowingGateTrustedIssuer, RecordFlowingGateSignatureOutcome,
};

use serde::{Deserialize, Serialize};

use super::flowing_fence::FlowingFenceState;

pub const SCHEMA: [&str; 12] = [
    "CREATE TABLE IF NOT EXISTS flowing_admissions (
        op_id TEXT PRIMARY KEY,
        receipt_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_admitted_units (
        unit_id TEXT PRIMARY KEY,
        op_id TEXT NOT NULL REFERENCES flowing_admissions(op_id)
    )",
    "CREATE TABLE IF NOT EXISTS flowing_admission_cancellations (
        admission_op_id TEXT PRIMARY KEY,
        cancel_op_id TEXT NOT NULL UNIQUE,
        request_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_candidate_witnesses (
        digest TEXT PRIMARY KEY,
        witness_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_gate_certificates (
        handle TEXT PRIMARY KEY,
        certificate_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_gate_evidence (
        digest TEXT PRIMARY KEY,
        evidence_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_attempt_pins (
        op_id TEXT PRIMARY KEY,
        witness_digest TEXT NOT NULL,
        source_cut_id TEXT NOT NULL,
        candidate_cut_id TEXT NOT NULL,
        retained_at TEXT NOT NULL,
        released_at TEXT
    )",
    "CREATE INDEX IF NOT EXISTS flowing_attempt_pins_live_idx
        ON flowing_attempt_pins(source_cut_id, candidate_cut_id)
        WHERE released_at IS NULL",
    "CREATE TABLE IF NOT EXISTS flowing_attempt_finishes (
        op_id TEXT PRIMARY KEY,
        receipt_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_coverage_premises (
        domain TEXT PRIMARY KEY,
        premises_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_gate_trusted_issuers (
        issuer_id TEXT PRIMARY KEY,
        issuer_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_gate_certificate_signatures (
        handle TEXT NOT NULL,
        issuer_id TEXT NOT NULL,
        issuer_epoch INTEGER NOT NULL,
        signature_json TEXT NOT NULL,
        PRIMARY KEY (handle, issuer_id, issuer_epoch)
    )",
];

/// A durable, attempt-owned pair of cut roots. The source holder still owns
/// every selected unit; this row preserves the exact review basis and output
/// across a gate worker crash. A terminal attempt may release only this row
/// after the ref authority confirms its outcome and the source holder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingAttemptPin {
    pub op_id: String,
    pub witness_digest: String,
    pub source_cut_id: String,
    pub candidate_cut_id: String,
    pub retained_at: String,
    pub released_at: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetainFlowingAttemptOutcome {
    Retained(FlowingAttemptPin),
    Existing(FlowingAttemptPin),
    IdentityMismatch,
    Released,
    AttemptTerminal,
    WitnessMissing,
    SourceCutMissing,
    SourceCutMismatch,
    CandidateCutMissing,
    CandidateCutMismatch,
    UnitHolderMissing { unit_id: String },
    UnitBasisMissing { unit_id: String },
    UnitBasisMismatch { unit_id: String },
    MissingContent { content_id: String },
    Invalid { field: &'static str },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseFlowingAttemptOutcome {
    Released,
    AlreadyReleased,
    Missing,
    NotTerminal,
    Admitted,
    UnitHolderMissing { unit_id: String },
    Invalid { field: &'static str },
}

/// The ref-owned result of an exact gate attempt that did not pass. Failed
/// and unrun stay distinct from cancellation and from a stale candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingAttemptFinishReceipt {
    pub request: FlowingAdmissionRequest,
    pub verdict: FlowingGateVerdict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingAttemptFinishRefusal {
    IdentityMismatch,
    InvalidRequest(FlowingAdmissionRefusal),
    AttemptPinMissing,
    AttemptPinMismatch,
    AttemptPinReleased,
    CandidateWitnessMissing,
    CandidateWitnessMismatch,
    GateCertificateMissing,
    GateCertificateMismatch,
    GateIssuer(FlowingGateIssuerRefusal),
    GatePlanIncomplete,
    GatePassed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingAttemptFinishOutcome {
    Finished(FlowingAttemptFinishReceipt),
    Existing(FlowingAttemptFinishReceipt),
    AlreadyAdmitted(Box<FlowingAdmissionReceipt>),
    AlreadyCancelled(FlowingCancelReceipt),
    Refused(FlowingAttemptFinishRefusal),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowingUnitOutcome {
    Applied,
    Equivalent,
    Neutralized,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingSelectedUnit {
    pub unit_id: String,
    pub basis_digest: String,
    pub principal: String,
    pub intent: String,
    pub outcome: FlowingUnitOutcome,
}

/// Durable output of the native VCS's complete-prefix proof. This is source
/// evidence, not a fleet verdict or permission to admit. The ref store keeps
/// the exact witness so an admission request cannot choose its own unit set
/// or outcomes after candidate construction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingCandidateWitness {
    pub contribution_id: String,
    pub revision_sequence: i64,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub source_cut_id: String,
    pub source_manifest_hash: String,
    pub expected_trunk_cut_id: Option<String>,
    pub candidate_cut_id: String,
    pub candidate_manifest_hash: String,
    pub source_atoms_digest: String,
    pub units: Vec<FlowingSelectedUnit>,
}

impl FlowingCandidateWitness {
    pub fn digest(&self) -> crate::StoreResult<String> {
        let bytes = serde_json::to_vec(&("native-candidate-witness-v1", self))?;
        Ok(format!(
            "sha256:{}",
            crate::chunking::content_hash_hex(&bytes)
        ))
    }

    pub fn matches_request(&self, request: &FlowingAdmissionRequest) -> bool {
        self.contribution_id == request.contribution_id
            && self.revision_sequence == request.revision_sequence
            && self.source_branch_id == request.source_branch_id
            && self.source_incarnation_id == request.source_incarnation_id
            && self.source_cut_id == request.source_cut_id
            && self.source_manifest_hash == request.source_manifest_hash
            && self.expected_trunk_cut_id == request.expected_trunk_cut_id
            && self.candidate_cut_id == request.candidate_cut_id
            && self.candidate_manifest_hash == request.candidate_manifest_hash
            && self.units == request.units
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowingGateVerdict {
    Passed,
    Failed,
    Unrun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingGateCheck {
    pub check_id: String,
    pub input_digest: String,
    pub evidence_digest: String,
    pub verdict: FlowingGateVerdict,
}

/// Exact process output behind a check digest. A process that cannot start is
/// unrun; a process that runs and exits unsuccessfully is failed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingGateEvidence {
    pub attempt_op_id: String,
    pub check_id: String,
    pub input_digest: String,
    pub program: String,
    pub args: Vec<String>,
    pub exit_code: Option<i32>,
    pub started: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub run_error: Option<String>,
}

impl FlowingGateEvidence {
    pub fn digest(&self) -> crate::StoreResult<String> {
        let bytes = serde_json::to_vec(&("native-gate-evidence-v1", self))?;
        Ok(format!(
            "sha256:{}",
            crate::chunking::content_hash_hex(&bytes)
        ))
    }

    pub fn verdict(&self) -> FlowingGateVerdict {
        if !self.started {
            FlowingGateVerdict::Unrun
        } else if self.exit_code == Some(0) {
            FlowingGateVerdict::Passed
        } else {
            FlowingGateVerdict::Failed
        }
    }
}

/// An exact gate result envelope. No production issuer writes this table yet:
/// the fleet must first execute a native cut and prove the required plan and
/// current norm basis. Ref admission refuses without a retained certificate,
/// and without a signature over its handle from an issuer the ref store's
/// trust root holds at its current epoch (see `issuer`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingGateCertificate {
    pub candidate_witness_digest: String,
    pub expected_trunk_cut_id: Option<String>,
    pub candidate_cut_id: String,
    pub candidate_manifest_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lineage_fences: Vec<super::flowing_fence::FlowingFenceState>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unit_holders: Vec<super::flowing_holders::FlowingUnitHolder>,
    pub source_eligibility_epoch: i64,
    pub source_owner_epoch: i64,
    pub coordinator: String,
    pub policy_digest: String,
    pub rules_digest: String,
    pub graph_coverage_digest: String,
    /// The reference-coverage premise vector the plan was derived under
    /// (RC-5). Ref admission refuses a certificate without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<super::flowing_coverage::FlowingCoverageBasis>,
    pub required_checks: Vec<String>,
    pub checks: Vec<FlowingGateCheck>,
}

impl FlowingGateCertificate {
    pub fn handle(&self) -> crate::StoreResult<String> {
        let version = if self.coverage.is_some() {
            "native-gate-certificate-v4"
        } else if !self.unit_holders.is_empty() {
            "native-gate-certificate-v3"
        } else if self.lineage_fences.is_empty() {
            "native-gate-certificate-v1"
        } else {
            "native-gate-certificate-v2"
        };
        let bytes = serde_json::to_vec(&(version, self))?;
        Ok(format!(
            "sha256:{}",
            crate::chunking::content_hash_hex(&bytes)
        ))
    }

    pub fn matches_request(&self, request: &FlowingAdmissionRequest) -> bool {
        self.candidate_witness_digest == request.candidate_witness_digest
            && self.expected_trunk_cut_id == request.expected_trunk_cut_id
            && self.candidate_cut_id == request.candidate_cut_id
            && self.candidate_manifest_hash == request.candidate_manifest_hash
            && self.source_eligibility_epoch == request.expected_eligibility_epoch
            && self.source_owner_epoch == request.expected_owner_epoch
            && self.coordinator == request.coordinator
            && (self.unit_holders.is_empty()
                || (self.unit_holders.len() == request.units.len()
                    && self
                        .unit_holders
                        .iter()
                        .zip(&request.units)
                        .all(|(holder, selected)| {
                            holder.unit_id == selected.unit_id
                                && holder.holder_branch_id == request.source_branch_id
                        })))
    }

    pub fn admission_refusal(&self) -> Option<FlowingAdmissionRefusal> {
        if self.candidate_witness_digest.trim().is_empty()
            || self.candidate_cut_id.trim().is_empty()
            || self.candidate_manifest_hash.trim().is_empty()
            || self.policy_digest.trim().is_empty()
            || self.rules_digest.trim().is_empty()
            || self.graph_coverage_digest.trim().is_empty()
            || self.source_eligibility_epoch < 0
            || self.source_owner_epoch < 0
            || self.coordinator.trim().is_empty()
            || self.required_checks.is_empty()
            || self.required_checks.len() != self.checks.len()
            || self
                .coverage
                .as_ref()
                .is_some_and(|coverage| !coverage.is_well_formed())
        {
            return Some(FlowingAdmissionRefusal::GatePlanIncomplete);
        }
        if self
            .lineage_fences
            .windows(2)
            .any(|pair| pair[0].source_branch_id >= pair[1].source_branch_id)
            || self.lineage_fences.iter().any(|fence| {
                fence.source_branch_id.trim().is_empty()
                    || fence.incarnation_id.trim().is_empty()
                    || fence.owner.trim().is_empty()
                    || fence.owner_epoch < 0
                    || fence.eligibility_epoch < 0
                    || fence.held
                    || fence.revision.is_some()
                    || !fence.admission_enabled
            })
        {
            return Some(FlowingAdmissionRefusal::GatePlanIncomplete);
        }
        let mut holder_units = std::collections::BTreeSet::new();
        if (!self.unit_holders.is_empty() && self.lineage_fences.is_empty())
            || self.unit_holders.iter().any(|holder| {
                holder.unit_id.trim().is_empty()
                    || !holder_units.insert(&holder.unit_id)
                    || holder.holder_branch_id.trim().is_empty()
                    || holder.holder_cut_id.trim().is_empty()
                    || holder.holder_manifest_hash.trim().is_empty()
                    || holder.proof_digest.trim().is_empty()
                    || holder
                        .handoff_op_id
                        .as_ref()
                        .is_some_and(|op| op.trim().is_empty())
            })
        {
            return Some(FlowingAdmissionRefusal::GatePlanIncomplete);
        }
        let mut seen = std::collections::BTreeSet::new();
        for (required, check) in self.required_checks.iter().zip(&self.checks) {
            if required.trim().is_empty()
                || required != &check.check_id
                || !seen.insert(required)
                || check.input_digest.trim().is_empty()
                || check.evidence_digest.trim().is_empty()
            {
                return Some(FlowingAdmissionRefusal::GatePlanIncomplete);
            }
        }
        if self
            .checks
            .iter()
            .any(|check| check.verdict == FlowingGateVerdict::Failed)
        {
            return Some(FlowingAdmissionRefusal::GateFailed);
        }
        if self
            .checks
            .iter()
            .any(|check| check.verdict == FlowingGateVerdict::Unrun)
        {
            return Some(FlowingAdmissionRefusal::GateUnrun);
        }
        None
    }
}

/// Exact request that the coordinator has gated against a proposed trunk
/// result. The store rechecks mutable ref and source facts at commit; the
/// caller must hold the norm-ledger exclusion and establish the certificate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingAdmissionRequest {
    pub op_id: String,
    pub certificate_handle: String,
    #[serde(default)]
    pub candidate_witness_digest: String,
    #[serde(default)]
    pub contribution_id: String,
    #[serde(default)]
    pub revision_sequence: i64,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub source_cut_id: String,
    pub source_manifest_hash: String,
    pub expected_eligibility_epoch: i64,
    pub expected_owner_epoch: i64,
    pub coordinator: String,
    pub expected_trunk_cut_id: Option<String>,
    pub candidate_cut_id: String,
    pub candidate_manifest_hash: String,
    pub units: Vec<FlowingSelectedUnit>,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingAdmissionReceipt {
    pub request: FlowingAdmissionRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingAdmissionRefusal {
    IdentityMismatch,
    Invalid {
        field: &'static str,
    },
    SourceMissing,
    SourceNotActive,
    SourceNotTrunkChild,
    SourceNotDirectTwig,
    WrongIncarnation,
    StaleEligibilityEpoch {
        current: i64,
    },
    StaleOwnerEpoch {
        current: i64,
    },
    WrongOwner,
    Held,
    RevisionPending,
    AdmissionDisabled,
    SourceCutMissing,
    SourceCutMismatch,
    SourceCutNotRetained,
    TrunkMissing,
    TrunkNotActive,
    TrunkReserved,
    TrunkStale {
        current: Option<String>,
    },
    CandidateMissing,
    CandidateMismatch,
    CandidateWitnessMissing,
    CandidateWitnessMismatch,
    AttemptPinMissing,
    AttemptPinMismatch,
    AttemptPinReleased,
    GateCertificateMissing,
    GateCertificateMismatch,
    GateIssuer(FlowingGateIssuerRefusal),
    GatePlanIncomplete,
    LineageUnavailable,
    LineageChanged,
    HolderUnavailable,
    HolderChanged,
    /// No coverage basis on the certificate, or no recorded premises.
    CoverageUnavailable,
    /// The certificate's premise vector is not the current one.
    CoverageStale {
        premise: &'static str,
    },
    /// A required scope is unknown and no owner can be routed to validate it.
    CoverageScopeUnknown {
        scope_id: String,
    },
    /// A scope that must route every owner lacks this owner's validation of
    /// the exact candidate at the current graph epoch.
    CoverageOwnerUnvalidated {
        scope_id: String,
        owner: String,
    },
    GateFailed,
    GateUnrun,
    UnitMissing {
        unit_id: String,
    },
    UnitBasisMissing {
        unit_id: String,
    },
    UnitBasisMismatch {
        unit_id: String,
    },
    UnitPinMissing {
        unit_id: String,
    },
    UnitPinReleased {
        unit_id: String,
    },
    UnitNotHeldBySource {
        unit_id: String,
    },
    UnverifiedLineage {
        unit_id: String,
    },
    UnitAlreadyAdmitted {
        unit_id: String,
    },
    UnitParked {
        unit_id: String,
        park_op_id: String,
    },
    AttemptCancelled {
        cancel_op_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingAdmissionOutcome {
    Admitted(FlowingAdmissionReceipt),
    Existing(FlowingAdmissionReceipt),
    Refused(FlowingAdmissionRefusal),
}

/// A cancellation is a ref-authority operation ordered against the attempted
/// trunk CAS. It fences one admission op id; it never disposes its units.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingCancelRequest {
    pub cancel_op_id: String,
    pub admission_op_id: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub expected_owner_epoch: i64,
    pub coordinator: String,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingCancelReceipt {
    pub request: FlowingCancelRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingCancelRefusal {
    Invalid { field: &'static str },
    IdentityMismatch,
    SourceMissing,
    WrongIncarnation,
    StaleOwnerEpoch { current: i64 },
    WrongOwner,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingCancelOutcome {
    Cancelled(FlowingCancelReceipt),
    Existing(FlowingCancelReceipt),
    AlreadyCancelled(FlowingCancelReceipt),
    AlreadyAdmitted(Box<FlowingAdmissionReceipt>),
    AlreadyFinished(Box<FlowingAttemptFinishReceipt>),
    Refused(FlowingCancelRefusal),
}

pub trait FlowingAdmissions {
    /// The ref authority's per-unit uniqueness index, read before preparing
    /// a candidate. Admission rechecks it under the trunk CAS.
    fn admitted_unit_operation(&self, unit_id: &str) -> crate::StoreResult<Option<String>>;
    /// Called by the native candidate constructor after it has proved source
    /// closure and retained the candidate cut. A host must not expose this
    /// store-only issuer API to an untrusted caller.
    fn record_candidate_witness(
        &mut self,
        witness: &FlowingCandidateWitness,
    ) -> crate::StoreResult<String>;
    fn candidate_witness(
        &self,
        digest: &str,
    ) -> crate::StoreResult<Option<FlowingCandidateWitness>>;
    fn retain_flowing_attempt(
        &mut self,
        op_id: &str,
        witness_digest: &str,
        retained_at: &str,
    ) -> crate::StoreResult<RetainFlowingAttemptOutcome>;
    fn flowing_attempt_pin(&self, op_id: &str) -> crate::StoreResult<Option<FlowingAttemptPin>>;
    /// Release a cancelled, failed or unrun attempt only after its selected
    /// units still have their durable source holder. An admitted attempt needs
    /// receipt/frontier reconciliation before these roots can move.
    fn release_terminal_flowing_attempt(
        &mut self,
        op_id: &str,
        released_at: &str,
    ) -> crate::StoreResult<ReleaseFlowingAttemptOutcome>;
    fn finish_flowing_attempt(
        &mut self,
        request: &FlowingAdmissionRequest,
    ) -> crate::StoreResult<FlowingAttemptFinishOutcome>;
    fn flowing_finish_for_attempt(
        &self,
        op_id: &str,
    ) -> crate::StoreResult<Option<FlowingAttemptFinishReceipt>>;
    fn admit_flowing_prefix(
        &mut self,
        request: &FlowingAdmissionRequest,
    ) -> crate::StoreResult<FlowingAdmissionOutcome>;
    fn flowing_admission_receipt(
        &self,
        op_id: &str,
    ) -> crate::StoreResult<Option<FlowingAdmissionReceipt>>;
    fn cancel_flowing_attempt(
        &mut self,
        request: &FlowingCancelRequest,
    ) -> crate::StoreResult<FlowingCancelOutcome>;
    /// Operator configuration of the ref authority's trust root. An issuer's
    /// epoch only rises; raising it retires every signature made earlier. A
    /// host must not expose this to a gate worker or any untrusted caller.
    fn configure_flowing_gate_issuer(
        &mut self,
        issuer: &FlowingGateTrustedIssuer,
    ) -> crate::StoreResult<ConfigureFlowingGateIssuerOutcome>;
    fn flowing_gate_trusted_issuers(&self) -> crate::StoreResult<Vec<FlowingGateTrustedIssuer>>;
    /// Retain an issuer's signature beside an existing certificate. It is
    /// verified against the current trust root here and again under the ref
    /// CAS, which is the check that authorizes anything.
    fn record_flowing_gate_signature(
        &mut self,
        signature: &FlowingGateIssuerSignature,
    ) -> crate::StoreResult<RecordFlowingGateSignatureOutcome>;
    fn flowing_gate_signatures(
        &self,
        certificate_handle: &str,
    ) -> crate::StoreResult<Vec<FlowingGateIssuerSignature>>;
    fn flowing_cancellation_for_attempt(
        &self,
        admission_op_id: &str,
    ) -> crate::StoreResult<Option<FlowingCancelReceipt>>;
    /// Trusted coverage-authority writer for this Home's current premise
    /// vector. Epochs never move backwards; a host must not expose this to an
    /// untrusted caller.
    fn record_flowing_coverage_premises(
        &mut self,
        premises: &super::flowing_coverage::FlowingCoveragePremises,
    ) -> crate::StoreResult<super::flowing_coverage::RecordCoveragePremisesOutcome>;
    fn flowing_coverage_premises(
        &self,
    ) -> crate::StoreResult<Option<super::flowing_coverage::FlowingCoveragePremises>>;
}

pub fn validate_cancel_request(request: &FlowingCancelRequest) -> Result<(), FlowingCancelRefusal> {
    for (field, value) in [
        ("cancel_op_id", request.cancel_op_id.as_str()),
        ("admission_op_id", request.admission_op_id.as_str()),
        ("source_branch_id", request.source_branch_id.as_str()),
        (
            "source_incarnation_id",
            request.source_incarnation_id.as_str(),
        ),
        ("coordinator", request.coordinator.as_str()),
        ("recorded_at", request.recorded_at.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(FlowingCancelRefusal::Invalid { field });
        }
    }
    if request.cancel_op_id == request.admission_op_id {
        return Err(FlowingCancelRefusal::Invalid {
            field: "admission_op_id",
        });
    }
    if request.expected_owner_epoch < 0 {
        return Err(FlowingCancelRefusal::Invalid {
            field: "expected_owner_epoch",
        });
    }
    Ok(())
}

pub fn validate_request(request: &FlowingAdmissionRequest) -> Result<(), FlowingAdmissionRefusal> {
    for (field, value) in [
        ("op_id", request.op_id.as_str()),
        ("certificate_handle", request.certificate_handle.as_str()),
        (
            "candidate_witness_digest",
            request.candidate_witness_digest.as_str(),
        ),
        ("contribution_id", request.contribution_id.as_str()),
        ("source_branch_id", request.source_branch_id.as_str()),
        (
            "source_incarnation_id",
            request.source_incarnation_id.as_str(),
        ),
        ("source_cut_id", request.source_cut_id.as_str()),
        (
            "source_manifest_hash",
            request.source_manifest_hash.as_str(),
        ),
        ("coordinator", request.coordinator.as_str()),
        ("candidate_cut_id", request.candidate_cut_id.as_str()),
        (
            "candidate_manifest_hash",
            request.candidate_manifest_hash.as_str(),
        ),
        ("recorded_at", request.recorded_at.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(FlowingAdmissionRefusal::Invalid { field });
        }
    }
    if request.expected_eligibility_epoch < 0 || request.expected_owner_epoch < 0 {
        return Err(FlowingAdmissionRefusal::Invalid { field: "epoch" });
    }
    if request.revision_sequence < 1 {
        return Err(FlowingAdmissionRefusal::Invalid {
            field: "revision_sequence",
        });
    }
    if request.units.is_empty() {
        return Err(FlowingAdmissionRefusal::Invalid { field: "units" });
    }
    let mut seen = std::collections::BTreeSet::new();
    for unit in &request.units {
        if unit.unit_id.trim().is_empty()
            || unit.basis_digest.trim().is_empty()
            || unit.principal.trim().is_empty()
            || unit.intent.trim().is_empty()
            || !seen.insert(unit.unit_id.as_str())
        {
            return Err(FlowingAdmissionRefusal::Invalid { field: "units" });
        }
    }
    Ok(())
}

pub fn check_fence(
    state: &FlowingFenceState,
    request: &FlowingAdmissionRequest,
) -> Result<(), FlowingAdmissionRefusal> {
    if state.incarnation_id != request.source_incarnation_id {
        return Err(FlowingAdmissionRefusal::WrongIncarnation);
    }
    if state.eligibility_epoch != request.expected_eligibility_epoch {
        return Err(FlowingAdmissionRefusal::StaleEligibilityEpoch {
            current: state.eligibility_epoch,
        });
    }
    if state.owner_epoch != request.expected_owner_epoch {
        return Err(FlowingAdmissionRefusal::StaleOwnerEpoch {
            current: state.owner_epoch,
        });
    }
    if state.owner != request.coordinator {
        return Err(FlowingAdmissionRefusal::WrongOwner);
    }
    if state.held {
        return Err(FlowingAdmissionRefusal::Held);
    }
    if state.revision.is_some() {
        return Err(FlowingAdmissionRefusal::RevisionPending);
    }
    if !state.admission_enabled {
        return Err(FlowingAdmissionRefusal::AdmissionDisabled);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_fence::{FlowingRevision, FlowingSourceKind};

    fn request() -> FlowingAdmissionRequest {
        FlowingAdmissionRequest {
            op_id: "admit-1".into(),
            certificate_handle: "certificate-1".into(),
            candidate_witness_digest: "sha256:witness-1".into(),
            contribution_id: "review-1".into(),
            revision_sequence: 1,
            source_branch_id: "twig-1".into(),
            source_incarnation_id: "incarnation-1".into(),
            source_cut_id: "source-cut".into(),
            source_manifest_hash: "source-manifest".into(),
            expected_eligibility_epoch: 2,
            expected_owner_epoch: 3,
            coordinator: "coordinator-1".into(),
            expected_trunk_cut_id: Some("trunk-before".into()),
            candidate_cut_id: "trunk-after".into(),
            candidate_manifest_hash: "candidate-manifest".into(),
            units: vec![FlowingSelectedUnit {
                unit_id: "unit-1".into(),
                basis_digest: "basis-1".into(),
                principal: "principal-1".into(),
                intent: "intent-1".into(),
                outcome: FlowingUnitOutcome::Applied,
            }],
            recorded_at: "now".into(),
        }
    }

    fn gate_certificate(request: &FlowingAdmissionRequest) -> FlowingGateCertificate {
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
            policy_digest: "sha256:policy".into(),
            rules_digest: "sha256:rules".into(),
            graph_coverage_digest: "sha256:coverage".into(),
            coverage: None,
            required_checks: vec!["all-targets".into()],
            checks: vec![FlowingGateCheck {
                check_id: "all-targets".into(),
                input_digest: "sha256:input".into(),
                evidence_digest: "sha256:result".into(),
                verdict: FlowingGateVerdict::Passed,
            }],
        }
    }

    #[test]
    fn lineage_certificate_keeps_legacy_identity_and_binds_new_vector() {
        let legacy = gate_certificate(&request());
        let value = serde_json::to_value(&legacy).unwrap();
        assert!(value.get("lineage_fences").is_none());
        assert_eq!(
            legacy.handle().unwrap(),
            "sha256:336dadb2cec9f7aa99e7fbdc2cd0c597"
        );
        let restored: FlowingGateCertificate = serde_json::from_value(value).unwrap();
        assert_eq!(restored.handle().unwrap(), legacy.handle().unwrap());
        let mut next = legacy.clone();
        next.lineage_fences
            .push(crate::branches::flowing_fence::FlowingFenceState {
                source_branch_id: "twig".into(),
                incarnation_id: "inc".into(),
                kind: FlowingSourceKind::Twig,
                owner: "coordinator".into(),
                owner_epoch: 0,
                eligibility_epoch: 0,
                held: false,
                revision: None,
                admission_enabled: true,
                opened_at: "t1".into(),
            });
        assert_eq!(next.admission_refusal(), None);
        assert_ne!(next.handle().unwrap(), legacy.handle().unwrap());
        let mut malformed = next.clone();
        malformed
            .lineage_fences
            .push(next.lineage_fences[0].clone());
        assert_eq!(
            malformed.admission_refusal(),
            Some(FlowingAdmissionRefusal::GatePlanIncomplete)
        );
        malformed = next.clone();
        malformed.lineage_fences[0].held = true;
        assert_eq!(
            malformed.admission_refusal(),
            Some(FlowingAdmissionRefusal::GatePlanIncomplete)
        );
        next.lineage_fences[0].eligibility_epoch += 1;
        assert_ne!(next.handle().unwrap(), malformed.handle().unwrap());
    }

    #[test]
    fn holder_certificate_binds_order_and_preserves_old_serialized_identity() {
        let mut certificate = gate_certificate(&request());
        assert!(serde_json::to_value(&certificate)
            .unwrap()
            .get("unit_holders")
            .is_none());
        certificate
            .lineage_fences
            .push(crate::branches::flowing_fence::FlowingFenceState {
                source_branch_id: "twig".into(),
                incarnation_id: "inc".into(),
                kind: FlowingSourceKind::Twig,
                owner: "coordinator".into(),
                owner_epoch: 0,
                eligibility_epoch: 0,
                held: false,
                revision: None,
                admission_enabled: true,
                opened_at: "t1".into(),
            });
        let old_value = serde_json::to_value(&certificate).unwrap();
        assert!(old_value.get("unit_holders").is_none());
        let restored: FlowingGateCertificate = serde_json::from_value(old_value).unwrap();
        assert_eq!(certificate.handle().unwrap(), restored.handle().unwrap());
        let old_handle = certificate.handle().unwrap();
        certificate
            .unit_holders
            .push(crate::branches::flowing_holders::FlowingUnitHolder {
                unit_id: request().units[0].unit_id.clone(),
                holder_branch_id: request().source_branch_id,
                holder_cut_id: "source".into(),
                holder_manifest_hash: "source-manifest".into(),
                handoff_op_id: None,
                proof_digest: "proof".into(),
            });
        assert_eq!(certificate.admission_refusal(), None);
        assert!(certificate.matches_request(&request()));
        assert_ne!(certificate.handle().unwrap(), old_handle);
        let mut changed = certificate.clone();
        changed.unit_holders[0].proof_digest = "changed".into();
        assert_ne!(changed.handle().unwrap(), certificate.handle().unwrap());
        changed.unit_holders[0].unit_id = "wrong".into();
        assert!(!changed.matches_request(&request()));
        changed = certificate.clone();
        changed.unit_holders.push(changed.unit_holders[0].clone());
        assert_eq!(
            changed.admission_refusal(),
            Some(FlowingAdmissionRefusal::GatePlanIncomplete)
        );
        changed = certificate.clone();
        changed.unit_holders[0].handoff_op_id = Some(" ".into());
        assert_eq!(
            changed.admission_refusal(),
            Some(FlowingAdmissionRefusal::GatePlanIncomplete)
        );
        changed = certificate;
        changed.lineage_fences.clear();
        assert_eq!(
            changed.admission_refusal(),
            Some(FlowingAdmissionRefusal::GatePlanIncomplete)
        );
    }

    #[test]
    fn coverage_certificate_keeps_legacy_identity_and_requires_a_well_formed_basis() {
        use crate::branches::flowing_coverage::tests::{basis_for, premises};
        let legacy = gate_certificate(&request());
        assert!(serde_json::to_value(&legacy)
            .unwrap()
            .get("coverage")
            .is_none());
        let mut bound = legacy.clone();
        bound.coverage = Some(basis_for(&premises(), &request().candidate_manifest_hash));
        assert_eq!(bound.admission_refusal(), None);
        assert_ne!(bound.handle().unwrap(), legacy.handle().unwrap());
        let restored: FlowingGateCertificate =
            serde_json::from_value(serde_json::to_value(&bound).unwrap()).unwrap();
        assert_eq!(restored.handle().unwrap(), bound.handle().unwrap());
        let mut malformed = bound.clone();
        malformed.coverage.as_mut().unwrap().premises_digest.clear();
        assert_eq!(
            malformed.admission_refusal(),
            Some(FlowingAdmissionRefusal::GatePlanIncomplete)
        );
        let mut changed = bound.clone();
        changed.coverage.as_mut().unwrap().graph_epoch += 1;
        assert_ne!(changed.handle().unwrap(), bound.handle().unwrap());
    }

    #[test]
    fn gate_certificate_requires_exact_bindings_and_every_planned_result() {
        let request = request();
        let valid = gate_certificate(&request);
        assert!(valid.matches_request(&request));
        assert_eq!(valid.admission_refusal(), None);
        assert_ne!(valid.handle().unwrap(), "certificate-1");

        let mut wrong_candidate = valid.clone();
        wrong_candidate.candidate_manifest_hash = "other".into();
        assert!(!wrong_candidate.matches_request(&request));
        assert_ne!(valid.handle().unwrap(), wrong_candidate.handle().unwrap());
        let mut wrong_owner = valid.clone();
        wrong_owner.source_owner_epoch += 1;
        assert!(!wrong_owner.matches_request(&request));

        let mut missing_policy = valid.clone();
        missing_policy.policy_digest.clear();
        assert_eq!(
            missing_policy.admission_refusal(),
            Some(FlowingAdmissionRefusal::GatePlanIncomplete)
        );
        let mut omitted = valid.clone();
        omitted.checks.clear();
        assert_eq!(
            omitted.admission_refusal(),
            Some(FlowingAdmissionRefusal::GatePlanIncomplete)
        );
        let mut duplicated = valid.clone();
        duplicated.required_checks.push("all-targets".into());
        duplicated.checks.push(duplicated.checks[0].clone());
        assert_eq!(
            duplicated.admission_refusal(),
            Some(FlowingAdmissionRefusal::GatePlanIncomplete)
        );
        let mut failed = valid.clone();
        failed.checks[0].verdict = FlowingGateVerdict::Failed;
        assert_eq!(
            failed.admission_refusal(),
            Some(FlowingAdmissionRefusal::GateFailed)
        );
        let mut unrun = valid;
        unrun.checks[0].verdict = FlowingGateVerdict::Unrun;
        assert_eq!(
            unrun.admission_refusal(),
            Some(FlowingAdmissionRefusal::GateUnrun)
        );
    }

    fn fence() -> FlowingFenceState {
        FlowingFenceState {
            source_branch_id: "twig-1".into(),
            incarnation_id: "incarnation-1".into(),
            kind: FlowingSourceKind::Twig,
            owner: "coordinator-1".into(),
            owner_epoch: 3,
            eligibility_epoch: 2,
            held: false,
            revision: None,
            admission_enabled: true,
            opened_at: "earlier".into(),
        }
    }

    fn cancel_request() -> FlowingCancelRequest {
        FlowingCancelRequest {
            cancel_op_id: "cancel-1".into(),
            admission_op_id: "admit-1".into(),
            source_branch_id: "twig-1".into(),
            source_incarnation_id: "incarnation-1".into(),
            expected_owner_epoch: 3,
            coordinator: "coordinator-1".into(),
            recorded_at: "now".into(),
        }
    }

    #[test]
    fn cancellation_request_rejects_missing_or_reused_identity_and_invalid_epoch() {
        let valid = cancel_request();
        assert_eq!(validate_cancel_request(&valid), Ok(()));

        let mut missing = valid.clone();
        missing.admission_op_id = " ".into();
        assert_eq!(
            validate_cancel_request(&missing),
            Err(FlowingCancelRefusal::Invalid {
                field: "admission_op_id"
            })
        );

        let mut reused = valid.clone();
        reused.admission_op_id = reused.cancel_op_id.clone();
        assert_eq!(
            validate_cancel_request(&reused),
            Err(FlowingCancelRefusal::Invalid {
                field: "admission_op_id"
            })
        );

        let mut negative_epoch = valid;
        negative_epoch.expected_owner_epoch = -1;
        assert_eq!(
            validate_cancel_request(&negative_epoch),
            Err(FlowingCancelRefusal::Invalid {
                field: "expected_owner_epoch"
            })
        );
    }

    #[test]
    fn request_validation_pins_each_refusal() {
        let valid = request();
        assert_eq!(validate_request(&valid), Ok(()));

        let mut missing_identity = valid.clone();
        missing_identity.certificate_handle = "  ".into();
        assert_eq!(
            validate_request(&missing_identity),
            Err(FlowingAdmissionRefusal::Invalid {
                field: "certificate_handle"
            })
        );

        let mut missing_witness = valid.clone();
        missing_witness.candidate_witness_digest = " ".into();
        assert_eq!(
            validate_request(&missing_witness),
            Err(FlowingAdmissionRefusal::Invalid {
                field: "candidate_witness_digest"
            })
        );

        let mut missing_revision = valid.clone();
        missing_revision.revision_sequence = 0;
        assert_eq!(
            validate_request(&missing_revision),
            Err(FlowingAdmissionRefusal::Invalid {
                field: "revision_sequence"
            })
        );

        let mut negative_epoch = valid.clone();
        negative_epoch.expected_owner_epoch = -1;
        assert_eq!(
            validate_request(&negative_epoch),
            Err(FlowingAdmissionRefusal::Invalid { field: "epoch" })
        );

        let mut empty_units = valid.clone();
        empty_units.units.clear();
        assert_eq!(
            validate_request(&empty_units),
            Err(FlowingAdmissionRefusal::Invalid { field: "units" })
        );

        let mut duplicate_units = valid;
        duplicate_units.units.push(duplicate_units.units[0].clone());
        assert_eq!(
            validate_request(&duplicate_units),
            Err(FlowingAdmissionRefusal::Invalid { field: "units" })
        );
    }

    #[test]
    fn fence_validation_pins_each_refusal() {
        let request = request();
        let valid = fence();
        assert_eq!(check_fence(&valid, &request), Ok(()));

        let mut wrong_incarnation = valid.clone();
        wrong_incarnation.incarnation_id = "other".into();
        assert_eq!(
            check_fence(&wrong_incarnation, &request),
            Err(FlowingAdmissionRefusal::WrongIncarnation)
        );

        let mut stale_eligibility = valid.clone();
        stale_eligibility.eligibility_epoch += 1;
        assert_eq!(
            check_fence(&stale_eligibility, &request),
            Err(FlowingAdmissionRefusal::StaleEligibilityEpoch { current: 3 })
        );

        let mut stale_owner = valid.clone();
        stale_owner.owner_epoch += 1;
        assert_eq!(
            check_fence(&stale_owner, &request),
            Err(FlowingAdmissionRefusal::StaleOwnerEpoch { current: 4 })
        );

        let mut wrong_owner = valid.clone();
        wrong_owner.owner = "other".into();
        assert_eq!(
            check_fence(&wrong_owner, &request),
            Err(FlowingAdmissionRefusal::WrongOwner)
        );

        let mut held = valid.clone();
        held.held = true;
        assert_eq!(
            check_fence(&held, &request),
            Err(FlowingAdmissionRefusal::Held)
        );

        let mut revision_pending = valid.clone();
        revision_pending.revision = Some(FlowingRevision {
            begin_op_id: "revision-1".into(),
            before_cut_id: Some("source-cut".into()),
            after_cut_id: "next-cut".into(),
        });
        assert_eq!(
            check_fence(&revision_pending, &request),
            Err(FlowingAdmissionRefusal::RevisionPending)
        );

        let mut disabled = valid;
        disabled.admission_enabled = false;
        assert_eq!(
            check_fence(&disabled, &request),
            Err(FlowingAdmissionRefusal::AdmissionDisabled)
        );
    }
}
