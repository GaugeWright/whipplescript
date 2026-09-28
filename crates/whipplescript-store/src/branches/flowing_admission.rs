//! Atomic ref entries for gated flowing-source admission (DR-0130, FB-3).
//!
//! A gate attempt is disposable; an accepted unit is not. The ref entry and
//! per-unit uniqueness index must commit with the trunk CAS so a second
//! coordinator cannot admit a still-visible source prefix after a crash.
//! This first store slice accepts only a direct twig: member-twig handoffs
//! and named branches need transitive Hold/lineage checks. No host exposes
//! this operation until candidate construction, gate certification and
//! recovery are wired.

#[cfg(feature = "native")]
mod native;

use serde::{Deserialize, Serialize};

use super::flowing_fence::FlowingFenceState;

pub const SCHEMA: [&str; 3] = [
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
];

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

/// Exact request that the coordinator has gated against a proposed trunk
/// result. The store rechecks mutable ref and source facts at commit; the
/// caller must hold the norm-ledger exclusion and establish the certificate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingAdmissionRequest {
    pub op_id: String,
    pub certificate_handle: String,
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
    Invalid { field: &'static str },
    SourceMissing,
    SourceNotActive,
    SourceNotTrunkChild,
    SourceNotDirectTwig,
    WrongIncarnation,
    StaleEligibilityEpoch { current: i64 },
    StaleOwnerEpoch { current: i64 },
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
    TrunkStale { current: Option<String> },
    CandidateMissing,
    CandidateMismatch,
    UnitMissing { unit_id: String },
    UnitBasisMissing { unit_id: String },
    UnitBasisMismatch { unit_id: String },
    UnitPinMissing { unit_id: String },
    UnitPinReleased { unit_id: String },
    UnitNotHeldBySource { unit_id: String },
    UnverifiedLineage { unit_id: String },
    UnitAlreadyAdmitted { unit_id: String },
    AttemptCancelled { cancel_op_id: String },
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
    AlreadyAdmitted(FlowingAdmissionReceipt),
    Refused(FlowingCancelRefusal),
}

pub trait FlowingAdmissions {
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
    fn flowing_cancellation_for_attempt(
        &self,
        admission_op_id: &str,
    ) -> crate::StoreResult<Option<FlowingCancelReceipt>>;
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
