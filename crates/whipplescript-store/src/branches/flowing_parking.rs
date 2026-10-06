//! Ref-owned transfer of an owed flowing unit to a named parked holder.
//!
//! Parking is not settlement. The exact retained unit cut, source fence move,
//! and transfer receipt commit together beside the trunk admission index.

#[cfg(feature = "native")]
pub(crate) mod native;

use serde::{Deserialize, Serialize};

use super::flowing_admission::FlowingAdmissionReceipt;
use super::flowing_fence::FlowingFenceState;
use super::flowing_holders::FlowingUnitHolder;
use crate::StoreResult;

pub const SCHEMA: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS flowing_parked_units (
        unit_id TEXT PRIMARY KEY,
        op_id TEXT NOT NULL UNIQUE,
        holder_id TEXT NOT NULL,
        receipt_json TEXT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS flowing_parked_holder_idx
        ON flowing_parked_units(holder_id, unit_id)",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParkFlowingUnit {
    pub op_id: String,
    pub unit_id: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub source_cut_id: String,
    pub source_manifest_hash: String,
    pub basis_digest: String,
    pub principal: String,
    pub intent: String,
    pub expected_eligibility_epoch: i64,
    pub expected_owner_epoch: i64,
    pub parked_holder_id: String,
    pub actor: String,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingParkReceipt {
    pub request: ParkFlowingUnit,
    /// Retained source evidence that the parked holder now owns.
    pub former_holder: FlowingUnitHolder,
    pub source_fence_after: FlowingFenceState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingParkRefusal {
    Invalid { field: &'static str },
    IdentityMismatch,
    SourceMissing,
    SourceNotActive,
    SourceMoved,
    WrongIncarnation,
    StaleEligibilityEpoch { current: i64 },
    StaleOwnerEpoch { current: i64 },
    WrongOwner,
    RevisionPending,
    UnitHolderUnavailable,
    UnitNotHeldBySource,
    EpochExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingParkOutcome {
    Parked(FlowingParkReceipt),
    Existing(FlowingParkReceipt),
    AlreadyParked(FlowingParkReceipt),
    AlreadyAdmitted(FlowingAdmissionReceipt),
    Refused(FlowingParkRefusal),
}

pub trait FlowingParking {
    fn park_flowing_unit(&mut self, request: &ParkFlowingUnit) -> StoreResult<FlowingParkOutcome>;
    fn parked_flowing_unit(&self, unit_id: &str) -> StoreResult<Option<FlowingParkReceipt>>;
    fn flowing_park_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingParkReceipt>>;
    fn parked_holder_units(&self, holder_id: &str) -> StoreResult<Vec<FlowingParkReceipt>>;
}

pub fn missing_field(request: &ParkFlowingUnit) -> Option<&'static str> {
    if request.parked_holder_id == request.source_branch_id {
        return Some("parked_holder_id");
    }
    [
        ("op_id", request.op_id.as_str()),
        ("unit_id", request.unit_id.as_str()),
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
        ("basis_digest", request.basis_digest.as_str()),
        ("principal", request.principal.as_str()),
        ("intent", request.intent.as_str()),
        ("parked_holder_id", request.parked_holder_id.as_str()),
        ("actor", request.actor.as_str()),
        ("recorded_at", request.recorded_at.as_str()),
    ]
    .into_iter()
    .find_map(|(field, value)| value.trim().is_empty().then_some(field))
}

pub fn receipt_matches_keys(receipt: &FlowingParkReceipt, unit_id: &str, op_id: &str) -> bool {
    missing_field(&receipt.request).is_none()
        && receipt.request.unit_id == unit_id
        && receipt.request.op_id == op_id
        && receipt.former_holder.unit_id == unit_id
        && receipt.former_holder.holder_branch_id == receipt.request.source_branch_id
        && !receipt.former_holder.holder_cut_id.is_empty()
        && !receipt.former_holder.holder_manifest_hash.is_empty()
        && !receipt.former_holder.proof_digest.is_empty()
        && receipt.source_fence_after.source_branch_id == receipt.request.source_branch_id
        && receipt.source_fence_after.incarnation_id == receipt.request.source_incarnation_id
        && receipt.source_fence_after.owner == receipt.request.actor
        && receipt.source_fence_after.owner_epoch == receipt.request.expected_owner_epoch
        && receipt.request.expected_eligibility_epoch.checked_add(1)
            == Some(receipt.source_fence_after.eligibility_epoch)
}
