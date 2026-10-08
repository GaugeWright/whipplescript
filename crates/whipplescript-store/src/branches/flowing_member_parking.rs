//! Exact parked-member disposition for a closing flowing branch.
//!
//! A member's head and continuing holder are retained in the ref store in
//! the same transaction that makes the member non-writable. This does not
//! settle a unit, release a private pin, or close the parent branch.

#[cfg(feature = "native")]
pub(crate) mod native;

use serde::{Deserialize, Serialize};

use crate::StoreResult;

pub const SCHEMA: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS flowing_parked_members (
        member_branch_id TEXT PRIMARY KEY,
        op_id TEXT NOT NULL UNIQUE,
        source_branch_id TEXT NOT NULL,
        holder_id TEXT NOT NULL,
        retained_head_cut_id TEXT,
        receipt_json TEXT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS flowing_parked_members_holder_idx
        ON flowing_parked_members(holder_id, member_branch_id)",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParkFlowingMember {
    pub op_id: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub expected_source_eligibility_epoch: i64,
    pub expected_source_owner_epoch: i64,
    pub member_branch_id: String,
    /// `None` is valid for a created member that was never opened as a
    /// flowing source. Its branch row and head still remain in the roster.
    pub expected_member_incarnation_id: Option<String>,
    pub expected_member_head_cut_id: Option<String>,
    pub expected_member_head_manifest_hash: Option<String>,
    pub parked_holder_id: String,
    pub actor: String,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingMemberParkReceipt {
    pub request: ParkFlowingMember,
    pub source_close_op_id: String,
    pub member_created_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingMemberParkRefusal {
    Invalid { field: &'static str },
    IdentityMismatch,
    SourceMissing,
    SourceNotActive,
    CloseNotRequested,
    AdmissionNotDisabled,
    WrongIncarnation,
    StaleEligibilityEpoch { current: i64 },
    StaleOwnerEpoch { current: i64 },
    WrongOwner,
    MemberMissing,
    MemberNotActive,
    MemberNotChild,
    MemberIncarnationMismatch,
    MemberHeadChanged,
    MemberReserved,
    UnresolvedUnit,
    LivePrivatePin,
    LiveAttempt,
    RetainedCutMissing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingMemberParkOutcome {
    Parked(FlowingMemberParkReceipt),
    Existing(FlowingMemberParkReceipt),
    AlreadyParked(FlowingMemberParkReceipt),
    Refused(FlowingMemberParkRefusal),
}

pub trait FlowingMemberParking {
    fn park_flowing_member(
        &mut self,
        request: &ParkFlowingMember,
    ) -> StoreResult<FlowingMemberParkOutcome>;
    fn parked_flowing_member(
        &self,
        member_branch_id: &str,
    ) -> StoreResult<Option<FlowingMemberParkReceipt>>;
    fn flowing_member_park_receipt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingMemberParkReceipt>>;
}

pub fn missing_field(request: &ParkFlowingMember) -> Option<&'static str> {
    if request.expected_source_eligibility_epoch < 0 || request.expected_source_owner_epoch < 0 {
        return Some("expected_source_epoch");
    }
    if request.source_branch_id == request.member_branch_id
        || request.parked_holder_id == request.source_branch_id
        || request.parked_holder_id == request.member_branch_id
    {
        return Some("parked_holder_id");
    }
    if request.expected_member_head_cut_id.is_some()
        != request.expected_member_head_manifest_hash.is_some()
    {
        return Some("expected_member_head");
    }
    if request
        .expected_member_incarnation_id
        .as_ref()
        .is_some_and(|value| value.trim().is_empty())
        || request
            .expected_member_head_cut_id
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || request
            .expected_member_head_manifest_hash
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
    {
        return Some("expected_member_head");
    }
    [
        ("op_id", request.op_id.as_str()),
        ("source_branch_id", request.source_branch_id.as_str()),
        (
            "source_incarnation_id",
            request.source_incarnation_id.as_str(),
        ),
        ("member_branch_id", request.member_branch_id.as_str()),
        ("parked_holder_id", request.parked_holder_id.as_str()),
        ("actor", request.actor.as_str()),
        ("recorded_at", request.recorded_at.as_str()),
    ]
    .into_iter()
    .find_map(|(field, value)| value.trim().is_empty().then_some(field))
}

pub fn receipt_matches_keys(
    receipt: &FlowingMemberParkReceipt,
    member_branch_id: &str,
    op_id: &str,
    source_branch_id: &str,
    holder_id: &str,
    retained_head_cut_id: Option<&str>,
) -> bool {
    missing_field(&receipt.request).is_none()
        && receipt.request.member_branch_id == member_branch_id
        && receipt.request.op_id == op_id
        && receipt.request.source_branch_id == source_branch_id
        && receipt.request.parked_holder_id == holder_id
        && receipt.request.expected_member_head_cut_id.as_deref() == retained_head_cut_id
        && !receipt.source_close_op_id.trim().is_empty()
        && !receipt.member_created_at.trim().is_empty()
}
