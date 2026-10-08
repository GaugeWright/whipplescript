//! Atomic terminal disposition of a flowing branch after its close roster is resolved.
//!
//! The roster is re-read and every terminal unit receipt is verified under
//! the same ref exclusion that writes the source's closed status and receipt.

#[cfg(feature = "native")]
pub(crate) mod native;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use super::flowing_admission::FlowingAdmissionReceipt;
use super::flowing_close_roster::{FlowingCloseRoster, FlowingCloseUnitState};
use super::flowing_fence::FlowingFenceAction;
use super::flowing_parking::FlowingParkReceipt;
use super::flowing_sources::HandoffReceipt;
use super::{BranchStatus, MAINLINE_BRANCH_ID};
use crate::branches::CutRow;
use crate::StoreResult;

pub const SCHEMA: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS flowing_final_closes (
        source_branch_id TEXT PRIMARY KEY,
        op_id TEXT NOT NULL UNIQUE,
        roster_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL,
        retained_head_cut_id TEXT,
        receipt_json TEXT NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS flowing_final_closes_op_idx
        ON flowing_final_closes(op_id)",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCloseFlowingSource {
    pub op_id: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub expected_eligibility_epoch: i64,
    pub expected_owner_epoch: i64,
    pub expected_roster_digest: String,
    pub actor: String,
    pub recorded_at: String,
}

/// Store each operation receipt once. One admission may account for a large
/// prefix, so copying it for every selected unit would make a close receipt
/// quadratic in the prefix size.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingCloseEvidence {
    pub admissions: Vec<FlowingAdmissionReceipt>,
    pub parked_units: Vec<FlowingParkReceipt>,
    pub handoffs: Vec<HandoffReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingFinalCloseReceipt {
    pub request: FinalCloseFlowingSource,
    pub roster: FlowingCloseRoster,
    pub unit_evidence: FlowingCloseEvidence,
}

impl FlowingFinalCloseReceipt {
    pub fn digest(&self) -> StoreResult<String> {
        let bytes = serde_json::to_vec(&("flowing-final-close-v1", self))?;
        Ok(format!(
            "sha256:{}",
            crate::chunking::content_hash_hex(&bytes)
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingFinalCloseRefusal {
    Invalid { field: &'static str },
    IdentityMismatch,
    AlreadyClosed,
    SourceMissing,
    SourceNotActive,
    NotDirectSource,
    WrongIncarnation,
    StaleEligibilityEpoch { current: i64 },
    StaleOwnerEpoch { current: i64 },
    WrongOwner,
    CloseNotRequested,
    AdmissionEnabled,
    RevisionPending,
    StaleRoster,
    MemberUnresolved { branch_id: String },
    UnitOwed { unit_id: String },
    UnitReceiptMissing { unit_id: String },
    UnitReceiptMismatch { unit_id: String },
    PrivatePinLive,
    AttemptLive,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingFinalCloseOutcome {
    Closed(FlowingFinalCloseReceipt),
    Existing(FlowingFinalCloseReceipt),
    Refused(FlowingFinalCloseRefusal),
}

pub trait FlowingFinalClose {
    fn final_close_flowing_source(
        &mut self,
        request: &FinalCloseFlowingSource,
    ) -> StoreResult<FlowingFinalCloseOutcome>;
    fn flowing_final_close_receipt(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingFinalCloseReceipt>>;
}

pub fn missing_field(request: &FinalCloseFlowingSource) -> Option<&'static str> {
    if request.expected_eligibility_epoch < 0 || request.expected_owner_epoch < 0 {
        return Some("expected_source_epoch");
    }
    [
        ("op_id", request.op_id.as_str()),
        ("source_branch_id", request.source_branch_id.as_str()),
        (
            "source_incarnation_id",
            request.source_incarnation_id.as_str(),
        ),
        (
            "expected_roster_digest",
            request.expected_roster_digest.as_str(),
        ),
        ("actor", request.actor.as_str()),
        ("recorded_at", request.recorded_at.as_str()),
    ]
    .into_iter()
    .find_map(|(field, value)| value.trim().is_empty().then_some(field))
}

/// A transfer remains a disposition only while its receiving cut is in the
/// current named holder's line. A detached cut cannot silently carry work out
/// of a closing branch.
pub fn cut_in_current_ancestry<F>(
    branch_id: &str,
    head_cut_id: Option<&str>,
    retained_cut_id: &str,
    mut read_cut: F,
) -> StoreResult<bool>
where
    F: FnMut(&str) -> StoreResult<Option<CutRow>>,
{
    let mut cursor = head_cut_id.map(str::to_owned);
    let mut visited = BTreeSet::new();
    while let Some(id) = cursor {
        if !visited.insert(id.clone()) {
            return Ok(false);
        }
        let Some(cut) = read_cut(&id)? else {
            return Ok(false);
        };
        if cut.cut_id != id || cut.branch_id != branch_id {
            return Ok(false);
        }
        if id == retained_cut_id {
            return Ok(true);
        }
        cursor = cut.parent_cut_id;
    }
    Ok(false)
}

pub fn preflight(
    roster: &FlowingCloseRoster,
    request: &FinalCloseFlowingSource,
) -> Result<(), FlowingFinalCloseRefusal> {
    use FlowingFinalCloseRefusal as R;
    if roster.source_branch_id != request.source_branch_id
        || roster.source_fence.source_branch_id != request.source_branch_id
    {
        return Err(R::SourceMissing);
    }
    if roster.source_status != BranchStatus::Active {
        return Err(R::SourceNotActive);
    }
    if roster.source_parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID) {
        return Err(R::NotDirectSource);
    }
    if roster.source_fence.incarnation_id != request.source_incarnation_id {
        return Err(R::WrongIncarnation);
    }
    if roster.source_fence.eligibility_epoch != request.expected_eligibility_epoch {
        return Err(R::StaleEligibilityEpoch {
            current: roster.source_fence.eligibility_epoch,
        });
    }
    if roster.source_fence.owner_epoch != request.expected_owner_epoch {
        return Err(R::StaleOwnerEpoch {
            current: roster.source_fence.owner_epoch,
        });
    }
    if roster.source_fence.owner != request.actor {
        return Err(R::WrongOwner);
    }
    let Some(close) = roster.close_request.as_ref() else {
        return Err(R::CloseNotRequested);
    };
    if close.request.action != FlowingFenceAction::RequestClose
        || close.request.source_branch_id != request.source_branch_id
        || close.request.incarnation_id != request.source_incarnation_id
        || close.state.source_branch_id != request.source_branch_id
        || close.state.incarnation_id != request.source_incarnation_id
    {
        return Err(R::CloseNotRequested);
    }
    if roster.source_fence.admission_enabled {
        return Err(R::AdmissionEnabled);
    }
    if roster.source_fence.revision.is_some() {
        return Err(R::RevisionPending);
    }
    for member in &roster.members {
        if member.status != BranchStatus::Parked
            || member.parked.as_ref().is_none_or(|receipt| {
                receipt.request.member_branch_id != member.branch_id
                    || receipt.request.source_branch_id != request.source_branch_id
                    || receipt.source_close_op_id != close.request.op_id
                    || receipt.request.expected_member_head_cut_id != member.head_cut_id
            })
        {
            return Err(R::MemberUnresolved {
                branch_id: member.branch_id.clone(),
            });
        }
    }
    for unit in &roster.units {
        if matches!(
            unit.state,
            FlowingCloseUnitState::OwedBySource | FlowingCloseUnitState::OwedByMember { .. }
        ) || matches!(&unit.state, FlowingCloseUnitState::Transferred { target_branch_id }
            if target_branch_id == &request.source_branch_id
                || roster.members.iter().any(|member| member.branch_id == *target_branch_id))
        {
            return Err(R::UnitOwed {
                unit_id: unit.unit_id.clone(),
            });
        }
    }
    if !roster.live_private_pins.is_empty() {
        return Err(R::PrivatePinLive);
    }
    if !roster.live_attempts.is_empty() {
        return Err(R::AttemptLive);
    }
    Ok(())
}

pub fn receipt_matches_snapshot(receipt: &FlowingFinalCloseReceipt) -> bool {
    if preflight(&receipt.roster, &receipt.request).is_err() {
        return false;
    }
    let admissions: BTreeMap<_, _> = receipt
        .unit_evidence
        .admissions
        .iter()
        .map(|value| (value.request.op_id.as_str(), value))
        .collect();
    let parked: BTreeMap<_, _> = receipt
        .unit_evidence
        .parked_units
        .iter()
        .map(|value| (value.request.unit_id.as_str(), value))
        .collect();
    let handoffs: BTreeMap<_, _> = receipt
        .unit_evidence
        .handoffs
        .iter()
        .map(|value| (value.unit_id.as_str(), value))
        .collect();
    let admitted_units: BTreeSet<_> = receipt
        .unit_evidence
        .admissions
        .iter()
        .flat_map(|value| {
            value
                .request
                .units
                .iter()
                .map(|unit| (value.request.op_id.as_str(), unit.unit_id.as_str()))
        })
        .collect();
    let admission_selection_count: usize = receipt
        .unit_evidence
        .admissions
        .iter()
        .map(|value| value.request.units.len())
        .sum();
    if admissions.len() != receipt.unit_evidence.admissions.len()
        || parked.len() != receipt.unit_evidence.parked_units.len()
        || handoffs.len() != receipt.unit_evidence.handoffs.len()
        || admitted_units.len() != admission_selection_count
        || receipt.unit_evidence.admissions.iter().any(|admission| {
            admission.request.source_branch_id != receipt.roster.source_branch_id
                || admission.request.source_incarnation_id
                    != receipt.roster.source_fence.incarnation_id
        })
    {
        return false;
    }
    let mut used_admissions = BTreeSet::new();
    let mut roster_admitted_units = BTreeSet::new();
    let mut used_parked = BTreeSet::new();
    let mut used_handoffs = BTreeSet::new();
    for unit in &receipt.roster.units {
        let matches = match &unit.state {
            FlowingCloseUnitState::Admitted { op_id } => {
                let Some(admission) = admissions.get(op_id.as_str()) else {
                    return false;
                };
                used_admissions.insert(op_id.as_str());
                roster_admitted_units.insert((op_id.as_str(), unit.unit_id.as_str()));
                !admission.request.units.is_empty()
                    && admitted_units.contains(&(op_id.as_str(), unit.unit_id.as_str()))
            }
            FlowingCloseUnitState::Parked { op_id, holder_id } => {
                let Some(park) = parked.get(unit.unit_id.as_str()) else {
                    return false;
                };
                used_parked.insert(unit.unit_id.as_str());
                park.request.op_id == *op_id && park.request.parked_holder_id == *holder_id
            }
            FlowingCloseUnitState::Transferred { target_branch_id } => {
                let Some(handoff) = handoffs.get(unit.unit_id.as_str()) else {
                    return false;
                };
                used_handoffs.insert(unit.unit_id.as_str());
                unit.handoff_op_id.as_deref() == Some(handoff.op_id.as_str())
                    && handoff.target_branch_id == *target_branch_id
                    && handoff.source_branch_id == unit.original_source_branch_id
            }
            FlowingCloseUnitState::OwedBySource | FlowingCloseUnitState::OwedByMember { .. } => {
                return false;
            }
        };
        if !matches {
            return false;
        }
    }
    roster_admitted_units == admitted_units
        && used_admissions.len() == admissions.len()
        && used_parked.len() == parked.len()
        && used_handoffs.len() == handoffs.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::flowing_admission::FlowingAttemptPin;
    use crate::branches::flowing_close_roster::{
        FlowingCloseAttempt, FlowingCloseAttemptState, FlowingCloseMember, FlowingClosePrivatePin,
        FlowingCloseUnit,
    };
    use crate::branches::flowing_fence::{
        FlowingFenceReceipt, FlowingFenceState, FlowingFenceTransition, FlowingRevision,
        FlowingSourceKind,
    };

    fn ready() -> (FlowingCloseRoster, FinalCloseFlowingSource) {
        let before = FlowingFenceState {
            source_branch_id: "branch".into(),
            incarnation_id: "inc".into(),
            kind: FlowingSourceKind::Branch,
            owner: "owner".into(),
            owner_epoch: 0,
            eligibility_epoch: 0,
            held: false,
            revision: None,
            admission_enabled: true,
            opened_at: "t1".into(),
        };
        let mut disabled = before.clone();
        disabled.eligibility_epoch = 1;
        disabled.admission_enabled = false;
        let roster = FlowingCloseRoster {
            source_branch_id: "branch".into(),
            source_fence: disabled,
            source_status: BranchStatus::Active,
            source_parent_branch_id: Some(MAINLINE_BRANCH_ID.into()),
            source_branch_point_cut_id: None,
            source_head_cut_id: None,
            source_head_manifest_hash: None,
            close_request: Some(FlowingFenceReceipt {
                request: FlowingFenceTransition {
                    op_id: "request-close".into(),
                    source_branch_id: "branch".into(),
                    incarnation_id: "inc".into(),
                    expected_eligibility_epoch: 0,
                    expected_owner_epoch: 0,
                    actor: "owner".into(),
                    action: FlowingFenceAction::RequestClose,
                    recorded_at: "t2".into(),
                },
                state: before,
            }),
            members: Vec::new(),
            units: Vec::new(),
            live_private_pins: Vec::new(),
            live_attempts: Vec::new(),
        };
        let request = FinalCloseFlowingSource {
            op_id: "final-close".into(),
            source_branch_id: "branch".into(),
            source_incarnation_id: "inc".into(),
            expected_eligibility_epoch: 1,
            expected_owner_epoch: 0,
            expected_roster_digest: "exact-roster".into(),
            actor: "owner".into(),
            recorded_at: "t3".into(),
        };
        (roster, request)
    }

    #[test]
    fn close_preflight_requires_exact_source_fence_and_close_request() {
        use FlowingFinalCloseRefusal as R;
        let (roster, request) = ready();
        assert_eq!(preflight(&roster, &request), Ok(()));

        let mut changed = roster.clone();
        changed.source_branch_id = "other".into();
        assert_eq!(preflight(&changed, &request), Err(R::SourceMissing));

        let mut changed = roster.clone();
        changed.source_status = BranchStatus::Closed;
        assert_eq!(preflight(&changed, &request), Err(R::SourceNotActive));

        let mut changed = roster.clone();
        changed.source_parent_branch_id = Some("branch".into());
        assert_eq!(preflight(&changed, &request), Err(R::NotDirectSource));

        let mut changed_request = request.clone();
        changed_request.source_incarnation_id = "other-inc".into();
        assert_eq!(
            preflight(&roster, &changed_request),
            Err(R::WrongIncarnation)
        );

        let mut changed_request = request.clone();
        changed_request.expected_eligibility_epoch = 2;
        assert_eq!(
            preflight(&roster, &changed_request),
            Err(R::StaleEligibilityEpoch { current: 1 })
        );

        let mut changed_request = request.clone();
        changed_request.expected_owner_epoch = 1;
        assert_eq!(
            preflight(&roster, &changed_request),
            Err(R::StaleOwnerEpoch { current: 0 })
        );

        let mut changed_request = request.clone();
        changed_request.actor = "foreign".into();
        assert_eq!(preflight(&roster, &changed_request), Err(R::WrongOwner));

        let mut changed = roster.clone();
        changed.close_request = None;
        assert_eq!(preflight(&changed, &request), Err(R::CloseNotRequested));

        let mut changed = roster.clone();
        changed
            .close_request
            .as_mut()
            .unwrap()
            .request
            .incarnation_id = "previous-incarnation".into();
        assert_eq!(preflight(&changed, &request), Err(R::CloseNotRequested));

        let mut changed = roster.clone();
        changed.source_fence.admission_enabled = true;
        assert_eq!(preflight(&changed, &request), Err(R::AdmissionEnabled));

        let mut changed = roster;
        changed.source_fence.revision = Some(FlowingRevision {
            begin_op_id: "revise".into(),
            before_cut_id: None,
            after_cut_id: "new-cut".into(),
        });
        assert_eq!(preflight(&changed, &request), Err(R::RevisionPending));
    }

    #[test]
    fn close_preflight_keeps_members_units_pins_and_attempts_owed() {
        use FlowingFinalCloseRefusal as R;
        let (roster, request) = ready();

        let mut changed = roster.clone();
        changed.members.push(FlowingCloseMember {
            branch_id: "member".into(),
            status: BranchStatus::Active,
            head_cut_id: None,
            source_fence: None,
            parked: None,
        });
        assert_eq!(
            preflight(&changed, &request),
            Err(R::MemberUnresolved {
                branch_id: "member".into()
            })
        );

        let mut changed = roster.clone();
        changed.units.push(FlowingCloseUnit {
            unit_id: "unit".into(),
            original_source_branch_id: "branch".into(),
            handoff_op_id: None,
            state: FlowingCloseUnitState::OwedBySource,
        });
        assert_eq!(
            preflight(&changed, &request),
            Err(R::UnitOwed {
                unit_id: "unit".into()
            })
        );

        let mut changed = roster.clone();
        changed.units.push(FlowingCloseUnit {
            unit_id: "returned".into(),
            original_source_branch_id: "member".into(),
            handoff_op_id: Some("handoff".into()),
            state: FlowingCloseUnitState::Transferred {
                target_branch_id: "branch".into(),
            },
        });
        assert_eq!(
            preflight(&changed, &request),
            Err(R::UnitOwed {
                unit_id: "returned".into()
            })
        );

        let mut changed = roster.clone();
        changed.live_private_pins.push(FlowingClosePrivatePin {
            pin_id: "pin".into(),
            twig_branch_id: "member".into(),
            cut_id: "cut".into(),
            manifest_hash: "manifest".into(),
        });
        assert_eq!(preflight(&changed, &request), Err(R::PrivatePinLive));

        let mut changed = roster;
        changed.live_attempts.push(FlowingCloseAttempt {
            pin: FlowingAttemptPin {
                op_id: "attempt".into(),
                witness_digest: "witness".into(),
                source_cut_id: "source-cut".into(),
                candidate_cut_id: "candidate-cut".into(),
                retained_at: "t2".into(),
                released_at: None,
            },
            source_branch_id: "branch".into(),
            source_incarnation_id: "inc".into(),
            unit_ids: Vec::new(),
            state: FlowingCloseAttemptState::Pending,
        });
        assert_eq!(preflight(&changed, &request), Err(R::AttemptLive));
    }
}
