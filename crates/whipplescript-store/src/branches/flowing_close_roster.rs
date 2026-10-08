//! One ref-store snapshot of work a flowing source must account for at close.
//!
//! This is an inventory, not permission to close. A final close must verify
//! every named receipt, resolve member and private work, and recapture under
//! the same ref exclusion that changes the source's state.

#[cfg(feature = "native")]
pub(crate) mod native;

use super::flowing_admission::{
    FlowingAdmissionReceipt, FlowingAttemptFinishReceipt, FlowingAttemptPin, FlowingCancelRequest,
    FlowingCandidateWitness, FlowingGateVerdict,
};
use super::flowing_fence::FlowingFenceState;
use super::BranchStatus;
use crate::{StoreError, StoreResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingCloseMember {
    pub branch_id: String,
    pub status: BranchStatus,
    pub head_cut_id: Option<String>,
    pub source_fence: Option<FlowingFenceState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingCloseUnitState {
    OwedBySource,
    OwedByMember { branch_id: String },
    Transferred { target_branch_id: String },
    Parked { op_id: String, holder_id: String },
    Admitted { op_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingCloseUnit {
    pub unit_id: String,
    pub original_source_branch_id: String,
    pub state: FlowingCloseUnitState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingClosePrivatePin {
    pub pin_id: String,
    pub twig_branch_id: String,
    pub cut_id: String,
    pub manifest_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingCloseAttemptState {
    Pending,
    Admitted,
    Cancelled { cancel_op_id: String },
    Failed,
    Unrun,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingCloseAttempt {
    pub pin: FlowingAttemptPin,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub unit_ids: Vec<String>,
    pub state: FlowingCloseAttemptState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingCloseRoster {
    pub source_branch_id: String,
    pub source_fence: FlowingFenceState,
    pub source_status: BranchStatus,
    pub source_head_cut_id: Option<String>,
    pub source_head_manifest_hash: Option<String>,
    pub members: Vec<FlowingCloseMember>,
    pub units: Vec<FlowingCloseUnit>,
    pub live_private_pins: Vec<FlowingClosePrivatePin>,
    pub live_attempts: Vec<FlowingCloseAttempt>,
}

/// Reads one internally consistent ref snapshot. `None` means this branch has
/// no flowing source fence; it does not mean that the branch has no work.
pub trait FlowingCloseRosterReader {
    fn flowing_close_roster(
        &mut self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingCloseRoster>>;
}

/// Classify a live attempt pin from rows read in the same ref snapshot. A
/// missing witness or ambiguous terminal state cannot disappear from a close
/// roster just because its source cannot be identified.
#[doc(hidden)]
pub fn classify_attempt(
    pin: FlowingAttemptPin,
    witness_json: Option<String>,
    admission_json: Option<String>,
    cancellation_row: Option<(String, String)>,
    finish_json: Option<String>,
) -> StoreResult<FlowingCloseAttempt> {
    let witness_json = witness_json.ok_or_else(|| {
        StoreError::Conflict("live flowing attempt lost its candidate witness".into())
    })?;
    let witness: FlowingCandidateWitness = serde_json::from_str(&witness_json)?;
    if pin.op_id.trim().is_empty()
        || pin.retained_at.trim().is_empty()
        || witness.source_branch_id.trim().is_empty()
        || witness.source_incarnation_id.trim().is_empty()
        || witness.digest()? != pin.witness_digest
        || witness.source_cut_id != pin.source_cut_id
        || witness.candidate_cut_id != pin.candidate_cut_id
    {
        return Err(StoreError::Conflict(
            "live flowing attempt differs from its witness".into(),
        ));
    }
    let terminal_count = admission_json.is_some() as u8
        + cancellation_row.is_some() as u8
        + finish_json.is_some() as u8;
    if terminal_count > 1 {
        return Err(StoreError::Conflict(
            "live flowing attempt has conflicting terminal results".into(),
        ));
    }
    let state = if let Some(json) = admission_json {
        let receipt: FlowingAdmissionReceipt = serde_json::from_str(&json)?;
        if receipt.request.op_id != pin.op_id
            || receipt.request.candidate_witness_digest != pin.witness_digest
            || !witness.matches_request(&receipt.request)
        {
            return Err(StoreError::Conflict(
                "live flowing admission differs from its attempt".into(),
            ));
        }
        FlowingCloseAttemptState::Admitted
    } else if let Some((cancel_op_id, json)) = cancellation_row {
        let request: FlowingCancelRequest = serde_json::from_str(&json)?;
        if request.admission_op_id != pin.op_id
            || request.source_branch_id != witness.source_branch_id
            || request.source_incarnation_id != witness.source_incarnation_id
            || request.cancel_op_id != cancel_op_id
            || cancel_op_id.trim().is_empty()
        {
            return Err(StoreError::Conflict(
                "live flowing cancellation differs from its attempt".into(),
            ));
        }
        FlowingCloseAttemptState::Cancelled { cancel_op_id }
    } else if let Some(json) = finish_json {
        let receipt: FlowingAttemptFinishReceipt = serde_json::from_str(&json)?;
        if receipt.request.op_id != pin.op_id
            || receipt.request.candidate_witness_digest != pin.witness_digest
            || !witness.matches_request(&receipt.request)
        {
            return Err(StoreError::Conflict(
                "live flowing finish differs from its attempt".into(),
            ));
        }
        match receipt.verdict {
            FlowingGateVerdict::Failed => FlowingCloseAttemptState::Failed,
            FlowingGateVerdict::Unrun => FlowingCloseAttemptState::Unrun,
            FlowingGateVerdict::Passed => {
                return Err(StoreError::Conflict(
                    "live flowing finish reports a passed gate without admission".into(),
                ))
            }
        }
    } else {
        FlowingCloseAttemptState::Pending
    };
    Ok(FlowingCloseAttempt {
        pin,
        source_branch_id: witness.source_branch_id,
        source_incarnation_id: witness.source_incarnation_id,
        unit_ids: witness.units.into_iter().map(|unit| unit.unit_id).collect(),
        state,
    })
}

/// Classify a declared unit without silently discarding a conflicting
/// terminal state. The SQL backends call this inside their snapshot.
#[doc(hidden)]
pub fn classify_unit(
    source_branch_id: &str,
    original_source_branch_id: String,
    handoff_target: Option<String>,
    admitted_op: Option<String>,
    parked: Option<(String, String)>,
) -> StoreResult<FlowingCloseUnitState> {
    if original_source_branch_id.trim().is_empty()
        || handoff_target
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || admitted_op
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        || parked
            .as_ref()
            .is_some_and(|(op, holder)| op.trim().is_empty() || holder.trim().is_empty())
    {
        return Err(crate::StoreError::Conflict(
            "flowing close unit has an empty ref identity".into(),
        ));
    }
    if admitted_op.is_some() && parked.is_some() {
        return Err(crate::StoreError::Conflict(
            "flowing unit is both admitted and parked".into(),
        ));
    }
    if let Some(op_id) = admitted_op {
        return Ok(FlowingCloseUnitState::Admitted { op_id });
    }
    if let Some((op_id, holder_id)) = parked {
        return Ok(FlowingCloseUnitState::Parked { op_id, holder_id });
    }
    if let Some(target_branch_id) = handoff_target {
        return Ok(if target_branch_id == source_branch_id {
            FlowingCloseUnitState::OwedBySource
        } else {
            FlowingCloseUnitState::Transferred { target_branch_id }
        });
    }
    Ok(if original_source_branch_id == source_branch_id {
        FlowingCloseUnitState::OwedBySource
    } else {
        FlowingCloseUnitState::OwedByMember {
            branch_id: original_source_branch_id,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_keeps_owed_and_terminal_states_distinct() {
        assert_eq!(
            classify_unit("branch", "member".into(), None, None, None).unwrap(),
            FlowingCloseUnitState::OwedByMember {
                branch_id: "member".into()
            }
        );
        assert_eq!(
            classify_unit("branch", "member".into(), Some("branch".into()), None, None).unwrap(),
            FlowingCloseUnitState::OwedBySource
        );
        assert_eq!(
            classify_unit(
                "branch",
                "member".into(),
                None,
                None,
                Some(("park-1".into(), "holder-1".into())),
            )
            .unwrap(),
            FlowingCloseUnitState::Parked {
                op_id: "park-1".into(),
                holder_id: "holder-1".into()
            }
        );
        assert!(classify_unit(
            "branch",
            "member".into(),
            None,
            Some("admit-1".into()),
            Some(("park-1".into(), "holder-1".into())),
        )
        .is_err());
        assert!(classify_unit("branch", "member".into(), None, Some(" ".into()), None).is_err());
    }
}
