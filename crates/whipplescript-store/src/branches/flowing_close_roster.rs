//! One ref-store snapshot of work a flowing source must account for at close.
//!
//! This is an inventory, not permission to close. A final close must verify
//! every named receipt, resolve member and private work, and recapture under
//! the same ref exclusion that changes the source's state.

#[cfg(feature = "native")]
pub(crate) mod native;

use super::flowing_fence::FlowingFenceState;
use super::BranchStatus;
use crate::StoreResult;

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
pub struct FlowingCloseRoster {
    pub source_branch_id: String,
    pub source_fence: FlowingFenceState,
    pub source_status: BranchStatus,
    pub source_head_cut_id: Option<String>,
    pub source_head_manifest_hash: Option<String>,
    pub members: Vec<FlowingCloseMember>,
    pub units: Vec<FlowingCloseUnit>,
    pub live_private_pins: Vec<FlowingClosePrivatePin>,
}

/// Reads one internally consistent ref snapshot. `None` means this branch has
/// no flowing source fence; it does not mean that the branch has no work.
pub trait FlowingCloseRosterReader {
    fn flowing_close_roster(
        &mut self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingCloseRoster>>;
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
