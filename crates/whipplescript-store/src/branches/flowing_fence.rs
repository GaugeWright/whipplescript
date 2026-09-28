//! Ref-owned source fences for flowing admission (DR-0130, FB-3).
//!
//! The source's eligibility epoch, Hold, owner epoch and in-flight revision
//! live beside the branch ref. Each transition and its exact retry receipt
//! share one transaction. Admission still needs a separate atomic trunk CAS
//! that reads these rows, and every production mutation door must acquire a
//! revision fence before acknowledging a changed selected unit.

#[cfg(feature = "native")]
mod native;

use serde::{Deserialize, Serialize};

use crate::StoreResult;

pub const SCHEMA: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS flowing_source_fences (
        source_branch_id TEXT PRIMARY KEY,
        state_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_source_fence_ops (
        op_id TEXT PRIMARY KEY,
        request_json TEXT NOT NULL,
        state_json TEXT NOT NULL
    )",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingRevision {
    pub begin_op_id: String,
    pub before_cut_id: Option<String>,
    pub after_cut_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowingSourceKind {
    Branch,
    Twig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingFenceState {
    pub source_branch_id: String,
    pub incarnation_id: String,
    pub kind: FlowingSourceKind,
    pub owner: String,
    pub owner_epoch: i64,
    pub eligibility_epoch: i64,
    pub held: bool,
    pub revision: Option<FlowingRevision>,
    pub admission_enabled: bool,
    pub opened_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenFlowingSource {
    pub source_branch_id: String,
    pub incarnation_id: String,
    pub kind: FlowingSourceKind,
    pub owner: String,
    pub opened_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenFlowingSourceOutcome {
    Opened(FlowingFenceState),
    Existing(FlowingFenceState),
    IdentityMismatch,
    BranchMissing,
    BranchNotActive,
    BranchAlreadyMoved,
    BranchAlreadyHasChildren,
    InvalidKindParent,
    InvalidKindName,
    Invalid { field: &'static str },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowingFenceAction {
    Hold,
    ReleaseHold,
    BeginRevision {
        before_cut_id: Option<String>,
        after_cut_id: String,
    },
    FinishRevision {
        begin_op_id: String,
    },
    AbortRevision {
        begin_op_id: String,
    },
    Takeover {
        new_owner: String,
    },
    InvalidateEligibility {
        reason: String,
    },
    DisableAdmission,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingFenceTransition {
    pub op_id: String,
    pub source_branch_id: String,
    pub incarnation_id: String,
    pub expected_eligibility_epoch: i64,
    pub expected_owner_epoch: i64,
    /// An authenticated host must supply the actor. The store records the
    /// claim and fences state; it does not authenticate this string.
    pub actor: String,
    pub action: FlowingFenceAction,
    pub recorded_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingFenceReceipt {
    pub request: FlowingFenceTransition,
    pub state: FlowingFenceState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingFenceRefusal {
    Missing,
    BranchNotActive,
    WrongIncarnation,
    StaleEligibilityEpoch { current: i64 },
    StaleOwnerEpoch { current: i64 },
    HeadMismatch { current: Option<String> },
    RevisionPending,
    RevisionMissing,
    RevisionMismatch,
    AdmissionDisabled,
    IdentityMismatch,
    EpochExhausted,
    Invalid { field: &'static str },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingFenceOutcome {
    Applied(FlowingFenceReceipt),
    Existing(FlowingFenceReceipt),
    Refused(FlowingFenceRefusal),
}

pub trait FlowingFence {
    fn open_flowing_source(
        &mut self,
        request: &OpenFlowingSource,
    ) -> StoreResult<OpenFlowingSourceOutcome>;
    fn flowing_source(&self, source_branch_id: &str) -> StoreResult<Option<FlowingFenceState>>;
    fn transition_flowing_source(
        &mut self,
        request: &FlowingFenceTransition,
    ) -> StoreResult<FlowingFenceOutcome>;
    fn flowing_fence_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingFenceReceipt>>;
}

pub fn missing_open_field(request: &OpenFlowingSource) -> Option<&'static str> {
    [
        ("source_branch_id", request.source_branch_id.as_str()),
        ("incarnation_id", request.incarnation_id.as_str()),
        ("owner", request.owner.as_str()),
        ("opened_at", request.opened_at.as_str()),
    ]
    .into_iter()
    .find_map(|(field, value)| value.trim().is_empty().then_some(field))
}

pub fn missing_transition_field(request: &FlowingFenceTransition) -> Option<&'static str> {
    [
        ("op_id", request.op_id.as_str()),
        ("source_branch_id", request.source_branch_id.as_str()),
        ("incarnation_id", request.incarnation_id.as_str()),
        ("actor", request.actor.as_str()),
        ("recorded_at", request.recorded_at.as_str()),
    ]
    .into_iter()
    .find_map(|(field, value)| value.trim().is_empty().then_some(field))
}

fn next_epoch(epoch: i64) -> Result<i64, FlowingFenceRefusal> {
    epoch
        .checked_add(1)
        .ok_or(FlowingFenceRefusal::EpochExhausted)
}

/// Pure transition used by both SQL backends. The caller reads the branch
/// head and fence state under the transaction that persists its result.
pub fn decide(
    state: &FlowingFenceState,
    request: &FlowingFenceTransition,
    branch_head: Option<&str>,
) -> Result<FlowingFenceState, FlowingFenceRefusal> {
    if state.incarnation_id != request.incarnation_id {
        return Err(FlowingFenceRefusal::WrongIncarnation);
    }
    if state.eligibility_epoch != request.expected_eligibility_epoch {
        return Err(FlowingFenceRefusal::StaleEligibilityEpoch {
            current: state.eligibility_epoch,
        });
    }
    if state.owner_epoch != request.expected_owner_epoch {
        return Err(FlowingFenceRefusal::StaleOwnerEpoch {
            current: state.owner_epoch,
        });
    }
    let mut after = state.clone();
    match &request.action {
        FlowingFenceAction::Hold => {
            if !state.held {
                after.held = true;
                after.eligibility_epoch = next_epoch(state.eligibility_epoch)?;
            }
        }
        FlowingFenceAction::ReleaseHold => {
            if state.held {
                after.held = false;
                after.eligibility_epoch = next_epoch(state.eligibility_epoch)?;
            }
        }
        FlowingFenceAction::BeginRevision {
            before_cut_id,
            after_cut_id,
        } => {
            if !state.admission_enabled {
                return Err(FlowingFenceRefusal::AdmissionDisabled);
            }
            if state.revision.is_some() {
                return Err(FlowingFenceRefusal::RevisionPending);
            }
            if after_cut_id.trim().is_empty() || before_cut_id.as_deref() == Some(after_cut_id) {
                return Err(FlowingFenceRefusal::Invalid {
                    field: "after_cut_id",
                });
            }
            if branch_head != before_cut_id.as_deref() {
                return Err(FlowingFenceRefusal::HeadMismatch {
                    current: branch_head.map(str::to_owned),
                });
            }
            after.revision = Some(FlowingRevision {
                begin_op_id: request.op_id.clone(),
                before_cut_id: before_cut_id.clone(),
                after_cut_id: after_cut_id.clone(),
            });
            after.eligibility_epoch = next_epoch(state.eligibility_epoch)?;
        }
        FlowingFenceAction::FinishRevision { begin_op_id }
        | FlowingFenceAction::AbortRevision { begin_op_id } => {
            let Some(revision) = state.revision.as_ref() else {
                // MUTATION-SUCCESS-EXPR: Ok(state.clone())
                return Err(FlowingFenceRefusal::RevisionMissing);
            };
            if revision.begin_op_id != *begin_op_id {
                return Err(FlowingFenceRefusal::RevisionMismatch);
            }
            let expected_head = match request.action {
                FlowingFenceAction::FinishRevision { .. } => Some(revision.after_cut_id.as_str()),
                FlowingFenceAction::AbortRevision { .. } => revision.before_cut_id.as_deref(),
                _ => unreachable!(),
            };
            if branch_head != expected_head {
                return Err(FlowingFenceRefusal::HeadMismatch {
                    current: branch_head.map(str::to_owned),
                });
            }
            after.revision = None;
            after.eligibility_epoch = next_epoch(state.eligibility_epoch)?;
        }
        FlowingFenceAction::Takeover { new_owner } => {
            if new_owner.trim().is_empty() || *new_owner == state.owner {
                return Err(FlowingFenceRefusal::Invalid { field: "new_owner" });
            }
            after.owner = new_owner.clone();
            after.owner_epoch = next_epoch(state.owner_epoch)?;
            after.eligibility_epoch = next_epoch(state.eligibility_epoch)?;
        }
        FlowingFenceAction::InvalidateEligibility { reason } => {
            if reason.trim().is_empty() {
                return Err(FlowingFenceRefusal::Invalid { field: "reason" });
            }
            after.eligibility_epoch = next_epoch(state.eligibility_epoch)?;
        }
        FlowingFenceAction::DisableAdmission => {
            if state.revision.is_some() {
                return Err(FlowingFenceRefusal::RevisionPending);
            }
            if state.admission_enabled {
                after.admission_enabled = false;
                after.eligibility_epoch = next_epoch(state.eligibility_epoch)?;
            }
        }
    }
    Ok(after)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> FlowingFenceState {
        FlowingFenceState {
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            kind: FlowingSourceKind::Branch,
            owner: "owner-a".into(),
            owner_epoch: 0,
            eligibility_epoch: 0,
            held: false,
            revision: None,
            admission_enabled: true,
            opened_at: "t0".into(),
        }
    }

    fn request(action: FlowingFenceAction) -> FlowingFenceTransition {
        FlowingFenceTransition {
            op_id: "op-1".into(),
            source_branch_id: "branch".into(),
            incarnation_id: "inc-1".into(),
            expected_eligibility_epoch: 0,
            expected_owner_epoch: 0,
            actor: "mediator".into(),
            action,
            recorded_at: "t1".into(),
        }
    }

    #[test]
    fn stale_identity_and_invalid_revision_basis_cannot_be_admitted() {
        let current = state();
        let mut wrong_incarnation = request(FlowingFenceAction::Hold);
        wrong_incarnation.incarnation_id = "inc-2".into();
        assert_eq!(
            decide(&current, &wrong_incarnation, None),
            Err(FlowingFenceRefusal::WrongIncarnation)
        );
        let mut former_owner = request(FlowingFenceAction::Hold);
        former_owner.expected_owner_epoch = 1;
        assert_eq!(
            decide(&current, &former_owner, None),
            Err(FlowingFenceRefusal::StaleOwnerEpoch { current: 0 })
        );
        for after_cut_id in ["", "before"] {
            let begin = request(FlowingFenceAction::BeginRevision {
                before_cut_id: Some("before".into()),
                after_cut_id: after_cut_id.into(),
            });
            assert_eq!(
                decide(&current, &begin, Some("before")),
                Err(FlowingFenceRefusal::Invalid {
                    field: "after_cut_id"
                })
            );
        }
        let begin = request(FlowingFenceAction::BeginRevision {
            before_cut_id: None,
            after_cut_id: "after".into(),
        });
        assert_eq!(
            decide(&current, &begin, Some("unselected-head")),
            Err(FlowingFenceRefusal::HeadMismatch {
                current: Some("unselected-head".into())
            })
        );
    }

    #[test]
    fn pending_revision_and_invalid_control_changes_cannot_clear_the_fence() {
        let mut pending = state();
        pending.revision = Some(FlowingRevision {
            begin_op_id: "begin-1".into(),
            before_cut_id: None,
            after_cut_id: "after".into(),
        });
        let wrong_finish = request(FlowingFenceAction::FinishRevision {
            begin_op_id: "other-begin".into(),
        });
        assert_eq!(
            decide(&pending, &wrong_finish, Some("after")),
            Err(FlowingFenceRefusal::RevisionMismatch)
        );
        assert_eq!(
            decide(
                &pending,
                &request(FlowingFenceAction::DisableAdmission),
                None
            ),
            Err(FlowingFenceRefusal::RevisionPending)
        );
        assert_eq!(
            decide(
                &pending,
                &request(FlowingFenceAction::BeginRevision {
                    before_cut_id: None,
                    after_cut_id: "another".into(),
                }),
                None
            ),
            Err(FlowingFenceRefusal::RevisionPending)
        );
        assert_eq!(
            decide(
                &state(),
                &request(FlowingFenceAction::FinishRevision {
                    begin_op_id: "begin-1".into(),
                }),
                Some("after")
            ),
            Err(FlowingFenceRefusal::RevisionMissing)
        );
        assert_eq!(
            decide(
                &state(),
                &request(FlowingFenceAction::Takeover {
                    new_owner: "owner-a".into(),
                }),
                None
            ),
            Err(FlowingFenceRefusal::Invalid { field: "new_owner" })
        );
        assert_eq!(
            decide(
                &state(),
                &request(FlowingFenceAction::InvalidateEligibility { reason: " ".into() }),
                None
            ),
            Err(FlowingFenceRefusal::Invalid { field: "reason" })
        );
    }
}
