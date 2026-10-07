//! Ref-owned source fences for flowing admission (DR-0130, FB-3).
//!
//! The source's eligibility epoch, Hold, owner epoch and in-flight revision
//! live beside the branch ref. Each transition and its exact retry receipt
//! share one transaction. Admission still needs a separate atomic trunk CAS
//! that reads these rows, and every production mutation door must acquire a
//! revision fence before acknowledging a changed selected unit.

#[cfg(feature = "native")]
pub(crate) mod native;

use serde::{Deserialize, Serialize};

use std::collections::BTreeSet;

use crate::branches::{BranchRow, CreateBranch, CutRow};
use crate::{StoreError, StoreResult};

pub const SCHEMA: [&str; 4] = [
    "CREATE TABLE IF NOT EXISTS flowing_source_fences (
        source_branch_id TEXT PRIMARY KEY,
        state_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_source_fence_ops (
        op_id TEXT PRIMARY KEY,
        request_json TEXT NOT NULL,
        state_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_member_openings (
        branch_id TEXT PRIMARY KEY,
        request_json TEXT NOT NULL,
        branch_json TEXT NOT NULL,
        state_json TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_source_openings (
        source_branch_id TEXT PRIMARY KEY,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingSourceOpeningReceipt {
    pub request: OpenFlowingSource,
    pub state: FlowingFenceState,
}

pub fn validate_source_opening_receipt(
    key: &str,
    receipt: &FlowingSourceOpeningReceipt,
) -> StoreResult<()> {
    if receipt.request.source_branch_id != key
        || missing_open_field(&receipt.request).is_some()
        || receipt.state != initial_state(&receipt.request)
    {
        return Err(StoreError::Conflict(
            "flowing source opening receipt is inconsistent".into(),
        ));
    }
    Ok(())
}

/// Immutable identity and result of the transaction that created a member.
/// Current branch and fence rows are intentionally absent from retry matching:
/// both can change after the member opens.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingMemberOpeningRequest {
    pub branch_id: String,
    pub parent_branch_id: String,
    pub at_cut: Option<(String, String)>,
    pub created_at: String,
    pub idempotency_key: Option<String>,
    pub source: OpenFlowingSource,
}

impl FlowingMemberOpeningRequest {
    pub fn new(branch: &CreateBranch<'_>, source: &OpenFlowingSource) -> Self {
        Self {
            branch_id: branch.branch_id.to_owned(),
            parent_branch_id: branch.parent_branch_id.to_owned(),
            at_cut: branch
                .at_cut
                .map(|(cut, manifest)| (cut.to_owned(), manifest.to_owned())),
            created_at: branch.created_at.to_owned(),
            idempotency_key: branch.idempotency_key.map(str::to_owned),
            source: source.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FlowingMemberOpeningReceipt {
    pub request: FlowingMemberOpeningRequest,
    pub branch: BranchRow,
    pub source: FlowingFenceState,
}

pub fn validate_member_opening_receipt(
    key: &str,
    receipt: &FlowingMemberOpeningReceipt,
) -> StoreResult<()> {
    let request = &receipt.request;
    let branch = &receipt.branch;
    if request.branch_id != key
        || request.parent_branch_id.is_empty()
        || request.created_at.is_empty()
        || request.source.source_branch_id != key
        || request.source.kind != FlowingSourceKind::Twig
        || missing_open_field(&request.source).is_some()
        || receipt.source != initial_state(&request.source)
        || branch.branch_id != key
        || branch.name.is_some()
        || branch.parent_branch_id.as_deref() != Some(request.parent_branch_id.as_str())
        || branch.created_at != request.created_at
        || branch.updated_at != request.created_at
        || branch.status != crate::branches::BranchStatus::Active
        || branch.adopted_merge_cut_id.is_some()
        || branch.head_cut_id != branch.branch_point_cut_id
        || branch.head_manifest_hash != branch.branch_point_manifest_hash
        || request.at_cut.as_ref().is_some_and(|(cut, manifest)| {
            branch.branch_point_cut_id.as_deref() != Some(cut)
                || branch.branch_point_manifest_hash.as_deref() != Some(manifest)
        })
    {
        return Err(StoreError::Conflict(
            "flowing member opening receipt is inconsistent".into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenFlowingSourceOutcome {
    Opened(FlowingFenceState),
    /// The original opening state when its immutable receipt exists. Stores
    /// opened before that receipt was introduced can return current state.
    Existing(FlowingFenceState),
    IdentityMismatch,
    BranchMissing,
    BranchNotActive,
    BranchAlreadyMoved,
    BranchAlreadyHasChildren,
    InvalidKindParent,
    InvalidKindName,
    Invalid {
        field: &'static str,
    },
}

/// One ref-authority transaction creates a direct twig member and opens its
/// source fence. The caller never observes a newly created writable member
/// without its source identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenFlowingMemberOutcome {
    Opened {
        branch: BranchRow,
        source: FlowingFenceState,
    },
    /// The original opening result. These snapshots are evidence of that
    /// opening, not a read of the member's current head or source fence.
    Existing {
        branch: BranchRow,
        source: FlowingFenceState,
    },
    Refused(OpenFlowingMemberRefusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OpenFlowingMemberRefusal {
    Invalid { field: &'static str },
    ParentMissing,
    ParentNotActive,
    ParentNotFlowing,
    ParentAdmissionDisabled,
    ExistingBranchWithoutSource,
    IdentityMismatch,
}

pub fn missing_member_field(
    branch: &CreateBranch<'_>,
    source: &OpenFlowingSource,
) -> Option<&'static str> {
    if branch.branch_id.is_empty() || source.source_branch_id != branch.branch_id {
        return Some("branch_id");
    }
    if branch.name.is_some() {
        return Some("name");
    }
    if branch.parent_branch_id.is_empty() {
        return Some("parent_branch_id");
    }
    if branch.created_at.is_empty() {
        return Some("created_at");
    }
    if source.kind != FlowingSourceKind::Twig {
        return Some("kind");
    }
    missing_open_field(source)
}

pub fn initial_state(request: &OpenFlowingSource) -> FlowingFenceState {
    FlowingFenceState {
        source_branch_id: request.source_branch_id.clone(),
        incarnation_id: request.incarnation_id.clone(),
        kind: request.kind.clone(),
        owner: request.owner.clone(),
        owner_epoch: 0,
        eligibility_epoch: 0,
        held: false,
        revision: None,
        admission_enabled: true,
        opened_at: request.opened_at.clone(),
    }
}

/// An explicit member point must be on the parent's current cut ancestry.
/// An unrelated but extant cut would silently import content into a member.
pub fn member_point_is_ancestor(
    current_head: Option<&str>,
    requested_cut: &str,
    requested_manifest: &str,
    mut read_cut: impl FnMut(&str) -> StoreResult<Option<CutRow>>,
) -> StoreResult<bool> {
    let mut cursor = current_head.map(str::to_owned);
    let mut seen = BTreeSet::new();
    while let Some(id) = cursor {
        if !seen.insert(id.clone()) {
            // MUTATION-SUCCESS-EXPR: Ok(true)
            return Err(StoreError::Conflict("cyclic member cut ancestry".into()));
        }
        let Some(cut) = read_cut(&id)? else {
            // MUTATION-SUCCESS-EXPR: Ok(true)
            return Err(StoreError::Conflict("missing member cut ancestor".into()));
        };
        if id == requested_cut {
            return Ok(cut.manifest_hash == requested_manifest);
        }
        cursor = cut.parent_cut_id;
    }
    Ok(false)
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
    fn open_flowing_member(
        &mut self,
        branch: CreateBranch<'_>,
        source: &OpenFlowingSource,
    ) -> StoreResult<OpenFlowingMemberOutcome>;
    fn open_flowing_source(
        &mut self,
        request: &OpenFlowingSource,
    ) -> StoreResult<OpenFlowingSourceOutcome>;
    fn flowing_source(&self, source_branch_id: &str) -> StoreResult<Option<FlowingFenceState>>;
    fn flowing_source_opening(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<Option<FlowingSourceOpeningReceipt>>;
    fn flowing_member_opening(
        &self,
        branch_id: &str,
    ) -> StoreResult<Option<FlowingMemberOpeningReceipt>>;
    fn transition_flowing_source(
        &mut self,
        request: &FlowingFenceTransition,
    ) -> StoreResult<FlowingFenceOutcome>;
    fn flowing_fence_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingFenceReceipt>>;
}

/// A flowing source may grow a new tail without invalidating a selected
/// immutable prefix. A ref move with another ancestry needs the revision
/// fence taken before the move; an unrecorded cut proves neither case.
#[doc(hidden)]
pub fn require_head_move(
    state: &FlowingFenceState,
    before_cut_id: Option<&str>,
    after_cut_id: &str,
    manifest_hash: &str,
    cut: Option<&crate::branches::CutRow>,
) -> StoreResult<()> {
    if !state.admission_enabled {
        return Err(StoreError::Conflict(format!(
            "flowing source `{}` no longer accepts head moves",
            state.source_branch_id
        )));
    }
    let Some(cut) = cut else {
        return Err(StoreError::Conflict(format!(
            "flowing source `{}` needs a recorded cut before its head moves",
            state.source_branch_id
        )));
    };
    if cut.cut_id != after_cut_id
        || cut.branch_id != state.source_branch_id
        || cut.manifest_hash != manifest_hash
    {
        return Err(StoreError::Conflict(format!(
            "flowing source `{}` cut differs from the proposed head",
            state.source_branch_id
        )));
    }
    if let Some(revision) = state.revision.as_ref() {
        if revision.before_cut_id.as_deref() != before_cut_id
            || revision.after_cut_id != after_cut_id
        {
            return Err(StoreError::Conflict(format!(
                "flowing source `{}` head move differs from its pending revision",
                state.source_branch_id
            )));
        }
    } else if cut.parent_cut_id.as_deref() != before_cut_id {
        return Err(StoreError::Conflict(format!(
            "flowing source `{}` rewrite needs a revision fence",
            state.source_branch_id
        )));
    }
    Ok(())
}

#[doc(hidden)]
pub fn refuse_legacy_shape_move(source_branch_id: &str) -> StoreError {
    StoreError::Conflict(format!(
        "flowing source `{source_branch_id}` needs a controlled lifecycle move"
    ))
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

    fn cut(id: &str, parent: Option<&str>, manifest: &str) -> CutRow {
        CutRow {
            cut_id: id.into(),
            change_id: id.into(),
            branch_id: "branch".into(),
            manifest_hash: manifest.into(),
            parent_cut_id: parent.map(str::to_owned),
            origin: None,
            actor: None,
            intent: None,
            recorded_at: "t0".into(),
        }
    }

    #[test]
    fn member_point_requires_current_ancestry_and_complete_history() {
        let rows = [
            ("root", cut("root", None, "m-root")),
            ("head", cut("head", Some("root"), "m-head")),
            ("unrelated", cut("unrelated", None, "m-other")),
        ]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
        let read = |id: &str| Ok(rows.get(id).cloned());
        assert!(member_point_is_ancestor(Some("head"), "root", "m-root", read).unwrap());
        assert!(!member_point_is_ancestor(Some("head"), "root", "wrong", read).unwrap());
        assert!(!member_point_is_ancestor(Some("head"), "unrelated", "m-other", read).unwrap());
        assert!(!member_point_is_ancestor(None, "root", "m-root", read).unwrap());

        let missing = [("head", cut("head", Some("absent"), "m-head"))]
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert!(matches!(
            member_point_is_ancestor(Some("head"), "root", "m-root", |id| {
                Ok(missing.get(id).cloned())
            }),
            Err(StoreError::Conflict(message)) if message == "missing member cut ancestor"
        ));
        let cycle = [
            ("head", cut("head", Some("root"), "m-head")),
            ("root", cut("root", Some("head"), "m-root")),
        ]
        .into_iter()
        .collect::<std::collections::BTreeMap<_, _>>();
        assert!(matches!(
            member_point_is_ancestor(Some("head"), "absent", "m", |id| {
                Ok(cycle.get(id).cloned())
            }),
            Err(StoreError::Conflict(message)) if message == "cyclic member cut ancestry"
        ));
    }

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
