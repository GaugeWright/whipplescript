//! Atomic source-ref entry for a content-derived flowing rewrite (FB-2).
//!
//! The caller protects content publication and takes the ref-owned revision
//! fence first. This entry binds the old source, the current parent, the
//! complete still-owed root roster, the output cut, and the source ref move.
//! A separate finish-revision transition can recover after a crash here.

#[cfg(feature = "native")]
mod native;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::flowing_fence::{FlowingFenceState, FlowingSourceKind};
use super::flowing_sources::{ContributionBasis, ContributionDeclaration, PrivateCutPin};
use super::{BranchRow, BranchStatus};
use crate::vcs::flowing_rewrite::{FlowingDisjointRebase, FlowingRewriteRoot};
use crate::StoreResult;

pub const SCHEMA: [&str; 1] = ["CREATE TABLE IF NOT EXISTS flowing_rewrites (
        op_id TEXT PRIMARY KEY,
        after_cut_id TEXT NOT NULL UNIQUE,
        witness_json TEXT NOT NULL,
        witness_digest TEXT NOT NULL
    )"];

/// Immutable source roots and ref bases recorded at the same commit as the
/// rewritten head. The output change id is deliberately absent: it cannot
/// stand in for these constituent identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingRewriteReceipt {
    pub op_id: String,
    pub begin_revision_op_id: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub source_eligibility_epoch_before_revision: i64,
    pub source_owner_epoch: i64,
    pub old_head_cut_id: String,
    pub old_head_manifest_hash: String,
    pub old_point_cut_id: Option<String>,
    pub old_point_manifest_hash: Option<String>,
    pub parent_branch_id: String,
    pub parent_head_cut_id: Option<String>,
    pub parent_head_manifest_hash: Option<String>,
    pub after_cut_id: String,
    pub after_manifest_hash: String,
    pub roots: Vec<FlowingRewriteRoot>,
    pub actor: String,
    pub recorded_at: String,
}

#[derive(Clone, Copy, Debug)]
pub struct CommitFlowingRewrite<'a> {
    op_id: &'a str,
    begin_revision_op_id: &'a str,
    plan: &'a FlowingDisjointRebase,
    after_cut_id: &'a str,
    after_manifest_hash: &'a str,
    actor: &'a str,
    recorded_at: &'a str,
}

impl<'a> CommitFlowingRewrite<'a> {
    pub(crate) fn new(
        op_id: &'a str,
        begin_revision_op_id: &'a str,
        plan: &'a FlowingDisjointRebase,
        after_cut_id: &'a str,
        after_manifest_hash: &'a str,
        actor: &'a str,
        recorded_at: &'a str,
    ) -> Self {
        Self {
            op_id,
            begin_revision_op_id,
            plan,
            after_cut_id,
            after_manifest_hash,
            actor,
            recorded_at,
        }
    }

    pub fn receipt(self) -> FlowingRewriteReceipt {
        let plan = self.plan;
        FlowingRewriteReceipt {
            op_id: self.op_id.to_owned(),
            begin_revision_op_id: self.begin_revision_op_id.to_owned(),
            source_branch_id: plan.source_branch_id().to_owned(),
            source_incarnation_id: plan.source_incarnation_id().to_owned(),
            source_eligibility_epoch_before_revision: plan.source_eligibility_epoch(),
            source_owner_epoch: plan.source_owner_epoch(),
            old_head_cut_id: plan.old_head_cut_id().to_owned(),
            old_head_manifest_hash: plan.old_head_manifest_hash().to_owned(),
            old_point_cut_id: plan.old_point_cut_id().map(str::to_owned),
            old_point_manifest_hash: plan.old_point_manifest_hash().map(str::to_owned),
            parent_branch_id: plan.parent_branch_id().to_owned(),
            parent_head_cut_id: plan.parent_head_cut_id().map(str::to_owned),
            parent_head_manifest_hash: plan.parent_head_manifest_hash().map(str::to_owned),
            after_cut_id: self.after_cut_id.to_owned(),
            after_manifest_hash: self.after_manifest_hash.to_owned(),
            roots: plan.roots().to_vec(),
            actor: self.actor.to_owned(),
            recorded_at: self.recorded_at.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingRewriteRefusal {
    Invalid { field: &'static str },
    IdentityMismatch,
    SourceMissing,
    SourceNotActive,
    SourceMoved,
    ParentMissing,
    ParentMoved,
    RevisionMissing,
    RevisionMismatch,
    UnitRosterChanged,
    UnitBasisChanged { unit_id: String },
    UnitNoLongerOwed { unit_id: String },
    CutAlreadyRecorded,
    OperationAlreadyRecorded,
    HeadReserved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingRewriteOutcome {
    Committed(FlowingRewriteReceipt),
    Existing(FlowingRewriteReceipt),
    Refused(FlowingRewriteRefusal),
}

pub trait FlowingRewrites {
    /// The final embedding proof runs inside the branch transaction. It must
    /// not reopen this branch store, await, or perform effects.
    fn commit_flowing_rewrite(
        &mut self,
        request: CommitFlowingRewrite<'_>,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<FlowingRewriteOutcome>;
    fn flowing_rewrite_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingRewriteReceipt>>;
    fn flowing_rewrite_for_cut(
        &self,
        after_cut_id: &str,
    ) -> StoreResult<Option<FlowingRewriteReceipt>>;
}

pub fn digest(receipt: &FlowingRewriteReceipt) -> String {
    let bytes = serde_json::to_vec(&("flowing-rewrite-v1", receipt))
        .expect("flowing rewrite receipt serializes");
    format!("sha256:{}", crate::chunking::content_hash_hex(&bytes))
}

pub fn missing_field(receipt: &FlowingRewriteReceipt) -> Option<&'static str> {
    [
        ("op_id", receipt.op_id.as_str()),
        (
            "begin_revision_op_id",
            receipt.begin_revision_op_id.as_str(),
        ),
        ("source_branch_id", receipt.source_branch_id.as_str()),
        (
            "source_incarnation_id",
            receipt.source_incarnation_id.as_str(),
        ),
        ("old_head_cut_id", receipt.old_head_cut_id.as_str()),
        (
            "old_head_manifest_hash",
            receipt.old_head_manifest_hash.as_str(),
        ),
        ("parent_branch_id", receipt.parent_branch_id.as_str()),
        ("after_cut_id", receipt.after_cut_id.as_str()),
        ("after_manifest_hash", receipt.after_manifest_hash.as_str()),
        ("actor", receipt.actor.as_str()),
        ("recorded_at", receipt.recorded_at.as_str()),
    ]
    .into_iter()
    .find_map(|(field, value)| value.trim().is_empty().then_some(field))
}

/// Snapshot of a unit's authoritative source rows, read inside the same
/// transaction that will move the ref. A prepared content plan is not itself
/// a current ownership claim.
#[derive(Clone)]
pub struct RewriteUnitState {
    pub declaration: ContributionDeclaration,
    pub basis: Option<ContributionBasis>,
    pub pin: Option<PrivateCutPin>,
    pub handed_off: bool,
    pub admitted: bool,
}

pub fn check_current(
    receipt: &FlowingRewriteReceipt,
    source: Option<BranchRow>,
    parent: Option<BranchRow>,
    fence: Option<FlowingFenceState>,
    reserved: bool,
    units: &[RewriteUnitState],
) -> Result<BranchRow, FlowingRewriteRefusal> {
    use FlowingRewriteRefusal as R;
    if let Some(field) = missing_field(receipt) {
        return Err(R::Invalid { field });
    }
    if receipt.after_cut_id == receipt.old_head_cut_id
        || receipt.source_branch_id == receipt.parent_branch_id
        || receipt.roots.is_empty()
        || receipt.old_point_cut_id.is_some() != receipt.old_point_manifest_hash.is_some()
        || receipt.parent_head_cut_id.is_some() != receipt.parent_head_manifest_hash.is_some()
    {
        return Err(R::Invalid {
            field: "rewrite_basis",
        });
    }
    let Some(mut source) = source else {
        // MUTATION-SUCCESS-EXPR: Ok(parent.expect("parent row stands in for the missing source"))
        return Err(R::SourceMissing);
    };
    if source.status != BranchStatus::Active {
        return Err(R::SourceNotActive);
    }
    if reserved {
        return Err(R::HeadReserved);
    }
    if source.parent_branch_id.as_deref() != Some(receipt.parent_branch_id.as_str())
        || source.head_cut_id.as_deref() != Some(receipt.old_head_cut_id.as_str())
        || source.head_manifest_hash.as_deref() != Some(receipt.old_head_manifest_hash.as_str())
        || source.branch_point_cut_id != receipt.old_point_cut_id
        || source.branch_point_manifest_hash != receipt.old_point_manifest_hash
    {
        return Err(R::SourceMoved);
    }
    let Some(parent) = parent else {
        // MUTATION-SUCCESS-EXPR: Ok(source)
        return Err(R::ParentMissing);
    };
    if parent.status != BranchStatus::Active
        || parent.head_cut_id != receipt.parent_head_cut_id
        || parent.head_manifest_hash != receipt.parent_head_manifest_hash
    {
        return Err(R::ParentMoved);
    }
    let Some(fence) = fence else {
        // MUTATION-SUCCESS-EXPR: Ok(source)
        return Err(R::RevisionMissing);
    };
    let Some(revision) = fence.revision else {
        // MUTATION-SUCCESS-EXPR: Ok(source)
        return Err(R::RevisionMissing);
    };
    if fence.source_branch_id != receipt.source_branch_id
        || fence.incarnation_id != receipt.source_incarnation_id
        || fence.kind != FlowingSourceKind::Twig
        || !fence.admission_enabled
        || fence.owner_epoch != receipt.source_owner_epoch
        || Some(fence.eligibility_epoch)
            != receipt
                .source_eligibility_epoch_before_revision
                .checked_add(1)
        || revision.begin_op_id != receipt.begin_revision_op_id
        || revision.before_cut_id.as_deref() != Some(receipt.old_head_cut_id.as_str())
        || revision.after_cut_id != receipt.after_cut_id
    {
        return Err(R::RevisionMismatch);
    }
    let roots: BTreeMap<_, _> = receipt
        .roots
        .iter()
        .map(|root| (root.unit_id(), root))
        .collect();
    if roots.len() != receipt.roots.len() || units.len() != roots.len() {
        return Err(R::UnitRosterChanged);
    }
    let mut seen = BTreeSet::new();
    for unit in units {
        let id = unit.declaration.unit_id.as_str();
        let Some(root) = roots.get(id) else {
            // MUTATION-SUCCESS-EXPR: Ok(source)
            return Err(R::UnitRosterChanged);
        };
        if !seen.insert(id) {
            return Err(R::UnitRosterChanged);
        }
        if unit.handed_off || unit.admitted {
            return Err(R::UnitNoLongerOwed { unit_id: id.into() });
        }
        let Some(basis) = unit.basis.as_ref() else {
            // MUTATION-SUCCESS-EXPR: Ok(source)
            return Err(R::UnitBasisChanged { unit_id: id.into() });
        };
        let Some(pin) = unit.pin.as_ref() else {
            // MUTATION-SUCCESS-EXPR: Ok(source)
            return Err(R::UnitBasisChanged { unit_id: id.into() });
        };
        if basis.basis_digest != root.basis_digest()
            || basis.atoms != root.atoms()
            || basis.atoms.is_empty()
            || pin.released_at.is_some()
            || pin.pin_id != unit.declaration.pin_id
            || pin.twig_branch_id != receipt.source_branch_id
            || pin.principal != unit.declaration.principal
            || pin.cut_id != unit.declaration.source_cut_id
            || pin.manifest_hash != unit.declaration.source_manifest_hash
        {
            return Err(R::UnitBasisChanged { unit_id: id.into() });
        }
    }
    source.branch_point_cut_id = receipt.parent_head_cut_id.clone();
    source.branch_point_manifest_hash = receipt.parent_head_manifest_hash.clone();
    source.head_cut_id = Some(receipt.after_cut_id.clone());
    source.head_manifest_hash = Some(receipt.after_manifest_hash.clone());
    source.updated_at.clone_from(&receipt.recorded_at);
    Ok(source)
}
