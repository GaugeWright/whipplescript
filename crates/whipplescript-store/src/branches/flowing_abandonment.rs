//! Ref-owned whole-twig abandonment: one source head and every unit's
//! disposition are a single durable transaction.

#[cfg(feature = "native")]
pub(crate) mod native;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::flowing_fence::{FlowingFenceState, FlowingSourceKind};
use super::flowing_sources::{ContributionBasis, ContributionDeclaration, PrivateCutPin};
use super::{BranchRow, BranchStatus, MAINLINE_BRANCH_ID};
use crate::vcs::flowing_abandonment::{AbandonedUnitBasis, WholeTwigAbandonment};
use crate::StoreResult;

pub const SCHEMA: [&str; 2] = [
    "CREATE TABLE IF NOT EXISTS flowing_abandonments (
        op_id TEXT PRIMARY KEY,
        after_cut_id TEXT NOT NULL UNIQUE,
        witness_json TEXT NOT NULL,
        witness_digest TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS flowing_abandoned_units (
        unit_id TEXT PRIMARY KEY,
        op_id TEXT NOT NULL
    )",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingAbandonmentReceipt {
    pub op_id: String,
    pub begin_revision_op_id: String,
    pub source_branch_id: String,
    pub source_incarnation_id: String,
    pub source_eligibility_epoch_before_revision: i64,
    pub source_owner_epoch: i64,
    pub before_cut_id: String,
    pub before_manifest_hash: String,
    pub branch_point_cut_id: Option<String>,
    pub branch_point_manifest_hash: Option<String>,
    pub after_cut_id: String,
    pub after_manifest_hash: String,
    pub units: Vec<AbandonedUnitBasis>,
    pub actor: String,
    pub recorded_at: String,
}

#[derive(Clone, Copy, Debug)]
pub struct CommitFlowingAbandonment<'a> {
    op_id: &'a str,
    begin_revision_op_id: &'a str,
    plan: &'a WholeTwigAbandonment,
    after_cut_id: &'a str,
    after_manifest_hash: &'a str,
    actor: &'a str,
    recorded_at: &'a str,
}

impl<'a> CommitFlowingAbandonment<'a> {
    pub(crate) fn new(
        op_id: &'a str,
        begin_revision_op_id: &'a str,
        plan: &'a WholeTwigAbandonment,
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

    pub fn receipt(self) -> FlowingAbandonmentReceipt {
        FlowingAbandonmentReceipt {
            op_id: self.op_id.to_owned(),
            begin_revision_op_id: self.begin_revision_op_id.to_owned(),
            source_branch_id: self.plan.source_branch_id().to_owned(),
            source_incarnation_id: self.plan.source_incarnation_id().to_owned(),
            source_eligibility_epoch_before_revision: self.plan.source_eligibility_epoch(),
            source_owner_epoch: self.plan.source_owner_epoch(),
            before_cut_id: self.plan.before_cut_id().to_owned(),
            before_manifest_hash: self.plan.before_manifest_hash().to_owned(),
            branch_point_cut_id: self.plan.branch_point_cut_id().map(str::to_owned),
            branch_point_manifest_hash: self.plan.branch_point_manifest_hash().map(str::to_owned),
            after_cut_id: self.after_cut_id.to_owned(),
            after_manifest_hash: self.after_manifest_hash.to_owned(),
            units: self.plan.units().to_vec(),
            actor: self.actor.to_owned(),
            recorded_at: self.recorded_at.to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingAbandonmentRefusal {
    Invalid,
    IdentityMismatch,
    SourceMissing,
    SourceNotActive,
    SourceMoved,
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
pub enum FlowingAbandonmentOutcome {
    Committed(FlowingAbandonmentReceipt),
    Existing(FlowingAbandonmentReceipt),
    Refused(FlowingAbandonmentRefusal),
}

pub trait FlowingAbandonments {
    fn commit_flowing_abandonment(
        &mut self,
        request: CommitFlowingAbandonment<'_>,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<FlowingAbandonmentOutcome>;
    fn flowing_abandonment_receipt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingAbandonmentReceipt>>;
    fn flowing_abandonment_for_cut(
        &self,
        after_cut_id: &str,
    ) -> StoreResult<Option<FlowingAbandonmentReceipt>>;
    fn abandoned_unit_operation(&self, unit_id: &str) -> StoreResult<Option<String>>;
}

pub fn digest(receipt: &FlowingAbandonmentReceipt) -> String {
    let bytes = serde_json::to_vec(&("flowing-abandonment-v1", receipt))
        .expect("flowing abandonment receipt serializes");
    format!("sha256:{}", crate::chunking::content_hash_hex(&bytes))
}

#[derive(Clone)]
pub struct AbandonUnitState {
    pub declaration: ContributionDeclaration,
    pub basis: Option<ContributionBasis>,
    pub pin: Option<PrivateCutPin>,
    pub handed_off: bool,
    pub admitted: bool,
    pub parked: bool,
    pub abandoned: bool,
}

pub fn check_current(
    receipt: &FlowingAbandonmentReceipt,
    source: Option<BranchRow>,
    fence: Option<FlowingFenceState>,
    reserved: bool,
    units: &[AbandonUnitState],
) -> Result<BranchRow, FlowingAbandonmentRefusal> {
    use FlowingAbandonmentRefusal as R;
    if [
        &receipt.op_id,
        &receipt.begin_revision_op_id,
        &receipt.source_branch_id,
        &receipt.source_incarnation_id,
        &receipt.before_cut_id,
        &receipt.before_manifest_hash,
        &receipt.after_cut_id,
        &receipt.after_manifest_hash,
        &receipt.actor,
        &receipt.recorded_at,
    ]
    .iter()
    .any(|value| value.trim().is_empty())
        || receipt.units.is_empty()
        || receipt.after_cut_id == receipt.before_cut_id
        || receipt.branch_point_cut_id.is_some() != receipt.branch_point_manifest_hash.is_some()
        || receipt.source_eligibility_epoch_before_revision < 0
        || receipt.source_owner_epoch < 0
    {
        // MUTATION-SUCCESS-EXPR: Err(R::SourceMissing)
        return Err(R::Invalid);
    }
    let Some(mut source) = source else {
        // MUTATION-SUCCESS-EXPR: Err(R::Invalid)
        return Err(R::SourceMissing);
    };
    if source.status != BranchStatus::Active {
        return Err(R::SourceNotActive);
    }
    if reserved {
        return Err(R::HeadReserved);
    }
    if source.name.is_some()
        || source.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID)
        || source.branch_point_cut_id != receipt.branch_point_cut_id
        || source.branch_point_manifest_hash != receipt.branch_point_manifest_hash
        || source.head_cut_id.as_deref() != Some(receipt.before_cut_id.as_str())
        || source.head_manifest_hash.as_deref() != Some(receipt.before_manifest_hash.as_str())
    {
        // MUTATION-SUCCESS-EXPR: Ok(source.clone())
        return Err(R::SourceMoved);
    }
    let Some(fence) = fence else {
        // MUTATION-SUCCESS-EXPR: Ok(source.clone())
        return Err(R::RevisionMissing);
    };
    let Some(revision) = fence.revision else {
        // MUTATION-SUCCESS-EXPR: Ok(source.clone())
        return Err(R::RevisionMissing);
    };
    if fence.source_branch_id != receipt.source_branch_id
        || fence.incarnation_id != receipt.source_incarnation_id
        || fence.kind != FlowingSourceKind::Twig
        || !fence.admission_enabled
        || fence.owner != receipt.actor
        || fence.owner_epoch != receipt.source_owner_epoch
        || Some(fence.eligibility_epoch)
            != receipt
                .source_eligibility_epoch_before_revision
                .checked_add(1)
        || revision.begin_op_id != receipt.begin_revision_op_id
        || revision.before_cut_id.as_deref() != Some(receipt.before_cut_id.as_str())
        || revision.after_cut_id != receipt.after_cut_id
    {
        return Err(R::RevisionMismatch);
    }
    let roots: BTreeMap<_, _> = receipt
        .units
        .iter()
        .map(|unit| (unit.unit_id(), unit))
        .collect();
    if roots.len() != receipt.units.len() || units.len() != roots.len() {
        // MUTATION-SUCCESS-EXPR: Ok(source.clone())
        return Err(R::UnitRosterChanged);
    }
    let mut seen = BTreeSet::new();
    for unit in units {
        let id = unit.declaration.unit_id.as_str();
        let Some(root) = roots.get(id) else {
            // MUTATION-SUCCESS-EXPR: Ok(source.clone())
            return Err(R::UnitRosterChanged);
        };
        if !seen.insert(id) {
            // MUTATION-SUCCESS-EXPR: Ok(source.clone())
            return Err(R::UnitRosterChanged);
        }
        if unit.handed_off || unit.admitted || unit.parked || unit.abandoned {
            // MUTATION-SUCCESS-EXPR: Ok(source.clone())
            return Err(R::UnitNoLongerOwed { unit_id: id.into() });
        }
        let Some(basis) = unit.basis.as_ref() else {
            // MUTATION-SUCCESS-EXPR: Ok(source.clone())
            return Err(R::UnitBasisChanged { unit_id: id.into() });
        };
        let Some(pin) = unit.pin.as_ref() else {
            // MUTATION-SUCCESS-EXPR: Ok(source.clone())
            return Err(R::UnitBasisChanged { unit_id: id.into() });
        };
        let encoded = serde_json::to_vec(&(
            "flowing-source-selection-v1",
            &pin.pin_id,
            &pin.twig_branch_id,
            &pin.cut_id,
            &pin.manifest_hash,
            &basis.atoms,
        ))
        .expect("bound atoms serialize");
        let bound_digest = format!("sha256:{}", crate::chunking::content_hash_hex(&encoded));
        if basis.basis_digest != root.basis_digest()
            || basis.basis_digest != bound_digest
            || basis.atoms != root.atoms()
            || basis.atoms.is_empty()
            || pin.released_at.is_some()
            || pin.pin_id != unit.declaration.pin_id
            || pin.twig_branch_id != receipt.source_branch_id
            || pin.principal != unit.declaration.principal
            || pin.cut_id != unit.declaration.source_cut_id
            || pin.manifest_hash != unit.declaration.source_manifest_hash
        {
            // MUTATION-SUCCESS-EXPR: Ok(source.clone())
            return Err(R::UnitBasisChanged { unit_id: id.into() });
        }
    }
    source.head_cut_id = Some(receipt.after_cut_id.clone());
    source.head_manifest_hash = Some(receipt.after_manifest_hash.clone());
    source.updated_at.clone_from(&receipt.recorded_at);
    Ok(source)
}
