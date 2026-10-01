//! Exact source-change extraction for a retained private cut (DR-0130, FB-2).
//!
//! This is a read-only preparation step. It makes no handoff or admission
//! claim: those require the target-content proof and an atomic receipt. In
//! particular, legacy rewrite/transport cuts lack constituent lineage, so
//! they refuse here instead of manufacturing change identities from a diff.

use std::collections::{BTreeMap, BTreeSet};

use crate::branches::flowing_admission::{
    FlowingAdmissions, FlowingSelectedUnit, RetainFlowingAttemptOutcome,
};
#[cfg(feature = "native")]
use crate::branches::flowing_admission::{FlowingCandidateWitness, FlowingUnitOutcome};
use crate::branches::flowing_sources::{
    BindContributionBasis, BindContributionBasisOutcome, ContributionBasis, FlowingSources,
    HandoffContribution, HandoffContributionOutcome, HandoffReceipt,
};
use crate::branches::{BranchStatus, Branches, CutRecord, CutRow};
use crate::content::ContentBlobs;
use crate::selection::{self, SelAtom, SelExpr};
#[cfg(feature = "native")]
use crate::source_review_native::NativeRevision;

#[cfg(feature = "native")]
mod named_branch_candidate;
use crate::{StoreError, StoreResult};

use super::{RawManifest, WorkspaceVcs};

/// The actual source changes selected from one immutable, retained twig cut.
/// Only `WorkspaceVcs::select_private_changes` constructs this value; callers
/// cannot substitute a list of asserted identities for a content derivation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FlowingSourceAtom {
    pub cut_id: String,
    pub change_id: String,
    pub path: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingSelection {
    pin_id: String,
    source_branch_id: String,
    source_cut_id: String,
    source_manifest_hash: String,
    changes: Vec<FlowingSourceAtom>,
    digest: String,
}

impl FlowingSelection {
    pub fn pin_id(&self) -> &str {
        &self.pin_id
    }
    pub fn source_branch_id(&self) -> &str {
        &self.source_branch_id
    }
    pub fn source_cut_id(&self) -> &str {
        &self.source_cut_id
    }
    pub fn source_manifest_hash(&self) -> &str {
        &self.source_manifest_hash
    }
    pub fn changes(&self) -> &[FlowingSourceAtom] {
        &self.changes
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingSelectionOutcome {
    Selected(FlowingSelection),
    PinMissing,
    PinReleased,
    CutMissing,
    CutMismatch,
    MissingManifest { cut_id: String },
    MissingContent { content_id: String },
    MissingParent { cut_id: String },
    CyclicLineage { cut_id: String },
    UnsupportedLineage { cut_id: String },
    UnsupportedSelection,
    NothingSelected,
}

/// A content comparison for one bound unit against one recorded target cut.
/// This is preparation only: it neither proves who authored the target cut
/// nor transfers the unit. Handoff or trunk admission must bind this exact
/// comparison to the target ref transition and record its receipt atomically.
/// Its fields are private so a caller cannot supply asserted effects in place
/// of a read.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FlowingTargetEffect {
    pub path: String,
    pub before: Option<String>,
    pub after: Option<String>,
    pub disposition: FlowingEffectDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowingEffectDisposition {
    Applied,
    Equivalent,
    Neutralized,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingTargetEffects {
    unit_id: String,
    basis_digest: String,
    target_branch_id: String,
    target_before_cut_id: Option<String>,
    target_after_cut_id: String,
    target_after_manifest_hash: String,
    effects: Vec<FlowingTargetEffect>,
}

impl FlowingTargetEffects {
    pub fn unit_id(&self) -> &str {
        &self.unit_id
    }
    pub fn basis_digest(&self) -> &str {
        &self.basis_digest
    }
    pub fn target_branch_id(&self) -> &str {
        &self.target_branch_id
    }
    pub fn target_before_cut_id(&self) -> Option<&str> {
        self.target_before_cut_id.as_deref()
    }
    pub fn target_after_cut_id(&self) -> &str {
        &self.target_after_cut_id
    }
    pub fn target_after_manifest_hash(&self) -> &str {
        &self.target_after_manifest_hash
    }
    pub fn effects(&self) -> &[FlowingTargetEffect] {
        &self.effects
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingTargetEffectsOutcome {
    Verified(FlowingTargetEffects),
    UnitMissing,
    BasisMissing,
    TargetMissing,
    TargetNotParent,
    TargetCutMissing,
    TargetCutMismatch,
    InitialNoopNeedsGenesis,
    MissingManifest { cut_id: String },
    MissingContent { content_id: String },
    IncoherentSourcePath { path: String },
    BeforeMismatch { path: String },
    OmittedEffect { path: String },
    UnexpectedEffect { path: String },
}

/// Ordered per-unit effects of one mixed target cut. This is a content
/// comparison only; no holder transfers until an atomic batch receipt exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingBatchUnitEffect {
    unit_id: String,
    source_branch_id: String,
    source_cut_id: String,
    basis_digest: String,
    effects: Vec<FlowingTargetEffect>,
}

impl FlowingBatchUnitEffect {
    pub fn unit_id(&self) -> &str {
        &self.unit_id
    }
    pub fn source_branch_id(&self) -> &str {
        &self.source_branch_id
    }
    pub fn source_cut_id(&self) -> &str {
        &self.source_cut_id
    }
    pub fn basis_digest(&self) -> &str {
        &self.basis_digest
    }
    pub fn effects(&self) -> &[FlowingTargetEffect] {
        &self.effects
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingBatchTargetEffects {
    target_branch_id: String,
    target_before_cut_id: Option<String>,
    target_after_cut_id: String,
    target_after_manifest_hash: String,
    units: Vec<FlowingBatchUnitEffect>,
}

impl FlowingBatchTargetEffects {
    pub fn target_branch_id(&self) -> &str {
        &self.target_branch_id
    }
    pub fn target_before_cut_id(&self) -> Option<&str> {
        self.target_before_cut_id.as_deref()
    }
    pub fn target_after_cut_id(&self) -> &str {
        &self.target_after_cut_id
    }
    pub fn target_after_manifest_hash(&self) -> &str {
        &self.target_after_manifest_hash
    }
    pub fn units(&self) -> &[FlowingBatchUnitEffect] {
        &self.units
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingBatchTargetEffectsOutcome {
    Verified(FlowingBatchTargetEffects),
    EmptySelection,
    DuplicateUnit { unit_id: String },
    Refused(FlowingTargetEffectsOutcome),
}

/// A content-derived, complete direct-twig prefix at an unchanged trunk base.
/// The recorded cut is a GC root, but this is preparation, not a gate verdict
/// or permission to advance the trunk ref.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCandidate {
    pub contribution_id: String,
    pub revision_sequence: i64,
    pub source_cut_id: String,
    pub expected_trunk_cut_id: Option<String>,
    pub candidate_cut_id: String,
    pub candidate_manifest_hash: String,
    pub source_atoms_digest: String,
    pub candidate_witness_digest: String,
    pub units: Vec<FlowingSelectedUnit>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeCandidateOutcome {
    Prepared(NativeCandidate),
    StaleBase,
    SourceMismatch,
    IncompletePrefix,
    MissingContent { content_id: String },
    UnitAlreadyAdmitted { unit_id: String },
    UnprovenBasis { unit_id: String },
    CandidateMismatch,
}

/// A receiving branch's complete currently reachable handoff chain. This is
/// a read-only content proof, not a gate certificate or permission to move a
/// ref. A later admission must recapture the exact branch head and fences.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingBranchLineage {
    branch_id: String,
    head_cut_id: Option<String>,
    head_manifest_hash: Option<String>,
    handoffs: Vec<HandoffReceipt>,
    sources: Vec<FlowingHandoffSource>,
}

/// Source facts captured by the same lineage inspection that verifies each
/// receipt. Review upload uses these facts rather than rereading the unit after
/// the content proof, which would mix two observations in one revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingHandoffSource {
    pub unit_id: String,
    pub source_cut_id: String,
    pub pin_id: String,
    pub basis_digest: String,
    pub principal: String,
    pub intent: String,
}

/// One complete handoff prefix chosen at an actual branch cut. Later units
/// remain visible and owed; this value does not move either branch ref.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingBranchPrefix {
    branch_id: String,
    selected_cut_id: String,
    selected_manifest_hash: String,
    selected_handoffs: Vec<HandoffReceipt>,
    selected_sources: Vec<FlowingHandoffSource>,
    later_handoffs: Vec<HandoffReceipt>,
    observed_head_cut_id: Option<String>,
}

impl FlowingBranchLineage {
    pub fn branch_id(&self) -> &str {
        &self.branch_id
    }
    pub fn head_cut_id(&self) -> Option<&str> {
        self.head_cut_id.as_deref()
    }
    pub fn head_manifest_hash(&self) -> Option<&str> {
        self.head_manifest_hash.as_deref()
    }
    pub fn handoffs(&self) -> &[HandoffReceipt] {
        &self.handoffs
    }

    /// A selected cut must be one of this verified chain's receipt boundaries.
    /// Selecting a branch point with no units would mint no review obligation.
    pub fn prefix_through(&self, selected_cut_id: &str) -> Option<FlowingBranchPrefix> {
        let position = self
            .handoffs
            .iter()
            .position(|receipt| receipt.target_after_cut_id == selected_cut_id)?;
        let (selected, later) = self.handoffs.split_at(position + 1);
        let (selected_sources, _) = self.sources.split_at(position + 1);
        Some(FlowingBranchPrefix {
            branch_id: self.branch_id.clone(),
            selected_cut_id: selected_cut_id.to_owned(),
            selected_manifest_hash: selected.last()?.target_after_manifest_hash.clone(),
            selected_handoffs: selected.to_vec(),
            selected_sources: selected_sources.to_vec(),
            later_handoffs: later.to_vec(),
            observed_head_cut_id: self.head_cut_id.clone(),
        })
    }
}

impl FlowingBranchPrefix {
    pub fn branch_id(&self) -> &str {
        &self.branch_id
    }
    pub fn selected_cut_id(&self) -> &str {
        &self.selected_cut_id
    }
    pub fn selected_manifest_hash(&self) -> &str {
        &self.selected_manifest_hash
    }
    pub fn selected_handoffs(&self) -> &[HandoffReceipt] {
        &self.selected_handoffs
    }
    pub fn selected_sources(&self) -> &[FlowingHandoffSource] {
        &self.selected_sources
    }
    pub fn later_handoffs(&self) -> &[HandoffReceipt] {
        &self.later_handoffs
    }
    pub fn observed_head_cut_id(&self) -> Option<&str> {
        self.observed_head_cut_id.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingBranchLineageOutcome {
    Verified(FlowingBranchLineage),
    BranchMissing,
    NotFlowingBranch,
    CutMissing { cut_id: String },
    CutMismatch { cut_id: String },
    CyclicLineage { cut_id: String },
    MissingReceipt { cut_id: String },
    UnreachableReceipt { op_id: String },
    ReceiptMismatch { op_id: String },
    EffectsUnproved { unit_id: String },
}

/// The complete VCS snapshot a source unit says it read when it began.
/// The host records this at declaration; candidate preparation recomputes it
/// from the immutable cut immediately before that unit's first write.
pub fn native_read_basis_digest(cut_id: Option<&str>, manifest_hash: Option<&str>) -> String {
    let bytes = serde_json::to_vec(&("native-read-basis-v1", cut_id, manifest_hash))
        .expect("string tuple serializes");
    format!("sha256:{}", crate::chunking::content_hash_hex(&bytes))
}

/// Conservative predecessor basis: every earlier unit in the same prefix,
/// even when a semantic dependency graph might allow a smaller set.
pub fn native_dependency_basis_digest(prior: &[(String, String)]) -> String {
    let bytes = serde_json::to_vec(&("native-source-predecessors-v1", prior))
        .expect("string tuple serializes");
    format!("sha256:{}", crate::chunking::content_hash_hex(&bytes))
}

fn requires_unproved_semantics(expr: &SelExpr) -> bool {
    match expr {
        SelExpr::Union(left, right)
        | SelExpr::Intersect(left, right)
        | SelExpr::Difference(left, right) => {
            requires_unproved_semantics(left) || requires_unproved_semantics(right)
        }
        SelExpr::Atom(SelAtom::Decl(_) | SelAtom::Region(_)) => true,
        SelExpr::Atom(SelAtom::DependentsOf(inner)) => requires_unproved_semantics(inner),
        SelExpr::Atom(_) => false,
    }
}

type NetSourcePaths<'a> = BTreeMap<&'a str, (Option<&'a str>, Option<&'a str>)>;
type NetSourceResult<'a> = StoreResult<Result<NetSourcePaths<'a>, FlowingTargetEffectsOutcome>>;

impl<B: Branches + FlowingSources, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// Match every cut reachable from a named branch's head to its branch
    /// point with one immutable handoff receipt, and rederive each receipt's
    /// effects from the bound source atoms and actual target content. Any
    /// local edit, rewrite, orphan receipt or omitted target cut refuses until
    /// constituent transport lineage can account for it explicitly.
    pub fn inspect_flowing_branch_lineage(
        &self,
        branch_id: &str,
    ) -> StoreResult<FlowingBranchLineageOutcome>
    where
        B: FlowingAdmissions,
    {
        use FlowingBranchLineageOutcome as R;
        let Some(branch) = self.branches.get_branch(branch_id)? else {
            return Ok(R::BranchMissing);
        };
        let Some(fence) = self.branches.flowing_source(branch_id)? else {
            return Ok(R::NotFlowingBranch);
        };
        if branch.name.is_none()
            || fence.kind != crate::branches::flowing_fence::FlowingSourceKind::Branch
        {
            return Ok(R::NotFlowingBranch);
        }
        match branch.branch_point_cut_id.as_deref() {
            Some(base_id) => {
                let Some(base) = self.branches.get_cut(base_id)? else {
                    return Ok(R::CutMissing {
                        cut_id: base_id.to_owned(),
                    });
                };
                if branch.branch_point_manifest_hash.as_deref() != Some(base.manifest_hash.as_str())
                {
                    return Ok(R::CutMismatch {
                        cut_id: base_id.to_owned(),
                    });
                }
            }
            None if branch.branch_point_manifest_hash.is_some() => {
                return Ok(R::CutMismatch {
                    cut_id: branch.branch_id.clone(),
                });
            }
            None => {}
        }
        let mut by_cut = BTreeMap::new();
        for receipt in self.branches.target_handoffs(branch_id)? {
            if by_cut
                .insert(receipt.target_after_cut_id.clone(), receipt.clone())
                .is_some()
            {
                return Ok(R::ReceiptMismatch {
                    op_id: receipt.op_id,
                });
            }
        }
        let mut reverse = Vec::new();
        let mut reverse_sources = Vec::new();
        let mut cursor = branch.head_cut_id.clone();
        let mut expected_manifest = branch.head_manifest_hash.clone();
        let mut seen = BTreeSet::new();
        while cursor != branch.branch_point_cut_id {
            let Some(cut_id) = cursor else {
                return Ok(R::CutMismatch {
                    cut_id: branch.branch_id.clone(),
                });
            };
            if !seen.insert(cut_id.clone()) {
                return Ok(R::CyclicLineage { cut_id });
            }
            let Some(cut) = self.branches.get_cut(&cut_id)? else {
                return Ok(R::CutMissing { cut_id });
            };
            if cut.branch_id != branch_id
                || expected_manifest.as_deref() != Some(cut.manifest_hash.as_str())
            {
                return Ok(R::CutMismatch { cut_id });
            }
            let Some(receipt) = by_cut.remove(&cut_id) else {
                return Ok(R::MissingReceipt { cut_id });
            };
            if receipt.target_branch_id != branch_id
                || receipt.target_before_cut_id != cut.parent_cut_id
                || receipt.target_after_manifest_hash != cut.manifest_hash
                || cut.origin.as_deref()
                    != Some(format!("transport:{}", receipt.source_branch_id).as_str())
                || cut.actor.as_deref() != Some(receipt.actor.as_str())
            {
                return Ok(R::ReceiptMismatch {
                    op_id: receipt.op_id,
                });
            }
            let Some(unit) = self.branches.contribution_declaration(&receipt.unit_id)? else {
                return Ok(R::ReceiptMismatch {
                    op_id: receipt.op_id,
                });
            };
            let Some(basis) = self.branches.contribution_basis(&receipt.unit_id)? else {
                return Ok(R::EffectsUnproved {
                    unit_id: receipt.unit_id,
                });
            };
            if receipt.source_branch_id != unit.source_branch_id
                || receipt.source_cut_id != unit.source_cut_id
                || receipt.source_manifest_hash != unit.source_manifest_hash
                || receipt.source_basis_digest != basis.basis_digest
                || receipt.original_principal != unit.principal
            {
                return Ok(R::ReceiptMismatch {
                    op_id: receipt.op_id,
                });
            }
            let FlowingTargetEffectsOutcome::Verified(effects) =
                self.verify_private_target_effects(&receipt.unit_id, &cut_id)?
            else {
                return Ok(R::EffectsUnproved {
                    unit_id: receipt.unit_id,
                });
            };
            if effects.effects() != receipt.effects
                || effects.target_before_cut_id() != receipt.target_before_cut_id.as_deref()
                || effects.target_after_manifest_hash() != receipt.target_after_manifest_hash
            {
                return Ok(R::ReceiptMismatch {
                    op_id: receipt.op_id,
                });
            }
            expected_manifest = match cut.parent_cut_id.as_deref() {
                Some(parent_id) => self
                    .branches
                    .get_cut(parent_id)?
                    .map(|parent| parent.manifest_hash),
                None => None,
            };
            cursor = cut.parent_cut_id;
            reverse_sources.push(FlowingHandoffSource {
                unit_id: receipt.unit_id.clone(),
                source_cut_id: unit.source_cut_id,
                pin_id: unit.pin_id,
                basis_digest: basis.basis_digest,
                principal: unit.principal,
                intent: unit.intent,
            });
            reverse.push(receipt);
        }
        if let Some((_, extra)) = by_cut.into_iter().next() {
            return Ok(R::UnreachableReceipt { op_id: extra.op_id });
        }
        if expected_manifest != branch.branch_point_manifest_hash {
            return Ok(R::CutMismatch {
                cut_id: branch.branch_id,
            });
        }
        reverse.reverse();
        reverse_sources.reverse();
        Ok(R::Verified(FlowingBranchLineage {
            branch_id: branch_id.to_owned(),
            head_cut_id: branch.head_cut_id,
            head_manifest_hash: branch.head_manifest_hash,
            handoffs: reverse,
            sources: reverse_sources,
        }))
    }

    /// Retain the exact review source and candidate while a gate attempt is
    /// outstanding. The same content publication exclusion covers the ref
    /// row and every constituent body, including writes neutralized in the
    /// final candidate. A ref-only caller cannot establish this closure.
    pub fn retain_review_attempt(
        &mut self,
        op_id: &str,
        witness_digest: &str,
        retained_at: &str,
    ) -> StoreResult<RetainFlowingAttemptOutcome>
    where
        B: FlowingAdmissions,
    {
        use RetainFlowingAttemptOutcome as R;
        let Some(witness) = self.branches.candidate_witness(witness_digest)? else {
            return self
                .branches
                .retain_flowing_attempt(op_id, witness_digest, retained_at);
        };
        let mut ids = BTreeSet::new();
        for manifest_hash in [
            &witness.source_manifest_hash,
            &witness.candidate_manifest_hash,
        ] {
            let Some(manifest) = self.load_manifest_opt_raw(manifest_hash)? else {
                return Ok(R::MissingContent {
                    content_id: manifest_hash.clone(),
                });
            };
            ids.insert(manifest_hash.clone());
            match manifest {
                RawManifest::Tree(_) => {
                    ids.extend(crate::manifest_tree::reachable_ids(
                        &self.content,
                        manifest_hash,
                    )?);
                }
                RawManifest::Flat(files) => ids.extend(files.into_values()),
            }
        }
        for unit in &witness.units {
            let Some(basis) = self.branches.contribution_basis(&unit.unit_id)? else {
                return Ok(R::UnitBasisMissing {
                    unit_id: unit.unit_id.clone(),
                });
            };
            if basis.basis_digest != unit.basis_digest {
                return Ok(R::UnitBasisMismatch {
                    unit_id: unit.unit_id.clone(),
                });
            }
            for atom in basis.atoms {
                ids.extend(atom.before);
                ids.extend(atom.after);
            }
        }
        for id in &ids {
            if !self.content.cached_read_available(id)? {
                return Ok(R::MissingContent {
                    content_id: id.clone(),
                });
            }
        }
        let ids = ids.into_iter().collect::<Vec<_>>();
        let branches = &mut self.branches;
        self.content.publish_retained(&ids, || {
            branches.retain_flowing_attempt(op_id, witness_digest, retained_at)
        })
    }

    fn net_source_paths<'a>(&self, basis: &'a ContributionBasis) -> NetSourceResult<'a> {
        let mut selected = BTreeMap::new();
        for atom in &basis.atoms {
            if let Some((_, previous_after)) = selected.get_mut(atom.path.as_str()) {
                if *previous_after != atom.before.as_deref() {
                    return Ok(Err(FlowingTargetEffectsOutcome::IncoherentSourcePath {
                        path: atom.path.clone(),
                    }));
                }
                *previous_after = atom.after.as_deref();
            } else {
                selected.insert(
                    atom.path.as_str(),
                    (atom.before.as_deref(), atom.after.as_deref()),
                );
            }
            for content_id in [atom.before.as_deref(), atom.after.as_deref()]
                .into_iter()
                .flatten()
            {
                if !self.content.cached_read_available(content_id)? {
                    return Ok(Err(FlowingTargetEffectsOutcome::MissingContent {
                        content_id: content_id.to_owned(),
                    }));
                }
            }
        }
        Ok(Ok(selected))
    }

    /// Prepare the complete selected direct-twig prefix at its original trunk
    /// branch point. This refuses selective skips and a moved trunk. When
    /// units write the same path, their ordered source atoms must reproduce
    /// the selected manifest before any per-unit outcome is recorded.
    #[cfg(feature = "native")]
    pub fn prepare_native_review_candidate(
        &mut self,
        revision: &NativeRevision,
        expected_trunk_cut_id: Option<&str>,
        candidate_cut_id: &str,
        actor: &str,
        recorded_at: &str,
    ) -> StoreResult<NativeCandidateOutcome>
    where
        B: FlowingAdmissions,
    {
        use NativeCandidateOutcome as R;
        if candidate_cut_id.trim().is_empty() || actor.trim().is_empty() {
            return Ok(R::CandidateMismatch);
        }
        let Some(source) = self.branches.get_branch(&revision.source_branch_id)? else {
            return Ok(R::SourceMismatch);
        };
        let Some(trunk) = self
            .branches
            .get_branch(crate::branches::MAINLINE_BRANCH_ID)?
        else {
            return Ok(R::StaleBase);
        };
        let Some(fence) = self.branches.flowing_source(&revision.source_branch_id)? else {
            return Ok(R::SourceMismatch);
        };
        if source.status != BranchStatus::Active
            || source.name.is_some()
            || source.parent_branch_id.as_deref() != Some(crate::branches::MAINLINE_BRANCH_ID)
            || fence.kind != crate::branches::flowing_fence::FlowingSourceKind::Twig
            || fence.incarnation_id != revision.source_incarnation_id
            || !fence.admission_enabled
            || fence.held
            || fence.revision.is_some()
        {
            return Ok(R::SourceMismatch);
        }
        if trunk.status != BranchStatus::Active
            || trunk.head_cut_id.as_deref() != expected_trunk_cut_id
            || source.branch_point_cut_id.as_deref() != expected_trunk_cut_id
            || source.branch_point_manifest_hash != trunk.head_manifest_hash
        {
            return Ok(R::StaleBase);
        }
        if let Some(base_id) = expected_trunk_cut_id {
            let Some(base) = self.branches.get_cut(base_id)? else {
                return Ok(R::StaleBase);
            };
            if base.branch_id != crate::branches::MAINLINE_BRANCH_ID
                || Some(base.manifest_hash.as_str()) != trunk.head_manifest_hash.as_deref()
                || self.load_manifest_opt_raw(&base.manifest_hash)?.is_none()
            {
                return Ok(R::StaleBase);
            }
        }
        let Some(selected_cut) = self.branches.get_cut(&revision.source_cut_id)? else {
            return Ok(R::SourceMismatch);
        };
        if selected_cut.branch_id != revision.source_branch_id
            || selected_cut.manifest_hash != revision.source_manifest_hash
        {
            return Ok(R::SourceMismatch);
        }
        // A later append remains harmless; a rewrite or missing ancestor does
        // not establish that the selected cut still belongs to this line.
        let mut head_cursor = source.head_cut_id.clone();
        let mut head_seen = BTreeSet::new();
        while let Some(id) = head_cursor {
            if !head_seen.insert(id.clone()) {
                return Ok(R::SourceMismatch);
            }
            if id == revision.source_cut_id {
                break;
            }
            head_cursor = self
                .branches
                .get_cut(&id)?
                .and_then(|cut| cut.parent_cut_id);
        }
        if !head_seen.contains(&revision.source_cut_id) {
            return Ok(R::SourceMismatch);
        }

        let mut cuts = Vec::new();
        let mut cursor = Some(revision.source_cut_id.clone());
        let mut seen = BTreeSet::new();
        while cursor.as_deref() != expected_trunk_cut_id {
            let Some(id) = cursor else {
                return Ok(R::SourceMismatch);
            };
            if !seen.insert(id.clone()) {
                return Ok(R::SourceMismatch);
            }
            let Some(cut) = self.branches.get_cut(&id)? else {
                return Ok(R::SourceMismatch);
            };
            if cut.branch_id != revision.source_branch_id
                || !cut
                    .origin
                    .as_deref()
                    .is_some_and(|origin| origin.starts_with("write:"))
                || self.load_manifest_opt_raw(&cut.manifest_hash)?.is_none()
            {
                return Ok(R::SourceMismatch);
            }
            cursor = cut.parent_cut_id.clone();
            cuts.push(cut);
        }
        cuts.reverse();
        let selected_ids: BTreeSet<&str> = revision
            .units
            .iter()
            .map(|unit| unit.unit_id.as_str())
            .collect();
        let declared_ids: BTreeSet<String> = self
            .branches
            .source_contributions(&revision.source_branch_id)?
            .into_iter()
            .filter(|unit| seen.contains(&unit.source_cut_id))
            .map(|unit| unit.unit_id)
            .collect();
        if selected_ids.len() != revision.units.len()
            || selected_ids != declared_ids.iter().map(String::as_str).collect()
        {
            return Ok(R::IncompletePrefix);
        }
        let mut atoms = Vec::new();
        for cut in &cuts {
            let mut change_units = Vec::new();
            self.push_units_for_cut(cut, &mut change_units)?;
            for change in change_units {
                for id in [change.before.as_deref(), change.after.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    if !self.content.cached_read_available(id)? {
                        return Ok(R::MissingContent {
                            content_id: id.into(),
                        });
                    }
                }
                atoms.push(FlowingSourceAtom {
                    cut_id: change.cut_id,
                    change_id: change.change_id,
                    path: change.path,
                    before: change.before,
                    after: change.after,
                });
            }
        }
        let expected: BTreeMap<(String, String), FlowingSourceAtom> = atoms
            .iter()
            .map(|atom| ((atom.cut_id.clone(), atom.path.clone()), atom.clone()))
            .collect();
        if atoms.is_empty() || expected.len() != atoms.len() || revision.units.is_empty() {
            return Ok(R::IncompletePrefix);
        }
        let mut owners = BTreeMap::new();
        let mut cut_owners = BTreeMap::new();
        let mut declarations = BTreeMap::new();
        for unit in &revision.units {
            if self
                .branches
                .admitted_unit_operation(&unit.unit_id)?
                .is_some()
            {
                return Ok(R::UnitAlreadyAdmitted {
                    unit_id: unit.unit_id.clone(),
                });
            }
            let Some(declared) = self.branches.contribution_declaration(&unit.unit_id)? else {
                return Ok(R::IncompletePrefix);
            };
            let Some(basis) = self.branches.contribution_basis(&unit.unit_id)? else {
                return Ok(R::IncompletePrefix);
            };
            let Some(pin) = self.branches.private_cut_pin(&unit.pin_id)? else {
                return Ok(R::IncompletePrefix);
            };
            let Some(declared_cut) = self.branches.get_cut(&unit.source_cut_id)? else {
                return Ok(R::IncompletePrefix);
            };
            if declared.source_branch_id != revision.source_branch_id
                || declared.source_cut_id != unit.source_cut_id
                || declared.pin_id != unit.pin_id
                || declared.principal != unit.principal
                || declared.intent != unit.intent
                || basis.basis_digest != unit.basis_digest
                || declared_cut.manifest_hash != declared.source_manifest_hash
                || !seen.contains(&unit.source_cut_id)
                || pin.released_at.is_some()
                || pin.twig_branch_id != revision.source_branch_id
                || pin.cut_id != unit.source_cut_id
                || pin.manifest_hash != declared.source_manifest_hash
                || self.branches.contribution_handoff(&unit.unit_id)?.is_some()
            {
                return Ok(R::IncompletePrefix);
            }
            for atom in &basis.atoms {
                let key = (atom.cut_id.clone(), atom.path.clone());
                if expected.get(&key) != Some(atom)
                    || owners.insert(key, unit.unit_id.clone()).is_some()
                {
                    return Ok(R::IncompletePrefix);
                }
                if cut_owners
                    .insert(atom.cut_id.clone(), unit.unit_id.clone())
                    .is_some_and(|owner| owner != unit.unit_id)
                {
                    return Ok(R::IncompletePrefix);
                }
            }
            match self.net_source_paths(&basis)? {
                Ok(_) => {}
                Err(FlowingTargetEffectsOutcome::MissingContent { content_id }) => {
                    return Ok(R::MissingContent { content_id });
                }
                Err(_) => return Ok(R::IncompletePrefix),
            }
            declarations.insert(unit.unit_id.clone(), declared);
        }
        if owners.len() != expected.len() {
            return Ok(R::IncompletePrefix);
        }
        // A unit occupies whole consecutive cuts. Its declared read snapshot
        // must be the cut before its first write; its dependency basis names
        // every earlier unit, so an unknown edge cannot escape the prefix.
        let mut ordered: Vec<(String, String)> = Vec::new();
        let mut finished = BTreeSet::new();
        let mut previous_owner: Option<&str> = None;
        let mut last_cut_by_owner = BTreeMap::new();
        let mut basis_evidence = Vec::new();
        for cut in &cuts {
            let Some(owner) = cut_owners.get(&cut.cut_id).map(String::as_str) else {
                return Ok(R::IncompletePrefix);
            };
            if previous_owner != Some(owner) {
                if !finished.insert(owner) {
                    return Ok(R::IncompletePrefix);
                }
                let parent_manifest = match cut.parent_cut_id.as_deref() {
                    Some(parent_id) => {
                        let Some(parent) = self.branches.get_cut(parent_id)? else {
                            return Ok(R::SourceMismatch);
                        };
                        Some(parent.manifest_hash)
                    }
                    None => None,
                };
                let Some(declared) = declarations.get(owner) else {
                    return Ok(R::IncompletePrefix);
                };
                let read = native_read_basis_digest(
                    cut.parent_cut_id.as_deref(),
                    parent_manifest.as_deref(),
                );
                let deps = native_dependency_basis_digest(&ordered);
                if declared.read_basis_digest != read || declared.dependency_basis_digest != deps {
                    return Ok(R::UnprovenBasis {
                        unit_id: owner.into(),
                    });
                }
                basis_evidence.push((owner.to_owned(), read, deps));
                let Some(unit) = revision.units.iter().find(|unit| unit.unit_id == owner) else {
                    return Ok(R::IncompletePrefix);
                };
                ordered.push((owner.to_owned(), unit.basis_digest.clone()));
                previous_owner = Some(owner);
            }
            last_cut_by_owner.insert(owner.to_owned(), cut.cut_id.clone());
        }
        if ordered
            .iter()
            .map(|(id, _)| id.as_str())
            .collect::<Vec<_>>()
            != revision
                .units
                .iter()
                .map(|unit| unit.unit_id.as_str())
                .collect::<Vec<_>>()
            || declarations.iter().any(|(id, declaration)| {
                last_cut_by_owner.get(id) != Some(&declaration.source_cut_id)
            })
        {
            return Ok(R::IncompletePrefix);
        }
        // Reproduce the exact selected source manifest from the trunk base.
        // This proves the before content each dependent actually saw, even
        // when a predecessor's write is later undone by another unit. The
        // last substantive owner of a surviving path effect is Applied;
        // earlier overwritten owners are Neutralized. A unit with only
        // no-op atoms is Equivalent.
        let base_manifest = self.load_manifest(trunk.head_manifest_hash.as_deref())?;
        let selected_manifest = self.load_manifest(Some(&selected_cut.manifest_hash))?;
        let mut composed = base_manifest.clone();
        let mut substantive_units = BTreeSet::new();
        let mut last_substantive_owner = BTreeMap::new();
        for atom in &atoms {
            if composed.get(&atom.path).map(String::as_str) != atom.before.as_deref() {
                return Ok(R::SourceMismatch);
            }
            let key = (atom.cut_id.clone(), atom.path.clone());
            let Some(owner) = owners.get(&key) else {
                return Ok(R::IncompletePrefix);
            };
            if atom.before != atom.after {
                substantive_units.insert(owner.clone());
                last_substantive_owner.insert(atom.path.clone(), owner.clone());
            }
            match &atom.after {
                Some(after) => {
                    composed.insert(atom.path.clone(), after.clone());
                }
                None => {
                    composed.remove(&atom.path);
                }
            }
        }
        if composed != selected_manifest {
            return Ok(R::SourceMismatch);
        }
        let applied_units: BTreeSet<String> = last_substantive_owner
            .into_iter()
            .filter(|(path, _)| base_manifest.get(path) != selected_manifest.get(path))
            .map(|(_, owner)| owner)
            .collect();
        let outcomes: Vec<FlowingSelectedUnit> = revision
            .units
            .iter()
            .map(|unit| FlowingSelectedUnit {
                unit_id: unit.unit_id.clone(),
                basis_digest: unit.basis_digest.clone(),
                principal: unit.principal.clone(),
                intent: unit.intent.clone(),
                outcome: if applied_units.contains(&unit.unit_id) {
                    FlowingUnitOutcome::Applied
                } else if substantive_units.contains(&unit.unit_id) {
                    FlowingUnitOutcome::Neutralized
                } else {
                    FlowingUnitOutcome::Equivalent
                },
            })
            .collect();
        let Some(raw) = self.load_manifest_opt_raw(&selected_cut.manifest_hash)? else {
            return Ok(R::SourceMismatch);
        };
        let mut retained_ids = match raw {
            RawManifest::Tree(_) => {
                crate::manifest_tree::reachable_ids(&self.content, &selected_cut.manifest_hash)?
            }
            RawManifest::Flat(manifest) => manifest.into_values().collect(),
        };
        retained_ids.insert(selected_cut.manifest_hash.clone());
        for id in retained_ids {
            if !self.content.cached_read_available(&id)? {
                return Ok(R::MissingContent { content_id: id });
            }
        }
        // Every source write is owned by a selected unit, and the destination
        // is exactly the source's branch point. The selected source manifest
        // is therefore the complete proposed trunk result, including undo.
        let no_op = if let Some(base) = trunk.head_manifest_hash.as_deref() {
            base == selected_cut.manifest_hash
        } else {
            self.load_manifest(Some(&selected_cut.manifest_hash))?
                .is_empty()
        };
        if no_op {
            if expected_trunk_cut_id != Some(candidate_cut_id) {
                return Ok(R::CandidateMismatch);
            }
        } else {
            let origin = format!("transport:{}", revision.source_branch_id);
            let matches = |cut: &CutRow| {
                cut.branch_id == crate::branches::MAINLINE_BRANCH_ID
                    && cut.parent_cut_id.as_deref() == expected_trunk_cut_id
                    && cut.manifest_hash == selected_cut.manifest_hash
                    && cut.change_id == candidate_cut_id
                    && cut.origin.as_deref() == Some(origin.as_str())
                    && cut.actor.as_deref() == Some(actor)
                    && cut.intent.as_deref() == Some(revision.contribution_id.as_str())
                    && cut.recorded_at == recorded_at
            };
            if let Some(existing) = self.branches.get_cut(candidate_cut_id)? {
                if !matches(&existing) {
                    return Ok(R::CandidateMismatch);
                }
            } else {
                self.branches.record_cut(CutRecord {
                    cut_id: candidate_cut_id,
                    change_id: candidate_cut_id,
                    branch_id: crate::branches::MAINLINE_BRANCH_ID,
                    manifest_hash: &selected_cut.manifest_hash,
                    parent_cut_id: expected_trunk_cut_id,
                    origin: Some(&origin),
                    actor: Some(actor),
                    intent: Some(&revision.contribution_id),
                    recorded_at,
                })?;
            }
            if !self
                .branches
                .get_cut(candidate_cut_id)?
                .as_ref()
                .is_some_and(matches)
            {
                return Ok(R::CandidateMismatch);
            }
        }
        let witness = serde_json::to_vec(&(
            "native-closed-prefix-v1",
            revision,
            expected_trunk_cut_id,
            &atoms,
            &basis_evidence,
            &outcomes,
            candidate_cut_id,
            &selected_cut.manifest_hash,
        ))?;
        let source_atoms_digest = format!("sha256:{}", crate::chunking::content_hash_hex(&witness));
        let candidate_witness = FlowingCandidateWitness {
            contribution_id: revision.contribution_id.clone(),
            revision_sequence: revision.sequence,
            source_branch_id: revision.source_branch_id.clone(),
            source_incarnation_id: revision.source_incarnation_id.clone(),
            source_cut_id: revision.source_cut_id.clone(),
            source_manifest_hash: revision.source_manifest_hash.clone(),
            expected_trunk_cut_id: expected_trunk_cut_id.map(str::to_owned),
            candidate_cut_id: candidate_cut_id.into(),
            candidate_manifest_hash: selected_cut.manifest_hash.clone(),
            source_atoms_digest: source_atoms_digest.clone(),
            units: outcomes.clone(),
        };
        let candidate_witness_digest =
            self.branches.record_candidate_witness(&candidate_witness)?;
        Ok(R::Prepared(NativeCandidate {
            contribution_id: revision.contribution_id.clone(),
            revision_sequence: revision.sequence,
            source_cut_id: revision.source_cut_id.clone(),
            expected_trunk_cut_id: expected_trunk_cut_id.map(str::to_owned),
            candidate_cut_id: candidate_cut_id.into(),
            candidate_manifest_hash: selected_cut.manifest_hash,
            source_atoms_digest,
            candidate_witness_digest,
            units: outcomes,
        }))
    }

    /// Prepare a direct twig's prospective trunk cut from its bound source
    /// atoms. This is content preparation, not admission: the caller still
    /// owes candidate retention, a gate certificate, norm exclusion and the
    /// ref-owned receipt. For an equivalent result on an existing trunk cut,
    /// `target_cut_id` must be that cut's id; no new cut is minted. An empty
    /// trunk has no cut against which to record a metadata-only result yet.
    pub fn prepare_direct_trunk_candidate(
        &mut self,
        unit_id: &str,
        target_cut_id: &str,
        actor: &str,
        recorded_at: &str,
    ) -> StoreResult<FlowingTargetEffectsOutcome> {
        if target_cut_id.trim().is_empty() || actor.trim().is_empty() {
            return Err(StoreError::Conflict(
                "trunk candidate cut id and actor must be nonempty".to_owned(),
            ));
        }
        let Some(unit) = self.branches.contribution_declaration(unit_id)? else {
            return Ok(FlowingTargetEffectsOutcome::UnitMissing);
        };
        let Some(basis) = self.branches.contribution_basis(unit_id)? else {
            return Ok(FlowingTargetEffectsOutcome::BasisMissing);
        };
        let Some(source) = self.branches.get_branch(&unit.source_branch_id)? else {
            return Ok(FlowingTargetEffectsOutcome::TargetNotParent);
        };
        if source.parent_branch_id.as_deref() != Some(crate::branches::MAINLINE_BRANCH_ID)
            || source.name.is_some()
        {
            return Ok(FlowingTargetEffectsOutcome::TargetNotParent);
        }
        let Some(trunk) = self
            .branches
            .get_branch(crate::branches::MAINLINE_BRANCH_ID)?
        else {
            return Ok(FlowingTargetEffectsOutcome::TargetMissing);
        };
        if trunk.status != BranchStatus::Active {
            return Ok(FlowingTargetEffectsOutcome::TargetMissing);
        }
        if let Some(head_id) = trunk.head_cut_id.as_deref() {
            let Some(head) = self.branches.get_cut(head_id)? else {
                return Ok(FlowingTargetEffectsOutcome::TargetCutMissing);
            };
            if head.branch_id != trunk.branch_id
                || trunk.head_manifest_hash.as_deref() != Some(head.manifest_hash.as_str())
                || self.load_manifest_opt_raw(&head.manifest_hash)?.is_none()
            {
                return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
            }
        } else if trunk.head_manifest_hash.is_some() {
            return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
        }
        let selected = match self.net_source_paths(&basis)? {
            Ok(selected) => selected,
            Err(refusal) => return Ok(refusal),
        };
        let mut changes = BTreeMap::new();
        for (path, (before, after)) in &selected {
            let current = self.manifest_entry(trunk.head_manifest_hash.as_deref(), path)?;
            if current.as_deref() != *before && current.as_deref() != *after {
                return Ok(FlowingTargetEffectsOutcome::BeforeMismatch {
                    path: (*path).to_owned(),
                });
            }
            if current.as_deref() != *after {
                changes.insert((*path).to_owned(), after.map(str::to_owned));
            }
        }
        if changes.is_empty() {
            let Some(head_id) = trunk.head_cut_id.as_deref() else {
                return Ok(FlowingTargetEffectsOutcome::InitialNoopNeedsGenesis);
            };
            let Some(head_manifest_hash) = trunk.head_manifest_hash.clone() else {
                return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
            };
            if target_cut_id != head_id {
                return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
            }
            let effects = selected
                .into_iter()
                .map(|(path, (before, after))| FlowingTargetEffect {
                    path: path.to_owned(),
                    before: after.map(str::to_owned),
                    after: after.map(str::to_owned),
                    disposition: if before == after {
                        FlowingEffectDisposition::Neutralized
                    } else {
                        FlowingEffectDisposition::Equivalent
                    },
                })
                .collect();
            return Ok(FlowingTargetEffectsOutcome::Verified(
                FlowingTargetEffects {
                    unit_id: unit_id.to_owned(),
                    basis_digest: basis.basis_digest,
                    target_branch_id: trunk.branch_id,
                    target_before_cut_id: Some(head_id.to_owned()),
                    target_after_cut_id: head_id.to_owned(),
                    target_after_manifest_hash: head_manifest_hash,
                    effects,
                },
            ));
        }
        let manifest_hash = self.advance_manifest(trunk.head_manifest_hash.as_deref(), &changes)?;
        let mut change_ids = basis.atoms.iter().map(|atom| atom.change_id.as_str());
        let first_change_id = change_ids.next().unwrap_or(target_cut_id);
        let change_id = if change_ids.all(|id| id == first_change_id) {
            first_change_id
        } else {
            target_cut_id
        };
        let origin = format!("transport:{}", unit.source_branch_id);
        let matches_candidate = |cut: &CutRow| {
            cut.branch_id == trunk.branch_id
                && cut.manifest_hash == manifest_hash
                && cut.parent_cut_id == trunk.head_cut_id
                && cut.change_id == change_id
                && cut.origin.as_deref() == Some(origin.as_str())
                && cut.actor.as_deref() == Some(actor)
                && cut.intent.as_deref() == Some(unit.intent.as_str())
                && cut.recorded_at == recorded_at
        };
        if let Some(existing) = self.branches.get_cut(target_cut_id)? {
            if !matches_candidate(&existing) {
                return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
            }
        } else {
            self.branches.record_cut(CutRecord {
                cut_id: target_cut_id,
                change_id,
                branch_id: &trunk.branch_id,
                manifest_hash: &manifest_hash,
                parent_cut_id: trunk.head_cut_id.as_deref(),
                origin: Some(&origin),
                actor: Some(actor),
                intent: Some(&unit.intent),
                recorded_at,
            })?;
        }
        if !self
            .branches
            .get_cut(target_cut_id)?
            .as_ref()
            .is_some_and(matches_candidate)
        {
            return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
        }
        self.verify_trunk_target_effects(unit_id, target_cut_id)
    }

    /// Build a target cut from a bound unit and the current parent-branch
    /// manifest, then re-read it through the exact target-effect verifier.
    /// This only prepares an immutable candidate. The later handoff still
    /// performs target-head CAS and receipt insertion in one transaction; a
    /// stale candidate remains an orphan cut and never transfers ownership.
    pub fn prepare_private_handoff_target(
        &mut self,
        unit_id: &str,
        target_cut_id: &str,
        actor: &str,
        recorded_at: &str,
    ) -> StoreResult<FlowingTargetEffectsOutcome> {
        if target_cut_id.trim().is_empty() || actor.trim().is_empty() {
            return Err(StoreError::Conflict(
                "handoff target cut id and actor must be nonempty".to_owned(),
            ));
        }
        let Some(unit) = self.branches.contribution_declaration(unit_id)? else {
            return Ok(FlowingTargetEffectsOutcome::UnitMissing);
        };
        let Some(basis) = self.branches.contribution_basis(unit_id)? else {
            return Ok(FlowingTargetEffectsOutcome::BasisMissing);
        };
        let Some(source) = self.branches.get_branch(&unit.source_branch_id)? else {
            return Ok(FlowingTargetEffectsOutcome::TargetNotParent);
        };
        let Some(target_branch_id) = source.parent_branch_id.as_deref() else {
            return Ok(FlowingTargetEffectsOutcome::TargetNotParent);
        };
        if target_branch_id == crate::branches::MAINLINE_BRANCH_ID {
            return Ok(FlowingTargetEffectsOutcome::TargetNotParent);
        }
        let Some(target) = self.branches.get_branch(target_branch_id)? else {
            return Ok(FlowingTargetEffectsOutcome::TargetMissing);
        };
        if target.status != BranchStatus::Active {
            return Ok(FlowingTargetEffectsOutcome::TargetMissing);
        }
        let selected = match self.net_source_paths(&basis)? {
            Ok(selected) => selected,
            Err(refusal) => return Ok(refusal),
        };
        let mut changes = BTreeMap::new();
        for (path, (before, after)) in selected {
            let current = self.manifest_entry(target.head_manifest_hash.as_deref(), path)?;
            if current.as_deref() != before && current.as_deref() != after {
                return Ok(FlowingTargetEffectsOutcome::BeforeMismatch {
                    path: path.to_owned(),
                });
            }
            if current.as_deref() != after {
                changes.insert(path.to_owned(), after.map(str::to_owned));
            }
        }
        let manifest_hash = if changes.is_empty() {
            match target.head_manifest_hash.clone() {
                Some(hash) => hash,
                None => self.store_manifest(&BTreeMap::new())?,
            }
        } else {
            self.advance_manifest(target.head_manifest_hash.as_deref(), &changes)?
        };
        let mut change_ids = basis.atoms.iter().map(|atom| atom.change_id.as_str());
        let first_change_id = change_ids.next().unwrap_or(target_cut_id);
        let change_id = if change_ids.all(|id| id == first_change_id) {
            first_change_id
        } else {
            target_cut_id
        };
        let origin = format!("transport:{}", unit.source_branch_id);
        let matches_candidate = |cut: &CutRow| {
            cut.branch_id == target.branch_id
                && cut.manifest_hash == manifest_hash
                && cut.parent_cut_id == target.head_cut_id
                && cut.change_id == change_id
                && cut.origin.as_deref() == Some(origin.as_str())
                && cut.actor.as_deref() == Some(actor)
                && cut.intent.as_deref() == Some(unit.intent.as_str())
                && cut.recorded_at == recorded_at
        };
        if let Some(existing) = self.branches.get_cut(target_cut_id)? {
            if !matches_candidate(&existing) {
                return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
            }
        } else {
            self.branches.record_cut(CutRecord {
                cut_id: target_cut_id,
                change_id,
                branch_id: &target.branch_id,
                manifest_hash: &manifest_hash,
                parent_cut_id: target.head_cut_id.as_deref(),
                origin: Some(&origin),
                actor: Some(actor),
                intent: Some(&unit.intent),
                recorded_at,
            })?;
        }
        // Another writer can win between the preceding read and record, so
        // re-read before giving the caller a witness for this cut identity.
        if !self
            .branches
            .get_cut(target_cut_id)?
            .as_ref()
            .is_some_and(matches_candidate)
        {
            return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
        }
        self.verify_private_target_effects(unit_id, target_cut_id)
    }

    /// Publish one content-verified unit onto its parent branch. Retain the
    /// candidate's entire manifest closure while the branch authority moves
    /// the target ref and records the holder receipt in one transaction.
    /// A retry of an already recorded operation reads its receipt without
    /// requiring old content still to be cached.
    pub fn handoff_private_selection(
        &mut self,
        op_id: &str,
        witness: &FlowingTargetEffects,
        actor: &str,
        recorded_at: &str,
    ) -> StoreResult<HandoffContributionOutcome> {
        let request = HandoffContribution::new(op_id, witness, actor, recorded_at);
        if self.branches.handoff_receipt(op_id)?.is_some() {
            return self.branches.handoff_contribution(request);
        }
        let Some(unit) = self.branches.contribution_declaration(witness.unit_id())? else {
            return Ok(HandoffContributionOutcome::UnitMissing);
        };
        let Some(basis) = self.branches.contribution_basis(witness.unit_id())? else {
            return Ok(HandoffContributionOutcome::BasisMissing);
        };
        let root = witness.target_after_manifest_hash();
        let Some(raw) = self.load_manifest_opt_raw(root)? else {
            return Ok(HandoffContributionOutcome::TargetManifestMissing);
        };
        let mut ids = match raw {
            RawManifest::Tree(_) => crate::manifest_tree::reachable_ids(&self.content, root)?,
            RawManifest::Flat(manifest) => manifest.into_values().collect(),
        };
        ids.insert(root.to_owned());
        ids.insert(unit.source_manifest_hash);
        for atom in basis.atoms {
            ids.extend(atom.before);
            ids.extend(atom.after);
        }
        let ids: Vec<String> = ids.into_iter().collect();
        let branches = &mut self.branches;
        self.content
            .publish_retained(&ids, || branches.handoff_contribution(request))
    }

    /// Check that the target cut contains exactly one bound unit's net path
    /// effects. Consecutive source writes to one path compose in ancestry
    /// order; a selection that skips an intermediate write refuses. Mixed
    /// target output stays unsupported until its constituent lineage is
    /// recorded.
    /// No caller may treat `Verified` as a transfer or admission receipt.
    pub fn verify_private_target_effects(
        &self,
        unit_id: &str,
        target_cut_id: &str,
    ) -> StoreResult<FlowingTargetEffectsOutcome> {
        self.verify_target_effects(unit_id, target_cut_id, false)
    }

    /// Compare one recorded target cut with an ordered batch of bound source
    /// units. Consecutive writes to the same path compose, including an undo
    /// that leaves the target's net content unchanged. Every changed target
    /// path must be explained by the batch. This neither records derivation
    /// lineage, source ordering or dependency compatibility, nor authorizes
    /// a head move or holder transfer.
    pub fn verify_private_batch_target_effects(
        &self,
        unit_ids: &[&str],
        target_cut_id: &str,
    ) -> StoreResult<FlowingBatchTargetEffectsOutcome> {
        use FlowingBatchTargetEffectsOutcome as R;
        use FlowingTargetEffectsOutcome as E;
        if unit_ids.is_empty() {
            return Ok(R::EmptySelection);
        }
        let mut seen_units = BTreeSet::new();
        for unit_id in unit_ids {
            if !seen_units.insert(*unit_id) {
                return Ok(R::DuplicateUnit {
                    unit_id: (*unit_id).to_owned(),
                });
            }
        }
        let Some(target_cut) = self.branches.get_cut(target_cut_id)? else {
            // MUTATION-SUCCESS-EXPR: Ok(R::Verified(FlowingBatchTargetEffects { target_branch_id: String::new(), target_before_cut_id: None, target_after_cut_id: target_cut_id.to_owned(), target_after_manifest_hash: String::new(), units: Vec::new() }))
            return Ok(R::Refused(E::TargetCutMissing));
        };
        let target_branch_id = target_cut.branch_id.clone();
        let before_manifest_hash = if let Some(parent_id) = target_cut.parent_cut_id.as_deref() {
            let Some(parent) = self.branches.get_cut(parent_id)? else {
                // MUTATION-SUCCESS-EXPR: Ok(R::Verified(FlowingBatchTargetEffects { target_branch_id: String::new(), target_before_cut_id: None, target_after_cut_id: target_cut_id.to_owned(), target_after_manifest_hash: String::new(), units: Vec::new() }))
                return Ok(R::Refused(E::TargetCutMismatch));
            };
            Some(parent.manifest_hash)
        } else {
            None
        };
        let Some(after_root) = self.load_manifest_opt_raw(&target_cut.manifest_hash)? else {
            let missing_cut_id = target_cut.cut_id;
            let refusal = E::MissingManifest {
                cut_id: missing_cut_id,
            };
            // MUTATION-SUCCESS-EXPR: Ok(R::Verified(FlowingBatchTargetEffects { target_branch_id: String::new(), target_before_cut_id: None, target_after_cut_id: target_cut_id.to_owned(), target_after_manifest_hash: String::new(), units: Vec::new() }))
            return Ok(R::Refused(refusal));
        };
        // The one-unit verifier owns target ancestry and branch-point
        // validation. A mixed cut may differ from its first unit's final
        // effect or contain paths owned by later units; those are the two
        // content refusals this batch comparison can resolve. Every other
        // refusal, including an invalid target cut, remains final.
        let preflight = self.verify_private_target_effects(unit_ids[0], target_cut_id)?;
        if !matches!(
            preflight,
            E::Verified(_) | E::OmittedEffect { .. } | E::UnexpectedEffect { .. }
        ) {
            return Ok(R::Refused(preflight));
        }

        let mut simulated: BTreeMap<String, Option<String>> = BTreeMap::new();
        let mut units = Vec::with_capacity(unit_ids.len());
        for unit_id in unit_ids {
            let Some(unit) = self.branches.contribution_declaration(unit_id)? else {
                // MUTATION-SUCCESS-EXPR: Ok(R::Verified(FlowingBatchTargetEffects { target_branch_id: String::new(), target_before_cut_id: None, target_after_cut_id: target_cut_id.to_owned(), target_after_manifest_hash: String::new(), units: Vec::new() }))
                return Ok(R::Refused(E::UnitMissing));
            };
            let Some(basis) = self.branches.contribution_basis(unit_id)? else {
                // MUTATION-SUCCESS-EXPR: Ok(R::Verified(FlowingBatchTargetEffects { target_branch_id: String::new(), target_before_cut_id: None, target_after_cut_id: target_cut_id.to_owned(), target_after_manifest_hash: String::new(), units: Vec::new() }))
                return Ok(R::Refused(E::BasisMissing));
            };
            let Some(source) = self.branches.get_branch(&unit.source_branch_id)? else {
                // MUTATION-SUCCESS-EXPR: Ok(R::Verified(FlowingBatchTargetEffects { target_branch_id: String::new(), target_before_cut_id: None, target_after_cut_id: target_cut_id.to_owned(), target_after_manifest_hash: String::new(), units: Vec::new() }))
                return Ok(R::Refused(E::TargetNotParent));
            };
            if source.parent_branch_id.as_deref() != Some(target_branch_id.as_str()) {
                return Ok(R::Refused(E::TargetNotParent));
            }
            let selected = match self.net_source_paths(&basis)? {
                Ok(selected) => selected,
                Err(refusal) => return Ok(R::Refused(refusal)),
            };
            let mut effects = Vec::new();
            for (path, (expected_before, expected_after)) in selected {
                let current = if let Some(current) = simulated.get(path) {
                    current.clone()
                } else {
                    self.manifest_entry(before_manifest_hash.as_deref(), path)?
                };
                if current.as_deref() != expected_before && current.as_deref() != expected_after {
                    return Ok(R::Refused(E::BeforeMismatch {
                        path: path.to_owned(),
                    }));
                }
                let disposition = if expected_before == expected_after {
                    FlowingEffectDisposition::Neutralized
                } else if current.as_deref() == expected_after {
                    FlowingEffectDisposition::Equivalent
                } else {
                    FlowingEffectDisposition::Applied
                };
                effects.push(FlowingTargetEffect {
                    path: path.to_owned(),
                    before: current,
                    after: expected_after.map(str::to_owned),
                    disposition,
                });
                simulated.insert(path.to_owned(), expected_after.map(str::to_owned));
            }
            units.push(FlowingBatchUnitEffect {
                unit_id: unit.unit_id,
                source_branch_id: unit.source_branch_id,
                source_cut_id: unit.source_cut_id,
                basis_digest: basis.basis_digest,
                effects,
            });
        }
        for (path, expected) in &simulated {
            if self.manifest_entry(Some(&target_cut.manifest_hash), path)? != *expected {
                return Ok(R::Refused(E::OmittedEffect { path: path.clone() }));
            }
        }
        let before_is_tree = match before_manifest_hash.as_deref() {
            Some(hash) => matches!(
                self.load_manifest_opt_raw(hash)?,
                Some(RawManifest::Tree(_))
            ),
            None => false,
        };
        let changed_paths: BTreeSet<String> = if let Some(before_root) = before_manifest_hash
            .as_deref()
            .filter(|_| before_is_tree && matches!(after_root, RawManifest::Tree(_)))
        {
            crate::manifest_tree::diff(&self.content, before_root, &target_cut.manifest_hash)?
                .into_iter()
                .map(|change| change.path)
                .collect()
        } else {
            let before = self.load_manifest(before_manifest_hash.as_deref())?;
            let after = self.load_manifest(Some(&target_cut.manifest_hash))?;
            before
                .keys()
                .chain(after.keys())
                .filter(|path| before.get(*path) != after.get(*path))
                .cloned()
                .collect()
        };
        for path in changed_paths {
            if !simulated.contains_key(&path) {
                return Ok(R::Refused(E::UnexpectedEffect { path }));
            }
        }
        Ok(R::Verified(FlowingBatchTargetEffects {
            target_branch_id,
            target_before_cut_id: target_cut.parent_cut_id,
            target_after_cut_id: target_cut.cut_id,
            target_after_manifest_hash: target_cut.manifest_hash,
            units,
        }))
    }

    /// Check one bound unit against a recorded trunk candidate. This is a
    /// content proof only: admission still needs the gate certificate, source
    /// fence and atomic ref/receipt transaction. A branch handoff cannot use
    /// this method to move the trunk ref.
    pub fn verify_trunk_target_effects(
        &self,
        unit_id: &str,
        target_cut_id: &str,
    ) -> StoreResult<FlowingTargetEffectsOutcome> {
        self.verify_target_effects(unit_id, target_cut_id, true)
    }

    fn verify_target_effects(
        &self,
        unit_id: &str,
        target_cut_id: &str,
        trunk: bool,
    ) -> StoreResult<FlowingTargetEffectsOutcome> {
        let Some(unit) = self.branches.contribution_declaration(unit_id)? else {
            return Ok(FlowingTargetEffectsOutcome::UnitMissing);
        };
        let Some(basis) = self.branches.contribution_basis(unit_id)? else {
            return Ok(FlowingTargetEffectsOutcome::BasisMissing);
        };
        let Some(source) = self.branches.get_branch(&unit.source_branch_id)? else {
            return Ok(FlowingTargetEffectsOutcome::TargetNotParent);
        };
        let Some(target_branch_id) = source.parent_branch_id.as_deref() else {
            return Ok(FlowingTargetEffectsOutcome::TargetNotParent);
        };
        if (target_branch_id == crate::branches::MAINLINE_BRANCH_ID) != trunk {
            return Ok(FlowingTargetEffectsOutcome::TargetNotParent);
        }
        let Some(target_branch) = self.branches.get_branch(target_branch_id)? else {
            return Ok(FlowingTargetEffectsOutcome::TargetMissing);
        };
        let Some(target_cut) = self.branches.get_cut(target_cut_id)? else {
            return Ok(FlowingTargetEffectsOutcome::TargetCutMissing);
        };
        if target_cut.branch_id != target_branch_id {
            return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
        }
        let before_manifest_hash = if let Some(parent_id) = target_cut.parent_cut_id.as_deref() {
            let Some(parent) = self.branches.get_cut(parent_id)? else {
                return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
            };
            if parent.branch_id != target_branch_id
                && (target_branch.branch_point_cut_id.as_deref() != Some(parent_id)
                    || target_branch.branch_point_manifest_hash.as_deref()
                        != Some(parent.manifest_hash.as_str()))
            {
                return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
            }
            if self.load_manifest_opt_raw(&parent.manifest_hash)?.is_none() {
                return Ok(FlowingTargetEffectsOutcome::MissingManifest {
                    cut_id: parent.cut_id,
                });
            }
            Some(parent.manifest_hash)
        } else if target_branch.branch_point_cut_id.is_none()
            && target_branch.branch_point_manifest_hash.is_none()
        {
            None
        } else {
            return Ok(FlowingTargetEffectsOutcome::TargetCutMismatch);
        };
        let Some(after_root) = self.load_manifest_opt_raw(&target_cut.manifest_hash)? else {
            return Ok(FlowingTargetEffectsOutcome::MissingManifest {
                cut_id: target_cut.cut_id,
            });
        };
        let selected = match self.net_source_paths(&basis)? {
            Ok(selected) => selected,
            Err(refusal) => return Ok(refusal),
        };
        let mut effects = Vec::new();
        for (path, (expected_before, expected_after)) in &selected {
            let old = self.manifest_entry(before_manifest_hash.as_deref(), path)?;
            let new = self.manifest_entry(Some(&target_cut.manifest_hash), path)?;
            if old.as_deref() != *expected_before && old.as_deref() != *expected_after {
                return Ok(FlowingTargetEffectsOutcome::BeforeMismatch {
                    path: (*path).to_owned(),
                });
            }
            if new.as_deref() != *expected_after {
                return Ok(FlowingTargetEffectsOutcome::OmittedEffect {
                    path: (*path).to_owned(),
                });
            }
            effects.push(FlowingTargetEffect {
                path: (*path).to_owned(),
                before: old.clone(),
                after: new,
                disposition: if expected_before == expected_after {
                    FlowingEffectDisposition::Neutralized
                } else if old.as_deref() == *expected_after {
                    FlowingEffectDisposition::Equivalent
                } else {
                    FlowingEffectDisposition::Applied
                },
            });
        }
        // Tree-to-tree comparisons skip shared subtrees. Flat legacy roots
        // have no structure to skip, so only those cuts pay a full-map scan.
        let before_is_tree = match before_manifest_hash.as_deref() {
            Some(hash) => matches!(
                self.load_manifest_opt_raw(hash)?,
                Some(RawManifest::Tree(_))
            ),
            None => false,
        };
        let changed_paths: BTreeSet<String> = if let Some(before_root) = before_manifest_hash
            .as_deref()
            .filter(|_| before_is_tree && matches!(after_root, RawManifest::Tree(_)))
        {
            crate::manifest_tree::diff(&self.content, before_root, &target_cut.manifest_hash)?
                .into_iter()
                .map(|change| change.path)
                .collect()
        } else {
            let before = self.load_manifest(before_manifest_hash.as_deref())?;
            let after = self.load_manifest(Some(&target_cut.manifest_hash))?;
            before
                .keys()
                .chain(after.keys())
                .filter(|path| before.get(*path) != after.get(*path))
                .cloned()
                .collect()
        };
        for path in changed_paths {
            if !selected.contains_key(path.as_str()) {
                return Ok(FlowingTargetEffectsOutcome::UnexpectedEffect { path: path.clone() });
            }
        }
        Ok(FlowingTargetEffectsOutcome::Verified(
            FlowingTargetEffects {
                unit_id: unit_id.to_owned(),
                basis_digest: basis.basis_digest,
                target_branch_id: target_branch_id.to_owned(),
                target_before_cut_id: target_cut.parent_cut_id,
                target_after_cut_id: target_cut.cut_id,
                target_after_manifest_hash: target_cut.manifest_hash,
                effects,
            },
        ))
    }

    /// Bind an already-derived exact source selection to one declared unit.
    /// The content authority verifies and retains every referenced payload
    /// through the branch-store transaction; a missing or erased source
    /// cannot acquire a durable basis. The branch store rechecks the pin and
    /// cut and enforces unique ownership for every source atom.
    pub fn bind_private_selection(
        &mut self,
        unit_id: &str,
        selection: &FlowingSelection,
        bound_at: &str,
    ) -> StoreResult<BindContributionBasisOutcome> {
        let mut ids = BTreeSet::new();
        ids.insert(selection.source_manifest_hash.clone());
        for atom in &selection.changes {
            ids.extend(atom.before.iter().cloned());
            ids.extend(atom.after.iter().cloned());
        }
        let ids: Vec<String> = ids.into_iter().collect();
        let branches = &mut self.branches;
        self.content.publish_retained(&ids, || {
            branches
                .bind_contribution_basis(BindContributionBasis::new(unit_id, selection, bound_at))
        })
    }

    /// Select a unit's constituent per-path writes from the pinned cut's
    /// recorded ancestry. Missing content or an unmodeled rewrite refuses;
    /// `change_units` archaeology may skip unreadable cuts and therefore is
    /// not a safe declaration basis by itself.
    pub fn select_private_changes(
        &self,
        pin_id: &str,
        expr: &SelExpr,
    ) -> StoreResult<FlowingSelectionOutcome> {
        if requires_unproved_semantics(expr) {
            return Ok(FlowingSelectionOutcome::UnsupportedSelection);
        }
        let Some(pin) = self.branches.private_cut_pin(pin_id)? else {
            return Ok(FlowingSelectionOutcome::PinMissing);
        };
        if pin.released_at.is_some() {
            return Ok(FlowingSelectionOutcome::PinReleased);
        }
        let Some(mut cut) = self.branches.get_cut(&pin.cut_id)? else {
            return Ok(FlowingSelectionOutcome::CutMissing);
        };
        if cut.branch_id != pin.twig_branch_id || cut.manifest_hash != pin.manifest_hash {
            return Ok(FlowingSelectionOutcome::CutMismatch);
        }
        let Some(branch) = self.branches.get_branch(&pin.twig_branch_id)? else {
            return Ok(FlowingSelectionOutcome::UnsupportedLineage { cut_id: pin.cut_id });
        };

        let mut lineage: Vec<CutRow> = Vec::new();
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(cut.cut_id.clone()) {
                return Ok(FlowingSelectionOutcome::CyclicLineage { cut_id: cut.cut_id });
            }
            if self.load_manifest_opt_raw(&cut.manifest_hash)?.is_none() {
                return Ok(FlowingSelectionOutcome::MissingManifest { cut_id: cut.cut_id });
            }
            // A rewrite or mixed transport needs an explicit source-identity
            // derivation edge. Its output cut/change id is not that edge.
            if !cut
                .origin
                .as_deref()
                .is_some_and(|origin| origin.starts_with("write:"))
            {
                return Ok(FlowingSelectionOutcome::UnsupportedLineage { cut_id: cut.cut_id });
            }
            let parent_id = cut.parent_cut_id.clone();
            lineage.push(cut);
            let Some(parent_id) = parent_id else {
                // A pre-lineage cut cannot be diffed against an invented
                // empty tree if this twig inherited a nonempty branch point.
                // Its original base may have moved during a later rebase;
                // refusing the ambiguous case preserves source identity.
                if branch.branch_point_manifest_hash.is_some() {
                    return Ok(FlowingSelectionOutcome::UnsupportedLineage {
                        cut_id: lineage.last().expect("just pushed").cut_id.clone(),
                    });
                }
                break;
            };
            let Some(parent) = self.branches.get_cut(&parent_id)? else {
                return Ok(FlowingSelectionOutcome::MissingParent { cut_id: parent_id });
            };
            if self.load_manifest_opt_raw(&parent.manifest_hash)?.is_none() {
                return Ok(FlowingSelectionOutcome::MissingManifest {
                    cut_id: parent.cut_id,
                });
            }
            if parent.branch_id != pin.twig_branch_id {
                break;
            }
            cut = parent;
        }
        lineage.reverse();
        let mut universe = Vec::new();
        for cut in &lineage {
            self.push_units_for_cut(cut, &mut universe)?;
        }
        let selected = selection::eval(expr, &universe);
        if selected.is_empty() {
            return Ok(FlowingSelectionOutcome::NothingSelected);
        }
        let changes: Vec<FlowingSourceAtom> = selected
            .into_iter()
            .map(|index| {
                let unit = &universe[index];
                FlowingSourceAtom {
                    cut_id: unit.cut_id.clone(),
                    change_id: unit.change_id.clone(),
                    path: unit.path.clone(),
                    before: unit.before.clone(),
                    after: unit.after.clone(),
                }
            })
            .collect();
        // A manifest name is not a retained payload. Check both sides of
        // every selected effect, including a chunk root's children, before
        // returning a basis that a later reconciliation could consume.
        let content_ids: BTreeSet<&str> = changes
            .iter()
            .flat_map(|change| [change.before.as_deref(), change.after.as_deref()])
            .flatten()
            .collect();
        for content_id in content_ids {
            if !self.content.cached_read_available(content_id)? {
                return Ok(FlowingSelectionOutcome::MissingContent {
                    content_id: content_id.to_owned(),
                });
            }
        }
        let bytes = serde_json::to_vec(&(
            "flowing-source-selection-v1",
            &pin.pin_id,
            &pin.twig_branch_id,
            &pin.cut_id,
            &pin.manifest_hash,
            &changes,
        ))?;
        let digest = format!("sha256:{}", crate::chunking::content_hash_hex(&bytes));
        Ok(FlowingSelectionOutcome::Selected(FlowingSelection {
            pin_id: pin.pin_id,
            source_branch_id: pin.twig_branch_id,
            source_cut_id: pin.cut_id,
            source_manifest_hash: pin.manifest_hash,
            changes,
            digest,
        }))
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::branches::flowing_admission::FlowingCandidateWitness;
    use crate::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
    };
    use crate::branches::flowing_sources::{
        DeclareContribution, DeclareContributionOutcome, PinPrivateCut, PinPrivateCutOutcome,
        ReleasePrivateCut, ReleasePrivateCutOutcome,
    };
    use crate::branches::{BranchStore, CutRecord, MAINLINE_BRANCH_ID};
    use crate::content::ContentStore;
    use crate::source_review::{ReviewError, ReviewStore};
    use crate::source_review_native::{NativeCandidateRequest, NativeUpload};
    use crate::vcs::flowing_gate::{
        NativeGateCommand, NativeGateExecution, NativeGateExecutor, NativeGatePlan,
        NativeGatePlanAuthority, NativeGateRun,
    };
    use crate::vcs::NativeWorkspaceVcs;

    struct FixturePlanAuthority(NativeGatePlan);

    impl NativeGatePlanAuthority for FixturePlanAuthority {
        fn required_plan(
            &mut self,
            _vcs: &NativeWorkspaceVcs,
            _witness: &FlowingCandidateWitness,
            _attempt_op_id: &str,
        ) -> StoreResult<NativeGatePlan> {
            Ok(self.0.clone())
        }
    }

    struct ChangingPlanAuthority {
        initial: NativeGatePlan,
        changed: NativeGatePlan,
        captures: usize,
    }

    impl NativeGatePlanAuthority for ChangingPlanAuthority {
        fn required_plan(
            &mut self,
            _vcs: &NativeWorkspaceVcs,
            _witness: &FlowingCandidateWitness,
            _attempt_op_id: &str,
        ) -> StoreResult<NativeGatePlan> {
            self.captures += 1;
            Ok(if self.captures == 1 {
                self.initial.clone()
            } else {
                self.changed.clone()
            })
        }
    }

    fn run_fixture_gate(
        vcs: &mut NativeWorkspaceVcs,
        witness_digest: &str,
        plan: &NativeGatePlan,
        scratch: &std::path::Path,
        executor: &mut impl NativeGateExecutor,
    ) -> StoreResult<NativeGateRun> {
        vcs.run_native_candidate_gate(
            witness_digest,
            &plan.attempt_op_id,
            scratch,
            &mut FixturePlanAuthority(plan.clone()),
            executor,
        )
    }

    struct LocalProcessFixture;

    impl NativeGateExecutor for LocalProcessFixture {
        fn run(
            &mut self,
            check: &NativeGateCommand,
            cut_root: &std::path::Path,
        ) -> NativeGateExecution {
            match std::process::Command::new(&check.program)
                .args(&check.args)
                .current_dir(cut_root)
                .output()
            {
                Ok(output) => NativeGateExecution {
                    exit_code: output.status.code(),
                    started: true,
                    stdout: output.stdout,
                    stderr: output.stderr,
                    run_error: None,
                },
                Err(error) => NativeGateExecution {
                    exit_code: None,
                    started: false,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    run_error: Some(error.to_string()),
                },
            }
        }
    }

    struct MoveTrunkDuringCheck(rusqlite::Connection);

    impl NativeGateExecutor for MoveTrunkDuringCheck {
        fn run(
            &mut self,
            _check: &NativeGateCommand,
            _cut_root: &std::path::Path,
        ) -> NativeGateExecution {
            self.0
                .execute(
                    "UPDATE branches SET head_cut_id = 'moved' WHERE branch_id = ?1",
                    [MAINLINE_BRANCH_ID],
                )
                .expect("move trunk during gate");
            NativeGateExecution {
                exit_code: Some(0),
                started: true,
                stdout: b"passed\n".to_vec(),
                stderr: Vec::new(),
                run_error: None,
            }
        }
    }

    fn expect_gate_refusal<T: std::fmt::Debug>(result: StoreResult<T>, reason: &str) {
        match result {
            Err(StoreError::Conflict(message)) => {
                assert_eq!(message, format!("candidate gate refuses: {reason}"));
            }
            other => panic!("expected native gate refusal `{reason}`, got {other:?}"),
        }
    }

    fn workspace() -> WorkspaceVcs<BranchStore, ContentStore> {
        WorkspaceVcs::from_parts(
            BranchStore::open_in_memory().expect("branches"),
            ContentStore::open(":memory:").expect("content"),
        )
    }

    fn pin(vcs: &mut WorkspaceVcs<BranchStore, ContentStore>, cut_id: &str, pin_id: &str) {
        let cut = vcs
            .branches
            .get_cut(cut_id)
            .expect("read pinned cut")
            .expect("pinned cut exists");
        assert_eq!(
            vcs.branches
                .pin_private_cut(PinPrivateCut {
                    pin_id,
                    twig_branch_id: "twig",
                    cut_id,
                    manifest_hash: &cut.manifest_hash,
                    principal: "s:author",
                    retained_at: "t4",
                })
                .expect("pin private cut"),
            PinPrivateCutOutcome::Pinned
        );
    }

    fn declare(vcs: &mut WorkspaceVcs<BranchStore, ContentStore>, unit_id: &str, pin_id: &str) {
        assert_eq!(
            vcs.branches
                .declare_contribution(DeclareContribution {
                    unit_id,
                    pin_id,
                    principal: "s:author",
                    intent: "customer change",
                    read_basis_digest: "reads-1",
                    dependency_basis_digest: "deps-1",
                    scope_digest: unit_id,
                    declared_at: "t5",
                })
                .expect("declare contribution"),
            DeclareContributionOutcome::Declared
        );
    }

    fn declare_native(
        vcs: &mut WorkspaceVcs<BranchStore, ContentStore>,
        unit_id: &str,
        pin_id: &str,
        prior_cut_id: Option<&str>,
        prior: &[(String, String)],
        read_override: Option<&str>,
    ) {
        let prior_manifest = prior_cut_id.map(|id| {
            vcs.branches
                .get_cut(id)
                .expect("native candidate test")
                .expect("native candidate test")
                .manifest_hash
        });
        let read = native_read_basis_digest(prior_cut_id, prior_manifest.as_deref());
        let deps = native_dependency_basis_digest(prior);
        assert_eq!(
            vcs.branches
                .declare_contribution(DeclareContribution {
                    unit_id,
                    pin_id,
                    principal: "s:author",
                    intent: "customer change",
                    read_basis_digest: read_override.unwrap_or(&read),
                    dependency_basis_digest: &deps,
                    scope_digest: unit_id,
                    declared_at: "t5",
                })
                .expect("native candidate test"),
            DeclareContributionOutcome::Declared
        );
    }

    fn bound_unit() -> WorkspaceVcs<BranchStore, ContentStore> {
        bound_unit_with_flowing_target(false)
    }

    fn bind_extra_unit(
        vcs: &mut WorkspaceVcs<BranchStore, ContentStore>,
        source_branch_id: &str,
        path: &str,
        body: Option<&str>,
        cut_id: &str,
        pin_id: &str,
        unit_id: &str,
    ) {
        vcs.write(source_branch_id, path, body, cut_id, "t7")
            .expect("write extra source cut");
        let cut = vcs
            .branches
            .get_cut(cut_id)
            .expect("read extra source cut")
            .expect("extra source cut exists");
        assert_eq!(
            vcs.branches
                .pin_private_cut(PinPrivateCut {
                    pin_id,
                    twig_branch_id: source_branch_id,
                    cut_id,
                    manifest_hash: &cut.manifest_hash,
                    principal: "s:author",
                    retained_at: "t8",
                })
                .expect("pin extra source cut"),
            PinPrivateCutOutcome::Pinned
        );
        declare(vcs, unit_id, pin_id);
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                pin_id,
                &selection::parse(&format!("change({cut_id})"))
                    .expect("parse extra source selection"),
            )
            .expect("select extra source change")
        else {
            panic!("bound extra source change")
        };
        assert_eq!(
            vcs.bind_private_selection(unit_id, &selection, "t9")
                .expect("bind extra source selection"),
            BindContributionBasisOutcome::Bound
        );
    }

    fn bound_direct_twig() -> WorkspaceVcs<BranchStore, ContentStore> {
        let mut vcs = workspace();
        vcs.init("t0").expect("initialize workspace");
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .expect("create direct twig");
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .expect("write source cut");
        pin(&mut vcs, "twig-a", "pin-a");
        declare(&mut vcs, "unit-a", "pin-a");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                "pin-a",
                &selection::parse("path(a.txt)").expect("parse source selection"),
            )
            .expect("select source changes")
        else {
            panic!("source selection")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a", &selection, "t3")
                .expect("bind source unit"),
            BindContributionBasisOutcome::Bound
        );
        vcs
    }

    fn reviewed_two_unit_twig() -> (WorkspaceVcs<BranchStore, ContentStore>, ReviewStore) {
        reviewed_two_unit_twig_with_read(None)
    }

    fn reviewed_two_unit_twig_with_read(
        second_read_override: Option<&str>,
    ) -> (WorkspaceVcs<BranchStore, ContentStore>, ReviewStore) {
        reviewed_two_unit_twig_variant(second_read_override, false)
    }

    fn reviewed_two_unit_twig_variant(
        second_read_override: Option<&str>,
        undo_first_write: bool,
    ) -> (WorkspaceVcs<BranchStore, ContentStore>, ReviewStore) {
        let mut vcs = workspace();
        vcs.init("t0").expect("native candidate test");
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .expect("native candidate test");
        assert!(matches!(
            vcs.branches
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "inc-1".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t1".into(),
                })
                .expect("native candidate test"),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .expect("native candidate test");
        pin(&mut vcs, "twig-a", "pin-a");
        declare_native(&mut vcs, "unit-a", "pin-a", None, &[], None);
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                "pin-a",
                &selection::parse("path(a.txt)").expect("native candidate test"),
            )
            .expect("native candidate test")
        else {
            panic!("first selection")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a", &selection, "t3")
                .expect("native candidate test"),
            BindContributionBasisOutcome::Bound
        );
        if undo_first_write {
            vcs.write("twig", "a.txt", None, "twig-undo", "t4")
                .expect("dependent undoes predecessor write");
        }
        vcs.write("twig", "b.txt", Some("B"), "twig-b", "t5")
            .expect("second source write");
        pin(&mut vcs, "twig-b", "pin-b");
        let prior = vec![("unit-a".into(), selection.digest().into())];
        declare_native(
            &mut vcs,
            "unit-b",
            "pin-b",
            Some("twig-a"),
            &prior,
            second_read_override,
        );
        let expression = if undo_first_write {
            "change(twig-undo) | change(twig-b)"
        } else {
            "path(b.txt)"
        };
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                "pin-b",
                &selection::parse(expression).expect("native candidate test"),
            )
            .expect("native candidate test")
        else {
            panic!("second selection")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-b", &selection, "t6")
                .expect("native candidate test"),
            BindContributionBasisOutcome::Bound
        );
        let mut reviews = ReviewStore::open(":memory:").expect("native candidate test");
        reviews
            .create_native_contribution(
                "review-a",
                "s:author",
                "two files",
                MAINLINE_BRANCH_ID,
                &[],
            )
            .expect("native candidate test");
        (vcs, reviews)
    }

    fn upload_two_units(
        vcs: &WorkspaceVcs<BranchStore, ContentStore>,
        reviews: &mut ReviewStore,
        units: &[&str],
    ) {
        reviews
            .upload_native_revision(
                &vcs.branches,
                NativeUpload {
                    contribution_id: "review-a",
                    upload_id: "upload-a",
                    actor: "s:author",
                    source_branch_id: "twig",
                    source_cut_id: "twig-b",
                    unit_ids: units,
                },
            )
            .expect("native candidate test");
    }

    fn native_candidate_request<'a>(
        candidate_cut_id: &'a str,
        recorded_at: &'a str,
    ) -> NativeCandidateRequest<'a> {
        NativeCandidateRequest {
            contribution_id: "review-a",
            sequence: 1,
            expected_trunk_cut_id: None,
            candidate_cut_id,
            actor: "coordinator",
            recorded_at,
        }
    }

    #[test]
    fn native_candidate_proves_complete_prefix_and_keeps_later_tail_out() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        upload_two_units(&vcs, &mut reviews, &["unit-a", "unit-b"]);
        let selected = vcs
            .branches
            .get_cut("twig-b")
            .expect("native candidate test")
            .expect("native candidate test");
        vcs.write("twig", "later.txt", Some("tail"), "twig-tail", "t6")
            .expect("native candidate test");
        let prepared = reviews
            .prepare_native_candidate(&mut vcs, native_candidate_request("candidate-a", "t7"))
            .expect("native candidate test");
        let NativeCandidateOutcome::Prepared(candidate) = prepared else {
            panic!("complete prefix must construct a candidate: {prepared:?}")
        };
        assert_eq!(candidate.candidate_manifest_hash, selected.manifest_hash);
        assert_eq!(candidate.units.len(), 2);
        assert!(candidate
            .units
            .iter()
            .all(|unit| unit.outcome == FlowingUnitOutcome::Applied));
        assert!(candidate.source_atoms_digest.starts_with("sha256:"));
        let witness = vcs
            .branches
            .candidate_witness(&candidate.candidate_witness_digest)
            .expect("native candidate test")
            .expect("candidate proof must be durable at the ref authority");
        assert_eq!(witness.contribution_id, candidate.contribution_id);
        assert_eq!(witness.revision_sequence, candidate.revision_sequence);
        assert_eq!(witness.source_atoms_digest, candidate.source_atoms_digest);
        assert_eq!(witness.units, candidate.units);
        assert!(matches!(
            vcs.retain_review_attempt("gate-attempt-a", &candidate.candidate_witness_digest, "t7",)
                .expect("retain exact source and candidate closure"),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        let pin = vcs
            .branches
            .flowing_attempt_pin("gate-attempt-a")
            .expect("read retained attempt")
            .expect("attempt pin is durable");
        assert_eq!(pin.source_cut_id, "twig-b");
        assert_eq!(pin.candidate_cut_id, "candidate-a");
        assert!(vcs
            .branches
            .pinned_cuts("t8")
            .expect("collector roots")
            .contains("candidate-a"));
        assert_eq!(
            vcs.cut_manifest("candidate-a")
                .expect("native candidate test")
                .expect("native candidate test")
                .len(),
            2
        );
        assert_eq!(
            reviews
                .prepare_native_candidate(&mut vcs, native_candidate_request("candidate-a", "t7"))
                .expect("native candidate test"),
            NativeCandidateOutcome::Prepared(candidate)
        );
        assert!(vcs
            .branches
            .get_branch(MAINLINE_BRANCH_ID)
            .expect("native candidate test")
            .expect("native candidate test")
            .head_cut_id
            .is_none());
    }

    #[test]
    fn native_gate_runs_the_retained_cut_and_records_each_result() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        upload_two_units(&vcs, &mut reviews, &["unit-a", "unit-b"]);
        vcs.write("twig", "later.txt", Some("not selected"), "twig-tail", "t8")
            .expect("append later source tail");
        let prepared = reviews
            .prepare_native_candidate(&mut vcs, native_candidate_request("candidate-a", "t7"))
            .expect("prepare exact prefix");
        let NativeCandidateOutcome::Prepared(candidate) = prepared else {
            panic!("complete prefix must prepare: {prepared:?}")
        };
        assert!(matches!(
            vcs.retain_review_attempt("gate-attempt-a", &candidate.candidate_witness_digest, "t7")
                .expect("pin exact gate attempt"),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        let plan = NativeGatePlan {
            attempt_op_id: "gate-attempt-a".into(),
            candidate_witness_digest: candidate.candidate_witness_digest.clone(),
            coordinator: "coordinator".into(),
            policy_digest: "policy-v1".into(),
            rules_digest: "rules-v1".into(),
            graph_coverage_digest: "full-prefix-v1".into(),
            checks: vec![
                NativeGateCommand {
                    check_id: "cut-content".into(),
                    program: "sh".into(),
                    args: vec!["-c".into(), "test \"$(cat a.txt)\" = A && test \"$(cat b.txt)\" = B && test ! -e later.txt && echo exact-cut && echo changed > a.txt".into()],
                },
                NativeGateCommand {
                    check_id: "failed-check".into(),
                    program: "sh".into(),
                    args: vec!["-c".into(), "test \"$(cat a.txt)\" = A || exit 9; echo refused >&2; exit 7".into()],
                },
                NativeGateCommand {
                    check_id: "unrun-check".into(),
                    program: "/whip/nonexistent-gate-check".into(),
                    args: vec![],
                },
            ],
        };
        let scratch = std::env::temp_dir().join(format!(
            "whip-native-gate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let mut executor = LocalProcessFixture;
        expect_gate_refusal(
            vcs.run_native_candidate_gate(
                &candidate.candidate_witness_digest,
                "",
                &scratch,
                &mut FixturePlanAuthority(plan.clone()),
                &mut executor,
            ),
            "candidate or attempt identity is incomplete",
        );
        assert!(!scratch.exists());
        expect_gate_refusal(
            run_fixture_gate(&mut vcs, "sha256:missing", &plan, &scratch, &mut executor),
            "candidate witness is missing",
        );
        assert!(!scratch.exists());
        let empty = NativeGatePlan {
            checks: Vec::new(),
            ..plan.clone()
        };
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &empty,
                &scratch,
                &mut executor,
            ),
            "plan is incomplete",
        );
        assert!(!scratch.exists());
        let run = run_fixture_gate(
            &mut vcs,
            &candidate.candidate_witness_digest,
            &plan,
            &scratch,
            &mut executor,
        )
        .expect("record every result");
        assert_eq!(
            run.certificate.admission_refusal(),
            Some(crate::branches::flowing_admission::FlowingAdmissionRefusal::GateFailed)
        );
        assert_eq!(
            run.certificate
                .checks
                .iter()
                .map(|check| check.verdict)
                .collect::<Vec<_>>(),
            vec![
                crate::branches::flowing_admission::FlowingGateVerdict::Passed,
                crate::branches::flowing_admission::FlowingGateVerdict::Failed,
                crate::branches::flowing_admission::FlowingGateVerdict::Unrun,
            ]
        );
        assert_eq!(
            vcs.branches
                .native_gate_certificate(&run.handle)
                .expect("read certificate"),
            Some(run.certificate.clone())
        );
        let first = vcs
            .branches
            .native_gate_evidence(&run.certificate.checks[0].evidence_digest)
            .expect("read output")
            .expect("output retained");
        assert_eq!(first.stdout, b"exact-cut\n");
        assert!(first.started);
        assert_eq!(first.exit_code, Some(0));
        let second = vcs
            .branches
            .native_gate_evidence(&run.certificate.checks[1].evidence_digest)
            .expect("read failed check")
            .expect("failed output retained");
        assert_eq!(second.exit_code, Some(7));
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &plan,
                &scratch,
                &mut executor,
            ),
            "scratch path must be absent",
        );
        std::fs::remove_dir_all(&scratch).expect("remove test scratch");

        let passing = NativeGatePlan {
            checks: vec![plan.checks[0].clone()],
            ..plan
        };
        let passed = run_fixture_gate(
            &mut vcs,
            &candidate.candidate_witness_digest,
            &passing,
            &scratch,
            &mut executor,
        )
        .expect("run passing check against exact cut");
        assert_eq!(passed.certificate.admission_refusal(), None);
        assert_ne!(passed.handle, run.handle);
        std::fs::remove_dir_all(&scratch).expect("remove test scratch");

        let mut changed = passing.clone();
        changed.policy_digest = "policy-v2".into();
        let certificate_count_before: i64 = vcs
            .branches
            .test_connection()
            .query_row(
                "SELECT COUNT(*) FROM flowing_gate_certificates",
                [],
                |row| row.get(0),
            )
            .expect("count retained certificates");
        let mut authority = ChangingPlanAuthority {
            initial: passing.clone(),
            changed,
            captures: 0,
        };
        expect_gate_refusal(
            vcs.run_native_candidate_gate(
                &candidate.candidate_witness_digest,
                &passing.attempt_op_id,
                &scratch,
                &mut authority,
                &mut executor,
            ),
            "required plan changed during checks",
        );
        assert_eq!(authority.captures, 2);
        let certificate_count_after: i64 = vcs
            .branches
            .test_connection()
            .query_row(
                "SELECT COUNT(*) FROM flowing_gate_certificates",
                [],
                |row| row.get(0),
            )
            .expect("count retained certificates");
        assert_eq!(certificate_count_after, certificate_count_before);
        std::fs::remove_dir_all(&scratch).expect("remove test scratch");

        assert!(matches!(
            vcs.branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "hold-after-gate".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: "inc-1".into(),
                    expected_eligibility_epoch: 0,
                    expected_owner_epoch: 0,
                    actor: "coordinator".into(),
                    action: FlowingFenceAction::Hold,
                    recorded_at: "t9".into(),
                })
                .expect("hold source"),
            FlowingFenceOutcome::Applied(_)
        ));
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &passing,
                &scratch,
                &mut executor,
            ),
            "source eligibility or coordinator changed",
        );
        assert!(!scratch.exists());
    }

    #[test]
    fn native_gate_subject_reader_refuses_missing_coordinates_and_witness() {
        let vcs = workspace();
        for (witness, attempt) in [("", "attempt"), ("witness", "")] {
            assert!(format!(
                "{:?}",
                vcs.capture_native_gate_subject(witness, attempt)
                    .unwrap_err()
            )
            .contains("candidate or attempt identity is incomplete"));
        }
        assert!(format!(
            "{:?}",
            vcs.capture_native_gate_subject("missing", "attempt")
                .unwrap_err()
        )
        .contains("candidate witness is missing"));
    }

    #[test]
    fn native_gate_refuses_changed_attempt_and_cut_basis() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        upload_two_units(&vcs, &mut reviews, &["unit-a", "unit-b"]);
        let prepared = reviews
            .prepare_native_candidate(&mut vcs, native_candidate_request("candidate-a", "t7"))
            .expect("prepare native candidate");
        let NativeCandidateOutcome::Prepared(candidate) = prepared else {
            panic!("candidate must prepare: {prepared:?}")
        };
        assert!(matches!(
            vcs.retain_review_attempt("gate-op", &candidate.candidate_witness_digest, "t7")
                .expect("retain gate attempt"),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        let plan = NativeGatePlan {
            attempt_op_id: "gate-op".into(),
            candidate_witness_digest: candidate.candidate_witness_digest.clone(),
            coordinator: "coordinator".into(),
            policy_digest: "policy".into(),
            rules_digest: "rules".into(),
            graph_coverage_digest: "coverage".into(),
            checks: vec![NativeGateCommand {
                check_id: "check".into(),
                program: "sh".into(),
                args: vec!["-c".into(), "true".into()],
            }],
        };
        let root = std::env::temp_dir().join(format!(
            "whip-gate-basis-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir(&root).expect("fixture root");
        let scratch = root.join("scratch");
        let mut executor = LocalProcessFixture;

        let duplicate = NativeGatePlan {
            checks: vec![plan.checks[0].clone(), plan.checks[0].clone()],
            ..plan.clone()
        };
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &duplicate,
                &scratch,
                &mut executor,
            ),
            "check identity or command is incomplete",
        );
        let missing_pin = NativeGatePlan {
            attempt_op_id: "missing-pin".into(),
            ..plan.clone()
        };
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &missing_pin,
                &scratch,
                &mut executor,
            ),
            "candidate attempt is not retained",
        );
        let mut foreign_witness = vcs
            .branches
            .candidate_witness(&candidate.candidate_witness_digest)
            .unwrap()
            .unwrap();
        foreign_witness.contribution_id = "another-review".into();
        let foreign_digest = vcs
            .branches
            .record_candidate_witness(&foreign_witness)
            .expect("record distinct witness");
        assert!(matches!(
            vcs.retain_review_attempt("foreign-op", &foreign_digest, "t8")
                .expect("retain foreign attempt"),
            RetainFlowingAttemptOutcome::Retained(_)
        ));
        let foreign_pin = NativeGatePlan {
            attempt_op_id: "foreign-op".into(),
            ..plan.clone()
        };
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &foreign_digest,
                &foreign_pin,
                &scratch,
                &mut executor,
            ),
            "plan is incomplete",
        );
        assert!(!scratch.exists());
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &foreign_pin,
                &scratch,
                &mut executor,
            ),
            "candidate attempt pin differs from witness",
        );

        vcs.branches.test_connection().execute_batch("CREATE TEMP TABLE saved_fence AS SELECT * FROM flowing_source_fences WHERE source_branch_id = 'twig'; DELETE FROM flowing_source_fences WHERE source_branch_id = 'twig';")
            .unwrap();
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &plan,
                &scratch,
                &mut executor,
            ),
            "source fence is missing",
        );
        vcs.branches.test_connection().execute_batch("INSERT INTO flowing_source_fences SELECT * FROM saved_fence; DROP TABLE saved_fence;")
            .unwrap();

        vcs.branches.test_connection().execute_batch("CREATE TEMP TABLE saved_trunk AS SELECT * FROM branches WHERE branch_id = 'main'; DELETE FROM branches WHERE branch_id = 'main';")
            .unwrap();
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &plan,
                &scratch,
                &mut executor,
            ),
            "trunk is missing",
        );
        vcs.branches
            .test_connection()
            .execute_batch(
                "INSERT INTO branches SELECT * FROM saved_trunk; DROP TABLE saved_trunk;",
            )
            .unwrap();

        vcs.branches
            .test_connection()
            .execute(
                "UPDATE branches SET head_cut_id = 'moved' WHERE branch_id = ?1",
                [MAINLINE_BRANCH_ID],
            )
            .unwrap();
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &plan,
                &scratch,
                &mut executor,
            ),
            "trunk base changed",
        );
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE branches SET head_cut_id = NULL WHERE branch_id = ?1",
                [MAINLINE_BRANCH_ID],
            )
            .unwrap();

        vcs.branches.test_connection().execute_batch("CREATE TEMP TABLE saved_candidate AS SELECT * FROM cuts WHERE cut_id = 'candidate-a'; DELETE FROM cuts WHERE cut_id = 'candidate-a';")
            .unwrap();
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &plan,
                &scratch,
                &mut executor,
            ),
            "candidate cut is missing",
        );
        vcs.branches
            .test_connection()
            .execute_batch(
                "INSERT INTO cuts SELECT * FROM saved_candidate; DROP TABLE saved_candidate;",
            )
            .unwrap();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE cuts SET manifest_hash = 'wrong' WHERE cut_id = 'candidate-a'",
                [],
            )
            .unwrap();
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &plan,
                &scratch,
                &mut executor,
            ),
            "candidate cut differs from retained witness",
        );
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE cuts SET manifest_hash = ?1 WHERE cut_id = 'candidate-a'",
                [&candidate.candidate_manifest_hash],
            )
            .unwrap();
        assert!(!scratch.exists());

        let db_path = root.join("branches.sqlite");
        vcs.branches
            .test_connection()
            .execute("VACUUM INTO ?1", [db_path.to_str().unwrap()])
            .unwrap();
        vcs.branches = BranchStore::open(&db_path).expect("reopen branch fixture from disk");
        let mut moving = MoveTrunkDuringCheck(rusqlite::Connection::open(&db_path).unwrap());
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &plan,
                &scratch,
                &mut moving,
            ),
            "trunk or source changed during checks",
        );
        std::fs::remove_dir_all(&scratch).expect("remove projection");
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE branches SET head_cut_id = NULL WHERE branch_id = ?1",
                [MAINLINE_BRANCH_ID],
            )
            .unwrap();

        assert!(matches!(
            vcs.branches
                .cancel_flowing_attempt(&crate::branches::flowing_admission::FlowingCancelRequest {
                    cancel_op_id: "cancel-gate-op".into(),
                    admission_op_id: "gate-op".into(),
                    source_branch_id: "twig".into(),
                    source_incarnation_id: "inc-1".into(),
                    expected_owner_epoch: 0,
                    coordinator: "coordinator".into(),
                    recorded_at: "t9".into(),
                })
                .expect("cancel attempt"),
            crate::branches::flowing_admission::FlowingCancelOutcome::Cancelled(_)
        ));
        expect_gate_refusal(
            run_fixture_gate(
                &mut vcs,
                &candidate.candidate_witness_digest,
                &plan,
                &scratch,
                &mut executor,
            ),
            "candidate attempt was cancelled",
        );
        drop(moving);
        drop(vcs);
        std::fs::remove_dir_all(root).expect("remove gate fixture");
    }

    #[test]
    fn review_attempt_refuses_a_lost_body_without_creating_a_pin() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        upload_two_units(&vcs, &mut reviews, &["unit-a", "unit-b"]);
        let prepared = reviews
            .prepare_native_candidate(&mut vcs, native_candidate_request("candidate-a", "t7"))
            .expect("prepare complete candidate");
        let NativeCandidateOutcome::Prepared(candidate) = prepared else {
            panic!("candidate must be ready: {prepared:?}")
        };
        let lost_body = vcs
            .cut_manifest("candidate-a")
            .expect("candidate manifest")
            .expect("candidate manifest exists")["a.txt"]
            .clone();
        assert!(matches!(
            vcs.content.erase(&lost_body, "t8").expect("erase body"),
            crate::content::EraseOutcome::Erased { .. }
        ));
        assert_eq!(
            vcs.retain_review_attempt("gate-attempt-a", &candidate.candidate_witness_digest, "t9")
                .expect("refuse incomplete closure"),
            RetainFlowingAttemptOutcome::MissingContent {
                content_id: lost_body
            }
        );
        assert_eq!(
            vcs.branches.flowing_attempt_pin("gate-attempt-a").unwrap(),
            None
        );
    }

    #[test]
    fn native_candidate_applies_a_prefix_to_its_exact_existing_trunk_cut() {
        let mut vcs = workspace();
        vcs.init("t0").expect("mainline");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "base.txt",
            Some("base"),
            "trunk-base",
            "t1",
        )
        .expect("base cut");
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t2")
            .expect("twig");
        assert!(matches!(
            vcs.branches
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "inc-1".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t2".into(),
                })
                .expect("flowing source"),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t3")
            .expect("source write");
        pin(&mut vcs, "twig-a", "pin-a");
        declare_native(&mut vcs, "unit-a", "pin-a", Some("trunk-base"), &[], None);
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                "pin-a",
                &selection::parse("path(a.txt)").expect("selection expression"),
            )
            .expect("select")
        else {
            panic!("selected source atom required")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a", &selection, "t4")
                .expect("bind"),
            BindContributionBasisOutcome::Bound
        );
        let mut reviews = ReviewStore::open(":memory:").expect("review store");
        reviews
            .create_native_contribution("review-a", "s:author", "one file", MAINLINE_BRANCH_ID, &[])
            .expect("review contribution");
        reviews
            .upload_native_revision(
                &vcs.branches,
                NativeUpload {
                    contribution_id: "review-a",
                    upload_id: "upload-a",
                    actor: "s:author",
                    source_branch_id: "twig",
                    source_cut_id: "twig-a",
                    unit_ids: &["unit-a"],
                },
            )
            .expect("native revision");
        let outcome = reviews
            .prepare_native_candidate(
                &mut vcs,
                NativeCandidateRequest {
                    expected_trunk_cut_id: Some("trunk-base"),
                    ..native_candidate_request("candidate-on-base", "t5")
                },
            )
            .expect("candidate preparation");
        let NativeCandidateOutcome::Prepared(candidate) = outcome else {
            panic!("existing base should construct: {outcome:?}")
        };
        assert_eq!(
            candidate.expected_trunk_cut_id.as_deref(),
            Some("trunk-base")
        );
        assert_eq!(
            vcs.cut_manifest("candidate-on-base")
                .expect("candidate manifest")
                .expect("candidate cut")
                .len(),
            2
        );
        assert_eq!(
            vcs.branches
                .get_branch(MAINLINE_BRANCH_ID)
                .expect("trunk read")
                .expect("trunk")
                .head_cut_id
                .as_deref(),
            Some("trunk-base")
        );
    }

    #[test]
    fn native_candidate_keeps_a_neutralized_unit_as_a_metadata_only_result() {
        let mut vcs = workspace();
        vcs.init("t0").expect("mainline");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "base.txt",
            Some("base"),
            "trunk-base",
            "t1",
        )
        .expect("base cut");
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t2")
            .expect("twig");
        assert!(matches!(
            vcs.branches
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "inc-1".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t2".into(),
                })
                .expect("flowing source"),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        vcs.write("twig", "scratch.txt", Some("temporary"), "twig-add", "t3")
            .expect("add");
        vcs.write("twig", "scratch.txt", None, "twig-undo", "t4")
            .expect("undo");
        pin(&mut vcs, "twig-undo", "pin-undo");
        declare_native(
            &mut vcs,
            "unit-undo",
            "pin-undo",
            Some("trunk-base"),
            &[],
            None,
        );
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                "pin-undo",
                &selection::parse("path(scratch.txt)").expect("selection expression"),
            )
            .expect("select")
        else {
            panic!("selected source atoms required")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-undo", &selection, "t5")
                .expect("bind"),
            BindContributionBasisOutcome::Bound
        );
        let mut reviews = ReviewStore::open(":memory:").expect("review store");
        reviews
            .create_native_contribution("review-a", "s:author", "undo", MAINLINE_BRANCH_ID, &[])
            .expect("review contribution");
        reviews
            .upload_native_revision(
                &vcs.branches,
                NativeUpload {
                    contribution_id: "review-a",
                    upload_id: "upload-a",
                    actor: "s:author",
                    source_branch_id: "twig",
                    source_cut_id: "twig-undo",
                    unit_ids: &["unit-undo"],
                },
            )
            .expect("native revision");
        let outcome = reviews
            .prepare_native_candidate(
                &mut vcs,
                NativeCandidateRequest {
                    expected_trunk_cut_id: Some("trunk-base"),
                    candidate_cut_id: "trunk-base",
                    ..native_candidate_request("trunk-base", "t6")
                },
            )
            .expect("candidate preparation");
        let NativeCandidateOutcome::Prepared(candidate) = outcome else {
            panic!("neutralized prefix should keep exact base: {outcome:?}")
        };
        assert_eq!(candidate.candidate_cut_id, "trunk-base");
        assert_eq!(candidate.units[0].outcome, FlowingUnitOutcome::Neutralized);
        assert_eq!(
            vcs.branches
                .get_branch(MAINLINE_BRANCH_ID)
                .expect("trunk read")
                .expect("trunk")
                .head_cut_id
                .as_deref(),
            Some("trunk-base")
        );
    }

    #[test]
    fn native_candidate_refuses_an_omitted_unit_and_a_changed_base() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        upload_two_units(&vcs, &mut reviews, &["unit-b"]);
        assert_eq!(
            reviews
                .prepare_native_candidate(
                    &mut vcs,
                    native_candidate_request("candidate-omitted", "t6")
                )
                .expect("native candidate test"),
            NativeCandidateOutcome::IncompletePrefix
        );
        assert!(vcs
            .branches
            .get_cut("candidate-omitted")
            .expect("native candidate test")
            .is_none());
        vcs.write(
            MAINLINE_BRANCH_ID,
            "other.txt",
            Some("new"),
            "trunk-new",
            "t7",
        )
        .expect("native candidate test");
        assert_eq!(
            reviews
                .prepare_native_candidate(
                    &mut vcs,
                    native_candidate_request("candidate-stale", "t8")
                )
                .expect("native candidate test"),
            NativeCandidateOutcome::StaleBase
        );
    }

    #[test]
    fn native_candidate_refuses_unaccounted_review_predecessors() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        reviews
            .create_native_contribution(
                "review-dependent",
                "s:author",
                "dependent work",
                MAINLINE_BRANCH_ID,
                &["review-a"],
            )
            .expect("dependent contribution");
        reviews
            .upload_native_revision(
                &vcs.branches,
                NativeUpload {
                    contribution_id: "review-dependent",
                    upload_id: "dependent-upload",
                    actor: "s:author",
                    source_branch_id: "twig",
                    source_cut_id: "twig-b",
                    unit_ids: &["unit-a", "unit-b"],
                },
            )
            .expect("dependent revision");
        let err = reviews
            .prepare_native_candidate(
                &mut vcs,
                NativeCandidateRequest {
                    contribution_id: "review-dependent",
                    ..native_candidate_request("candidate-dependent", "t6")
                },
            )
            .expect_err("review predecessor has no admission receipt");
        assert!(matches!(err, ReviewError::Invalid(reason)
            if reason == "review predecessors need admission receipts before candidate construction"));
        assert!(vcs
            .branches
            .get_cut("candidate-dependent")
            .expect("candidate lookup")
            .is_none());
    }

    #[test]
    fn native_candidate_refuses_a_nontrunk_review_target() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        reviews
            .create_native_contribution("review-side", "s:author", "side work", "side", &[])
            .expect("side contribution");
        let err = reviews
            .prepare_native_candidate(
                &mut vcs,
                NativeCandidateRequest {
                    contribution_id: "review-side",
                    ..native_candidate_request("candidate-side", "t6")
                },
            )
            .expect_err("candidate must target trunk");
        assert!(matches!(err, ReviewError::Invalid(reason)
            if reason == "native candidate needs the trunk target"));
        assert!(vcs
            .branches
            .get_cut("candidate-side")
            .expect("candidate lookup")
            .is_none());
    }

    #[test]
    fn native_candidate_includes_even_unbound_prefix_obligations_in_closure() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        declare(&mut vcs, "unit-unbound", "pin-b");
        upload_two_units(&vcs, &mut reviews, &["unit-a", "unit-b"]);
        assert_eq!(
            reviews
                .prepare_native_candidate(
                    &mut vcs,
                    native_candidate_request("candidate-unbound", "t6")
                )
                .expect("native candidate test"),
            NativeCandidateOutcome::IncompletePrefix
        );
        assert!(vcs
            .branches
            .get_cut("candidate-unbound")
            .expect("native candidate test")
            .is_none());
    }

    #[test]
    fn native_candidate_refuses_an_unproved_read_basis() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig_with_read(Some("wrong"));
        upload_two_units(&vcs, &mut reviews, &["unit-a", "unit-b"]);
        assert_eq!(
            reviews
                .prepare_native_candidate(
                    &mut vcs,
                    native_candidate_request("candidate-bad-basis", "t6")
                )
                .expect("native candidate test"),
            NativeCandidateOutcome::UnprovenBasis {
                unit_id: "unit-b".into()
            }
        );
        assert!(vcs
            .branches
            .get_cut("candidate-bad-basis")
            .expect("native candidate test")
            .is_none());
    }

    #[test]
    fn native_candidate_refuses_a_reused_cut_identity() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        upload_two_units(&vcs, &mut reviews, &["unit-a", "unit-b"]);
        let selected = vcs
            .branches
            .get_cut("twig-b")
            .expect("native candidate test")
            .expect("native candidate test");
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "candidate-taken",
                change_id: "candidate-taken",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: &selected.manifest_hash,
                parent_cut_id: None,
                origin: Some("transport:twig"),
                actor: Some("someone-else"),
                intent: Some("review-a"),
                recorded_at: "t6",
            })
            .expect("native candidate test");
        assert_eq!(
            reviews
                .prepare_native_candidate(
                    &mut vcs,
                    native_candidate_request("candidate-taken", "t6")
                )
                .expect("native candidate test"),
            NativeCandidateOutcome::CandidateMismatch
        );
    }

    #[test]
    fn native_candidate_refuses_overlap_with_an_unproven_read_basis() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        vcs.write("twig", "a.txt", Some("A2"), "twig-a2", "t6")
            .expect("native candidate test");
        pin(&mut vcs, "twig-a2", "pin-a2");
        declare(&mut vcs, "unit-a2", "pin-a2");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                "pin-a2",
                &selection::parse("change(twig-a2)").expect("native candidate test"),
            )
            .expect("native candidate test")
        else {
            panic!("third selection")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a2", &selection, "t7")
                .expect("native candidate test"),
            BindContributionBasisOutcome::Bound
        );
        reviews
            .upload_native_revision(
                &vcs.branches,
                NativeUpload {
                    contribution_id: "review-a",
                    upload_id: "upload-overlap",
                    actor: "s:author",
                    source_branch_id: "twig",
                    source_cut_id: "twig-a2",
                    unit_ids: &["unit-a", "unit-b", "unit-a2"],
                },
            )
            .expect("native candidate test");
        assert_eq!(
            reviews
                .prepare_native_candidate(
                    &mut vcs,
                    native_candidate_request("candidate-overlap", "t8")
                )
                .expect("native candidate test"),
            NativeCandidateOutcome::UnprovenBasis {
                unit_id: "unit-a2".into()
            }
        );
        assert!(vcs
            .branches
            .get_cut("candidate-overlap")
            .expect("native candidate test")
            .is_none());
    }

    #[test]
    fn native_candidate_accounts_a_neutralized_predecessor_and_applied_dependent() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig();
        vcs.write("twig", "a.txt", Some("A2"), "twig-a2", "t6")
            .expect("later source write");
        pin(&mut vcs, "twig-a2", "pin-a2");
        let prior: Vec<(String, String)> = ["unit-a", "unit-b"]
            .into_iter()
            .map(|unit_id| {
                let basis = vcs
                    .branches
                    .contribution_basis(unit_id)
                    .expect("read contribution")
                    .expect("bound contribution");
                (unit_id.into(), basis.basis_digest)
            })
            .collect();
        declare_native(&mut vcs, "unit-a2", "pin-a2", Some("twig-b"), &prior, None);
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                "pin-a2",
                &selection::parse("change(twig-a2)").expect("select later write"),
            )
            .expect("derive later write")
        else {
            panic!("third selection")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a2", &selection, "t7")
                .expect("bind later write"),
            BindContributionBasisOutcome::Bound
        );
        reviews
            .upload_native_revision(
                &vcs.branches,
                NativeUpload {
                    contribution_id: "review-a",
                    upload_id: "upload-overlap",
                    actor: "s:author",
                    source_branch_id: "twig",
                    source_cut_id: "twig-a2",
                    unit_ids: &["unit-a", "unit-b", "unit-a2"],
                },
            )
            .expect("upload exact prefix");
        let prepared = reviews
            .prepare_native_candidate(
                &mut vcs,
                native_candidate_request("candidate-overlap", "t8"),
            )
            .expect("prepare exact prefix");
        let NativeCandidateOutcome::Prepared(candidate) = prepared else {
            panic!("overlapping complete prefix must prepare: {prepared:?}")
        };
        assert_eq!(candidate.units.len(), 3);
        assert_eq!(candidate.units[0].outcome, FlowingUnitOutcome::Neutralized);
        assert_eq!(candidate.units[1].outcome, FlowingUnitOutcome::Applied);
        assert_eq!(candidate.units[2].outcome, FlowingUnitOutcome::Applied);
        let witness = vcs
            .branches
            .candidate_witness(&candidate.candidate_witness_digest)
            .expect("read witness")
            .expect("persisted witness");
        assert_eq!(witness.units, candidate.units);
        let candidate_manifest = vcs
            .cut_manifest("candidate-overlap")
            .expect("read candidate")
            .expect("recorded candidate");
        assert_eq!(candidate_manifest.len(), 2);
        assert_eq!(
            candidate_manifest.get("a.txt"),
            Some(&vcs.content.put_text("A2").expect("content id"))
        );
        assert_eq!(
            candidate_manifest.get("b.txt"),
            Some(&vcs.content.put_text("B").expect("content id"))
        );
    }

    #[test]
    fn native_candidate_replays_a_dependent_undo_before_accounting_both_units() {
        let (mut vcs, mut reviews) = reviewed_two_unit_twig_variant(None, true);
        upload_two_units(&vcs, &mut reviews, &["unit-a", "unit-b"]);
        let prepared = reviews
            .prepare_native_candidate(&mut vcs, native_candidate_request("candidate-undo", "t7"))
            .expect("prepare exact prefix");
        let NativeCandidateOutcome::Prepared(candidate) = prepared else {
            panic!("dependent undo must prepare: {prepared:?}")
        };
        assert_eq!(candidate.units.len(), 2);
        assert_eq!(candidate.units[0].outcome, FlowingUnitOutcome::Neutralized);
        assert_eq!(candidate.units[1].outcome, FlowingUnitOutcome::Applied);
        let candidate_manifest = vcs
            .cut_manifest("candidate-undo")
            .expect("read candidate")
            .expect("recorded candidate");
        assert_eq!(candidate_manifest.len(), 1);
        assert_eq!(
            candidate_manifest.get("b.txt"),
            Some(&vcs.content.put_text("B").expect("content id"))
        );
        let witness = vcs
            .branches
            .candidate_witness(&candidate.candidate_witness_digest)
            .expect("read witness")
            .expect("persisted witness");
        assert_eq!(witness.units, candidate.units);

        let (mut stale_vcs, mut stale_reviews) =
            reviewed_two_unit_twig_variant(Some("wrong"), true);
        upload_two_units(&stale_vcs, &mut stale_reviews, &["unit-a", "unit-b"]);
        assert_eq!(
            stale_reviews
                .prepare_native_candidate(
                    &mut stale_vcs,
                    native_candidate_request("candidate-stale-undo", "t7")
                )
                .expect("prepare stale prefix"),
            NativeCandidateOutcome::UnprovenBasis {
                unit_id: "unit-b".into()
            }
        );
    }

    #[test]
    fn direct_trunk_candidate_checks_actual_selected_content() {
        let mut vcs = bound_direct_twig();
        vcs.write("twig", "b.txt", Some("later"), "twig-tail", "t3")
            .expect("unselected tail remains on twig");
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .prepare_direct_trunk_candidate("unit-a", "trunk-exact", "coordinator", "t4")
            .expect("prepare candidate")
        else {
            panic!("trunk candidate should carry selected content")
        };
        assert_eq!(witness.target_branch_id(), MAINLINE_BRANCH_ID);
        assert_eq!(
            witness.effects()[0].disposition,
            FlowingEffectDisposition::Applied
        );
        assert_eq!(
            vcs.prepare_direct_trunk_candidate("unit-a", "trunk-exact", "coordinator", "t4")
                .expect("exact candidate retry"),
            FlowingTargetEffectsOutcome::Verified(witness.clone())
        );
        assert_eq!(
            vcs.prepare_direct_trunk_candidate("unit-a", "trunk-exact", "other", "t4")
                .expect("changed actor"),
            FlowingTargetEffectsOutcome::TargetCutMismatch
        );
        assert_eq!(
            vcs.verify_private_target_effects("unit-a", "trunk-exact")
                .expect("handoff verifier"),
            FlowingTargetEffectsOutcome::TargetNotParent
        );

        let empty_manifest = vcs
            .store_manifest(&BTreeMap::new())
            .expect("empty candidate manifest");
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "trunk-omitted",
                change_id: "candidate-omitted",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: &empty_manifest,
                parent_cut_id: None,
                origin: Some("transport:twig"),
                actor: Some("coordinator"),
                intent: None,
                recorded_at: "t4",
            })
            .expect("record omitted candidate");
        assert_eq!(
            vcs.verify_trunk_target_effects("unit-a", "trunk-omitted")
                .expect("verify omitted candidate"),
            FlowingTargetEffectsOutcome::OmittedEffect {
                path: "a.txt".into()
            }
        );
        assert!(vcs
            .branches
            .get_branch(MAINLINE_BRANCH_ID)
            .expect("read trunk")
            .expect("trunk exists")
            .head_cut_id
            .is_none());

        vcs.write(
            MAINLINE_BRANCH_ID,
            "a.txt",
            Some("A"),
            "trunk-existing",
            "t5",
        )
        .expect("fixture installs equivalent trunk content");
        let FlowingTargetEffectsOutcome::Verified(equivalent) = vcs
            .prepare_direct_trunk_candidate("unit-a", "trunk-existing", "coordinator", "t6")
            .expect("prepare metadata-only candidate")
        else {
            panic!("current trunk content should be equivalent")
        };
        assert_eq!(
            equivalent.effects()[0].disposition,
            FlowingEffectDisposition::Equivalent
        );
        assert_eq!(equivalent.target_before_cut_id(), Some("trunk-existing"));
        assert_eq!(equivalent.target_after_cut_id(), "trunk-existing");
        assert_eq!(
            vcs.prepare_direct_trunk_candidate("unit-a", "new-cut", "coordinator", "t6")
                .expect("no-op cannot mint a second cut"),
            FlowingTargetEffectsOutcome::TargetCutMismatch
        );
    }

    #[test]
    fn direct_trunk_planner_refuses_missing_cut_or_actor_before_recording() {
        let mut vcs = bound_direct_twig();
        for (cut_id, actor) in [("", "coordinator"), ("trunk-empty-actor", "")] {
            let error = vcs
                .prepare_direct_trunk_candidate("unit-a", cut_id, actor, "t4")
                .expect_err("a trunk candidate needs both identities");
            assert!(matches!(
                error,
                StoreError::Conflict(reason)
                    if reason == "trunk candidate cut id and actor must be nonempty"
            ));
        }
        assert!(vcs
            .branches
            .get_cut("trunk-empty-actor")
            .expect("read rejected cut")
            .is_none());
    }

    #[test]
    fn direct_trunk_initial_noop_keeps_unit_owed_without_inventing_genesis() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .unwrap();
        vcs.write("twig", "a.txt", None, "twig-undo", "t3").unwrap();
        pin(&mut vcs, "twig-undo", "pin-undo");
        declare(&mut vcs, "unit-undo", "pin-undo");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-undo", &selection::parse("path(a.txt)").unwrap())
            .unwrap()
        else {
            panic!("write and undo must remain selected")
        };
        assert_eq!(selection.changes().len(), 2);
        assert_eq!(
            vcs.bind_private_selection("unit-undo", &selection, "t4")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        assert_eq!(
            vcs.prepare_direct_trunk_candidate("unit-undo", "first-cut", "coordinator", "t5")
                .unwrap(),
            FlowingTargetEffectsOutcome::InitialNoopNeedsGenesis
        );
        assert!(vcs.branches.get_cut("first-cut").unwrap().is_none());
        assert!(vcs
            .branches
            .contribution_declaration("unit-undo")
            .unwrap()
            .is_some());
        assert!(vcs
            .branches
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
    }

    fn bound_unit_with_flowing_target(flowing: bool) -> WorkspaceVcs<BranchStore, ContentStore> {
        let mut vcs = workspace();
        vcs.init("t0").expect("initialize workspace");
        vcs.create_branch(
            "branch",
            flowing.then_some("feature"),
            MAINLINE_BRANCH_ID,
            "t1",
        )
        .expect("create target branch");
        if flowing {
            assert!(matches!(
                vcs.branches
                    .open_flowing_source(&OpenFlowingSource {
                        source_branch_id: "branch".into(),
                        incarnation_id: "branch-inc".into(),
                        kind: FlowingSourceKind::Branch,
                        owner: "coordinator".into(),
                        opened_at: "t1".into(),
                    })
                    .expect("open shared flowing branch"),
                OpenFlowingSourceOutcome::Opened(_)
            ));
        }
        vcs.create_branch("twig", None, "branch", "t1")
            .expect("create source twig");
        if flowing {
            assert!(matches!(
                vcs.branches
                    .open_flowing_source(&OpenFlowingSource {
                        source_branch_id: "twig".into(),
                        incarnation_id: "twig-inc".into(),
                        kind: FlowingSourceKind::Twig,
                        owner: "coordinator".into(),
                        opened_at: "t1".into(),
                    })
                    .expect("open flowing member twig"),
                OpenFlowingSourceOutcome::Opened(_)
            ));
        }
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .expect("write source cut");
        pin(&mut vcs, "twig-a", "pin-a");
        declare(&mut vcs, "unit-a", "pin-a");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes(
                "pin-a",
                &selection::parse("path(a.txt)").expect("parse source selection"),
            )
            .expect("select source changes")
        else {
            panic!("source selection")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a", &selection, "t3")
                .expect("bind source unit"),
            BindContributionBasisOutcome::Bound
        );
        vcs
    }

    #[test]
    fn handoff_to_flowing_branch_obeys_its_ref_owned_fence() {
        let mut allowed = bound_unit_with_flowing_target(true);
        assert!(matches!(
            allowed.inspect_flowing_branch_lineage("branch").unwrap(),
            FlowingBranchLineageOutcome::Verified(FlowingBranchLineage { handoffs, .. })
                if handoffs.is_empty()
        ));
        let witness = prepare_target(&mut allowed, "target-a");
        assert!(matches!(
            allowed
                .handoff_private_selection("handoff-a", &witness, "mediator", "t5")
                .unwrap(),
            HandoffContributionOutcome::Transferred(_)
        ));
        let FlowingBranchLineageOutcome::Verified(lineage) =
            allowed.inspect_flowing_branch_lineage("branch").unwrap()
        else {
            panic!("the target cut and durable receipt must form one checked chain")
        };
        assert_eq!(lineage.head_cut_id.as_deref(), Some("target-a"));
        assert_eq!(lineage.handoffs.len(), 1);
        assert_eq!(lineage.handoffs[0].unit_id, "unit-a");
        allowed
            .write("branch", "other.txt", Some("other"), "unreceipted", "t6")
            .unwrap();
        assert_eq!(
            allowed.inspect_flowing_branch_lineage("branch").unwrap(),
            FlowingBranchLineageOutcome::MissingReceipt {
                cut_id: "unreceipted".into()
            }
        );

        let mut closed = bound_unit_with_flowing_target(true);
        let witness = prepare_target(&mut closed, "target-a");
        let state = closed.branches.flowing_source("branch").unwrap().unwrap();
        assert!(matches!(
            closed
                .branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "disable".into(),
                    source_branch_id: "branch".into(),
                    incarnation_id: "branch-inc".into(),
                    expected_eligibility_epoch: state.eligibility_epoch,
                    expected_owner_epoch: state.owner_epoch,
                    actor: "coordinator".into(),
                    action: FlowingFenceAction::DisableAdmission,
                    recorded_at: "t5".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        assert_eq!(
            closed
                .handoff_private_selection("handoff-a", &witness, "mediator", "t6")
                .unwrap(),
            HandoffContributionOutcome::TargetFenceRefused
        );
        assert!(closed
            .branches
            .handoff_receipt("handoff-a")
            .unwrap()
            .is_none());
        assert!(closed
            .branches
            .get_branch("branch")
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
    }

    #[test]
    fn branch_lineage_orders_two_handoffs_by_cut_ancestry() {
        let mut vcs = bound_unit_with_flowing_target(true);
        let first = prepare_target(&mut vcs, "target-a");
        assert!(matches!(
            vcs.handoff_private_selection("handoff-z", &first, "mediator", "t5")
                .unwrap(),
            HandoffContributionOutcome::Transferred(_)
        ));
        vcs.create_branch("twig-b", None, "branch", "t6").unwrap();
        assert!(matches!(
            vcs.branches
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig-b".into(),
                    incarnation_id: "twig-b-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t6".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        vcs.write("twig-b", "b.txt", Some("B"), "twig-b-cut", "t7")
            .unwrap();
        let source = vcs.branches.get_cut("twig-b-cut").unwrap().unwrap();
        assert_eq!(
            vcs.branches
                .pin_private_cut(PinPrivateCut {
                    pin_id: "pin-b",
                    twig_branch_id: "twig-b",
                    cut_id: "twig-b-cut",
                    manifest_hash: &source.manifest_hash,
                    principal: "s:author",
                    retained_at: "t8",
                })
                .unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        assert_eq!(
            vcs.branches
                .declare_contribution(DeclareContribution {
                    unit_id: "unit-b",
                    pin_id: "pin-b",
                    principal: "s:author",
                    intent: "second change",
                    read_basis_digest: "reads-b",
                    dependency_basis_digest: "deps-b",
                    scope_digest: "scope-b",
                    declared_at: "t8",
                })
                .unwrap(),
            DeclareContributionOutcome::Declared
        );
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-b", &selection::parse("path(b.txt)").unwrap())
            .unwrap()
        else {
            panic!("second source cut must be selectable")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-b", &selection, "t9")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        let FlowingTargetEffectsOutcome::Verified(second) = vcs
            .prepare_private_handoff_target("unit-b", "target-b", "mediator", "t10")
            .unwrap()
        else {
            panic!("second target must derive from the first handoff")
        };
        assert!(matches!(
            vcs.handoff_private_selection("handoff-a", &second, "mediator", "t11")
                .unwrap(),
            HandoffContributionOutcome::Transferred(_)
        ));
        let FlowingBranchLineageOutcome::Verified(lineage) =
            vcs.inspect_flowing_branch_lineage("branch").unwrap()
        else {
            panic!("both target cuts must be accounted by exact source units")
        };
        assert_eq!(lineage.head_cut_id.as_deref(), Some("target-b"));
        assert_eq!(
            lineage
                .handoffs
                .iter()
                .map(|receipt| receipt.unit_id.as_str())
                .collect::<Vec<_>>(),
            vec!["unit-a", "unit-b"]
        );
        let first = lineage.prefix_through("target-a").unwrap();
        assert_eq!(first.selected_handoffs.len(), 1);
        assert_eq!(first.selected_handoffs[0].unit_id, "unit-a");
        assert_eq!(first.later_handoffs.len(), 1);
        assert_eq!(first.later_handoffs[0].unit_id, "unit-b");
        assert_eq!(first.observed_head_cut_id.as_deref(), Some("target-b"));
        assert_eq!(
            first.selected_manifest_hash,
            first.selected_handoffs[0].target_after_manifest_hash
        );
        assert_eq!(
            lineage
                .prefix_through("target-b")
                .unwrap()
                .later_handoffs
                .len(),
            0
        );
        assert!(lineage.prefix_through("not-a-cut").is_none());
    }

    fn prepare_target(
        vcs: &mut WorkspaceVcs<BranchStore, ContentStore>,
        target_cut_id: &str,
    ) -> FlowingTargetEffects {
        let basis = vcs
            .branches
            .contribution_basis("unit-a")
            .expect("read source basis")
            .expect("bound source unit");
        let after = basis.atoms[0].after.clone().expect("source result body");
        let manifest = vcs
            .store_manifest(&BTreeMap::from([("a.txt".to_owned(), after)]))
            .expect("prepare target manifest");
        vcs.branches
            .record_cut(CutRecord {
                cut_id: target_cut_id,
                change_id: "shared-unit-a",
                branch_id: "branch",
                manifest_hash: &manifest,
                parent_cut_id: None,
                origin: Some("transport:twig"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t4",
            })
            .expect("record prepared target cut");
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .verify_private_target_effects("unit-a", target_cut_id)
            .expect("read target effects")
        else {
            panic!("prepared target must contain selected unit")
        };
        witness
    }

    #[test]
    fn handoff_moves_exact_target_and_receipt_while_preserving_later_twig_tail() {
        let mut vcs = bound_unit();
        vcs.write("twig", "b.txt", Some("B"), "twig-tail", "t4")
            .unwrap();
        assert!(vcs.branches.target_handoffs("branch").unwrap().is_empty());
        let witness = prepare_target(&mut vcs, "target-a");
        let HandoffContributionOutcome::Transferred(receipt) = vcs
            .handoff_private_selection("handoff-a", &witness, "mediator", "t5")
            .unwrap()
        else {
            panic!("unit must transfer with target cut")
        };
        assert_eq!(receipt.source_cut_id, "twig-a");
        assert_eq!(receipt.target_after_cut_id, "target-a");
        assert_eq!(receipt.effects, witness.effects());
        assert_eq!(
            vcs.branches.target_handoffs("branch").unwrap(),
            vec![receipt.clone()]
        );
        assert!(vcs.branches.target_handoffs("twig").unwrap().is_empty());
        assert_eq!(
            vcs.branches
                .get_branch("branch")
                .unwrap()
                .unwrap()
                .head_cut_id,
            Some("target-a".into())
        );
        assert_eq!(
            vcs.branches
                .get_branch("twig")
                .unwrap()
                .unwrap()
                .head_cut_id,
            Some("twig-tail".into())
        );
        assert_eq!(
            vcs.handoff_private_selection("handoff-a", &witness, "mediator", "t5")
                .unwrap(),
            HandoffContributionOutcome::Existing(receipt.clone())
        );
        assert_eq!(
            vcs.handoff_private_selection("handoff-b", &witness, "mediator", "t6")
                .unwrap(),
            HandoffContributionOutcome::AlreadyTransferred
        );
        assert_eq!(
            vcs.branches
                .release_private_cut(ReleasePrivateCut {
                    pin_id: "pin-a",
                    released_by: "s:author",
                    reason: "holder transferred to branch",
                    released_at: "t6",
                })
                .unwrap(),
            ReleasePrivateCutOutcome::Released
        );
        assert!(vcs
            .branches
            .pinned_cuts("year-3000")
            .unwrap()
            .contains("twig-a"));
    }

    #[test]
    fn stale_target_handoff_leaves_twig_unit_and_pin_owed() {
        let mut vcs = bound_unit();
        let witness = prepare_target(&mut vcs, "target-a");
        vcs.write("branch", "other.txt", Some("other"), "other-cut", "t5")
            .unwrap();
        assert_eq!(
            vcs.handoff_private_selection("handoff-a", &witness, "mediator", "t6")
                .unwrap(),
            HandoffContributionOutcome::TargetStale {
                current_head_cut_id: Some("other-cut".into())
            }
        );
        assert!(vcs.branches.handoff_receipt("handoff-a").unwrap().is_none());
        assert!(vcs
            .branches
            .contribution_handoff("unit-a")
            .unwrap()
            .is_none());
        assert_eq!(
            vcs.branches
                .release_private_cut(ReleasePrivateCut {
                    pin_id: "pin-a",
                    released_by: "s:author",
                    reason: "cannot release unshared unit",
                    released_at: "t7",
                })
                .unwrap(),
            ReleasePrivateCutOutcome::HasDeclaredUnit
        );
    }

    #[test]
    fn target_cut_provenance_is_checked_inside_the_handoff_transaction() {
        let mut vcs = bound_unit();
        let witness = prepare_target(&mut vcs, "target-a");
        assert_eq!(
            vcs.handoff_private_selection("wrong-actor", &witness, "another", "t5")
                .unwrap(),
            HandoffContributionOutcome::TargetCutAuthorshipMismatch
        );
        assert!(vcs
            .branches
            .handoff_receipt("wrong-actor")
            .unwrap()
            .is_none());
        assert_eq!(
            vcs.branches
                .get_branch("branch")
                .unwrap()
                .unwrap()
                .head_cut_id,
            None
        );

        let mut vcs = bound_unit();
        let basis = vcs.branches.contribution_basis("unit-a").unwrap().unwrap();
        let after = basis.atoms[0].after.clone().unwrap();
        let manifest = vcs
            .store_manifest(&BTreeMap::from([("a.txt".to_owned(), after)]))
            .unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "unrelated-write",
                change_id: "unrelated-write",
                branch_id: "branch",
                manifest_hash: &manifest,
                parent_cut_id: None,
                origin: Some("write:a.txt"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t4",
            })
            .unwrap();
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .verify_private_target_effects("unit-a", "unrelated-write")
            .unwrap()
        else {
            panic!("bytes alone match")
        };
        assert_eq!(
            vcs.handoff_private_selection("wrong-origin", &witness, "mediator", "t5")
                .unwrap(),
            HandoffContributionOutcome::TargetCutAuthorshipMismatch
        );
        assert!(vcs
            .branches
            .handoff_receipt("wrong-origin")
            .unwrap()
            .is_none());
        assert_eq!(
            vcs.branches
                .get_branch("branch")
                .unwrap()
                .unwrap()
                .head_cut_id,
            None
        );
    }

    #[test]
    fn first_branch_cut_compares_inherited_parent_cut() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "base.txt",
            Some("base"),
            "main-base",
            "t1",
        )
        .unwrap();
        vcs.create_branch("branch", None, MAINLINE_BRANCH_ID, "t2")
            .unwrap();
        vcs.create_branch("twig", None, "branch", "t2").unwrap();
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t3")
            .unwrap();
        pin(&mut vcs, "twig-a", "pin-a");
        declare(&mut vcs, "unit-a", "pin-a");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-a", &selection::parse("path(a.txt)").unwrap())
            .unwrap()
        else {
            panic!("source selection")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a", &selection, "t4")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        let source_after = selection.changes()[0].after.clone();
        let target = vcs.branches.get_branch("branch").unwrap().unwrap();
        assert_eq!(target.head_cut_id.as_deref(), Some("main-base"));
        assert_eq!(target.branch_point_cut_id.as_deref(), Some("main-base"));
        let manifest = vcs
            .advance_manifest(
                target.branch_point_manifest_hash.as_deref(),
                &BTreeMap::from([("a.txt".to_owned(), source_after)]),
            )
            .unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "target-a",
                change_id: "shared-a",
                branch_id: "branch",
                manifest_hash: &manifest,
                parent_cut_id: target.branch_point_cut_id.as_deref(),
                origin: Some("transport:twig"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t5",
            })
            .unwrap();
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .verify_private_target_effects("unit-a", "target-a")
            .unwrap()
        else {
            panic!("inherited basis must verify")
        };
        assert_eq!(witness.target_before_cut_id(), Some("main-base"));
        assert!(matches!(
            vcs.handoff_private_selection("handoff-a", &witness, "mediator", "t6")
                .unwrap(),
            HandoffContributionOutcome::Transferred(_)
        ));
    }

    #[test]
    fn planner_refuses_missing_cut_or_actor_without_recording_a_candidate() {
        let mut vcs = bound_unit();
        for (cut_id, actor) in [("", "mediator"), ("target-empty-actor", "")] {
            let error = vcs
                .prepare_private_handoff_target("unit-a", cut_id, actor, "t5")
                .expect_err("a candidate needs both identities");
            assert!(matches!(
                error,
                StoreError::Conflict(reason)
                    if reason.contains("target cut id and actor must be nonempty")
            ));
        }
        assert!(vcs
            .branches
            .get_cut("target-empty-actor")
            .unwrap()
            .is_none());
        assert!(vcs
            .branches
            .contribution_handoff("unit-a")
            .unwrap()
            .is_none());
    }

    #[test]
    fn planner_builds_exact_target_and_stale_handoff_keeps_the_unit_owed() {
        let mut vcs = bound_unit();
        vcs.write("twig", "tail.txt", Some("later"), "twig-tail", "t4")
            .unwrap();
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .prepare_private_handoff_target("unit-a", "target-a", "mediator", "t5")
            .unwrap()
        else {
            panic!("planner must derive target from the selected atom")
        };
        assert_eq!(
            vcs.branches
                .get_branch("branch")
                .unwrap()
                .unwrap()
                .head_cut_id,
            None
        );
        assert_eq!(
            vcs.read("twig", "tail.txt").unwrap().as_deref(),
            Some("later")
        );
        assert_eq!(
            vcs.prepare_private_handoff_target("unit-a", "target-a", "mediator", "t5")
                .unwrap(),
            FlowingTargetEffectsOutcome::Verified(witness.clone())
        );
        assert_eq!(
            vcs.prepare_private_handoff_target("unit-a", "target-a", "mediator", "changed-time")
                .unwrap(),
            FlowingTargetEffectsOutcome::TargetCutMismatch
        );
        vcs.write("branch", "other.txt", Some("other"), "other-cut", "t6")
            .unwrap();
        assert_eq!(
            vcs.handoff_private_selection("handoff-a", &witness, "mediator", "t7")
                .unwrap(),
            HandoffContributionOutcome::TargetStale {
                current_head_cut_id: Some("other-cut".into())
            }
        );
        assert!(vcs
            .branches
            .contribution_handoff("unit-a")
            .unwrap()
            .is_none());
        assert_eq!(
            vcs.branches
                .get_branch("twig")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("twig-tail")
        );
        let FlowingTargetEffectsOutcome::Verified(retry) = vcs
            .prepare_private_handoff_target("unit-a", "target-retry", "mediator", "t8")
            .unwrap()
        else {
            panic!("retry must derive a fresh target from the moved head")
        };
        assert!(matches!(
            vcs.handoff_private_selection("handoff-retry", &retry, "mediator", "t9")
                .unwrap(),
            HandoffContributionOutcome::Transferred(_)
        ));
        assert_eq!(
            vcs.branches
                .get_branch("twig")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("twig-tail")
        );
    }

    #[test]
    fn planner_refuses_conflicting_target_without_minting_a_cut() {
        let mut vcs = bound_unit();
        vcs.write("branch", "a.txt", Some("other"), "other-cut", "t4")
            .unwrap();
        assert_eq!(
            vcs.prepare_private_handoff_target("unit-a", "target-a", "mediator", "t5")
                .unwrap(),
            FlowingTargetEffectsOutcome::BeforeMismatch {
                path: "a.txt".into()
            }
        );
        assert!(vcs.branches.get_cut("target-a").unwrap().is_none());
        assert!(vcs
            .branches
            .contribution_handoff("unit-a")
            .unwrap()
            .is_none());
    }

    #[test]
    fn planner_refuses_unavailable_source_body_without_minting_a_cut() {
        let mut vcs = bound_unit();
        let after = vcs
            .branches
            .contribution_basis("unit-a")
            .unwrap()
            .unwrap()
            .atoms[0]
            .after
            .clone()
            .unwrap();
        assert!(matches!(
            vcs.content.erase(&after, "t4").unwrap(),
            crate::content::EraseOutcome::Erased { .. }
        ));
        assert_eq!(
            vcs.prepare_private_handoff_target("unit-a", "target-a", "mediator", "t5")
                .unwrap(),
            FlowingTargetEffectsOutcome::MissingContent { content_id: after }
        );
        assert!(vcs.branches.get_cut("target-a").unwrap().is_none());
        assert!(vcs
            .branches
            .contribution_handoff("unit-a")
            .unwrap()
            .is_none());
    }

    #[test]
    fn target_effect_comparison_requires_the_actual_selected_bytes() {
        let mut vcs = bound_unit();
        vcs.write("branch", "a.txt", Some("A"), "branch-a", "t4")
            .unwrap();
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .verify_private_target_effects("unit-a", "branch-a")
            .unwrap()
        else {
            panic!("target must contain selected source content")
        };
        assert_eq!(witness.target_branch_id, "branch");
        assert_eq!(witness.effects.len(), 1);
        assert_eq!(witness.effects[0].path, "a.txt");
        assert_eq!(
            witness.effects[0].disposition,
            FlowingEffectDisposition::Applied
        );
        assert_eq!(
            vcs.verify_private_target_effects("missing", "branch-a")
                .unwrap(),
            FlowingTargetEffectsOutcome::UnitMissing
        );
        assert!(vcs
            .branches
            .contribution_declaration("unit-a")
            .unwrap()
            .is_some());
        assert_eq!(
            vcs.handoff_private_selection("op-equivalent", &witness, "mediator", "t6")
                .unwrap(),
            HandoffContributionOutcome::TargetStale {
                current_head_cut_id: Some("branch-a".into())
            }
        );
        assert!(vcs
            .branches
            .handoff_receipt("op-equivalent")
            .unwrap()
            .is_none());
        assert!(vcs
            .branches
            .pinned_cuts("year-3000")
            .unwrap()
            .contains("twig-a"));
    }

    #[test]
    fn mixed_target_comparison_composes_two_bound_writes_to_one_path() {
        let mut vcs = bound_unit();
        vcs.write("twig", "a.txt", Some("B"), "twig-b", "t7")
            .unwrap();
        pin(&mut vcs, "twig-b", "pin-b");
        declare(&mut vcs, "unit-b", "pin-b");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-b", &selection::parse("change(twig-b)").unwrap())
            .unwrap()
        else {
            panic!("second bound source change")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-b", &selection, "t8")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        vcs.write("branch", "a.txt", Some("B"), "target-b", "t9")
            .unwrap();
        let FlowingBatchTargetEffectsOutcome::Verified(batch) = vcs
            .verify_private_batch_target_effects(&["unit-a", "unit-b"], "target-b")
            .unwrap()
        else {
            panic!("ordered source writes explain the one target path")
        };
        assert_eq!(batch.target_branch_id(), "branch");
        assert_eq!(batch.target_before_cut_id(), None);
        assert_eq!(batch.units().len(), 2);
        assert_eq!(
            batch.units()[0].effects[0].disposition,
            FlowingEffectDisposition::Applied
        );
        assert_eq!(
            batch.units()[1].effects[0].disposition,
            FlowingEffectDisposition::Applied
        );
        assert_eq!(
            batch.units()[1].effects[0].before,
            batch.units()[0].effects[0].after
        );
        assert_eq!(
            vcs.verify_private_target_effects("unit-a", "target-b")
                .unwrap(),
            FlowingTargetEffectsOutcome::OmittedEffect {
                path: "a.txt".into()
            }
        );
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-b", "unit-a"], "target-b")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(
                FlowingTargetEffectsOutcome::BeforeMismatch {
                    path: "a.txt".into()
                }
            )
        );
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a"], "target-b")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(FlowingTargetEffectsOutcome::OmittedEffect {
                path: "a.txt".into()
            })
        );
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a", "unit-a"], "target-b")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::DuplicateUnit {
                unit_id: "unit-a".into()
            }
        );
        let mut with_extra = vcs.manifest("branch").unwrap().unwrap();
        with_extra.insert(
            "extra.txt".into(),
            vcs.content.put_text("unselected").unwrap(),
        );
        let extra_hash = vcs.store_manifest(&with_extra).unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "target-extra",
                change_id: "mixed-output",
                branch_id: "branch",
                manifest_hash: &extra_hash,
                parent_cut_id: None,
                origin: Some("transport:batch"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t10",
            })
            .unwrap();
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a", "unit-b"], "target-extra")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(
                FlowingTargetEffectsOutcome::UnexpectedEffect {
                    path: "extra.txt".into()
                }
            )
        );
    }

    #[test]
    fn mixed_target_comparison_keeps_both_units_when_net_content_is_unchanged() {
        let mut vcs = bound_unit();
        vcs.write("twig", "a.txt", None, "twig-undo", "t7").unwrap();
        pin(&mut vcs, "twig-undo", "pin-undo");
        declare(&mut vcs, "unit-undo", "pin-undo");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-undo", &selection::parse("change(twig-undo)").unwrap())
            .unwrap()
        else {
            panic!("undo source change")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-undo", &selection, "t8")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        let empty_hash = vcs.store_manifest(&BTreeMap::new()).unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "target-undo",
                change_id: "mixed-output",
                branch_id: "branch",
                manifest_hash: &empty_hash,
                parent_cut_id: None,
                origin: Some("transport:batch"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t9",
            })
            .unwrap();
        let FlowingBatchTargetEffectsOutcome::Verified(batch) = vcs
            .verify_private_batch_target_effects(&["unit-a", "unit-undo"], "target-undo")
            .unwrap()
        else {
            panic!("both source effects explain the no-op target cut")
        };
        assert_eq!(batch.units().len(), 2);
        assert_eq!(
            batch.units()[0].effects()[0].disposition,
            FlowingEffectDisposition::Applied
        );
        assert_eq!(
            batch.units()[1].effects()[0].disposition,
            FlowingEffectDisposition::Applied
        );
        assert_eq!(batch.units()[1].effects()[0].after, None);
        assert!(vcs
            .branches
            .contribution_handoff("unit-a")
            .unwrap()
            .is_none());
        assert!(vcs
            .branches
            .contribution_handoff("unit-undo")
            .unwrap()
            .is_none());
    }

    #[test]
    fn mixed_target_comparison_refuses_missing_target_and_source_facts() {
        let mut vcs = bound_unit();
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a"], "missing-cut")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(
                FlowingTargetEffectsOutcome::TargetCutMissing
            )
        );
        vcs.write("branch", "a.txt", Some("A"), "target-a", "t10")
            .unwrap();
        let target = vcs.branches.get_cut("target-a").unwrap().unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "orphan-parent",
                change_id: "orphan-parent",
                branch_id: "branch",
                manifest_hash: &target.manifest_hash,
                parent_cut_id: Some("missing-parent"),
                origin: Some("transport:twig"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t11",
            })
            .unwrap();
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a"], "orphan-parent")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(
                FlowingTargetEffectsOutcome::TargetCutMismatch
            )
        );
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "missing-manifest",
                change_id: "missing-manifest",
                branch_id: "branch",
                manifest_hash: "absent-manifest",
                parent_cut_id: None,
                origin: Some("transport:twig"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t12",
            })
            .unwrap();
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a"], "missing-manifest")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(
                FlowingTargetEffectsOutcome::MissingManifest {
                    cut_id: "missing-manifest".into()
                }
            )
        );
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a", "missing-unit"], "target-a")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(FlowingTargetEffectsOutcome::UnitMissing)
        );
        declare(&mut vcs, "unit-unbound", "pin-a");
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a", "unit-unbound"], "target-a")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(FlowingTargetEffectsOutcome::BasisMissing)
        );
        vcs.create_branch("other", None, MAINLINE_BRANCH_ID, "t13")
            .unwrap();
        bind_extra_unit(
            &mut vcs,
            "other",
            "b.txt",
            Some("B"),
            "other-b",
            "pin-other",
            "unit-other",
        );
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a", "unit-other"], "target-a")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(FlowingTargetEffectsOutcome::TargetNotParent)
        );
        vcs.branches.test_connection().execute(
            "UPDATE flowing_contributions SET source_branch_id = 'absent' WHERE unit_id = 'unit-other'",
            [],
        ).unwrap();
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a", "unit-other"], "target-a")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(FlowingTargetEffectsOutcome::TargetNotParent)
        );
    }

    #[test]
    fn mixed_target_comparison_refuses_a_later_unit_on_unrelated_before_content() {
        let mut vcs = bound_unit();
        bind_extra_unit(
            &mut vcs,
            "twig",
            "b.txt",
            Some("B"),
            "twig-b",
            "pin-b",
            "unit-b",
        );
        vcs.write("branch", "b.txt", Some("other"), "branch-other", "t10")
            .unwrap();
        let a = vcs
            .branches
            .contribution_basis("unit-a")
            .unwrap()
            .unwrap()
            .atoms[0]
            .after
            .clone()
            .unwrap();
        let b = vcs
            .branches
            .contribution_basis("unit-b")
            .unwrap()
            .unwrap()
            .atoms[0]
            .after
            .clone()
            .unwrap();
        let candidate_hash = vcs
            .store_manifest(&BTreeMap::from([("a.txt".into(), a), ("b.txt".into(), b)]))
            .unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "target-mixed",
                change_id: "target-mixed",
                branch_id: "branch",
                manifest_hash: &candidate_hash,
                parent_cut_id: Some("branch-other"),
                origin: Some("transport:batch"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t11",
            })
            .unwrap();
        assert_eq!(
            vcs.verify_private_batch_target_effects(&["unit-a", "unit-b"], "target-mixed")
                .unwrap(),
            FlowingBatchTargetEffectsOutcome::Refused(
                FlowingTargetEffectsOutcome::BeforeMismatch {
                    path: "b.txt".into()
                }
            )
        );
    }

    #[test]
    fn planner_records_an_existing_effect_as_equivalent() {
        let mut vcs = bound_unit();
        vcs.write("branch", "a.txt", Some("A"), "branch-a", "t4")
            .unwrap();
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .prepare_private_handoff_target("unit-a", "branch-equivalent", "mediator", "t5")
            .unwrap()
        else {
            panic!("same content is equivalent")
        };
        assert_eq!(
            witness.effects[0].disposition,
            FlowingEffectDisposition::Equivalent
        );
        assert!(vcs
            .branches
            .contribution_declaration("unit-a")
            .unwrap()
            .is_some());
    }

    #[test]
    fn target_effect_comparison_refuses_omission_and_extra_writes() {
        let mut vcs = bound_unit();
        vcs.write("branch", "b.txt", Some("B"), "branch-b", "t4")
            .unwrap();
        assert_eq!(
            vcs.verify_private_target_effects("unit-a", "branch-b")
                .unwrap(),
            FlowingTargetEffectsOutcome::OmittedEffect {
                path: "a.txt".into()
            }
        );
        vcs.write("branch", "a.txt", Some("A"), "branch-a", "t5")
            .unwrap();
        let mut mixed = vcs.manifest("branch").unwrap().unwrap();
        mixed.insert("b.txt".into(), vcs.content.put_text("B2").unwrap());
        let mixed_hash = vcs.store_manifest(&mixed).unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "branch-mixed",
                change_id: "mixed-output",
                branch_id: "branch",
                manifest_hash: &mixed_hash,
                parent_cut_id: Some("branch-b"),
                origin: Some("transport:twig"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t6",
            })
            .unwrap();
        assert_eq!(
            vcs.verify_private_target_effects("unit-a", "branch-mixed")
                .unwrap(),
            FlowingTargetEffectsOutcome::UnexpectedEffect {
                path: "b.txt".into()
            }
        );
    }

    #[test]
    fn target_effect_comparison_refuses_unrelated_before_and_composes_source_path() {
        let mut vcs = bound_unit();
        vcs.write("branch", "a.txt", Some("other"), "branch-other", "t4")
            .unwrap();
        vcs.write("branch", "a.txt", Some("A"), "branch-a", "t5")
            .unwrap();
        assert_eq!(
            vcs.verify_private_target_effects("unit-a", "branch-a")
                .unwrap(),
            FlowingTargetEffectsOutcome::BeforeMismatch {
                path: "a.txt".into()
            }
        );

        let mut repeated_vcs = workspace();
        repeated_vcs.init("t0").unwrap();
        repeated_vcs
            .create_branch("branch", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        repeated_vcs
            .create_branch("twig", None, "branch", "t1")
            .unwrap();
        repeated_vcs
            .write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .unwrap();
        repeated_vcs
            .write("twig", "a.txt", Some("B"), "twig-b", "t3")
            .unwrap();
        pin(&mut repeated_vcs, "twig-b", "pin-b");
        declare(&mut repeated_vcs, "unit-b", "pin-b");
        let FlowingSelectionOutcome::Selected(repeated) = repeated_vcs
            .select_private_changes("pin-b", &selection::parse("path(a.txt)").unwrap())
            .unwrap()
        else {
            panic!("repeated source selection")
        };
        assert_eq!(
            repeated_vcs
                .bind_private_selection("unit-b", &repeated, "t4")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        repeated_vcs
            .write("branch", "a.txt", Some("B"), "branch-b", "t5")
            .unwrap();
        let FlowingTargetEffectsOutcome::Verified(effects) = repeated_vcs
            .verify_private_target_effects("unit-b", "branch-b")
            .unwrap()
        else {
            panic!("consecutive writes must compose");
        };
        assert_eq!(effects.effects.len(), 1);
        assert_eq!(effects.effects[0].path, "a.txt");
        assert_eq!(effects.effects[0].before, None);
        assert_eq!(
            effects.effects[0].disposition,
            FlowingEffectDisposition::Applied
        );
        assert_eq!(
            effects.effects[0].after,
            Some(repeated_vcs.content.put_text("B").unwrap())
        );
    }

    #[test]
    fn target_effect_comparison_refuses_a_skipped_intermediate_source_write() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.create_branch("branch", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.create_branch("twig", None, "branch", "t1").unwrap();
        for (body, cut, time) in [
            ("A", "twig-a", "t2"),
            ("B", "twig-b", "t3"),
            ("C", "twig-c", "t4"),
        ] {
            vcs.write("twig", "a.txt", Some(body), cut, time).unwrap();
        }
        pin(&mut vcs, "twig-c", "pin-c");
        declare(&mut vcs, "unit-c", "pin-c");
        let FlowingSelectionOutcome::Selected(skipped) = vcs
            .select_private_changes(
                "pin-c",
                &selection::parse("change(twig-a) | change(twig-c)").unwrap(),
            )
            .unwrap()
        else {
            panic!("source selection");
        };
        assert_eq!(skipped.changes().len(), 2);
        assert_eq!(
            vcs.bind_private_selection("unit-c", &skipped, "t5")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        vcs.write("branch", "a.txt", Some("C"), "branch-c", "t6")
            .unwrap();
        assert_eq!(
            vcs.verify_private_target_effects("unit-c", "branch-c")
                .unwrap(),
            FlowingTargetEffectsOutcome::IncoherentSourcePath {
                path: "a.txt".into(),
            }
        );
    }

    #[test]
    fn planner_records_a_neutralized_undo() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.create_branch("branch", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.create_branch("twig", None, "branch", "t1").unwrap();
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .unwrap();
        vcs.write("twig", "a.txt", None, "twig-undo", "t3").unwrap();
        pin(&mut vcs, "twig-undo", "pin-undo");
        declare(&mut vcs, "unit-undo", "pin-undo");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-undo", &selection::parse("path(a.txt)").unwrap())
            .unwrap()
        else {
            panic!("select the write and undo");
        };
        assert_eq!(selection.changes().len(), 2);
        assert_eq!(
            vcs.bind_private_selection("unit-undo", &selection, "t4")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .prepare_private_handoff_target("unit-undo", "target-undo", "mediator", "t5")
            .unwrap()
        else {
            panic!("neutralized source unit must still be witnessed");
        };
        assert_eq!(witness.effects().len(), 1);
        assert_eq!(
            witness.effects()[0].disposition,
            FlowingEffectDisposition::Neutralized
        );
        assert!(serde_json::to_string(&witness.effects()[0])
            .unwrap()
            .contains(r#""disposition":"neutralized""#));
        assert!(matches!(
            vcs.handoff_private_selection("op-undo", &witness, "mediator", "t6")
                .unwrap(),
            HandoffContributionOutcome::Transferred(_)
        ));
    }

    #[test]
    fn pinned_cut_selects_real_changes_and_excludes_later_tail() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.write("twig", "a.txt", Some("A"), "c1", "t2").unwrap();
        pin(&mut vcs, "c1", "pin-1");
        vcs.write("twig", "b.txt", Some("B"), "c2", "t3").unwrap();
        let expression = selection::parse("path(*)").unwrap();
        let FlowingSelectionOutcome::Selected(first) =
            vcs.select_private_changes("pin-1", &expression).unwrap()
        else {
            panic!("expected exact source changes");
        };
        assert_eq!(first.source_cut_id(), "c1");
        assert_eq!(first.changes().len(), 1);
        assert_eq!(first.changes()[0].cut_id, "c1");
        assert_eq!(first.changes()[0].path, "a.txt");
        assert!(first.changes()[0].after.is_some());
        assert_eq!(
            first,
            match vcs.select_private_changes("pin-1", &expression).unwrap() {
                FlowingSelectionOutcome::Selected(second) => second,
                other => panic!("unexpected retry: {other:?}"),
            }
        );
        assert!(matches!(
            vcs.select_private_changes("pin-1", &selection::parse("path(b.txt)").unwrap())
                .unwrap(),
            FlowingSelectionOutcome::NothingSelected
        ));
    }

    #[test]
    fn missing_content_and_unmodeled_rewrite_refuse_selection() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "missing",
                change_id: "missing",
                branch_id: "twig",
                manifest_hash: "absent-manifest",
                parent_cut_id: None,
                origin: Some("write:a.txt"),
                actor: Some("s:author"),
                intent: None,
                recorded_at: "t2",
            })
            .unwrap();
        pin(&mut vcs, "missing", "pin-missing");
        let expression = selection::parse("path(*)").unwrap();
        assert_eq!(
            vcs.select_private_changes("pin-missing", &expression)
                .unwrap(),
            FlowingSelectionOutcome::MissingManifest {
                cut_id: "missing".into()
            }
        );

        vcs.write("twig", "a.txt", Some("A"), "c1", "t3").unwrap();
        let manifest = vcs.branches.get_cut("c1").unwrap().unwrap().manifest_hash;
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "rewrite",
                change_id: "new-output-id",
                branch_id: "twig",
                manifest_hash: &manifest,
                parent_cut_id: Some("c1"),
                origin: Some("rebase:mainline"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t4",
            })
            .unwrap();
        pin(&mut vcs, "rewrite", "pin-rewrite");
        assert_eq!(
            vcs.select_private_changes("pin-rewrite", &expression)
                .unwrap(),
            FlowingSelectionOutcome::UnsupportedLineage {
                cut_id: "rewrite".into()
            }
        );
        assert_eq!(
            vcs.select_private_changes("pin-rewrite", &selection::parse("region(core)").unwrap())
                .unwrap(),
            FlowingSelectionOutcome::UnsupportedSelection
        );
    }

    #[test]
    fn legacy_cut_without_parent_cannot_claim_inherited_files_as_source_work() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "inherited.txt",
            Some("base"),
            "main-1",
            "t1",
        )
        .unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t2")
            .unwrap();
        vcs.write("twig", "new.txt", Some("new"), "real-twig-cut", "t3")
            .unwrap();
        pin(&mut vcs, "real-twig-cut", "pin-real");
        let FlowingSelectionOutcome::Selected(real) = vcs
            .select_private_changes("pin-real", &selection::parse("path(*)").unwrap())
            .unwrap()
        else {
            panic!("a cut with a recorded inherited parent should select");
        };
        assert_eq!(real.changes().len(), 1);
        assert_eq!(real.changes()[0].path, "new.txt");
        let inherited_manifest = vcs
            .branches
            .get_cut("main-1")
            .unwrap()
            .unwrap()
            .manifest_hash;
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "legacy-twig-cut",
                change_id: "legacy-change",
                branch_id: "twig",
                manifest_hash: &inherited_manifest,
                parent_cut_id: None,
                origin: Some("write:inherited.txt"),
                actor: Some("s:author"),
                intent: None,
                recorded_at: "t3",
            })
            .unwrap();
        pin(&mut vcs, "legacy-twig-cut", "pin-legacy");
        assert_eq!(
            vcs.select_private_changes("pin-legacy", &selection::parse("path(*)").unwrap())
                .unwrap(),
            FlowingSelectionOutcome::UnsupportedLineage {
                cut_id: "legacy-twig-cut".into()
            }
        );
    }

    #[test]
    fn manifest_with_missing_file_body_cannot_supply_a_source_basis() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        let manifest = vcs
            .content
            .put_text(r#"{"ghost.txt":"absent-body"}"#)
            .unwrap();
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "ghost-cut",
                change_id: "ghost-change",
                branch_id: "twig",
                manifest_hash: &manifest,
                parent_cut_id: None,
                origin: Some("write:ghost.txt"),
                actor: Some("s:author"),
                intent: None,
                recorded_at: "t2",
            })
            .unwrap();
        pin(&mut vcs, "ghost-cut", "pin-ghost");
        assert_eq!(
            vcs.select_private_changes("pin-ghost", &selection::parse("path(*)").unwrap())
                .unwrap(),
            FlowingSelectionOutcome::MissingContent {
                content_id: "absent-body".into()
            }
        );
    }

    #[test]
    fn missing_or_released_pin_and_missing_parent_refuse() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        let expr = selection::parse("path(*)").unwrap();
        assert_eq!(
            vcs.select_private_changes("no-pin", &expr).unwrap(),
            FlowingSelectionOutcome::PinMissing
        );
        vcs.write("twig", "a.txt", Some("A"), "c1", "t2").unwrap();
        pin(&mut vcs, "c1", "pin-released");
        assert_eq!(
            vcs.branches
                .release_private_cut(ReleasePrivateCut {
                    pin_id: "pin-released",
                    released_by: "s:author",
                    reason: "explicitly abandoned",
                    released_at: "t3",
                })
                .unwrap(),
            ReleasePrivateCutOutcome::Released
        );
        assert_eq!(
            vcs.select_private_changes("pin-released", &expr).unwrap(),
            FlowingSelectionOutcome::PinReleased
        );
        let manifest = vcs.branches.get_cut("c1").unwrap().unwrap().manifest_hash;
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "orphan",
                change_id: "orphan",
                branch_id: "twig",
                manifest_hash: &manifest,
                parent_cut_id: Some("missing-parent"),
                origin: Some("write:a.txt"),
                actor: Some("s:author"),
                intent: None,
                recorded_at: "t4",
            })
            .unwrap();
        pin(&mut vcs, "orphan", "pin-orphan");
        assert_eq!(
            vcs.select_private_changes("pin-orphan", &expr).unwrap(),
            FlowingSelectionOutcome::MissingParent {
                cut_id: "missing-parent".into()
            }
        );
    }

    #[test]
    fn two_units_on_one_pin_bind_distinct_atoms_and_reject_double_ownership() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.write("twig", "a.txt", Some("A"), "c1", "t2").unwrap();
        vcs.write("twig", "b.txt", Some("B"), "c2", "t3").unwrap();
        pin(&mut vcs, "c2", "shared-pin");
        for unit in ["u-a", "u-b", "u-duplicate"] {
            declare(&mut vcs, unit, "shared-pin");
        }
        let FlowingSelectionOutcome::Selected(a) = vcs
            .select_private_changes("shared-pin", &selection::parse("path(a.txt)").unwrap())
            .unwrap()
        else {
            panic!("select a")
        };
        let FlowingSelectionOutcome::Selected(b) = vcs
            .select_private_changes("shared-pin", &selection::parse("path(b.txt)").unwrap())
            .unwrap()
        else {
            panic!("select b")
        };
        assert_ne!(a.digest(), b.digest());
        assert_eq!(
            vcs.bind_private_selection("u-a", &a, "t6").unwrap(),
            BindContributionBasisOutcome::Bound
        );
        assert_eq!(
            vcs.bind_private_selection("u-a", &a, "t6").unwrap(),
            BindContributionBasisOutcome::Existing
        );
        assert_eq!(
            vcs.bind_private_selection("u-a", &b, "t6").unwrap(),
            BindContributionBasisOutcome::IdentityMismatch
        );
        assert_eq!(
            vcs.bind_private_selection("u-b", &b, "t6").unwrap(),
            BindContributionBasisOutcome::Bound
        );
        assert_eq!(
            vcs.bind_private_selection("u-duplicate", &a, "t6").unwrap(),
            BindContributionBasisOutcome::AtomOwned {
                unit_id: "u-a".into(),
                cut_id: "c1".into(),
                path: "a.txt".into(),
            }
        );
        assert_eq!(
            vcs.branches.contribution_basis("u-duplicate").unwrap(),
            None
        );
        assert_eq!(
            vcs.branches
                .contribution_basis("u-a")
                .unwrap()
                .unwrap()
                .atoms,
            a.changes()
        );
        assert_eq!(
            vcs.branches
                .contribution_basis("u-b")
                .unwrap()
                .unwrap()
                .atoms,
            b.changes()
        );
        pin(&mut vcs, "c2", "other-pin");
        declare(&mut vcs, "u-other", "other-pin");
        assert_eq!(
            vcs.bind_private_selection("u-other", &a, "t6").unwrap(),
            BindContributionBasisOutcome::SelectionMismatch
        );
        assert_eq!(vcs.branches.contribution_basis("u-other").unwrap(), None);
    }

    #[test]
    fn erased_selected_content_refuses_binding_without_a_partial_basis() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.write("twig", "a.txt", Some("A"), "c1", "t2").unwrap();
        pin(&mut vcs, "c1", "pin-1");
        declare(&mut vcs, "u-a", "pin-1");
        let FlowingSelectionOutcome::Selected(a) = vcs
            .select_private_changes("pin-1", &selection::parse("path(*)").unwrap())
            .unwrap()
        else {
            panic!("select a")
        };
        let body = a.changes()[0].after.as_deref().unwrap();
        assert!(matches!(
            vcs.content.erase(body, "t5").unwrap(),
            crate::content::EraseOutcome::Erased { .. }
        ));
        assert!(vcs.bind_private_selection("u-a", &a, "t6").is_err());
        assert_eq!(vcs.branches.contribution_basis("u-a").unwrap(), None);
    }

    #[test]
    fn native_basis_binding_rolls_back_all_atom_owners_on_late_failure() {
        let mut vcs = super::super::tests::vcs();
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.write("twig", "a.txt", Some("A"), "c1", "t2").unwrap();
        vcs.write("twig", "b.txt", Some("B"), "c2", "t3").unwrap();
        let cut = vcs.branches.get_cut("c2").unwrap().unwrap();
        vcs.branches
            .pin_private_cut(PinPrivateCut {
                pin_id: "pin-both",
                twig_branch_id: "twig",
                cut_id: "c2",
                manifest_hash: &cut.manifest_hash,
                principal: "s:author",
                retained_at: "t4",
            })
            .unwrap();
        vcs.branches
            .declare_contribution(DeclareContribution {
                unit_id: "unit-both",
                pin_id: "pin-both",
                principal: "s:author",
                intent: "two files",
                read_basis_digest: "reads-1",
                dependency_basis_digest: "deps-1",
                scope_digest: "scope-both",
                declared_at: "t5",
            })
            .unwrap();
        let FlowingSelectionOutcome::Selected(basis) = vcs
            .select_private_changes("pin-both", &selection::parse("path(*)").unwrap())
            .unwrap()
        else {
            panic!("select both")
        };
        let connection = rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_second_atom BEFORE INSERT ON flowing_source_atom_owners \
             WHEN NEW.path = 'b.txt' BEGIN SELECT RAISE(ABORT, 'late atom failure'); END",
            )
            .unwrap();
        assert!(vcs
            .bind_private_selection("unit-both", &basis, "t6")
            .is_err());
        assert_eq!(vcs.branches.contribution_basis("unit-both").unwrap(), None);
        let owners: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM flowing_source_atom_owners",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(owners, 0);
        connection
            .execute_batch("DROP TRIGGER fail_second_atom")
            .unwrap();
        assert_eq!(
            vcs.bind_private_selection("unit-both", &basis, "t6")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
    }
}
