//! Exact source-change extraction for a retained private cut (DR-0130, FB-2).
//!
//! This is a read-only preparation step. It makes no handoff or admission
//! claim: those require the target-content proof and an atomic receipt. In
//! particular, legacy rewrite/transport cuts lack constituent lineage, so
//! they refuse here instead of manufacturing change identities from a diff.

use std::collections::{BTreeMap, BTreeSet};

use crate::branches::flowing_sources::{
    BindContributionBasis, BindContributionBasisOutcome, ContributionBasis, FlowingSources,
    HandoffContribution, HandoffContributionOutcome,
};
use crate::branches::{BranchStatus, Branches, CutRecord, CutRow};
use crate::content::ContentBlobs;
use crate::selection::{self, SelAtom, SelExpr};
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
/// nor transfers the unit. The later handoff must bind this exact comparison
/// to the target ref transition and record its receipt atomically. Its fields
/// are private so a caller cannot supply asserted effects in place of a read.
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
    MissingManifest { cut_id: String },
    MissingContent { content_id: String },
    IncoherentSourcePath { path: String },
    BeforeMismatch { path: String },
    OmittedEffect { path: String },
    UnexpectedEffect { path: String },
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
        // `record_cut` is first-writer-wins for its identity. A concurrent
        // writer can win between the preceding read and this write; re-read
        // before giving the caller a witness for that identity.
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
    /// No caller may treat `Verified` as a handoff receipt.
    pub fn verify_private_target_effects(
        &self,
        unit_id: &str,
        target_cut_id: &str,
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
        if target_branch_id == crate::branches::MAINLINE_BRANCH_ID {
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
    use crate::branches::flowing_sources::{
        DeclareContribution, DeclareContributionOutcome, PinPrivateCut, PinPrivateCutOutcome,
        ReleasePrivateCut, ReleasePrivateCutOutcome,
    };
    use crate::branches::{BranchStore, CutRecord, MAINLINE_BRANCH_ID};
    use crate::content::ContentStore;

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

    fn bound_unit() -> WorkspaceVcs<BranchStore, ContentStore> {
        let mut vcs = workspace();
        vcs.init("t0").expect("initialize workspace");
        vcs.create_branch("branch", None, MAINLINE_BRANCH_ID, "t1")
            .expect("create target branch");
        vcs.create_branch("twig", None, "branch", "t1")
            .expect("create source twig");
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
