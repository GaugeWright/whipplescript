//! Content-derived preparation for a disjoint flowing twig rebase (FB-2).
//!
//! Preparation establishes content replay, not compatibility of a unit's read
//! or dependency basis with the new parent. The writer below publishes the
//! cut, root edge, and ref move under an embedding-provided final authority
//! check. The reader verifies the historical edge and content independently;
//! neither step by itself certifies trunk admission.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::branches::flowing_admission::FlowingAdmissions;
use crate::branches::flowing_fence::FlowingSourceKind;
use crate::branches::flowing_rewrite::{
    CommitFlowingRewrite, FlowingRewriteOutcome, FlowingRewrites,
};
use crate::branches::flowing_sources::FlowingSources;
use crate::branches::{BranchStatus, Branches};
use crate::content::ContentBlobs;
use crate::StoreResult;

use super::flowing_selection::FlowingSourceAtom;
use super::WorkspaceVcs;

mod lineage;
mod roster;
pub use lineage::{
    CurrentFlowingRewritePrefix, CurrentFlowingRewritePrefixOutcome, FlowingRewriteLineage,
    FlowingRewriteLineageOutcome,
};
pub use roster::{
    CurrentFlowingRewriteRoster, CurrentFlowingRewriteRosterOutcome, FlowingRewriteOwedUnit,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowingRewriteRoot {
    unit_id: String,
    basis_digest: String,
    atoms: Vec<FlowingSourceAtom>,
}

impl FlowingRewriteRoot {
    pub fn unit_id(&self) -> &str {
        &self.unit_id
    }
    pub fn basis_digest(&self) -> &str {
        &self.basis_digest
    }
    pub fn atoms(&self) -> &[FlowingSourceAtom] {
        &self.atoms
    }
}

/// A preparation bound to both observed refs and the source fence. Its map is
/// a proposed result, not an admitted cut or evidence that the refs stayed put.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingDisjointRebase {
    source_branch_id: String,
    source_incarnation_id: String,
    source_eligibility_epoch: i64,
    source_owner_epoch: i64,
    old_head_cut_id: String,
    old_head_manifest_hash: String,
    old_point_cut_id: Option<String>,
    old_point_manifest_hash: Option<String>,
    parent_branch_id: String,
    parent_head_cut_id: Option<String>,
    parent_head_manifest_hash: Option<String>,
    roots: Vec<FlowingRewriteRoot>,
    proposed_manifest: BTreeMap<String, String>,
}

impl FlowingDisjointRebase {
    pub fn source_branch_id(&self) -> &str {
        &self.source_branch_id
    }
    pub fn source_incarnation_id(&self) -> &str {
        &self.source_incarnation_id
    }
    pub fn source_eligibility_epoch(&self) -> i64 {
        self.source_eligibility_epoch
    }
    pub fn source_owner_epoch(&self) -> i64 {
        self.source_owner_epoch
    }
    pub fn old_head_cut_id(&self) -> &str {
        &self.old_head_cut_id
    }
    pub fn old_head_manifest_hash(&self) -> &str {
        &self.old_head_manifest_hash
    }
    pub fn old_point_cut_id(&self) -> Option<&str> {
        self.old_point_cut_id.as_deref()
    }
    pub fn old_point_manifest_hash(&self) -> Option<&str> {
        self.old_point_manifest_hash.as_deref()
    }
    pub fn parent_branch_id(&self) -> &str {
        &self.parent_branch_id
    }
    pub fn parent_head_cut_id(&self) -> Option<&str> {
        self.parent_head_cut_id.as_deref()
    }
    pub fn parent_head_manifest_hash(&self) -> Option<&str> {
        self.parent_head_manifest_hash.as_deref()
    }
    pub fn roots(&self) -> &[FlowingRewriteRoot] {
        &self.roots
    }
    pub fn proposed_manifest(&self) -> &BTreeMap<String, String> {
        &self.proposed_manifest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingDisjointRebaseOutcome {
    Prepared(Box<FlowingDisjointRebase>),
    SourceMissing,
    SourceNotReady,
    ParentMissing,
    AlreadyAtParent,
    CutMissing { cut_id: String },
    CutMismatch { cut_id: String },
    UnsupportedLineage { cut_id: String },
    MissingContent { content_id: String },
    IncompleteRoots,
    UnitNotOwed { unit_id: String },
    UnitBasisMismatch { unit_id: String },
    Overlap { path: String },
}

impl<B: Branches + FlowingSources + FlowingAdmissions + FlowingRewrites, C: ContentBlobs>
    WorkspaceVcs<B, C>
{
    /// Derive a replayable result only when every old source atom belongs to
    /// exactly one still-owed bound unit and the new parent left all of those
    /// paths at the old branch-point value. No output cut is published here.
    pub fn prepare_disjoint_flowing_rebase(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<FlowingDisjointRebaseOutcome> {
        use FlowingDisjointRebaseOutcome as R;

        let Some(source) = self.branches.get_branch(source_branch_id)? else {
            return Ok(R::SourceMissing);
        };
        let Some(fence) = self.branches.flowing_source(source_branch_id)? else {
            return Ok(R::SourceNotReady);
        };
        if source.status != BranchStatus::Active
            || fence.kind != FlowingSourceKind::Twig
            || !fence.admission_enabled
            || fence.revision.is_some()
        {
            return Ok(R::SourceNotReady);
        }
        let Some(parent_branch_id) = source.parent_branch_id.as_deref() else {
            return Ok(R::ParentMissing);
        };
        let Some(parent) = self.branches.get_branch(parent_branch_id)? else {
            return Ok(R::ParentMissing);
        };
        if parent.status != BranchStatus::Active {
            return Ok(R::ParentMissing);
        }
        if let Some(parent_head_id) = parent.head_cut_id.as_deref() {
            let Some(parent_head) = self.branches.get_cut(parent_head_id)? else {
                return Ok(R::CutMissing {
                    cut_id: parent_head_id.to_owned(),
                });
            };
            if parent_head.branch_id != parent_branch_id
                || Some(parent_head.manifest_hash.as_str()) != parent.head_manifest_hash.as_deref()
            {
                return Ok(R::CutMismatch {
                    cut_id: parent_head_id.to_owned(),
                });
            }
        } else if parent.head_manifest_hash.is_some() {
            return Ok(R::ParentMissing);
        }
        if source.branch_point_cut_id == parent.head_cut_id
            && source.branch_point_manifest_hash == parent.head_manifest_hash
        {
            return Ok(R::AlreadyAtParent);
        }
        if let Some(point_id) = source.branch_point_cut_id.as_deref() {
            let Some(point) = self.branches.get_cut(point_id)? else {
                return Ok(R::CutMissing {
                    cut_id: point_id.to_owned(),
                });
            };
            if Some(point.manifest_hash.as_str()) != source.branch_point_manifest_hash.as_deref()
                || point.branch_id != parent_branch_id
            {
                return Ok(R::CutMismatch {
                    cut_id: point_id.to_owned(),
                });
            }
        } else if source.branch_point_manifest_hash.is_some() {
            return Ok(R::SourceNotReady);
        }
        let mut parent_cursor = parent.head_cut_id.clone();
        let mut parent_seen = BTreeSet::new();
        while parent_cursor != source.branch_point_cut_id {
            let Some(parent_cut_id) = parent_cursor else {
                return Ok(R::ParentMissing);
            };
            if !parent_seen.insert(parent_cut_id.clone()) {
                return Ok(R::UnsupportedLineage {
                    cut_id: parent_cut_id,
                });
            }
            let Some(parent_cut) = self.branches.get_cut(&parent_cut_id)? else {
                return Ok(R::CutMissing {
                    cut_id: parent_cut_id,
                });
            };
            if parent_cut.branch_id != parent_branch_id {
                return Ok(R::UnsupportedLineage {
                    cut_id: parent_cut_id,
                });
            }
            parent_cursor = parent_cut.parent_cut_id;
        }
        let Some(old_head_cut_id) = source.head_cut_id.as_deref() else {
            return Ok(R::IncompleteRoots);
        };
        let Some(old_head_manifest_hash) = source.head_manifest_hash.as_deref() else {
            return Ok(R::CutMismatch {
                cut_id: old_head_cut_id.to_owned(),
            });
        };
        let mut reverse = Vec::new();
        let mut cursor = Some(old_head_cut_id.to_owned());
        let mut expected_manifest = Some(old_head_manifest_hash.to_owned());
        let mut seen = BTreeSet::new();
        while cursor != source.branch_point_cut_id {
            let Some(cut_id) = cursor else {
                return Ok(R::IncompleteRoots);
            };
            if !seen.insert(cut_id.clone()) {
                return Ok(R::UnsupportedLineage { cut_id });
            }
            let Some(cut) = self.branches.get_cut(&cut_id)? else {
                return Ok(R::CutMissing { cut_id });
            };
            if cut.branch_id != source_branch_id
                || expected_manifest.as_deref() != Some(cut.manifest_hash.as_str())
            {
                return Ok(R::CutMismatch { cut_id });
            }
            let inherited = match cut.origin.as_deref() {
                Some(origin) if origin.starts_with("write:") => None,
                Some("flowing:rebase") => {
                    let FlowingRewriteLineageOutcome::Verified(lineage) =
                        self.verify_flowing_rewrite_lineage(&cut_id)?
                    else {
                        return Ok(R::UnsupportedLineage { cut_id });
                    };
                    let prior = lineage.receipt();
                    if prior.source_branch_id != source_branch_id
                        || prior.source_incarnation_id != fence.incarnation_id
                        || prior.parent_head_cut_id != source.branch_point_cut_id
                        || prior.parent_head_manifest_hash != source.branch_point_manifest_hash
                    {
                        return Ok(R::UnsupportedLineage { cut_id });
                    }
                    Some(lineage.source_atoms().to_vec())
                }
                _ => return Ok(R::UnsupportedLineage { cut_id }),
            };
            if self.load_manifest_opt_raw(&cut.manifest_hash)?.is_none() {
                return Ok(R::MissingContent {
                    content_id: cut.manifest_hash,
                });
            }
            expected_manifest = match cut.parent_cut_id.as_deref() {
                Some(parent_id) => {
                    let Some(predecessor) = self.branches.get_cut(parent_id)? else {
                        return Ok(R::CutMissing {
                            cut_id: parent_id.to_owned(),
                        });
                    };
                    Some(predecessor.manifest_hash)
                }
                None => None,
            };
            cursor = cut.parent_cut_id.clone();
            reverse.push((cut, inherited));
        }
        if expected_manifest != source.branch_point_manifest_hash || reverse.is_empty() {
            return Ok(R::IncompleteRoots);
        }
        reverse.reverse();
        let mut old_atoms = Vec::new();
        for (cut, inherited) in &reverse {
            if let Some(inherited) = inherited {
                old_atoms.extend(inherited.iter().cloned());
                continue;
            }
            let mut changes = Vec::new();
            self.push_units_for_cut(cut, &mut changes)?;
            if changes.is_empty() {
                return Ok(R::UnsupportedLineage {
                    cut_id: cut.cut_id.clone(),
                });
            }
            old_atoms.extend(changes.into_iter().map(|change| FlowingSourceAtom {
                cut_id: change.cut_id,
                change_id: change.change_id,
                path: change.path,
                before: change.before,
                after: change.after,
            }));
        }
        let old_keys: BTreeMap<(String, String), FlowingSourceAtom> = old_atoms
            .iter()
            .cloned()
            .map(|atom| ((atom.cut_id.clone(), atom.path.clone()), atom))
            .collect();
        if old_keys.len() != old_atoms.len() {
            return Ok(R::IncompleteRoots);
        }
        let old_atom_cuts: BTreeSet<&str> =
            old_atoms.iter().map(|atom| atom.cut_id.as_str()).collect();
        let mut owners = BTreeMap::new();
        let mut roots = Vec::new();
        for unit in self.branches.source_contributions(source_branch_id)? {
            if self.branches.contribution_handoff(&unit.unit_id)?.is_some()
                || self
                    .branches
                    .admitted_unit_operation(&unit.unit_id)?
                    .is_some()
            {
                return Ok(R::UnitNotOwed {
                    unit_id: unit.unit_id,
                });
            }
            let Some(pin) = self.branches.private_cut_pin(&unit.pin_id)? else {
                return Ok(R::UnitBasisMismatch {
                    unit_id: unit.unit_id,
                });
            };
            if pin.released_at.is_some()
                || pin.twig_branch_id != source_branch_id
                || pin.cut_id != unit.source_cut_id
                || pin.manifest_hash != unit.source_manifest_hash
                || !old_atom_cuts.contains(unit.source_cut_id.as_str())
            {
                return Ok(R::UnitBasisMismatch {
                    unit_id: unit.unit_id,
                });
            }
            let Some(basis) = self.branches.contribution_basis(&unit.unit_id)? else {
                return Ok(R::IncompleteRoots);
            };
            let encoded = serde_json::to_vec(&(
                "flowing-source-selection-v1",
                &pin.pin_id,
                &pin.twig_branch_id,
                &pin.cut_id,
                &pin.manifest_hash,
                &basis.atoms,
            ))?;
            let digest = format!("sha256:{}", crate::chunking::content_hash_hex(&encoded));
            if basis.basis_digest != digest || basis.atoms.is_empty() {
                return Ok(R::UnitBasisMismatch {
                    unit_id: unit.unit_id,
                });
            }
            for atom in &basis.atoms {
                let key = (atom.cut_id.clone(), atom.path.clone());
                if old_keys.get(&key) != Some(atom)
                    || owners.insert(key, unit.unit_id.clone()).is_some()
                {
                    return Ok(R::UnitBasisMismatch {
                        unit_id: unit.unit_id,
                    });
                }
            }
            roots.push(FlowingRewriteRoot {
                unit_id: unit.unit_id,
                basis_digest: basis.basis_digest,
                atoms: basis.atoms,
            });
        }
        if roots.is_empty() || owners.len() != old_keys.len() {
            return Ok(R::IncompleteRoots);
        }
        let old_point = self.load_manifest(source.branch_point_manifest_hash.as_deref())?;
        let old_head = self.load_manifest(Some(old_head_manifest_hash))?;
        let mut proposed_manifest = self.load_manifest(parent.head_manifest_hash.as_deref())?;
        let changed_paths: BTreeSet<&str> =
            old_atoms.iter().map(|atom| atom.path.as_str()).collect();
        for path in &changed_paths {
            if old_point.get(*path) != proposed_manifest.get(*path) {
                return Ok(R::Overlap {
                    path: (*path).to_owned(),
                });
            }
        }
        for atom in &old_atoms {
            if proposed_manifest.get(&atom.path) != atom.before.as_ref() {
                return Ok(R::UnitBasisMismatch {
                    unit_id: owners[&(atom.cut_id.clone(), atom.path.clone())].clone(),
                });
            }
            match &atom.after {
                Some(after) => {
                    proposed_manifest.insert(atom.path.clone(), after.clone());
                }
                None => {
                    proposed_manifest.remove(&atom.path);
                }
            }
        }
        if changed_paths
            .iter()
            .any(|path| old_head.get(*path) != proposed_manifest.get(*path))
        {
            return Ok(R::IncompleteRoots);
        }
        for content_id in old_atoms
            .iter()
            .flat_map(|atom| [atom.before.as_ref(), atom.after.as_ref()])
            .flatten()
            .chain(proposed_manifest.values())
        {
            if !self.content.cached_read_available(content_id)? {
                return Ok(R::MissingContent {
                    content_id: content_id.clone(),
                });
            }
        }
        roots.sort_by_key(|root| {
            old_atoms
                .iter()
                .position(|atom| owners[&(atom.cut_id.clone(), atom.path.clone())] == root.unit_id)
                .expect("a bound root owns an old atom")
        });
        Ok(R::Prepared(Box::new(FlowingDisjointRebase {
            source_branch_id: source_branch_id.to_owned(),
            source_incarnation_id: fence.incarnation_id,
            source_eligibility_epoch: fence.eligibility_epoch,
            source_owner_epoch: fence.owner_epoch,
            old_head_cut_id: old_head_cut_id.to_owned(),
            old_head_manifest_hash: old_head_manifest_hash.to_owned(),
            old_point_cut_id: source.branch_point_cut_id,
            old_point_manifest_hash: source.branch_point_manifest_hash,
            parent_branch_id: parent_branch_id.to_owned(),
            parent_head_cut_id: parent.head_cut_id,
            parent_head_manifest_hash: parent.head_manifest_hash,
            roots,
            proposed_manifest,
        })))
    }
}

impl<B: Branches + FlowingRewrites, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// Publish a prepared replay under retained content and one ref-owned
    /// transaction. The caller must have taken the matching BeginRevision and
    /// must hold the Home/norm exclusion needed by `check` to prove that each
    /// source unit's read, dependency and policy basis still applies to the
    /// new parent. The callback runs inside the branch transaction just
    /// before its first write; an embedding without that proof must refuse.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_prepared_disjoint_flowing_rebase(
        &mut self,
        plan: &FlowingDisjointRebase,
        op_id: &str,
        begin_revision_op_id: &str,
        after_cut_id: &str,
        actor: &str,
        recorded_at: &str,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<FlowingRewriteOutcome> {
        let prepared = crate::content::publication::PreparedBlobs::new(&self.content);
        let manifest_hash = crate::manifest_tree::build(&prepared, plan.proposed_manifest())?;
        let mut retained: BTreeSet<String> = prepared.ids().into_iter().collect();
        retained.extend(plan.proposed_manifest().values().cloned());
        retained.insert(plan.old_head_manifest_hash().to_owned());
        if let Some(hash) = plan.parent_head_manifest_hash() {
            retained.insert(hash.to_owned());
        }
        for atom in plan.roots().iter().flat_map(|root| root.atoms()) {
            retained.extend(atom.before.iter().cloned());
            retained.extend(atom.after.iter().cloned());
        }
        let ids: Vec<String> = retained.into_iter().collect();
        let branches = &mut self.branches;
        self.content.publish_retained(&ids, || {
            branches.commit_flowing_rewrite(
                CommitFlowingRewrite::new(
                    op_id,
                    begin_revision_op_id,
                    plan,
                    after_cut_id,
                    &manifest_hash,
                    actor,
                    recorded_at,
                ),
                check,
            )
        })
    }
}

#[cfg(all(test, feature = "native"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        OpenFlowingSource, OpenFlowingSourceOutcome,
    };
    use crate::branches::flowing_rewrite::{
        check_current, FlowingRewriteOutcome, FlowingRewriteReceipt, FlowingRewriteRefusal,
        FlowingRewrites, RewriteUnitState,
    };
    use crate::branches::flowing_sources::{
        BindContributionBasis, BindContributionBasisOutcome, DeclareContribution,
        DeclareContributionOutcome, PinPrivateCut, PinPrivateCutOutcome, ReleasePrivateCut,
        ReleasePrivateCutOutcome,
    };
    use crate::branches::{BranchStore, MAINLINE_BRANCH_ID};
    use crate::content::ContentStore;
    use crate::selection;
    use crate::vcs::flowing_selection::FlowingSelectionOutcome;

    fn workspace() -> WorkspaceVcs<BranchStore, ContentStore> {
        WorkspaceVcs::from_parts(
            BranchStore::open_in_memory().unwrap(),
            ContentStore::open(":memory:").unwrap(),
        )
    }

    fn bound_write(
        vcs: &mut WorkspaceVcs<BranchStore, ContentStore>,
        path: &str,
        body: &str,
        cut_id: &str,
        unit_id: &str,
    ) {
        vcs.write("twig", path, Some(body), cut_id, "t2").unwrap();
        let cut = vcs.branches.get_cut(cut_id).unwrap().unwrap();
        let pin_id = format!("pin-{unit_id}");
        assert_eq!(
            vcs.branches
                .pin_private_cut(PinPrivateCut {
                    pin_id: &pin_id,
                    twig_branch_id: "twig",
                    cut_id,
                    manifest_hash: &cut.manifest_hash,
                    principal: "s:author",
                    retained_at: "t3",
                })
                .unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        assert_eq!(
            vcs.branches
                .declare_contribution(DeclareContribution {
                    unit_id,
                    pin_id: &pin_id,
                    principal: "s:author",
                    intent: "rebase fixture",
                    read_basis_digest: "read-fixture",
                    dependency_basis_digest: "deps-fixture",
                    scope_digest: unit_id,
                    declared_at: "t3",
                })
                .unwrap(),
            DeclareContributionOutcome::Declared
        );
        let expr = selection::parse(&format!("change({cut_id})")).unwrap();
        let FlowingSelectionOutcome::Selected(selected) =
            vcs.select_private_changes(&pin_id, &expr).unwrap()
        else {
            panic!("select the exact write");
        };
        assert_eq!(
            vcs.branches
                .bind_contribution_basis(BindContributionBasis::new(unit_id, &selected, "t3"))
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
    }

    fn two_units() -> WorkspaceVcs<BranchStore, ContentStore> {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.write(MAINLINE_BRANCH_ID, "base.txt", Some("base"), "base", "t1")
            .unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        assert!(matches!(
            vcs.branches
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc-1".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "s:author".into(),
                    opened_at: "t1".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        bound_write(&mut vcs, "a.txt", "A", "cut-a", "unit-a");
        bound_write(&mut vcs, "b.txt", "B", "cut-b", "unit-b");
        vcs
    }

    #[test]
    fn whole_twig_abandonment_prepares_every_bound_unit_without_moving_a_ref() {
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as A;

        let vcs = two_units();
        let before = vcs.branches.get_branch("twig").unwrap().unwrap();
        let A::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("complete direct twig should prepare");
        };
        assert_eq!(plan.before_cut_id(), "cut-b");
        assert_eq!(plan.branch_point_cut_id(), Some("base"));
        assert_eq!(plan.units().len(), 2);
        assert_eq!(plan.units()[0].unit_id(), "unit-a");
        assert_eq!(plan.units()[1].unit_id(), "unit-b");
        assert_eq!(plan.units()[0].atoms()[0].cut_id, "cut-a");
        assert_eq!(plan.units()[1].atoms()[0].cut_id, "cut-b");
        assert_eq!(vcs.branches.get_branch("twig").unwrap().unwrap(), before);
    }

    #[test]
    fn whole_twig_abandonment_refuses_an_undeclared_tail_or_changed_basis() {
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as A;

        let mut vcs = two_units();
        vcs.write("twig", "tail.txt", Some("tail"), "tail", "t4")
            .unwrap();
        assert_eq!(
            vcs.prepare_whole_twig_abandonment("twig").unwrap(),
            A::IncompleteUnits
        );

        let vcs = two_units();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_contribution_basis SET atoms_json = '[]' WHERE unit_id = 'unit-a'",
                [],
            )
            .unwrap();
        assert_eq!(
            vcs.prepare_whole_twig_abandonment("twig").unwrap(),
            A::UnitBasisMismatch {
                unit_id: "unit-a".into()
            }
        );
    }

    #[test]
    fn whole_twig_abandonment_keeps_overlapping_unit_atoms_distinct() {
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as A;

        let mut vcs = two_units();
        bound_write(&mut vcs, "a.txt", "A2", "cut-a2", "unit-a2");
        let A::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("ordered overlapping writes should prepare together");
        };
        assert_eq!(plan.units().len(), 3);
        let first = plan
            .units()
            .iter()
            .find(|u| u.unit_id() == "unit-a")
            .unwrap();
        let last = plan
            .units()
            .iter()
            .find(|u| u.unit_id() == "unit-a2")
            .unwrap();
        assert_eq!(first.atoms()[0].after, last.atoms()[0].before);
        assert_eq!(last.atoms()[0].cut_id, "cut-a2");
    }

    #[test]
    fn whole_twig_abandonment_refuses_rewritten_lineage_until_it_can_prove_it() {
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as A;

        let (mut vcs, _) = committed_two_unit_rewrite();
        finish_rewrite(&mut vcs);
        assert_eq!(
            vcs.prepare_whole_twig_abandonment("twig").unwrap(),
            A::UnsupportedLineage {
                cut_id: "rebased".into()
            }
        );
    }

    fn begin_abandonment(
        vcs: &mut WorkspaceVcs<BranchStore, ContentStore>,
        plan: &crate::vcs::flowing_abandonment::WholeTwigAbandonment,
    ) {
        assert!(matches!(
            vcs.branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "begin-abandon".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: plan.source_incarnation_id().into(),
                    expected_eligibility_epoch: plan.source_eligibility_epoch(),
                    expected_owner_epoch: plan.source_owner_epoch(),
                    actor: "s:author".into(),
                    action: FlowingFenceAction::BeginRevision {
                        before_cut_id: Some(plan.before_cut_id().into()),
                        after_cut_id: "abandoned".into(),
                    },
                    recorded_at: "t5".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
    }

    #[test]
    fn whole_twig_abandonment_ref_entry_requires_active_unreserved_exact_revision() {
        use crate::branches::flowing_abandonment::{
            check_current as check_abandonment_current, AbandonUnitState,
            FlowingAbandonmentReceipt, FlowingAbandonmentRefusal as R,
        };
        use crate::branches::BranchStatus;
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as P;

        let mut vcs = two_units();
        let P::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        let source = vcs.branches.get_branch("twig").unwrap().unwrap();
        begin_abandonment(&mut vcs, &plan);
        let fence = vcs.branches.flowing_source("twig").unwrap().unwrap();
        let units: Vec<_> = vcs
            .branches
            .source_contributions("twig")
            .unwrap()
            .into_iter()
            .map(|declaration| AbandonUnitState {
                basis: vcs
                    .branches
                    .contribution_basis(&declaration.unit_id)
                    .unwrap(),
                pin: vcs.branches.private_cut_pin(&declaration.pin_id).unwrap(),
                handed_off: false,
                admitted: false,
                parked: false,
                abandoned: false,
                declaration,
            })
            .collect();
        let receipt = FlowingAbandonmentReceipt {
            op_id: "abandon-op".into(),
            begin_revision_op_id: "begin-abandon".into(),
            source_branch_id: plan.source_branch_id().into(),
            source_incarnation_id: plan.source_incarnation_id().into(),
            source_eligibility_epoch_before_revision: plan.source_eligibility_epoch(),
            source_owner_epoch: plan.source_owner_epoch(),
            before_cut_id: plan.before_cut_id().into(),
            before_manifest_hash: plan.before_manifest_hash().into(),
            branch_point_cut_id: plan.branch_point_cut_id().map(str::to_owned),
            branch_point_manifest_hash: plan.branch_point_manifest_hash().map(str::to_owned),
            after_cut_id: "abandoned".into(),
            after_manifest_hash: "replacement-manifest".into(),
            units: plan.units().to_vec(),
            actor: "s:author".into(),
            recorded_at: "t6".into(),
        };
        let check = |source, fence, reserved| {
            check_abandonment_current(&receipt, source, fence, reserved, &units)
        };
        assert!(check(Some(source.clone()), Some(fence.clone()), false).is_ok());
        let mut invalid = receipt.clone();
        invalid.op_id.clear();
        assert_eq!(
            check_abandonment_current(
                &invalid,
                Some(source.clone()),
                Some(fence.clone()),
                false,
                &units,
            ),
            Err(R::Invalid)
        );
        assert_eq!(
            check(None, Some(fence.clone()), false),
            Err(R::SourceMissing)
        );
        let mut inactive = source.clone();
        inactive.status = BranchStatus::Discarded;
        assert_eq!(
            check(Some(inactive), Some(fence.clone()), false),
            Err(R::SourceNotActive)
        );
        assert_eq!(
            check(Some(source.clone()), Some(fence.clone()), true),
            Err(R::HeadReserved)
        );
        let mut moved = source.clone();
        moved.head_cut_id = Some("another-cut".into());
        assert_eq!(
            check(Some(moved), Some(fence.clone()), false),
            Err(R::SourceMoved)
        );
        assert_eq!(
            check(Some(source.clone()), None, false),
            Err(R::RevisionMissing)
        );
        let mut missing_revision = fence.clone();
        missing_revision.revision = None;
        assert_eq!(
            check(Some(source.clone()), Some(missing_revision), false),
            Err(R::RevisionMissing)
        );
        let mut wrong_revision = fence.clone();
        wrong_revision.owner_epoch += 1;
        assert_eq!(
            check(Some(source.clone()), Some(wrong_revision), false),
            Err(R::RevisionMismatch)
        );
        assert_eq!(
            check_abandonment_current(
                &receipt,
                Some(source.clone()),
                Some(fence.clone()),
                false,
                &units[..1],
            ),
            Err(R::UnitRosterChanged)
        );
        let mut unknown_unit = units.clone();
        unknown_unit[0].declaration.unit_id = "unknown-unit".into();
        assert_eq!(
            check_abandonment_current(
                &receipt,
                Some(source.clone()),
                Some(fence.clone()),
                false,
                &unknown_unit,
            ),
            Err(R::UnitRosterChanged)
        );
        let mut terminal_unit = units.clone();
        terminal_unit[0].admitted = true;
        assert_eq!(
            check_abandonment_current(
                &receipt,
                Some(source.clone()),
                Some(fence.clone()),
                false,
                &terminal_unit,
            ),
            Err(R::UnitNoLongerOwed {
                unit_id: "unit-a".into()
            })
        );
        let mut duplicate_unit = units.clone();
        duplicate_unit[1] = duplicate_unit[0].clone();
        assert_eq!(
            check_abandonment_current(
                &receipt,
                Some(source.clone()),
                Some(fence.clone()),
                false,
                &duplicate_unit,
            ),
            Err(R::UnitRosterChanged)
        );
        let mut missing_basis = units.clone();
        missing_basis[0].basis = None;
        assert_eq!(
            check_abandonment_current(
                &receipt,
                Some(source.clone()),
                Some(fence.clone()),
                false,
                &missing_basis,
            ),
            Err(R::UnitBasisChanged {
                unit_id: "unit-a".into()
            })
        );
        let mut missing_pin = units.clone();
        missing_pin[0].pin = None;
        assert_eq!(
            check_abandonment_current(
                &receipt,
                Some(source.clone()),
                Some(fence.clone()),
                false,
                &missing_pin,
            ),
            Err(R::UnitBasisChanged {
                unit_id: "unit-a".into()
            })
        );
        let mut wrong_basis = units.clone();
        wrong_basis[0].basis.as_mut().unwrap().basis_digest = "wrong".into();
        assert_eq!(
            check_abandonment_current(&receipt, Some(source), Some(fence), false, &wrong_basis,),
            Err(R::UnitBasisChanged {
                unit_id: "unit-a".into()
            })
        );
    }

    #[test]
    fn whole_twig_abandonment_moves_head_and_disposes_every_unit_atomically() {
        use crate::branches::flowing_abandonment::{
            FlowingAbandonmentOutcome as A, FlowingAbandonments,
        };
        use crate::branches::flowing_close_roster::{
            FlowingCloseRosterReader, FlowingCloseUnitState,
        };
        use crate::vcs::flowing_abandonment::FlowingAbandonmentLineageOutcome as L;
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as P;

        let mut vcs = two_units();
        let P::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        let point = vcs
            .load_manifest(plan.branch_point_manifest_hash())
            .unwrap();
        begin_abandonment(&mut vcs, &plan);
        let A::Committed(receipt) = vcs
            .commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap()
        else {
            panic!("committed");
        };
        assert_eq!(receipt.units.len(), 2);
        let close_roster = vcs.branches.flowing_close_roster("twig").unwrap().unwrap();
        assert_eq!(close_roster.units.len(), 2);
        assert!(close_roster.units.iter().all(|unit| matches!(
            &unit.state,
            FlowingCloseUnitState::Abandoned { op_id } if op_id == "abandon-op"
        )));
        let L::Verified(lineage) = vcs.verify_flowing_abandonment_lineage("abandoned").unwrap()
        else {
            panic!("retained history independently verifies the disposition");
        };
        assert_eq!(lineage.receipt(), &receipt);
        assert_eq!(lineage.source_atoms().len(), 2);
        let host = vcs
            .read_abandonment_evidence("abandon-op")
            .unwrap()
            .expect("verified host disposition");
        assert_eq!(host.units.len(), 2);
        assert_eq!(host.after_cut_id, "abandoned");
        let wire = serde_json::to_vec(&host).unwrap();
        assert_eq!(
            crate::vcs::flowing_abandonment::FlowingHostAbandonmentEvidenceV1::decode(&wire)
                .unwrap(),
            host
        );
        let wire_text = String::from_utf8(wire).unwrap();
        for private in ["a.txt", "b.txt", "rebase fixture", "s:author"] {
            assert!(!wire_text.contains(private), "host wire exposed {private}");
        }
        assert!(vcs
            .read_abandonment_evidence("unknown-op")
            .unwrap()
            .is_none());
        let error = vcs.read_abandonment_evidence("").unwrap_err();
        assert!(format!("{error:?}").contains("operation identity is empty"));
        let mut changed: serde_json::Value = serde_json::from_str(&wire_text).unwrap();
        let decode = |value: &serde_json::Value| {
            crate::vcs::flowing_abandonment::FlowingHostAbandonmentEvidenceV1::decode(
                &serde_json::to_vec(value).unwrap(),
            )
            .unwrap_err()
        };
        changed["units"][1]["unit_id"] = "unit-a".into();
        let error = decode(&changed);
        assert!(format!("{error:?}").contains("invalid or duplicated"));
        changed["units"][1]["unit_id"] = "unit-b".into();
        changed["receipt_digest"] = "sha256:wrong".into();
        let error = decode(&changed);
        assert!(format!("{error:?}").contains("digest is invalid"));
        changed["receipt_digest"] = host.receipt_digest.clone().into();
        changed["schema"] = "whipplescript.flowing_abandonment_evidence.v2".into();
        let error = decode(&changed);
        assert!(format!("{error:?}").contains("wrong evidence schema"));
        changed["schema"] = host.schema.clone().into();
        changed["before_cut_id"] = host.after_cut_id.clone().into();
        let error = decode(&changed);
        assert!(format!("{error:?}").contains("required abandonment coordinate is invalid"));
        changed["before_cut_id"] = host.before_cut_id.clone().into();
        changed["branch_point_cut_id"] = "".into();
        let error = decode(&changed);
        assert!(format!("{error:?}").contains("branch point coordinate is empty"));
        changed["branch_point_cut_id"] = host.branch_point_cut_id.clone().unwrap().into();
        changed["units"] = serde_json::json!([]);
        let error = decode(&changed);
        assert!(format!("{error:?}").contains("abandonment evidence has no units"));
        changed["units"] = serde_json::to_value(&host.units).unwrap();
        changed["unexpected"] = true.into();
        assert!(
            crate::vcs::flowing_abandonment::FlowingHostAbandonmentEvidenceV1::decode(
                &serde_json::to_vec(&changed).unwrap()
            )
            .is_err(),
            "unknown wire fields require a new schema"
        );
        assert_eq!(
            vcs.branches
                .abandoned_unit_operation("unit-a")
                .unwrap()
                .as_deref(),
            Some("abandon-op")
        );
        assert_eq!(
            vcs.branches
                .abandoned_unit_operation("unit-b")
                .unwrap()
                .as_deref(),
            Some("abandon-op")
        );
        let head = vcs.branches.get_branch("twig").unwrap().unwrap();
        assert_eq!(head.head_cut_id.as_deref(), Some("abandoned"));
        assert_eq!(
            vcs.load_manifest(head.head_manifest_hash.as_deref())
                .unwrap(),
            point
        );
        assert_eq!(
            vcs.branches
                .flowing_abandonment_for_cut("abandoned")
                .unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || panic!("exact retry must not repeat the final check"),
            )
            .unwrap(),
            A::Existing(receipt.clone())
        );
        assert_eq!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "changed-time",
                &mut || panic!("mismatched retry must refuse before final check"),
            )
            .unwrap(),
            A::Refused(
                crate::branches::flowing_abandonment::FlowingAbandonmentRefusal::IdentityMismatch
            )
        );
        assert_eq!(
            vcs.branches
                .release_private_cut(ReleasePrivateCut {
                    pin_id: "pin-unit-a",
                    released_by: "s:author",
                    reason: "unit abandoned under exact disposition",
                    released_at: "t7",
                })
                .unwrap(),
            ReleasePrivateCutOutcome::Released
        );
        assert_eq!(
            vcs.branches
                .flowing_abandonment_receipt("abandon-op")
                .unwrap(),
            Some(receipt)
        );
    }

    #[test]
    fn whole_twig_abandonment_is_a_verified_final_close_disposition() {
        use crate::branches::flowing_abandonment::{
            digest, FlowingAbandonmentReceipt, FlowingAbandonments,
        };
        use crate::branches::flowing_close_host::{
            read_close_evidence, FlowingHostCloseDispositionV1, FlowingHostCloseEvidenceV1,
            FLOWING_CLOSE_EVIDENCE_V2,
        };
        use crate::branches::flowing_close_roster::{
            FlowingCloseRosterReader, FlowingCloseUnitState,
        };
        use crate::branches::flowing_final_close::{
            FinalCloseFlowingSource, FlowingFinalClose, FlowingFinalCloseOutcome,
            FlowingFinalCloseRefusal,
        };
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as P;

        let mut vcs = two_units();
        let P::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        begin_abandonment(&mut vcs, &plan);
        vcs.commit_prepared_whole_twig_abandonment(
            &plan,
            "abandon-op",
            "begin-abandon",
            "abandoned",
            "s:author",
            "t6",
            &mut || Ok(()),
        )
        .unwrap();
        for unit_id in ["unit-a", "unit-b"] {
            assert_eq!(
                vcs.branches
                    .release_private_cut(ReleasePrivateCut {
                        pin_id: &format!("pin-{unit_id}"),
                        released_by: "s:author",
                        reason: "unit abandoned under exact disposition",
                        released_at: "t7",
                    })
                    .unwrap(),
                ReleasePrivateCutOutcome::Released
            );
        }
        let fence = vcs.branches.flowing_source("twig").unwrap().unwrap();
        let finished = vcs
            .branches
            .transition_flowing_source(&FlowingFenceTransition {
                op_id: "finish-abandon".into(),
                source_branch_id: "twig".into(),
                incarnation_id: fence.incarnation_id,
                expected_eligibility_epoch: fence.eligibility_epoch,
                expected_owner_epoch: fence.owner_epoch,
                actor: "s:author".into(),
                action: FlowingFenceAction::FinishRevision {
                    begin_op_id: "begin-abandon".into(),
                },
                recorded_at: "t8".into(),
            })
            .unwrap();
        assert!(
            matches!(finished, FlowingFenceOutcome::Applied(_)),
            "{finished:?}"
        );
        for (op_id, action) in [
            ("request-close", FlowingFenceAction::RequestClose),
            ("disable", FlowingFenceAction::DisableAdmission),
        ] {
            let fence = vcs.branches.flowing_source("twig").unwrap().unwrap();
            let transition = vcs
                .branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: op_id.into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: fence.incarnation_id,
                    expected_eligibility_epoch: fence.eligibility_epoch,
                    expected_owner_epoch: fence.owner_epoch,
                    actor: "s:author".into(),
                    action,
                    recorded_at: "t8".into(),
                })
                .unwrap();
            assert!(
                matches!(transition, FlowingFenceOutcome::Applied(_)),
                "{transition:?}"
            );
        }
        let roster = vcs.branches.flowing_close_roster("twig").unwrap().unwrap();
        assert_eq!(roster.units.len(), 2);
        assert!(roster.units.iter().all(|unit| matches!(
            &unit.state,
            FlowingCloseUnitState::Abandoned { op_id } if op_id == "abandon-op"
        )));
        let request = FinalCloseFlowingSource {
            op_id: "final-close".into(),
            source_branch_id: "twig".into(),
            source_incarnation_id: roster.source_fence.incarnation_id.clone(),
            expected_eligibility_epoch: roster.source_fence.eligibility_epoch,
            expected_owner_epoch: roster.source_fence.owner_epoch,
            expected_roster_digest: roster.digest().unwrap(),
            actor: "s:author".into(),
            recorded_at: "t9".into(),
        };
        let original = vcs
            .branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap()
            .unwrap();
        let mut wrong_incarnation = original.clone();
        wrong_incarnation.source_incarnation_id = "other-incarnation".into();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_abandonments SET witness_json = ?1, witness_digest = ?2 \
                 WHERE op_id = 'abandon-op'",
                rusqlite::params![
                    serde_json::to_string(&wrong_incarnation).unwrap(),
                    digest(&wrong_incarnation)
                ],
            )
            .unwrap();
        assert_eq!(
            vcs.branches.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                unit_id: "unit-a".into(),
            })
        );
        let mut extra_value = serde_json::to_value(&original).unwrap();
        let mut extra_unit = extra_value["units"][0].clone();
        extra_unit["unit_id"] = "unit-z".into();
        extra_value["units"]
            .as_array_mut()
            .unwrap()
            .push(extra_unit);
        let extra: FlowingAbandonmentReceipt = serde_json::from_value(extra_value).unwrap();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_abandonments SET witness_json = ?1, witness_digest = ?2 \
                 WHERE op_id = 'abandon-op'",
                rusqlite::params![serde_json::to_string(&extra).unwrap(), digest(&extra)],
            )
            .unwrap();
        vcs.branches
            .test_connection()
            .execute(
                "INSERT INTO flowing_abandoned_units (unit_id, op_id) \
                 VALUES ('unit-z', 'abandon-op')",
                [],
            )
            .unwrap();
        assert_eq!(
            vcs.branches.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                unit_id: "unit-z".into(),
            })
        );
        vcs.branches
            .test_connection()
            .execute(
                "DELETE FROM flowing_abandoned_units WHERE unit_id = 'unit-z'",
                [],
            )
            .unwrap();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_abandonments SET witness_json = ?1, witness_digest = ?2 \
                 WHERE op_id = 'abandon-op'",
                rusqlite::params![serde_json::to_string(&original).unwrap(), digest(&original)],
            )
            .unwrap();
        let outcome = vcs.branches.final_close_flowing_source(&request).unwrap();
        let FlowingFinalCloseOutcome::Closed(receipt) = outcome else {
            panic!("exact abandonment dispositions close the source: {outcome:?}");
        };
        assert_eq!(receipt.unit_evidence.abandonments.len(), 1);
        assert_eq!(receipt.unit_evidence.abandonments[0].units.len(), 2);
        let host = read_close_evidence(&vcs.branches, "twig").unwrap().unwrap();
        assert_eq!(host.schema, FLOWING_CLOSE_EVIDENCE_V2);
        assert_eq!(
            FlowingHostCloseEvidenceV1::decode(&serde_json::to_vec(&host).unwrap()).unwrap(),
            host
        );
        assert!(host.units.iter().all(|unit| matches!(
            &unit.disposition,
            FlowingHostCloseDispositionV1::Abandoned { operation_id, .. }
                if operation_id == "abandon-op"
        )));
        assert_eq!(
            vcs.branches.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Existing(receipt)
        );
    }

    #[test]
    fn whole_twig_abandonment_lineage_refuses_a_rehashed_false_atom() {
        use crate::branches::flowing_abandonment::{digest, FlowingAbandonmentReceipt};
        use crate::vcs::flowing_abandonment::{
            FlowingAbandonmentLineageOutcome as L, WholeTwigAbandonmentOutcome as P,
        };

        let mut vcs = two_units();
        let P::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        begin_abandonment(&mut vcs, &plan);
        vcs.commit_prepared_whole_twig_abandonment(
            &plan,
            "abandon-op",
            "begin-abandon",
            "abandoned",
            "s:author",
            "t6",
            &mut || Ok(()),
        )
        .unwrap();
        let db = vcs.branches.test_connection();
        let raw: String = db
            .query_row(
                "SELECT witness_json FROM flowing_abandonments WHERE op_id = 'abandon-op'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        value["units"][0]["atoms"][0]["after"] = "sha256:false".into();
        let changed: FlowingAbandonmentReceipt = serde_json::from_value(value).unwrap();
        db.execute(
            "UPDATE flowing_abandonments SET witness_json = ?1, witness_digest = ?2 \
             WHERE op_id = 'abandon-op'",
            rusqlite::params![serde_json::to_string(&changed).unwrap(), digest(&changed)],
        )
        .unwrap();
        assert!(matches!(
            vcs.verify_flowing_abandonment_lineage("abandoned").unwrap(),
            L::IncompleteUnits
        ));
        let error = vcs.read_abandonment_evidence("abandon-op").unwrap_err();
        assert!(format!("{error:?}").contains("retained source lineage is unverified"));
    }

    #[test]
    fn whole_twig_abandonment_native_receipt_refuses_changed_digest_cut_and_unit_index() {
        use crate::branches::flowing_abandonment::{
            digest, FlowingAbandonmentOutcome as A, FlowingAbandonments,
        };
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as P;

        let mut vcs = two_units();
        let P::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        begin_abandonment(&mut vcs, &plan);
        let A::Committed(receipt) = vcs
            .commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap()
        else {
            panic!("committed");
        };
        let db = vcs.branches.test_connection();
        db.execute(
            "UPDATE flowing_abandonments SET witness_digest = 'wrong' WHERE op_id = 'abandon-op'",
            [],
        )
        .unwrap();
        let error = vcs
            .branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap_err();
        assert!(format!("{error:?}").contains("receipt differs from its row or digest"));
        db.execute(
            "UPDATE flowing_abandonments SET witness_digest = ?1 WHERE op_id = 'abandon-op'",
            [digest(&receipt)],
        )
        .unwrap();

        db.execute(
            "UPDATE cuts SET origin = 'write:forged' WHERE cut_id = 'abandoned'",
            [],
        )
        .unwrap();
        let error = vcs
            .branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap_err();
        assert!(format!("{error:?}").contains("receipt lost its exact cut"));
        db.execute(
            "UPDATE cuts SET origin = 'flowing:abandon' WHERE cut_id = 'abandoned'",
            [],
        )
        .unwrap();

        db.execute(
            "DELETE FROM flowing_abandoned_units WHERE unit_id = 'unit-b'",
            [],
        )
        .unwrap();
        let error = vcs
            .branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap_err();
        assert!(format!("{error:?}").contains("receipt differs from unit dispositions"));
    }

    #[test]
    fn whole_twig_abandonment_native_refuses_operation_collision_and_reserved_head() {
        use crate::branches::flowing_abandonment::{
            FlowingAbandonmentOutcome as A, FlowingAbandonmentRefusal as R,
        };
        use crate::branches::write_commit::INSERT_OP;
        use crate::branches::HeadReservationOutcome;
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as P;

        let mut vcs = two_units();
        let P::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        begin_abandonment(&mut vcs, &plan);
        assert_eq!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "cut-b",
                "s:author",
                "t6",
                &mut || panic!("reused cut must refuse before final check"),
            )
            .unwrap(),
            A::Refused(R::CutAlreadyRecorded)
        );
        vcs.branches
            .test_connection()
            .execute(
                INSERT_OP,
                rusqlite::params!["abandon-op", "unrelated", "[]", None::<&str>, "t5"],
            )
            .unwrap();
        assert_eq!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || panic!("operation collision must refuse before final check"),
            )
            .unwrap(),
            A::Refused(R::OperationAlreadyRecorded)
        );
        assert_eq!(
            vcs.branches
                .reserve_head("twig", "other-writer", "t5")
                .unwrap(),
            HeadReservationOutcome::Reserved
        );
        assert_eq!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "different-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || panic!("reserved head must refuse before final check"),
            )
            .unwrap(),
            A::Refused(R::HeadReserved)
        );
    }

    #[test]
    fn whole_twig_abandonment_native_refuses_foreign_prior_unit_receipt() {
        use crate::branches::flowing_abandonment::{
            digest, FlowingAbandonmentOutcome as A, FlowingAbandonments,
        };
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as P;

        let mut vcs = two_units();
        let P::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        begin_abandonment(&mut vcs, &plan);
        let A::Committed(mut prior) = vcs
            .commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap()
        else {
            panic!("committed");
        };
        prior.source_branch_id = "another-source".into();
        let db = vcs.branches.test_connection();
        db.execute(
            "UPDATE flowing_abandonments SET witness_json = ?1, witness_digest = ?2 \
             WHERE op_id = 'abandon-op'",
            rusqlite::params![serde_json::to_string(&prior).unwrap(), digest(&prior)],
        )
        .unwrap();
        db.execute(
            "UPDATE cuts SET branch_id = 'another-source' WHERE cut_id = 'abandoned'",
            [],
        )
        .unwrap();
        let error = vcs
            .commit_prepared_whole_twig_abandonment(
                &plan,
                "different-op",
                "begin-abandon",
                "different-cut",
                "s:author",
                "t7",
                &mut || panic!("foreign receipt must refuse before final check"),
            )
            .unwrap_err();
        assert!(format!("{error:?}").contains("abandoned unit differs from its source receipt"));
        assert!(vcs
            .branches
            .flowing_abandonment_receipt("different-op")
            .unwrap()
            .is_none());
    }

    #[test]
    fn whole_twig_abandonment_rolls_back_when_final_authority_refuses() {
        use crate::branches::flowing_abandonment::FlowingAbandonments;
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as P;

        let mut vcs = two_units();
        let P::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        begin_abandonment(&mut vcs, &plan);
        let refused = vcs.commit_prepared_whole_twig_abandonment(
            &plan,
            "abandon-op",
            "begin-abandon",
            "abandoned",
            "s:author",
            "t6",
            &mut || {
                Err(crate::StoreError::Conflict(
                    "current Home basis changed".into(),
                ))
            },
        );
        assert!(refused.is_err());
        assert_eq!(
            vcs.branches
                .get_branch("twig")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("cut-b")
        );
        assert!(vcs.branches.get_cut("abandoned").unwrap().is_none());
        assert!(vcs
            .branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap()
            .is_none());
        assert!(vcs
            .branches
            .abandoned_unit_operation("unit-a")
            .unwrap()
            .is_none());
    }

    #[test]
    fn whole_twig_abandonment_late_unit_insert_failure_keeps_every_unit_owed() {
        use crate::branches::flowing_abandonment::{
            FlowingAbandonmentOutcome, FlowingAbandonments,
        };
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as P;

        let mut vcs = two_units();
        let P::Prepared(plan) = vcs.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        begin_abandonment(&mut vcs, &plan);
        vcs.branches.test_connection().execute_batch(
            "CREATE TRIGGER fail_second_abandoned_unit BEFORE INSERT ON flowing_abandoned_units \
             WHEN NEW.unit_id = 'unit-b' BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
        ).unwrap();
        assert!(vcs
            .commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .is_err());
        assert_eq!(
            vcs.branches
                .get_branch("twig")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("cut-b")
        );
        assert!(vcs.branches.get_cut("abandoned").unwrap().is_none());
        assert!(vcs
            .branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap()
            .is_none());
        assert!(vcs
            .branches
            .abandoned_unit_operation("unit-a")
            .unwrap()
            .is_none());
        assert!(vcs
            .branches
            .abandoned_unit_operation("unit-b")
            .unwrap()
            .is_none());
        vcs.branches
            .test_connection()
            .execute_batch("DROP TRIGGER fail_second_abandoned_unit")
            .unwrap();
        assert!(matches!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap(),
            FlowingAbandonmentOutcome::Committed(_)
        ));
    }

    #[test]
    fn whole_twig_abandonment_refuses_stale_head_new_unit_and_prior_admission() {
        use crate::branches::flowing_abandonment::{
            FlowingAbandonmentOutcome as O, FlowingAbandonmentRefusal as R, FlowingAbandonments,
        };
        use crate::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome as P;

        let mut moved = two_units();
        let P::Prepared(plan) = moved.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        begin_abandonment(&mut moved, &plan);
        moved
            .branches
            .test_connection()
            .execute(
                "UPDATE branches SET head_cut_id = 'other' WHERE branch_id = 'twig'",
                [],
            )
            .unwrap();
        assert_eq!(
            moved
                .commit_prepared_whole_twig_abandonment(
                    &plan,
                    "abandon-op",
                    "begin-abandon",
                    "abandoned",
                    "s:author",
                    "t6",
                    &mut || Ok(()),
                )
                .unwrap(),
            O::Refused(R::SourceMoved)
        );
        assert!(moved
            .branches
            .abandoned_unit_operation("unit-a")
            .unwrap()
            .is_none());

        let mut added = two_units();
        let P::Prepared(plan) = added.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        begin_abandonment(&mut added, &plan);
        assert_eq!(
            added
                .branches
                .declare_contribution(DeclareContribution {
                    unit_id: "unit-later",
                    pin_id: "pin-unit-a",
                    principal: "s:author",
                    intent: "new declaration on retained cut",
                    read_basis_digest: "read",
                    dependency_basis_digest: "deps",
                    scope_digest: "later",
                    declared_at: "t6",
                })
                .unwrap(),
            DeclareContributionOutcome::Declared
        );
        assert_eq!(
            added
                .commit_prepared_whole_twig_abandonment(
                    &plan,
                    "abandon-op",
                    "begin-abandon",
                    "abandoned",
                    "s:author",
                    "t7",
                    &mut || Ok(()),
                )
                .unwrap(),
            O::Refused(R::UnitRosterChanged)
        );
        assert!(added
            .branches
            .abandoned_unit_operation("unit-a")
            .unwrap()
            .is_none());

        let mut admitted = two_units();
        let P::Prepared(plan) = admitted.prepare_whole_twig_abandonment("twig").unwrap() else {
            panic!("prepared");
        };
        begin_abandonment(&mut admitted, &plan);
        admitted
            .branches
            .test_connection()
            .execute_batch(
                "INSERT INTO flowing_admissions (op_id, receipt_json) VALUES ('cas-first', '{}'); \
             INSERT INTO flowing_admitted_units (unit_id, op_id) VALUES ('unit-a', 'cas-first');",
            )
            .unwrap();
        assert_eq!(
            admitted
                .commit_prepared_whole_twig_abandonment(
                    &plan,
                    "abandon-op",
                    "begin-abandon",
                    "abandoned",
                    "s:author",
                    "t6",
                    &mut || Ok(()),
                )
                .unwrap(),
            O::Refused(R::UnitNoLongerOwed {
                unit_id: "unit-a".into()
            })
        );
        assert!(admitted
            .branches
            .abandoned_unit_operation("unit-a")
            .unwrap()
            .is_none());
    }

    fn begin_rewrite(
        vcs: &mut WorkspaceVcs<BranchStore, ContentStore>,
        plan: &FlowingDisjointRebase,
    ) {
        assert!(matches!(
            vcs.branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "begin-rewrite".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: plan.source_incarnation_id().into(),
                    expected_eligibility_epoch: plan.source_eligibility_epoch(),
                    expected_owner_epoch: plan.source_owner_epoch(),
                    actor: "s:author".into(),
                    action: FlowingFenceAction::BeginRevision {
                        before_cut_id: Some(plan.old_head_cut_id().into()),
                        after_cut_id: "rebased".into(),
                    },
                    recorded_at: "t5".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
    }

    fn committed_two_unit_rewrite() -> (
        WorkspaceVcs<BranchStore, ContentStore>,
        FlowingRewriteReceipt,
    ) {
        let mut vcs = two_units();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "parent.txt",
            Some("parent"),
            "parent-next",
            "t4",
        )
        .unwrap();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin_rewrite(&mut vcs, &plan);
        let FlowingRewriteOutcome::Committed(receipt) = vcs
            .commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap()
        else {
            panic!("committed");
        };
        (vcs, receipt)
    }

    fn finish_rewrite(vcs: &mut WorkspaceVcs<BranchStore, ContentStore>) {
        let fence = vcs.branches.flowing_source("twig").unwrap().unwrap();
        assert!(matches!(
            vcs.branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "finish-rewrite".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: fence.incarnation_id,
                    expected_eligibility_epoch: fence.eligibility_epoch,
                    expected_owner_epoch: fence.owner_epoch,
                    actor: "s:author".into(),
                    action: FlowingFenceAction::FinishRevision {
                        begin_op_id: "begin-rewrite".into(),
                    },
                    recorded_at: "t7".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
    }

    #[test]
    fn rewrite_lineage_reader_rederives_both_old_roots_and_output_content() {
        let (vcs, receipt) = committed_two_unit_rewrite();
        let FlowingRewriteLineageOutcome::Verified(lineage) =
            vcs.verify_flowing_rewrite_lineage("rebased").unwrap()
        else {
            panic!("verified rewrite");
        };
        assert_eq!(lineage.receipt(), &receipt);
        assert_eq!(lineage.source_atoms().len(), 2);
        assert_eq!(lineage.source_atoms()[0].cut_id, "cut-a");
        assert_eq!(lineage.source_atoms()[1].cut_id, "cut-b");
        assert_eq!(
            vcs.verify_flowing_rewrite_lineage("absent").unwrap(),
            FlowingRewriteLineageOutcome::CutMissing {
                cut_id: "absent".into()
            }
        );
        assert_eq!(
            vcs.verify_flowing_rewrite_lineage("cut-a").unwrap(),
            FlowingRewriteLineageOutcome::ReceiptMissing {
                cut_id: "cut-a".into()
            }
        );
    }

    #[test]
    fn a_second_disjoint_rewrite_keeps_historical_and_later_units_owed() {
        use crate::vcs::flowing_rewrite::CurrentFlowingRewriteRosterOutcome as R;

        let (mut vcs, first) = committed_two_unit_rewrite();
        finish_rewrite(&mut vcs);
        bound_write(&mut vcs, "tail.txt", "tail", "tail-cut", "unit-tail");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "another-parent.txt",
            Some("parent-2"),
            "parent-2",
            "t8",
        )
        .unwrap();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("the second disjoint parent must be replayable");
        };
        assert_eq!(
            plan.roots()
                .iter()
                .map(FlowingRewriteRoot::unit_id)
                .collect::<Vec<_>>(),
            ["unit-a", "unit-b", "unit-tail"]
        );
        assert_eq!(plan.old_point_cut_id(), Some("parent-next"));
        assert_eq!(plan.parent_head_cut_id(), Some("parent-2"));
        assert!(matches!(
            vcs.branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "begin-rewrite-2".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: plan.source_incarnation_id().into(),
                    expected_eligibility_epoch: plan.source_eligibility_epoch(),
                    expected_owner_epoch: plan.source_owner_epoch(),
                    actor: "s:author".into(),
                    action: FlowingFenceAction::BeginRevision {
                        before_cut_id: Some(plan.old_head_cut_id().into()),
                        after_cut_id: "rebased-2".into(),
                    },
                    recorded_at: "t9".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        let FlowingRewriteOutcome::Committed(second) = vcs
            .commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-2",
                "begin-rewrite-2",
                "rebased-2",
                "s:author",
                "t10",
                &mut || Ok(()),
            )
            .unwrap()
        else {
            panic!("second rewrite must commit");
        };
        let fence = vcs.branches.flowing_source("twig").unwrap().unwrap();
        assert!(matches!(
            vcs.branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "finish-rewrite-2".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: fence.incarnation_id,
                    expected_eligibility_epoch: fence.eligibility_epoch,
                    expected_owner_epoch: fence.owner_epoch,
                    actor: "s:author".into(),
                    action: FlowingFenceAction::FinishRevision {
                        begin_op_id: "begin-rewrite-2".into(),
                    },
                    recorded_at: "t11".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        let FlowingRewriteLineageOutcome::Verified(lineage) =
            vcs.verify_flowing_rewrite_lineage("rebased-2").unwrap()
        else {
            panic!("second receipt must rederive the first receipt and later write");
        };
        assert_eq!(lineage.receipt(), &second);
        assert_eq!(lineage.source_atoms().len(), 3);
        assert_eq!(
            lineage.source_atoms()[0].cut_id,
            first.roots[0].atoms()[0].cut_id
        );
        assert_eq!(
            lineage.source_atoms()[1].cut_id,
            first.roots[1].atoms()[0].cut_id
        );
        assert_eq!(lineage.source_atoms()[2].cut_id, "tail-cut");
        let R::Verified(roster) = vcs
            .verify_current_flowing_rewrite_roster("twig", "rebased-2")
            .unwrap()
        else {
            panic!("all three units must remain separately owed");
        };
        assert_eq!(roster.units().len(), 3);
        assert!(roster.units().iter().all(|unit| unit.from_rewrite));

        vcs.branches
            .test_connection()
            .execute("DELETE FROM flowing_rewrites WHERE op_id = 'rewrite-1'", [])
            .unwrap();
        assert_eq!(
            vcs.verify_flowing_rewrite_lineage("rebased-2").unwrap(),
            FlowingRewriteLineageOutcome::ReceiptMissing {
                cut_id: "rebased".into()
            }
        );
    }

    #[test]
    fn current_rewrite_prefix_keeps_old_roots_distinct_from_later_writes() {
        use crate::vcs::flowing_rewrite::CurrentFlowingRewritePrefixOutcome as R;

        let (mut vcs, receipt) = committed_two_unit_rewrite();
        assert_eq!(
            vcs.verify_current_flowing_rewrite_prefix("twig", "rebased")
                .unwrap(),
            R::SourceNotReady
        );
        finish_rewrite(&mut vcs);
        let initial = vcs
            .verify_current_flowing_rewrite_prefix("twig", "rebased")
            .unwrap();
        let R::Verified(at_rewrite) = initial else {
            panic!("rewritten head must retain its historical roots: {initial:?}");
        };
        assert_eq!(at_rewrite.lineage().receipt(), &receipt);
        assert_eq!(at_rewrite.lineage().source_atoms().len(), 2);
        assert!(at_rewrite.tail_atoms().is_empty());

        vcs.write("twig", "later.txt", Some("later"), "later-cut", "t7")
            .unwrap();
        let after_append = vcs
            .verify_current_flowing_rewrite_prefix("twig", "rebased")
            .unwrap();
        let R::Verified(with_tail) = after_append else {
            panic!("an ordinary append must retain the rewrite prefix: {after_append:?}");
        };
        assert_eq!(with_tail.source_head_cut_id(), "later-cut");
        assert_eq!(with_tail.lineage().receipt(), &receipt);
        assert_eq!(with_tail.lineage().source_atoms().len(), 2);
        assert_eq!(with_tail.tail_atoms().len(), 1);
        assert_eq!(with_tail.tail_atoms()[0].cut_id, "later-cut");
        assert_eq!(with_tail.tail_atoms()[0].path, "later.txt");
        assert_eq!(
            vcs.verify_current_flowing_rewrite_prefix("twig", "cut-a")
                .unwrap(),
            R::UnsupportedTail {
                cut_id: "rebased".into()
            }
        );
    }

    #[test]
    fn rewritten_source_roster_accounts_for_old_roots_and_later_tail() {
        use crate::vcs::flowing_rewrite::CurrentFlowingRewriteRosterOutcome as R;

        let (mut vcs, _) = committed_two_unit_rewrite();
        finish_rewrite(&mut vcs);
        let R::Verified(before_tail) = vcs
            .verify_current_flowing_rewrite_roster("twig", "rebased")
            .unwrap()
        else {
            panic!("both historical roots are still owed");
        };
        assert_eq!(before_tail.units().len(), 2);
        assert!(before_tail.units().iter().all(|unit| unit.from_rewrite));

        vcs.write("twig", "unowned.txt", Some("draft"), "unowned", "t8")
            .unwrap();
        assert_eq!(
            vcs.verify_current_flowing_rewrite_roster("twig", "rebased")
                .unwrap(),
            R::IncompleteRoster
        );
        let R::Verified(selected) = vcs
            .verify_selected_flowing_rewrite_roster("twig", "rebased", "rebased")
            .unwrap()
        else {
            panic!("the old roots remain selectable before an unbound tail");
        };
        assert_eq!(selected.prefix().selected_cut_id(), "rebased");
        assert_eq!(selected.prefix().source_head_cut_id(), "unowned");
        assert_eq!(selected.prefix().later_cut_ids(), &["unowned"]);
        assert_eq!(selected.units().len(), 2);
        // A subsequent declaration cannot hide the earlier unowned write.
        bound_write(&mut vcs, "later.txt", "tail", "later-cut", "unit-tail");
        assert_eq!(
            vcs.verify_current_flowing_rewrite_roster("twig", "rebased")
                .unwrap(),
            R::IncompleteRoster
        );
        let R::Verified(selected) = vcs
            .verify_selected_flowing_rewrite_roster("twig", "rebased", "rebased")
            .unwrap()
        else {
            panic!("neither later cut changes the selected old roots");
        };
        assert_eq!(selected.units().len(), 2);
    }

    #[test]
    fn rewritten_source_roster_keeps_a_bound_tail_separately_owed() {
        use crate::vcs::flowing_rewrite::CurrentFlowingRewriteRosterOutcome as R;

        let (mut vcs, _) = committed_two_unit_rewrite();
        finish_rewrite(&mut vcs);
        bound_write(&mut vcs, "later.txt", "tail", "later-cut", "unit-tail");
        let result = vcs
            .verify_current_flowing_rewrite_roster("twig", "rebased")
            .unwrap();
        let R::Verified(roster) = result else {
            panic!("the old roots and new tail have exact owners: {result:?}");
        };
        assert_eq!(roster.units().len(), 3);
        assert_eq!(
            roster
                .units()
                .iter()
                .map(|unit| unit.unit_id.as_str())
                .collect::<Vec<_>>(),
            ["unit-a", "unit-b", "unit-tail"]
        );
        assert!(roster.units()[..2].iter().all(|unit| unit.from_rewrite));
        assert!(!roster.units()[2].from_rewrite);
        assert_eq!(roster.units()[2].atoms[0].cut_id, "later-cut");

        vcs.write("twig", "newer.txt", Some("unbound"), "newer-cut", "t9")
            .unwrap();
        assert_eq!(
            vcs.verify_current_flowing_rewrite_roster("twig", "rebased")
                .unwrap(),
            R::IncompleteRoster
        );
        let R::Verified(selected) = vcs
            .verify_selected_flowing_rewrite_roster("twig", "rebased", "later-cut")
            .unwrap()
        else {
            panic!("a bound selected prefix survives an unbound later tail");
        };
        assert_eq!(selected.prefix().selected_cut_id(), "later-cut");
        assert_eq!(selected.prefix().source_head_cut_id(), "newer-cut");
        assert_eq!(selected.prefix().later_cut_ids(), &["newer-cut"]);
        assert_eq!(selected.units().len(), 3);
        assert!(!matches!(
            vcs.verify_selected_flowing_rewrite_roster("twig", "rebased", "cut-a")
                .unwrap(),
            R::Verified(_)
        ));
    }

    #[test]
    fn rewrite_lineage_reader_refuses_missing_root_and_changed_output() {
        use rusqlite::params;

        let (vcs, receipt) = committed_two_unit_rewrite();
        let mut missing_root = receipt.clone();
        missing_root.roots.pop();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_rewrites SET witness_json = ?1, witness_digest = ?2 WHERE op_id = ?3",
                params![
                    serde_json::to_string(&missing_root).unwrap(),
                    crate::branches::flowing_rewrite::digest(&missing_root),
                    "rewrite-1"
                ],
            )
            .unwrap();
        assert_eq!(
            vcs.verify_flowing_rewrite_lineage("rebased").unwrap(),
            FlowingRewriteLineageOutcome::IncompleteRoots
        );

        let mut reversed_roots = receipt.clone();
        reversed_roots.roots.reverse();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_rewrites SET witness_json = ?1, witness_digest = ?2 WHERE op_id = ?3",
                params![
                    serde_json::to_string(&reversed_roots).unwrap(),
                    crate::branches::flowing_rewrite::digest(&reversed_roots),
                    "rewrite-1"
                ],
            )
            .unwrap();
        assert_eq!(
            vcs.verify_flowing_rewrite_lineage("rebased").unwrap(),
            FlowingRewriteLineageOutcome::IncompleteRoots
        );

        let mut changed_output = receipt.clone();
        changed_output.after_manifest_hash = receipt.old_head_manifest_hash.clone();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_rewrites SET witness_json = ?1, witness_digest = ?2 WHERE op_id = ?3",
                params![
                    serde_json::to_string(&changed_output).unwrap(),
                    crate::branches::flowing_rewrite::digest(&changed_output),
                    "rewrite-1"
                ],
            )
            .unwrap();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE cuts SET manifest_hash = ?1 WHERE cut_id = 'rebased'",
                [&changed_output.after_manifest_hash],
            )
            .unwrap();
        assert_eq!(
            vcs.verify_flowing_rewrite_lineage("rebased").unwrap(),
            FlowingRewriteLineageOutcome::OutputMismatch
        );
    }

    #[test]
    fn rewrite_lineage_reader_refuses_severed_old_source_ancestry() {
        let (vcs, _) = committed_two_unit_rewrite();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE cuts SET parent_cut_id = 'parent-next' WHERE cut_id = 'cut-b'",
                [],
            )
            .unwrap();
        assert!(matches!(
            vcs.verify_flowing_rewrite_lineage("rebased").unwrap(),
            FlowingRewriteLineageOutcome::UnsupportedLineage { .. }
        ));
    }

    #[test]
    fn rewrite_commits_roots_point_head_and_receipt_atomically() {
        let mut vcs = two_units();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "parent.txt",
            Some("parent"),
            "parent-next",
            "t4",
        )
        .unwrap();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin_rewrite(&mut vcs, &plan);
        let mut checked = 0;
        let result = vcs
            .commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || {
                    checked += 1;
                    Ok(())
                },
            )
            .unwrap();
        let FlowingRewriteOutcome::Committed(receipt) = result else {
            panic!("committed");
        };
        assert_eq!(checked, 1);
        assert_eq!(receipt.roots.len(), 2);
        assert_eq!(receipt.roots[0].unit_id(), "unit-a");
        assert_eq!(receipt.roots[1].unit_id(), "unit-b");
        let source = vcs.branches.get_branch("twig").unwrap().unwrap();
        assert_eq!(source.head_cut_id.as_deref(), Some("rebased"));
        assert_eq!(source.branch_point_cut_id.as_deref(), Some("parent-next"));
        assert_eq!(
            source.head_manifest_hash.as_deref(),
            Some(receipt.after_manifest_hash.as_str())
        );
        let cut = vcs.branches.get_cut("rebased").unwrap().unwrap();
        assert_eq!(cut.parent_cut_id.as_deref(), Some("parent-next"));
        assert_eq!(cut.origin.as_deref(), Some("flowing:rebase"));
        assert_eq!(
            vcs.branches.flowing_rewrite_for_cut("rebased").unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            vcs.branches.flowing_rewrite_receipt("rewrite-1").unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || panic!("an exact retry must read the receipt"),
            )
            .unwrap(),
            FlowingRewriteOutcome::Existing(receipt.clone()),
        );
        assert_eq!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-2",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap(),
            FlowingRewriteOutcome::Refused(FlowingRewriteRefusal::CutAlreadyRecorded),
        );
        assert_eq!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "different-time",
                &mut || panic!("changed retry must refuse"),
            )
            .unwrap(),
            FlowingRewriteOutcome::Refused(FlowingRewriteRefusal::IdentityMismatch),
        );
        assert!(matches!(
            vcs.branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "finish-rewrite".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc-1".into(),
                    expected_eligibility_epoch: 1,
                    expected_owner_epoch: 0,
                    actor: "s:author".into(),
                    action: FlowingFenceAction::FinishRevision {
                        begin_op_id: "begin-rewrite".into(),
                    },
                    recorded_at: "t7".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        assert!(vcs
            .branches
            .flowing_source("twig")
            .unwrap()
            .unwrap()
            .revision
            .is_none());
        assert_eq!(
            vcs.branches.flowing_rewrite_receipt("rewrite-1").unwrap(),
            Some(receipt),
        );
    }

    #[test]
    fn rewrite_stale_parent_and_failed_final_check_leave_old_source_ref() {
        let mut vcs = two_units();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "parent.txt",
            Some("parent"),
            "parent-next",
            "t4",
        )
        .unwrap();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin_rewrite(&mut vcs, &plan);
        let old = vcs.branches.get_branch("twig").unwrap().unwrap();
        let error = vcs
            .commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || Err(crate::StoreError::Conflict("semantic basis changed".into())),
            )
            .unwrap_err();
        assert!(format!("{error:?}").contains("semantic basis changed"));
        assert_eq!(vcs.branches.get_branch("twig").unwrap().unwrap(), old);
        assert!(vcs.branches.get_cut("rebased").unwrap().is_none());
        assert!(vcs
            .branches
            .flowing_rewrite_receipt("rewrite-1")
            .unwrap()
            .is_none());
        vcs.write(
            MAINLINE_BRANCH_ID,
            "later.txt",
            Some("later"),
            "parent-later",
            "t7",
        )
        .unwrap();
        assert_eq!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || panic!("stale parent must refuse first"),
            )
            .unwrap(),
            FlowingRewriteOutcome::Refused(FlowingRewriteRefusal::ParentMoved),
        );
        assert_eq!(vcs.branches.get_branch("twig").unwrap().unwrap(), old);
    }

    #[test]
    fn rewrite_receipt_insert_failure_rolls_back_cut_ref_and_operation() {
        let mut vcs = two_units();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "parent.txt",
            Some("parent"),
            "parent-next",
            "t4",
        )
        .unwrap();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin_rewrite(&mut vcs, &plan);
        let old = vcs.branches.get_branch("twig").unwrap().unwrap();
        vcs.branches
            .test_connection()
            .execute_batch(
                "CREATE TRIGGER fail_flowing_rewrite BEFORE INSERT ON flowing_rewrites \
             BEGIN SELECT RAISE(ABORT, 'injected rewrite failure'); END;",
            )
            .unwrap();
        assert!(vcs
            .commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .is_err());
        assert_eq!(vcs.branches.get_branch("twig").unwrap().unwrap(), old);
        assert!(vcs.branches.get_cut("rebased").unwrap().is_none());
        assert!(vcs
            .branches
            .flowing_rewrite_receipt("rewrite-1")
            .unwrap()
            .is_none());
        assert!(!vcs
            .branches
            .test_connection()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM ops WHERE op_id = 'rewrite-1')",
                [],
                |row| row.get::<_, bool>(0),
            )
            .unwrap());
        vcs.branches
            .test_connection()
            .execute_batch("DROP TRIGGER fail_flowing_rewrite")
            .unwrap();
        assert!(matches!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap(),
            FlowingRewriteOutcome::Committed(_)
        ));
    }

    #[test]
    fn rewrite_rechecks_all_units_and_bound_atoms_after_preparation() {
        let mut vcs = two_units();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "parent.txt",
            Some("parent"),
            "parent-next",
            "t4",
        )
        .unwrap();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin_rewrite(&mut vcs, &plan);
        let before = vcs.branches.get_branch("twig").unwrap().unwrap();
        vcs.branches
            .declare_contribution(DeclareContribution {
                unit_id: "unit-late",
                pin_id: "pin-unit-a",
                principal: "s:author",
                intent: "late declaration",
                read_basis_digest: "read-fixture",
                dependency_basis_digest: "deps-fixture",
                scope_digest: "late",
                declared_at: "t5",
            })
            .unwrap();
        assert_eq!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || panic!("roster changed"),
            )
            .unwrap(),
            FlowingRewriteOutcome::Refused(FlowingRewriteRefusal::UnitRosterChanged),
        );
        assert_eq!(vcs.branches.get_branch("twig").unwrap().unwrap(), before);
        assert!(vcs.branches.get_cut("rebased").unwrap().is_none());

        let mut vcs = two_units();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "parent.txt",
            Some("parent"),
            "parent-next",
            "t4",
        )
        .unwrap();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin_rewrite(&mut vcs, &plan);
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_contribution_basis SET atoms_json = '[]' WHERE unit_id = 'unit-a'",
                [],
            )
            .unwrap();
        assert_eq!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || panic!("basis changed"),
            )
            .unwrap(),
            FlowingRewriteOutcome::Refused(FlowingRewriteRefusal::UnitBasisChanged {
                unit_id: "unit-a".into(),
            }),
        );
        assert!(vcs.branches.get_cut("rebased").unwrap().is_none());
    }

    #[test]
    fn rewrite_preflight_refuses_each_broken_authority_basis() {
        #[derive(Clone)]
        struct Snapshot {
            receipt: FlowingRewriteReceipt,
            source: Option<crate::branches::BranchRow>,
            parent: Option<crate::branches::BranchRow>,
            fence: Option<crate::branches::flowing_fence::FlowingFenceState>,
            reserved: bool,
            units: Vec<RewriteUnitState>,
        }
        impl Snapshot {
            fn check(&self) -> Result<crate::branches::BranchRow, FlowingRewriteRefusal> {
                check_current(
                    &self.receipt,
                    self.source.clone(),
                    self.parent.clone(),
                    self.fence.clone(),
                    self.reserved,
                    &self.units,
                )
            }
        }
        let mut vcs = two_units();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "parent.txt",
            Some("parent"),
            "parent-next",
            "t4",
        )
        .unwrap();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin_rewrite(&mut vcs, &plan);
        let units = vcs
            .branches
            .source_contributions("twig")
            .unwrap()
            .into_iter()
            .map(|declaration| RewriteUnitState {
                basis: vcs
                    .branches
                    .contribution_basis(&declaration.unit_id)
                    .unwrap(),
                pin: vcs.branches.private_cut_pin(&declaration.pin_id).unwrap(),
                handed_off: false,
                admitted: false,
                declaration,
            })
            .collect();
        let snapshot = Snapshot {
            receipt: crate::branches::flowing_rewrite::CommitFlowingRewrite::new(
                "rewrite-1",
                "begin-rewrite",
                &plan,
                "rebased",
                "manifest",
                "s:author",
                "t6",
            )
            .receipt(),
            source: vcs.branches.get_branch("twig").unwrap(),
            parent: vcs.branches.get_branch(MAINLINE_BRANCH_ID).unwrap(),
            fence: vcs.branches.flowing_source("twig").unwrap(),
            reserved: false,
            units,
        };
        assert!(snapshot.check().is_ok());

        let mut changed = snapshot.clone();
        changed.receipt.op_id.clear();
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::Invalid { field: "op_id" })
        );
        let mut changed = snapshot.clone();
        changed.receipt.after_cut_id = changed.receipt.old_head_cut_id.clone();
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::Invalid {
                field: "rewrite_basis"
            })
        );
        let mut changed = snapshot.clone();
        changed.source = None;
        assert_eq!(changed.check(), Err(FlowingRewriteRefusal::SourceMissing));
        let mut changed = snapshot.clone();
        changed.source.as_mut().unwrap().status = crate::branches::BranchStatus::Discarded;
        assert_eq!(changed.check(), Err(FlowingRewriteRefusal::SourceNotActive));
        let mut changed = snapshot.clone();
        changed.reserved = true;
        assert_eq!(changed.check(), Err(FlowingRewriteRefusal::HeadReserved));
        let mut changed = snapshot.clone();
        changed.source.as_mut().unwrap().head_cut_id = Some("other".into());
        assert_eq!(changed.check(), Err(FlowingRewriteRefusal::SourceMoved));
        let mut changed = snapshot.clone();
        changed.parent = None;
        assert_eq!(changed.check(), Err(FlowingRewriteRefusal::ParentMissing));
        let mut changed = snapshot.clone();
        changed.parent.as_mut().unwrap().head_cut_id = Some("other".into());
        assert_eq!(changed.check(), Err(FlowingRewriteRefusal::ParentMoved));
        let mut changed = snapshot.clone();
        changed.fence = None;
        assert_eq!(changed.check(), Err(FlowingRewriteRefusal::RevisionMissing));
        let mut changed = snapshot.clone();
        changed.fence.as_mut().unwrap().revision = None;
        assert_eq!(changed.check(), Err(FlowingRewriteRefusal::RevisionMissing));
        let mut changed = snapshot.clone();
        changed.fence.as_mut().unwrap().owner_epoch += 1;
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::RevisionMismatch)
        );
        let mut changed = snapshot.clone();
        changed.units.clear();
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::UnitRosterChanged)
        );
        let mut changed = snapshot.clone();
        changed.units[0].handed_off = true;
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::UnitNoLongerOwed {
                unit_id: "unit-a".into()
            })
        );
        let mut changed = snapshot.clone();
        changed.units[0].admitted = true;
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::UnitNoLongerOwed {
                unit_id: "unit-a".into()
            })
        );
        let mut changed = snapshot.clone();
        changed.units[0].basis = None;
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::UnitBasisChanged {
                unit_id: "unit-a".into()
            })
        );
        let mut changed = snapshot.clone();
        changed.units[0].pin = None;
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::UnitBasisChanged {
                unit_id: "unit-a".into()
            })
        );
        let mut changed = snapshot.clone();
        changed.units[0].basis.as_mut().unwrap().atoms.clear();
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::UnitBasisChanged {
                unit_id: "unit-a".into()
            })
        );
        let mut changed = snapshot.clone();
        changed.units[0].pin.as_mut().unwrap().principal = "s:other".into();
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::UnitBasisChanged {
                unit_id: "unit-a".into()
            })
        );
        let mut changed = snapshot;
        changed.units[0].pin.as_mut().unwrap().released_at = Some("t7".into());
        assert_eq!(
            changed.check(),
            Err(FlowingRewriteRefusal::UnitBasisChanged {
                unit_id: "unit-a".into()
            })
        );
    }

    #[test]
    fn disjoint_parent_update_replays_every_owned_atom_without_moving_refs() {
        let mut vcs = two_units();
        let old = vcs.branches.get_branch("twig").unwrap().unwrap();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "parent.txt",
            Some("parent"),
            "parent-next",
            "t4",
        )
        .unwrap();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("disjoint source is replayable");
        };
        assert_eq!(plan.old_head_cut_id, "cut-b");
        assert_eq!(plan.parent_head_cut_id.as_deref(), Some("parent-next"));
        assert_eq!(
            plan.roots()
                .iter()
                .map(|root| root.unit_id())
                .collect::<Vec<_>>(),
            ["unit-a", "unit-b"]
        );
        assert_eq!(plan.proposed_manifest().len(), 4);
        assert_eq!(vcs.branches.get_branch("twig").unwrap().unwrap(), old);
    }

    #[test]
    fn overlap_and_missing_root_refuse_without_changing_source() {
        let mut vcs = two_units();
        let before = vcs.branches.get_branch("twig").unwrap().unwrap();
        vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some("other"), "overlap", "t4")
            .unwrap();
        assert_eq!(
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap(),
            FlowingDisjointRebaseOutcome::Overlap {
                path: "a.txt".into()
            }
        );
        assert_eq!(vcs.branches.get_branch("twig").unwrap().unwrap(), before);

        let mut unbound = two_units();
        unbound
            .write("twig", "tail.txt", Some("tail"), "tail", "t4")
            .unwrap();
        unbound
            .write(MAINLINE_BRANCH_ID, "parent.txt", Some("parent"), "p", "t5")
            .unwrap();
        assert_eq!(
            unbound.prepare_disjoint_flowing_rebase("twig").unwrap(),
            FlowingDisjointRebaseOutcome::IncompleteRoots
        );
    }

    #[test]
    fn successive_units_on_one_path_keep_both_roots_and_order() {
        let mut vcs = workspace();
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        assert!(matches!(
            vcs.branches
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc-1".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "s:author".into(),
                    opened_at: "t1".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        bound_write(&mut vcs, "a.txt", "A", "cut-a", "unit-a");
        bound_write(&mut vcs, "a.txt", "B", "cut-b", "unit-b");
        vcs.write(MAINLINE_BRANCH_ID, "other.txt", Some("other"), "p", "t4")
            .unwrap();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("ordered replay must prepare");
        };
        assert_eq!(
            plan.roots()
                .iter()
                .map(|root| root.unit_id())
                .collect::<Vec<_>>(),
            ["unit-a", "unit-b"]
        );
        assert_eq!(
            plan.proposed_manifest().get("a.txt"),
            Some(&vcs.content.put_text("B").unwrap())
        );
    }

    #[test]
    fn a_changed_root_basis_cannot_be_replayed_under_its_old_digest() {
        let mut vcs = two_units();
        vcs.write(MAINLINE_BRANCH_ID, "other.txt", Some("other"), "p", "t4")
            .unwrap();
        vcs.branches
            .test_connection()
            .execute(
                "UPDATE flowing_contribution_basis SET atoms_json = '[]' WHERE unit_id = 'unit-a'",
                [],
            )
            .unwrap();
        assert_eq!(
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap(),
            FlowingDisjointRebaseOutcome::UnitBasisMismatch {
                unit_id: "unit-a".into()
            }
        );
    }
}
