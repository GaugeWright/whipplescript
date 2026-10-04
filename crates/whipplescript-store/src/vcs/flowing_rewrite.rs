//! Content-derived preparation for a disjoint flowing twig rebase (FB-2).
//!
//! This establishes only content replay, not compatibility of a unit's read
//! or dependency basis with the new parent. It does not publish a cut or move
//! a ref. A future writer must retain the prepared bodies, record the exact
//! root edge, revalidate affected read/dependency bases, and atomically
//! recapture both refs and the source revision before making the head visible.

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

impl<B: Branches + FlowingSources + FlowingAdmissions, C: ContentBlobs> WorkspaceVcs<B, C> {
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
            if !cut
                .origin
                .as_deref()
                .is_some_and(|origin| origin.starts_with("write:"))
            {
                return Ok(R::UnsupportedLineage { cut_id });
            }
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
            reverse.push(cut);
        }
        if expected_manifest != source.branch_point_manifest_hash || reverse.is_empty() {
            return Ok(R::IncompleteRoots);
        }
        reverse.reverse();
        let mut old_atoms = Vec::new();
        for cut in &reverse {
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
                || !seen.contains(&unit.source_cut_id)
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
        DeclareContributionOutcome, PinPrivateCut, PinPrivateCutOutcome,
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
