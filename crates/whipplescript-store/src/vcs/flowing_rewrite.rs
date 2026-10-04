//! Content-derived preparation for a disjoint flowing twig rebase (FB-2).
//!
//! This establishes only content replay, not compatibility of a unit's read
//! or dependency basis with the new parent. It does not publish a cut or move
//! a ref. A future writer must retain the prepared bodies, record the exact
//! root edge, revalidate affected read/dependency bases, and atomically
//! recapture both refs and the source revision before making the head visible.

use std::collections::{BTreeMap, BTreeSet};

use crate::branches::flowing_admission::FlowingAdmissions;
use crate::branches::flowing_fence::FlowingSourceKind;
use crate::branches::flowing_sources::FlowingSources;
use crate::branches::{BranchStatus, Branches};
use crate::content::ContentBlobs;
use crate::StoreResult;

use super::flowing_selection::FlowingSourceAtom;
use super::WorkspaceVcs;

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[cfg(all(test, feature = "native"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::branches::flowing_fence::{
        FlowingFence, OpenFlowingSource, OpenFlowingSourceOutcome,
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
