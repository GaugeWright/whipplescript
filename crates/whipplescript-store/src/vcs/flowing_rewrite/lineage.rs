//! Read-only verification of one committed flowing rewrite edge.
//!
//! The rewritten cut's parent is the new parent-line cut, so walking that
//! ancestry cannot recover the source units. The immutable receipt names the
//! old source root; this reader checks it against both histories and the
//! actual output before any caller can use its constituent atoms.

use std::collections::{BTreeMap, BTreeSet};

use crate::branches::flowing_rewrite::{FlowingRewriteReceipt, FlowingRewrites};
use crate::branches::Branches;
use crate::content::ContentBlobs;
use crate::StoreResult;

use super::{FlowingSourceAtom, WorkspaceVcs};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingRewriteLineage {
    receipt: FlowingRewriteReceipt,
    /// Every old source write, in cut and path order, independently rederived
    /// from retained content. A root's own vector is not accepted as this list.
    source_atoms: Vec<FlowingSourceAtom>,
}

impl FlowingRewriteLineage {
    pub fn receipt(&self) -> &FlowingRewriteReceipt {
        &self.receipt
    }

    pub fn source_atoms(&self) -> &[FlowingSourceAtom] {
        &self.source_atoms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingRewriteLineageOutcome {
    Verified(Box<FlowingRewriteLineage>),
    CutMissing { cut_id: String },
    ReceiptMissing { cut_id: String },
    CutMismatch { cut_id: String },
    UnsupportedLineage { cut_id: String },
    MissingManifest { cut_id: String },
    MissingContent { content_id: String },
    IncompleteRoots,
    OutputMismatch,
}

impl<B: Branches + FlowingRewrites, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// Verify a historical disjoint rewrite without relying on today's source
    /// head, current unit rows, or a retained private pin. This is lineage
    /// evidence only; it says nothing about current read/dependency validity
    /// or permission to admit the units to trunk.
    pub fn verify_flowing_rewrite_lineage(
        &self,
        after_cut_id: &str,
    ) -> StoreResult<FlowingRewriteLineageOutcome> {
        use FlowingRewriteLineageOutcome as R;

        let Some(after_cut) = self.branches.get_cut(after_cut_id)? else {
            return Ok(R::CutMissing {
                cut_id: after_cut_id.into(),
            });
        };
        let Some(receipt) = self.branches.flowing_rewrite_for_cut(after_cut_id)? else {
            return Ok(R::ReceiptMissing {
                cut_id: after_cut_id.into(),
            });
        };
        if after_cut.origin.as_deref() != Some("flowing:rebase")
            || after_cut.cut_id != receipt.after_cut_id
            || after_cut.change_id != receipt.after_cut_id
            || after_cut.branch_id != receipt.source_branch_id
            || after_cut.manifest_hash != receipt.after_manifest_hash
            || after_cut.parent_cut_id != receipt.parent_head_cut_id
            || after_cut.actor.as_deref() != Some(receipt.actor.as_str())
            || after_cut.recorded_at != receipt.recorded_at
            || receipt.source_branch_id == receipt.parent_branch_id
            || receipt.after_cut_id == receipt.old_head_cut_id
            || receipt.old_point_cut_id.is_some() != receipt.old_point_manifest_hash.is_some()
            || receipt.parent_head_cut_id.is_some() != receipt.parent_head_manifest_hash.is_some()
        {
            return Ok(R::CutMismatch {
                cut_id: after_cut_id.into(),
            });
        }
        let Some(old_head) = self.branches.get_cut(&receipt.old_head_cut_id)? else {
            return Ok(R::CutMissing {
                cut_id: receipt.old_head_cut_id,
            });
        };
        if old_head.branch_id != receipt.source_branch_id
            || old_head.manifest_hash != receipt.old_head_manifest_hash
        {
            return Ok(R::CutMismatch {
                cut_id: old_head.cut_id,
            });
        }
        for (cut_id, hash) in [
            (
                receipt.old_point_cut_id.as_deref(),
                receipt.old_point_manifest_hash.as_deref(),
            ),
            (
                receipt.parent_head_cut_id.as_deref(),
                receipt.parent_head_manifest_hash.as_deref(),
            ),
        ] {
            if let Some(cut_id) = cut_id {
                let Some(cut) = self.branches.get_cut(cut_id)? else {
                    return Ok(R::CutMissing {
                        cut_id: cut_id.into(),
                    });
                };
                if cut.branch_id != receipt.parent_branch_id
                    || Some(cut.manifest_hash.as_str()) != hash
                {
                    return Ok(R::CutMismatch {
                        cut_id: cut_id.into(),
                    });
                }
            }
        }

        // The new parent must descend from the exact point the old source
        // inherited. A same-looking manifest on another line is not ancestry.
        let mut parent_cursor = receipt.parent_head_cut_id.clone();
        let mut parent_seen = BTreeSet::new();
        while parent_cursor != receipt.old_point_cut_id {
            let Some(cut_id) = parent_cursor else {
                return Ok(R::UnsupportedLineage {
                    cut_id: after_cut_id.into(),
                });
            };
            if !parent_seen.insert(cut_id.clone()) {
                return Ok(R::UnsupportedLineage { cut_id });
            }
            let Some(cut) = self.branches.get_cut(&cut_id)? else {
                return Ok(R::CutMissing { cut_id });
            };
            if cut.branch_id != receipt.parent_branch_id {
                return Ok(R::UnsupportedLineage { cut_id });
            }
            parent_cursor = cut.parent_cut_id;
        }

        let mut source_cursor = Some(receipt.old_head_cut_id.clone());
        let mut expected_hash = Some(receipt.old_head_manifest_hash.clone());
        let mut source_seen = BTreeSet::new();
        let mut reverse = Vec::new();
        while source_cursor != receipt.old_point_cut_id {
            let Some(cut_id) = source_cursor else {
                return Ok(R::UnsupportedLineage {
                    cut_id: receipt.old_head_cut_id,
                });
            };
            if !source_seen.insert(cut_id.clone()) {
                return Ok(R::UnsupportedLineage { cut_id });
            }
            let Some(cut) = self.branches.get_cut(&cut_id)? else {
                return Ok(R::CutMissing { cut_id });
            };
            if cut.branch_id != receipt.source_branch_id
                || cut
                    .origin
                    .as_deref()
                    .is_none_or(|origin| !origin.starts_with("write:"))
                || expected_hash.as_deref() != Some(cut.manifest_hash.as_str())
            {
                return Ok(R::UnsupportedLineage { cut_id });
            }
            expected_hash = match cut.parent_cut_id.as_deref() {
                Some(parent_id) => {
                    let Some(parent) = self.branches.get_cut(parent_id)? else {
                        return Ok(R::CutMissing {
                            cut_id: parent_id.into(),
                        });
                    };
                    Some(parent.manifest_hash)
                }
                None => None,
            };
            source_cursor = cut.parent_cut_id.clone();
            reverse.push(cut);
        }
        if reverse.is_empty() || expected_hash != receipt.old_point_manifest_hash {
            return Ok(R::IncompleteRoots);
        }
        reverse.reverse();

        let mut atoms = Vec::new();
        for cut in &reverse {
            if self.load_manifest_opt_raw(&cut.manifest_hash)?.is_none() {
                return Ok(R::MissingManifest {
                    cut_id: cut.cut_id.clone(),
                });
            }
            let mut changes = Vec::new();
            self.push_units_for_cut(cut, &mut changes)?;
            if changes.is_empty() {
                return Ok(R::UnsupportedLineage {
                    cut_id: cut.cut_id.clone(),
                });
            }
            atoms.extend(changes.into_iter().map(|change| FlowingSourceAtom {
                cut_id: change.cut_id,
                change_id: change.change_id,
                path: change.path,
                before: change.before,
                after: change.after,
            }));
        }
        let mut expected_atoms = BTreeMap::new();
        for (position, atom) in atoms.iter().enumerate() {
            if expected_atoms
                .insert((atom.cut_id.as_str(), atom.path.as_str()), (position, atom))
                .is_some()
            {
                return Ok(R::IncompleteRoots);
            }
        }
        let mut unit_ids = BTreeSet::new();
        let mut owned = BTreeSet::new();
        let mut last_root_first = None;
        for root in &receipt.roots {
            if !unit_ids.insert(root.unit_id())
                || root.basis_digest().is_empty()
                || root.atoms().is_empty()
            {
                return Ok(R::IncompleteRoots);
            }
            let mut last_atom = None;
            for atom in root.atoms() {
                let key = (atom.cut_id.as_str(), atom.path.as_str());
                let Some((position, expected)) = expected_atoms.get(&key) else {
                    return Ok(R::IncompleteRoots);
                };
                if *expected != atom
                    || !owned.insert(key)
                    || last_atom.is_some_and(|p| p >= *position)
                {
                    return Ok(R::IncompleteRoots);
                }
                last_atom = Some(*position);
            }
            let first = expected_atoms[&(
                root.atoms()[0].cut_id.as_str(),
                root.atoms()[0].path.as_str(),
            )]
                .0;
            if last_root_first.is_some_and(|p| p >= first) {
                return Ok(R::IncompleteRoots);
            }
            last_root_first = Some(first);
        }
        if receipt.roots.is_empty() || owned.len() != expected_atoms.len() {
            return Ok(R::IncompleteRoots);
        }

        let manifest = |hash: Option<&str>| -> StoreResult<Option<BTreeMap<String, String>>> {
            let Some(hash) = hash else {
                return Ok(Some(BTreeMap::new()));
            };
            self.load_manifest_opt(hash)
        };
        let Some(old_point) = manifest(receipt.old_point_manifest_hash.as_deref())? else {
            return Ok(R::MissingManifest {
                cut_id: receipt.old_point_cut_id.clone().unwrap_or_default(),
            });
        };
        let Some(old_head) = manifest(Some(&receipt.old_head_manifest_hash))? else {
            return Ok(R::MissingManifest {
                cut_id: receipt.old_head_cut_id,
            });
        };
        let Some(parent_head) = manifest(receipt.parent_head_manifest_hash.as_deref())? else {
            return Ok(R::MissingManifest {
                cut_id: receipt.parent_head_cut_id.clone().unwrap_or_default(),
            });
        };
        let Some(output) = manifest(Some(&receipt.after_manifest_hash))? else {
            return Ok(R::MissingManifest {
                cut_id: after_cut_id.into(),
            });
        };
        let changed_paths: BTreeSet<&str> = atoms.iter().map(|atom| atom.path.as_str()).collect();
        let mut replayed = parent_head;
        for path in &changed_paths {
            if old_point.get(*path) != replayed.get(*path) {
                return Ok(R::OutputMismatch);
            }
        }
        for atom in &atoms {
            if replayed.get(&atom.path) != atom.before.as_ref() {
                return Ok(R::OutputMismatch);
            }
            match &atom.after {
                Some(after) => {
                    replayed.insert(atom.path.clone(), after.clone());
                }
                None => {
                    replayed.remove(&atom.path);
                }
            }
        }
        if replayed != output
            || changed_paths
                .iter()
                .any(|path| old_head.get(*path) != output.get(*path))
        {
            return Ok(R::OutputMismatch);
        }
        for content_id in atoms
            .iter()
            .flat_map(|atom| [atom.before.as_ref(), atom.after.as_ref()])
            .flatten()
            .chain(output.values())
        {
            if !self.content.cached_read_available(content_id)? {
                return Ok(R::MissingContent {
                    content_id: content_id.clone(),
                });
            }
        }
        Ok(R::Verified(Box::new(FlowingRewriteLineage {
            receipt,
            source_atoms: atoms,
        })))
    }
}
