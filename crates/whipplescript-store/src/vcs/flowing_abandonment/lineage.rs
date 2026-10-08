//! Reconstruct a committed abandonment from retained source history. The
//! receipt is an assertion to check, never the source of its own atom proof.

use std::collections::{BTreeMap, BTreeSet};

use crate::branches::flowing_abandonment::{FlowingAbandonmentReceipt, FlowingAbandonments};
use crate::branches::{Branches, MAINLINE_BRANCH_ID};
use crate::content::ContentBlobs;
use crate::StoreResult;

use super::super::flowing_selection::FlowingSourceAtom;
use super::super::WorkspaceVcs;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingAbandonmentLineage {
    receipt: FlowingAbandonmentReceipt,
    source_atoms: Vec<FlowingSourceAtom>,
}

impl FlowingAbandonmentLineage {
    pub fn receipt(&self) -> &FlowingAbandonmentReceipt {
        &self.receipt
    }

    pub fn source_atoms(&self) -> &[FlowingSourceAtom] {
        &self.source_atoms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FlowingAbandonmentLineageOutcome {
    Verified(Box<FlowingAbandonmentLineage>),
    CutMissing { cut_id: String },
    ReceiptMissing { cut_id: String },
    UnsupportedLineage { cut_id: String },
    IncompleteUnits,
    OutputMismatch,
    MissingManifest { cut_id: String },
    MissingContent { content_id: String },
}

impl<B: Branches + FlowingAbandonments, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// Verify older dispositions first without using the process stack for
    /// source depth. Each disposition starts a new empty frontier at the
    /// original branch point, so its predecessor must also be proved.
    pub fn verify_flowing_abandonment_lineage(
        &self,
        after_cut_id: &str,
    ) -> StoreResult<FlowingAbandonmentLineageOutcome> {
        use FlowingAbandonmentLineageOutcome as R;

        let mut verified = BTreeMap::new();
        let mut visiting = BTreeSet::new();
        let mut pending = vec![(after_cut_id.to_owned(), false)];
        while let Some((cut_id, ready)) = pending.pop() {
            if verified.contains_key(&cut_id) {
                continue;
            }
            if ready {
                match self.verify_one_flowing_abandonment(&cut_id, &verified)? {
                    R::Verified(lineage) => {
                        verified.insert(cut_id.clone(), *lineage);
                    }
                    outcome => return Ok(outcome),
                }
                visiting.remove(&cut_id);
                continue;
            }
            if !visiting.insert(cut_id.clone()) {
                return Ok(R::UnsupportedLineage { cut_id });
            }
            let Some(receipt) = self.branches.flowing_abandonment_for_cut(&cut_id)? else {
                return Ok(R::ReceiptMissing { cut_id });
            };
            pending.push((cut_id.clone(), true));
            let mut cursor = Some(receipt.before_cut_id);
            let mut seen = BTreeSet::new();
            while cursor != receipt.branch_point_cut_id {
                let Some(id) = cursor else {
                    return Ok(R::UnsupportedLineage { cut_id });
                };
                if !seen.insert(id.clone()) {
                    return Ok(R::UnsupportedLineage { cut_id: id });
                }
                let Some(cut) = self.branches.get_cut(&id)? else {
                    return Ok(R::CutMissing { cut_id: id });
                };
                if cut.origin.as_deref() == Some("flowing:abandon") {
                    if !verified.contains_key(&id) {
                        if visiting.contains(&id) {
                            return Ok(R::UnsupportedLineage { cut_id: id });
                        }
                        pending.push((id, false));
                    }
                    break;
                }
                cursor = cut.parent_cut_id;
            }
        }
        match verified.remove(after_cut_id) {
            Some(lineage) => Ok(R::Verified(Box::new(lineage))),
            None => Ok(R::UnsupportedLineage {
                cut_id: after_cut_id.to_owned(),
            }),
        }
    }

    fn verify_one_flowing_abandonment(
        &self,
        after_cut_id: &str,
        verified: &BTreeMap<String, FlowingAbandonmentLineage>,
    ) -> StoreResult<FlowingAbandonmentLineageOutcome> {
        use FlowingAbandonmentLineageOutcome as R;

        let Some(receipt) = self.branches.flowing_abandonment_for_cut(after_cut_id)? else {
            return Ok(R::ReceiptMissing {
                cut_id: after_cut_id.to_owned(),
            });
        };
        let Some(after) = self.branches.get_cut(after_cut_id)? else {
            return Ok(R::CutMissing {
                cut_id: after_cut_id.to_owned(),
            });
        };
        let Some(before) = self.branches.get_cut(&receipt.before_cut_id)? else {
            return Ok(R::CutMissing {
                cut_id: receipt.before_cut_id,
            });
        };
        if after.origin.as_deref() != Some("flowing:abandon")
            || after.branch_id != receipt.source_branch_id
            || after.change_id != receipt.after_cut_id
            || after.parent_cut_id != receipt.branch_point_cut_id
            || after.manifest_hash != receipt.after_manifest_hash
            || after.actor.as_deref() != Some(receipt.actor.as_str())
            || after.recorded_at != receipt.recorded_at
            || before.branch_id != receipt.source_branch_id
            || before.manifest_hash != receipt.before_manifest_hash
            || receipt.before_cut_id == receipt.after_cut_id
            || receipt.branch_point_cut_id.is_some() != receipt.branch_point_manifest_hash.is_some()
        {
            return Ok(R::UnsupportedLineage {
                cut_id: after_cut_id.to_owned(),
            });
        }
        if let Some(point_id) = &receipt.branch_point_cut_id {
            let Some(point) = self.branches.get_cut(point_id)? else {
                return Ok(R::CutMissing {
                    cut_id: point_id.clone(),
                });
            };
            if point.branch_id != MAINLINE_BRANCH_ID
                || Some(&point.manifest_hash) != receipt.branch_point_manifest_hash.as_ref()
            {
                return Ok(R::UnsupportedLineage {
                    cut_id: point_id.clone(),
                });
            }
        }

        let mut cursor = Some(receipt.before_cut_id.clone());
        let mut expected_hash = Some(receipt.before_manifest_hash.clone());
        let mut seen = BTreeSet::new();
        let mut reverse = Vec::new();
        while cursor != receipt.branch_point_cut_id {
            let Some(id) = cursor else {
                return Ok(R::UnsupportedLineage {
                    cut_id: receipt.before_cut_id.clone(),
                });
            };
            if !seen.insert(id.clone()) {
                return Ok(R::UnsupportedLineage { cut_id: id });
            }
            let Some(cut) = self.branches.get_cut(&id)? else {
                return Ok(R::CutMissing { cut_id: id });
            };
            if cut.branch_id != receipt.source_branch_id
                || expected_hash.as_deref() != Some(cut.manifest_hash.as_str())
            {
                return Ok(R::UnsupportedLineage { cut_id: id });
            }
            if cut.origin.as_deref() == Some("flowing:abandon") {
                let Some(prior) = verified.get(&id) else {
                    return Ok(R::UnsupportedLineage { cut_id: id });
                };
                if prior.receipt.source_branch_id != receipt.source_branch_id
                    || prior.receipt.source_incarnation_id != receipt.source_incarnation_id
                    || prior.receipt.branch_point_cut_id != receipt.branch_point_cut_id
                    || prior.receipt.branch_point_manifest_hash
                        != receipt.branch_point_manifest_hash
                    || cut.parent_cut_id != receipt.branch_point_cut_id
                {
                    return Ok(R::UnsupportedLineage { cut_id: id });
                }
                expected_hash = receipt.branch_point_manifest_hash.clone();
                cursor = cut.parent_cut_id;
                break;
            }
            if !cut
                .origin
                .as_deref()
                .is_some_and(|origin| origin.starts_with("write:"))
            {
                return Ok(R::UnsupportedLineage { cut_id: id });
            }
            expected_hash = match cut.parent_cut_id.as_deref() {
                Some(parent_id) => {
                    let Some(parent) = self.branches.get_cut(parent_id)? else {
                        return Ok(R::CutMissing {
                            cut_id: parent_id.to_owned(),
                        });
                    };
                    Some(parent.manifest_hash)
                }
                None => None,
            };
            cursor = cut.parent_cut_id.clone();
            reverse.push(cut);
        }
        if cursor != receipt.branch_point_cut_id
            || expected_hash != receipt.branch_point_manifest_hash
            || reverse.is_empty()
        {
            return Ok(R::UnsupportedLineage {
                cut_id: after_cut_id.to_owned(),
            });
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
        let expected: BTreeMap<_, _> = atoms
            .iter()
            .map(|atom| ((atom.cut_id.as_str(), atom.path.as_str()), atom))
            .collect();
        if expected.len() != atoms.len() {
            return Ok(R::IncompleteUnits);
        }
        let mut owned = BTreeSet::new();
        let mut unit_ids = BTreeSet::new();
        for unit in &receipt.units {
            if !unit_ids.insert(unit.unit_id())
                || unit.basis_digest().is_empty()
                || unit.atoms().is_empty()
            {
                return Ok(R::IncompleteUnits);
            }
            for atom in unit.atoms() {
                let key = (atom.cut_id.as_str(), atom.path.as_str());
                if expected.get(&key) != Some(&atom) || !owned.insert(key) {
                    return Ok(R::IncompleteUnits);
                }
            }
        }
        if receipt.units.is_empty() || owned.len() != expected.len() {
            return Ok(R::IncompleteUnits);
        }
        let manifest = |hash: Option<&str>, cut_id: &str| -> StoreResult<Result<_, R>> {
            let Some(hash) = hash else {
                return Ok(Ok(BTreeMap::new()));
            };
            Ok(self
                .load_manifest_opt(hash)?
                .ok_or_else(|| R::MissingManifest {
                    cut_id: cut_id.to_owned(),
                }))
        };
        let point_id = receipt.branch_point_cut_id.as_deref().unwrap_or_default();
        let point = match manifest(receipt.branch_point_manifest_hash.as_deref(), point_id)? {
            Ok(value) => value,
            Err(outcome) => return Ok(outcome),
        };
        let old = match manifest(Some(&receipt.before_manifest_hash), &receipt.before_cut_id)? {
            Ok(value) => value,
            Err(outcome) => return Ok(outcome),
        };
        let output = match manifest(Some(&receipt.after_manifest_hash), after_cut_id)? {
            Ok(value) => value,
            Err(outcome) => return Ok(outcome),
        };
        let mut replay = point.clone();
        for atom in &atoms {
            if replay.get(&atom.path) != atom.before.as_ref() {
                return Ok(R::OutputMismatch);
            }
            match &atom.after {
                Some(after) => {
                    replay.insert(atom.path.clone(), after.clone());
                }
                None => {
                    replay.remove(&atom.path);
                }
            }
        }
        if replay != old || output != point {
            return Ok(R::OutputMismatch);
        }
        for content_id in atoms
            .iter()
            .flat_map(|atom| [atom.before.as_ref(), atom.after.as_ref()])
            .flatten()
            .chain(old.values())
            .chain(point.values())
        {
            if !self.content.cached_read_available(content_id)? {
                return Ok(R::MissingContent {
                    content_id: content_id.clone(),
                });
            }
        }
        Ok(R::Verified(Box::new(FlowingAbandonmentLineage {
            receipt,
            source_atoms: atoms,
        })))
    }
}
