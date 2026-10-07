//! Read-only content preparation for abandoning an entire direct twig.
//!
//! This establishes neither authorization nor a disposition. The ref writer
//! must later recheck this basis under BeginRevision, retain the content, and
//! commit the source head with every per-unit receipt in one transaction.

use std::collections::{BTreeMap, BTreeSet};

use crate::branches::flowing_admission::FlowingAdmissions;
use crate::branches::flowing_fence::FlowingSourceKind;
use crate::branches::flowing_sources::FlowingSources;
use crate::branches::{BranchStatus, Branches, MAINLINE_BRANCH_ID};
use crate::content::ContentBlobs;
use crate::StoreResult;

use super::flowing_selection::FlowingSourceAtom;
use super::WorkspaceVcs;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WholeTwigAbandonment {
    source_branch_id: String,
    source_incarnation_id: String,
    source_eligibility_epoch: i64,
    source_owner_epoch: i64,
    before_cut_id: String,
    before_manifest_hash: String,
    branch_point_cut_id: Option<String>,
    branch_point_manifest_hash: Option<String>,
    units: Vec<AbandonedUnitBasis>,
}

impl WholeTwigAbandonment {
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
    pub fn before_cut_id(&self) -> &str {
        &self.before_cut_id
    }
    pub fn before_manifest_hash(&self) -> &str {
        &self.before_manifest_hash
    }
    pub fn branch_point_cut_id(&self) -> Option<&str> {
        self.branch_point_cut_id.as_deref()
    }
    pub fn branch_point_manifest_hash(&self) -> Option<&str> {
        self.branch_point_manifest_hash.as_deref()
    }
    pub fn units(&self) -> &[AbandonedUnitBasis] {
        &self.units
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbandonedUnitBasis {
    unit_id: String,
    basis_digest: String,
    atoms: Vec<FlowingSourceAtom>,
}

impl AbandonedUnitBasis {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WholeTwigAbandonmentOutcome {
    Prepared(Box<WholeTwigAbandonment>),
    SourceNotReady,
    MissingCut { cut_id: String },
    UnsupportedLineage { cut_id: String },
    MissingContent { content_id: String },
    IncompleteUnits,
    UnitNotOwed { unit_id: String },
    UnitBasisMismatch { unit_id: String },
}

impl<B: Branches + FlowingSources + FlowingAdmissions, C: ContentBlobs> WorkspaceVcs<B, C> {
    /// Prove that every effective source atom belongs to exactly one still
    /// owed bound unit, and that replacing the whole twig head with its exact
    /// branch-point manifest removes all of those effects. A later writer
    /// must not infer that this read-only observation is still current.
    pub fn prepare_whole_twig_abandonment(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<WholeTwigAbandonmentOutcome> {
        use WholeTwigAbandonmentOutcome as R;
        let Some(source) = self.branches.get_branch(source_branch_id)? else {
            return Ok(R::SourceNotReady);
        };
        let Some(fence) = self.branches.flowing_source(source_branch_id)? else {
            return Ok(R::SourceNotReady);
        };
        if source.status != BranchStatus::Active
            || source.name.is_some()
            || source.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID)
            || fence.kind != FlowingSourceKind::Twig
            || !fence.admission_enabled
            || fence.revision.is_some()
            || source.head_cut_id == source.branch_point_cut_id
        {
            return Ok(R::SourceNotReady);
        }
        let Some(before_cut_id) = source.head_cut_id.as_deref() else {
            return Ok(R::SourceNotReady);
        };
        let Some(before_manifest_hash) = source.head_manifest_hash.as_deref() else {
            return Ok(R::SourceNotReady);
        };
        if let Some(point_id) = source.branch_point_cut_id.as_deref() {
            let Some(point) = self.branches.get_cut(point_id)? else {
                return Ok(R::MissingCut {
                    cut_id: point_id.to_owned(),
                });
            };
            if point.branch_id != MAINLINE_BRANCH_ID
                || Some(point.manifest_hash.as_str())
                    != source.branch_point_manifest_hash.as_deref()
            {
                return Ok(R::SourceNotReady);
            }
        } else if source.branch_point_manifest_hash.is_some() {
            return Ok(R::SourceNotReady);
        }
        let mut cursor = Some(before_cut_id.to_owned());
        let mut expected_manifest = Some(before_manifest_hash.to_owned());
        let mut seen = BTreeSet::new();
        let mut cut_manifests = BTreeMap::new();
        let mut reverse = Vec::new();
        while cursor != source.branch_point_cut_id {
            let Some(cut_id) = cursor else {
                return Ok(R::UnsupportedLineage {
                    cut_id: before_cut_id.to_owned(),
                });
            };
            if !seen.insert(cut_id.clone()) {
                return Ok(R::UnsupportedLineage { cut_id });
            }
            let Some(cut) = self.branches.get_cut(&cut_id)? else {
                return Ok(R::MissingCut { cut_id });
            };
            if cut.branch_id != source_branch_id
                || expected_manifest.as_deref() != Some(cut.manifest_hash.as_str())
                || !matches!(cut.origin.as_deref(), Some(origin) if origin.starts_with("write:"))
            {
                return Ok(R::UnsupportedLineage { cut_id });
            }
            cut_manifests.insert(cut.cut_id.clone(), cut.manifest_hash.clone());
            let mut changes = Vec::new();
            self.push_units_for_cut(&cut, &mut changes)?;
            if changes.is_empty() {
                return Ok(R::UnsupportedLineage { cut_id });
            }
            reverse.push(
                changes
                    .into_iter()
                    .map(|change| FlowingSourceAtom {
                        cut_id: change.cut_id,
                        change_id: change.change_id,
                        path: change.path,
                        before: change.before,
                        after: change.after,
                    })
                    .collect::<Vec<_>>(),
            );
            expected_manifest = match cut.parent_cut_id.as_deref() {
                Some(parent_id) => {
                    let Some(parent) = self.branches.get_cut(parent_id)? else {
                        return Ok(R::MissingCut {
                            cut_id: parent_id.to_owned(),
                        });
                    };
                    Some(parent.manifest_hash)
                }
                None => None,
            };
            cursor = cut.parent_cut_id;
        }
        if expected_manifest != source.branch_point_manifest_hash {
            return Ok(R::SourceNotReady);
        }
        reverse.reverse();
        let atoms: Vec<_> = reverse.into_iter().flatten().collect();
        let atom_map: BTreeMap<_, _> = atoms
            .iter()
            .map(|atom| ((atom.cut_id.as_str(), atom.path.as_str()), atom))
            .collect();
        if atoms.is_empty() || atom_map.len() != atoms.len() {
            return Ok(R::IncompleteUnits);
        }
        let mut owners = BTreeSet::new();
        let mut units = Vec::new();
        for declaration in self.branches.source_contributions(source_branch_id)? {
            if self
                .branches
                .contribution_handoff(&declaration.unit_id)?
                .is_some()
                || self
                    .branches
                    .admitted_unit_operation(&declaration.unit_id)?
                    .is_some()
                || self
                    .branches
                    .parked_flowing_unit(&declaration.unit_id)?
                    .is_some()
            {
                return Ok(R::UnitNotOwed {
                    unit_id: declaration.unit_id,
                });
            }
            let Some(pin) = self.branches.private_cut_pin(&declaration.pin_id)? else {
                return Ok(R::UnitBasisMismatch {
                    unit_id: declaration.unit_id,
                });
            };
            let Some(basis) = self.branches.contribution_basis(&declaration.unit_id)? else {
                return Ok(R::UnitBasisMismatch {
                    unit_id: declaration.unit_id,
                });
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
            if pin.released_at.is_some()
                || pin.twig_branch_id != source_branch_id
                || pin.pin_id != declaration.pin_id
                || pin.cut_id != declaration.source_cut_id
                || pin.manifest_hash != declaration.source_manifest_hash
                || cut_manifests.get(&pin.cut_id) != Some(&pin.manifest_hash)
                || pin.principal != declaration.principal
                || basis.basis_digest != digest
                || basis.atoms.is_empty()
            {
                return Ok(R::UnitBasisMismatch {
                    unit_id: declaration.unit_id,
                });
            }
            for atom in &basis.atoms {
                let key = (atom.cut_id.as_str(), atom.path.as_str());
                if atom_map.get(&key) != Some(&atom)
                    || !owners.insert((atom.cut_id.clone(), atom.path.clone()))
                {
                    return Ok(R::UnitBasisMismatch {
                        unit_id: declaration.unit_id,
                    });
                }
            }
            units.push(AbandonedUnitBasis {
                unit_id: declaration.unit_id,
                basis_digest: basis.basis_digest,
                atoms: basis.atoms,
            });
        }
        if units.is_empty() || owners.len() != atoms.len() {
            return Ok(R::IncompleteUnits);
        }
        let before = self.load_manifest(Some(before_manifest_hash))?;
        let point = self.load_manifest(source.branch_point_manifest_hash.as_deref())?;
        let mut replay = point.clone();
        for atom in &atoms {
            if replay.get(&atom.path) != atom.before.as_ref() {
                return Ok(R::IncompleteUnits);
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
        if replay != before {
            return Ok(R::IncompleteUnits);
        }
        for content_id in atoms
            .iter()
            .flat_map(|atom| [atom.before.as_ref(), atom.after.as_ref()])
            .flatten()
            .chain(point.values())
            .chain(before.values())
        {
            if !self.content.cached_read_available(content_id)? {
                return Ok(R::MissingContent {
                    content_id: content_id.clone(),
                });
            }
        }
        Ok(R::Prepared(Box::new(WholeTwigAbandonment {
            source_branch_id: source_branch_id.to_owned(),
            source_incarnation_id: fence.incarnation_id,
            source_eligibility_epoch: fence.eligibility_epoch,
            source_owner_epoch: fence.owner_epoch,
            before_cut_id: before_cut_id.to_owned(),
            before_manifest_hash: before_manifest_hash.to_owned(),
            branch_point_cut_id: source.branch_point_cut_id,
            branch_point_manifest_hash: source.branch_point_manifest_hash,
            units,
        })))
    }
}
