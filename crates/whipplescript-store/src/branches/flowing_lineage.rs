//! Mutable lineage policy captured from retained source facts. This is not
//! a content or holder proof; those remain prerequisites of ref admission.

use std::collections::{BTreeMap, BTreeSet};

use super::flowing_admission::{FlowingCandidateWitness, FlowingGateCertificate};
use super::flowing_fence::{FlowingFenceState, FlowingSourceKind};
use super::flowing_sources::{ContributionBasis, ContributionDeclaration, FlowingSources};
use super::{BranchRow, BranchStatus, Branches, CutRow, MAINLINE_BRANCH_ID};
use crate::StoreResult;

trait Reader {
    fn branch(&self, id: &str) -> StoreResult<Option<BranchRow>>;
    fn cut(&self, id: &str) -> StoreResult<Option<CutRow>>;
    fn fence(&self, id: &str) -> StoreResult<Option<FlowingFenceState>>;
    fn unit(&self, id: &str) -> StoreResult<Option<(ContributionDeclaration, ContributionBasis)>>;
}

struct StoreReader<'a, B>(&'a B);
impl<B: Branches + FlowingSources> Reader for StoreReader<'_, B> {
    fn branch(&self, id: &str) -> StoreResult<Option<BranchRow>> {
        self.0.get_branch(id)
    }
    fn cut(&self, id: &str) -> StoreResult<Option<CutRow>> {
        self.0.get_cut(id)
    }
    fn fence(&self, id: &str) -> StoreResult<Option<FlowingFenceState>> {
        self.0.flowing_source(id)
    }
    fn unit(&self, id: &str) -> StoreResult<Option<(ContributionDeclaration, ContributionBasis)>> {
        Ok(self
            .0
            .contribution_declaration(id)?
            .zip(self.0.contribution_basis(id)?))
    }
}

/// Unknown lineage is distinct from an empty policy scope. Missing retained
/// facts or ineligible applicable branches never produce a usable vector.
pub fn capture<B: Branches + FlowingSources>(
    branches: &B,
    witness: &FlowingCandidateWitness,
) -> StoreResult<Option<Vec<FlowingFenceState>>> {
    capture_from(&StoreReader(branches), witness)
}

fn ancestry(
    reader: &impl Reader,
    origin: &str,
    current_holder: &str,
    fences: &mut BTreeMap<String, FlowingFenceState>,
) -> StoreResult<bool> {
    let mut cursor = origin.to_owned();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(cursor.clone()) {
            return Ok(false);
        }
        let Some(branch) = reader.branch(&cursor)? else {
            return Ok(false);
        };
        if branch.branch_id != cursor {
            return Ok(false);
        }
        if cursor == MAINLINE_BRANCH_ID {
            return Ok(branch.status == BranchStatus::Active && branch.parent_branch_id.is_none());
        }
        // A transferred twig supplies provenance. Its named ancestors and
        // the current holder supply the applicable mutable policy.
        if branch.name.is_some() || cursor == current_holder {
            let Some(fence) = reader.fence(&cursor)? else {
                return Ok(false);
            };
            let expected_kind = if branch.name.is_some() {
                FlowingSourceKind::Branch
            } else {
                FlowingSourceKind::Twig
            };
            if branch.status != BranchStatus::Active
                || fence.source_branch_id != cursor
                || fence.kind != expected_kind
                || fence.incarnation_id.trim().is_empty()
                || fence.owner.trim().is_empty()
                || fence.owner_epoch < 0
                || fence.eligibility_epoch < 0
                || fence.held
                || fence.revision.is_some()
                || !fence.admission_enabled
            {
                return Ok(false);
            }
            if fences
                .insert(cursor.clone(), fence.clone())
                .is_some_and(|old| old != fence)
            {
                return Ok(false);
            }
        }
        let Some(parent) = branch.parent_branch_id else {
            return Ok(false);
        };
        cursor = parent;
    }
}

fn capture_from(
    reader: &impl Reader,
    witness: &FlowingCandidateWitness,
) -> StoreResult<Option<Vec<FlowingFenceState>>> {
    let mut fences = BTreeMap::new();
    if witness.units.is_empty()
        || !ancestry(
            reader,
            &witness.source_branch_id,
            &witness.source_branch_id,
            &mut fences,
        )?
    {
        return Ok(None);
    }
    for selected in &witness.units {
        let Some((declaration, basis)) = reader.unit(&selected.unit_id)? else {
            return Ok(None);
        };
        if declaration.unit_id != selected.unit_id
            || basis.unit_id != selected.unit_id
            || basis.basis_digest != selected.basis_digest
            || declaration.principal != selected.principal
            || declaration.intent != selected.intent
            || basis.atoms.is_empty()
        {
            return Ok(None);
        }
        let Some(source_cut) = reader.cut(&declaration.source_cut_id)? else {
            return Ok(None);
        };
        if source_cut.branch_id != declaration.source_branch_id
            || source_cut.manifest_hash != declaration.source_manifest_hash
            || !ancestry(
                reader,
                &declaration.source_branch_id,
                &witness.source_branch_id,
                &mut fences,
            )?
        {
            return Ok(None);
        }
        for atom in &basis.atoms {
            let Some(cut) = reader.cut(&atom.cut_id)? else {
                return Ok(None);
            };
            if cut.cut_id != atom.cut_id
                || cut.change_id != atom.change_id
                || !ancestry(
                    reader,
                    &cut.branch_id,
                    &witness.source_branch_id,
                    &mut fences,
                )?
            {
                return Ok(None);
            }
        }
    }
    if fences
        .get(&witness.source_branch_id)
        .is_none_or(|fence| fence.incarnation_id != witness.source_incarnation_id)
    {
        return Ok(None);
    }
    Ok(Some(fences.into_values().collect()))
}

/// A legacy certificate covers only its one source fence. Empty historical
/// metadata must not acquire authority over additional retained origins.
pub fn matches_certificate(
    current: &[FlowingFenceState],
    certificate: &FlowingGateCertificate,
    source_branch_id: &str,
) -> bool {
    if certificate.lineage_fences.is_empty() {
        current.len() == 1 && current[0].source_branch_id == source_branch_id
    } else {
        current == certificate.lineage_fences
    }
}

#[cfg(feature = "native")]
pub(crate) fn native_capture(
    connection: &rusqlite::Connection,
    witness: &FlowingCandidateWitness,
) -> StoreResult<Option<Vec<FlowingFenceState>>> {
    struct NativeReader<'a>(&'a rusqlite::Connection);
    impl Reader for NativeReader<'_> {
        fn branch(&self, id: &str) -> StoreResult<Option<BranchRow>> {
            super::BranchStore::row_by_id(self.0, id)
        }
        fn cut(&self, id: &str) -> StoreResult<Option<CutRow>> {
            super::BranchStore::cut_by_id(self.0, id)
        }
        fn fence(&self, id: &str) -> StoreResult<Option<FlowingFenceState>> {
            super::flowing_fence::native::read_state(self.0, id)
        }
        fn unit(
            &self,
            id: &str,
        ) -> StoreResult<Option<(ContributionDeclaration, ContributionBasis)>> {
            super::flowing_sources::native::lineage_unit(self.0, id)
        }
    }
    capture_from(&NativeReader(connection), witness)
}
