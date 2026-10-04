//! Reconstruct the still-owed unit roster on a twig after one disjoint rewrite.
//!
//! A rewrite receipt accounts for old source atoms, while ordinary writes
//! after it are new source atoms. Neither a receipt nor a cut id alone proves
//! that all of those atoms still have one accountable contribution.

use std::collections::{BTreeMap, BTreeSet};

use crate::branches::flowing_admission::FlowingAdmissions;
use crate::branches::flowing_rewrite::FlowingRewrites;
use crate::branches::flowing_sources::{ContributionDeclaration, FlowingSources};
use crate::branches::Branches;
use crate::content::ContentBlobs;
use crate::StoreResult;

use super::{CurrentFlowingRewritePrefix, CurrentFlowingRewritePrefixOutcome};
use crate::vcs::flowing_selection::FlowingSourceAtom;
use crate::vcs::WorkspaceVcs;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowingRewriteOwedUnit {
    pub unit_id: String,
    pub basis_digest: String,
    pub principal: String,
    pub intent: String,
    /// Historical receipt atoms or later ordinary-write atoms, never both.
    pub atoms: Vec<FlowingSourceAtom>,
    pub from_rewrite: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentFlowingRewriteRoster {
    prefix: CurrentFlowingRewritePrefix,
    units: Vec<FlowingRewriteOwedUnit>,
}

impl CurrentFlowingRewriteRoster {
    pub fn prefix(&self) -> &CurrentFlowingRewritePrefix {
        &self.prefix
    }

    pub fn units(&self) -> &[FlowingRewriteOwedUnit] {
        &self.units
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CurrentFlowingRewriteRosterOutcome {
    Verified(Box<CurrentFlowingRewriteRoster>),
    Source(CurrentFlowingRewritePrefixOutcome),
    IncompleteRoster,
    UnitNotOwed { unit_id: String },
    UnitBasisMismatch { unit_id: String },
}

fn basis_digest(
    declaration: &ContributionDeclaration,
    atoms: &[FlowingSourceAtom],
) -> StoreResult<String> {
    let encoded = serde_json::to_vec(&(
        "flowing-source-selection-v1",
        &declaration.pin_id,
        &declaration.source_branch_id,
        &declaration.source_cut_id,
        &declaration.source_manifest_hash,
        atoms,
    ))?;
    Ok(format!(
        "sha256:{}",
        crate::chunking::content_hash_hex(&encoded)
    ))
}

impl<B: Branches + FlowingRewrites + FlowingSources + FlowingAdmissions, C: ContentBlobs>
    WorkspaceVcs<B, C>
{
    /// Account for every atom on a one-rewrite twig with a still-owed bound
    /// unit. This read may race a source move; admission must recheck its exact
    /// head, fence, roots and unit states under ref exclusion. Old units' read,
    /// dependency and policy bases still need current semantic revalidation.
    pub fn verify_current_flowing_rewrite_roster(
        &self,
        source_branch_id: &str,
        after_cut_id: &str,
    ) -> StoreResult<CurrentFlowingRewriteRosterOutcome> {
        use CurrentFlowingRewriteRosterOutcome as R;
        let prefix =
            match self.verify_current_flowing_rewrite_prefix(source_branch_id, after_cut_id)? {
                CurrentFlowingRewritePrefixOutcome::Verified(prefix) => *prefix,
                outcome => return Ok(R::Source(outcome)),
            };
        self.verify_flowing_rewrite_roster_from_prefix(source_branch_id, prefix)
    }

    /// Account for exactly the units through `selected_cut_id`; an ordinary
    /// later tail remains owed but cannot invalidate this earlier selection.
    /// Admission must recapture the selected cut and current source ancestry
    /// under ref exclusion before using the result.
    pub fn verify_selected_flowing_rewrite_roster(
        &self,
        source_branch_id: &str,
        after_cut_id: &str,
        selected_cut_id: &str,
    ) -> StoreResult<CurrentFlowingRewriteRosterOutcome> {
        use CurrentFlowingRewriteRosterOutcome as R;
        let prefix = match self.verify_selected_flowing_rewrite_prefix(
            source_branch_id,
            after_cut_id,
            selected_cut_id,
        )? {
            CurrentFlowingRewritePrefixOutcome::Verified(prefix) => *prefix,
            outcome => return Ok(R::Source(outcome)),
        };
        self.verify_flowing_rewrite_roster_from_prefix(source_branch_id, prefix)
    }

    fn verify_flowing_rewrite_roster_from_prefix(
        &self,
        source_branch_id: &str,
        prefix: CurrentFlowingRewritePrefix,
    ) -> StoreResult<CurrentFlowingRewriteRosterOutcome> {
        use CurrentFlowingRewriteRosterOutcome as R;
        let later_cut_ids: BTreeSet<&str> =
            prefix.later_cut_ids().iter().map(String::as_str).collect();
        let mut declarations = BTreeMap::new();
        for declaration in self.branches.source_contributions(source_branch_id)? {
            if declarations
                .insert(declaration.unit_id.clone(), declaration)
                .is_some()
            {
                return Ok(R::IncompleteRoster);
            }
        }
        let mut units = Vec::new();
        let mut used = BTreeSet::new();
        for root in &prefix.lineage().receipt().roots {
            let Some(declaration) = declarations.get(root.unit_id()) else {
                return Ok(R::IncompleteRoster);
            };
            let Some(last_atom) = root.atoms().last() else {
                return Ok(R::UnitBasisMismatch {
                    unit_id: root.unit_id().into(),
                });
            };
            if declaration.source_cut_id != last_atom.cut_id
                || !used.insert(root.unit_id().to_owned())
            {
                return Ok(R::UnitBasisMismatch {
                    unit_id: root.unit_id().into(),
                });
            }
            if let Some(refusal) = self.verify_owed_rewrite_unit(declaration, root.atoms())? {
                return Ok(refusal);
            }
            if root.basis_digest() != basis_digest(declaration, root.atoms())? {
                return Ok(R::UnitBasisMismatch {
                    unit_id: root.unit_id().into(),
                });
            }
            units.push(FlowingRewriteOwedUnit {
                unit_id: root.unit_id().into(),
                basis_digest: root.basis_digest().into(),
                principal: declaration.principal.clone(),
                intent: declaration.intent.clone(),
                atoms: root.atoms().to_vec(),
                from_rewrite: true,
            });
        }

        let tail = prefix.tail_atoms();
        let expected: BTreeMap<_, _> = tail
            .iter()
            .enumerate()
            .map(|(position, atom)| ((atom.cut_id.as_str(), atom.path.as_str()), (position, atom)))
            .collect();
        if expected.len() != tail.len() {
            return Ok(R::IncompleteRoster);
        }
        let mut owners = BTreeMap::new();
        let mut cut_owners = BTreeMap::new();
        let mut tail_units = Vec::new();
        for declaration in declarations.values() {
            if used.contains(&declaration.unit_id)
                || later_cut_ids.contains(declaration.source_cut_id.as_str())
            {
                continue;
            }
            let Some(basis) = self.branches.contribution_basis(&declaration.unit_id)? else {
                return Ok(R::UnitBasisMismatch {
                    unit_id: declaration.unit_id.clone(),
                });
            };
            if basis.atoms.is_empty()
                || basis.basis_digest != basis_digest(declaration, &basis.atoms)?
            {
                return Ok(R::UnitBasisMismatch {
                    unit_id: declaration.unit_id.clone(),
                });
            }
            let mut first = None;
            let mut previous = None;
            for atom in &basis.atoms {
                let key = (atom.cut_id.as_str(), atom.path.as_str());
                let Some((position, expected_atom)) = expected.get(&key) else {
                    return Ok(R::UnitBasisMismatch {
                        unit_id: declaration.unit_id.clone(),
                    });
                };
                if *expected_atom != atom
                    || previous.is_some_and(|p| p >= *position)
                    || owners
                        .insert(
                            (atom.cut_id.clone(), atom.path.clone()),
                            declaration.unit_id.clone(),
                        )
                        .is_some()
                    || cut_owners
                        .insert(atom.cut_id.clone(), declaration.unit_id.clone())
                        .is_some_and(|owner| owner != declaration.unit_id)
                {
                    return Ok(R::UnitBasisMismatch {
                        unit_id: declaration.unit_id.clone(),
                    });
                }
                first.get_or_insert(*position);
                previous = Some(*position);
            }
            if declaration.source_cut_id != basis.atoms.last().expect("nonempty").cut_id {
                return Ok(R::UnitBasisMismatch {
                    unit_id: declaration.unit_id.clone(),
                });
            }
            if let Some(refusal) = self.verify_owed_rewrite_unit(declaration, &basis.atoms)? {
                return Ok(refusal);
            }
            tail_units.push((
                first.expect("nonempty"),
                FlowingRewriteOwedUnit {
                    unit_id: declaration.unit_id.clone(),
                    basis_digest: basis.basis_digest,
                    principal: declaration.principal.clone(),
                    intent: declaration.intent.clone(),
                    atoms: basis.atoms,
                    from_rewrite: false,
                },
            ));
            used.insert(declaration.unit_id.clone());
        }
        if used.len()
            != declarations
                .values()
                .filter(|declaration| !later_cut_ids.contains(declaration.source_cut_id.as_str()))
                .count()
            || owners.len() != tail.len()
        {
            return Ok(R::IncompleteRoster);
        }
        tail_units.sort_by_key(|(position, _)| *position);
        let mut finished = BTreeSet::new();
        let mut previous_owner = None;
        for atom in tail {
            let Some(owner) = cut_owners.get(&atom.cut_id) else {
                return Ok(R::IncompleteRoster);
            };
            if previous_owner != Some(owner.as_str()) && !finished.insert(owner.as_str()) {
                return Ok(R::IncompleteRoster);
            }
            previous_owner = Some(owner.as_str());
        }
        units.extend(tail_units.into_iter().map(|(_, unit)| unit));
        Ok(R::Verified(Box::new(CurrentFlowingRewriteRoster {
            prefix,
            units,
        })))
    }

    fn verify_owed_rewrite_unit(
        &self,
        declaration: &ContributionDeclaration,
        atoms: &[FlowingSourceAtom],
    ) -> StoreResult<Option<CurrentFlowingRewriteRosterOutcome>> {
        use CurrentFlowingRewriteRosterOutcome as R;

        if self
            .branches
            .admitted_unit_operation(&declaration.unit_id)?
            .is_some()
            || self
                .branches
                .contribution_handoff(&declaration.unit_id)?
                .is_some()
        {
            return Ok(Some(R::UnitNotOwed {
                unit_id: declaration.unit_id.clone(),
            }));
        }
        let Some(pin) = self.branches.private_cut_pin(&declaration.pin_id)? else {
            return Ok(Some(R::UnitBasisMismatch {
                unit_id: declaration.unit_id.clone(),
            }));
        };
        let Some(basis) = self.branches.contribution_basis(&declaration.unit_id)? else {
            return Ok(Some(R::UnitBasisMismatch {
                unit_id: declaration.unit_id.clone(),
            }));
        };
        let Some(cut) = self.branches.get_cut(&declaration.source_cut_id)? else {
            return Ok(Some(R::UnitBasisMismatch {
                unit_id: declaration.unit_id.clone(),
            }));
        };
        if pin.released_at.is_some()
            || pin.pin_id != declaration.pin_id
            || pin.twig_branch_id != declaration.source_branch_id
            || pin.cut_id != declaration.source_cut_id
            || pin.manifest_hash != declaration.source_manifest_hash
            || pin.principal != declaration.principal
            || cut.branch_id != declaration.source_branch_id
            || cut.manifest_hash != declaration.source_manifest_hash
            || basis.unit_id != declaration.unit_id
            || basis.atoms != atoms
            || basis.basis_digest != basis_digest(declaration, atoms)?
        {
            return Ok(Some(R::UnitBasisMismatch {
                unit_id: declaration.unit_id.clone(),
            }));
        }
        Ok(None)
    }
}
