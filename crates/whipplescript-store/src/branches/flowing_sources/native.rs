use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use super::{
    derived_cut_digest, missing_basis_field, missing_declaration_field, missing_derived_cut_field,
    missing_handoff_field, missing_pin_field, missing_release_field, BindContributionBasis,
    BindContributionBasisOutcome, ContributionBasis, ContributionDeclaration, DeclareContribution,
    DeclareContributionOutcome, FlowingDerivedCut, FlowingSources, HandoffContribution,
    HandoffContributionOutcome, HandoffReceipt, PinPrivateCut, PinPrivateCutOutcome, PrivateCutPin,
    RecordFlowingDerivedCut, RecordFlowingDerivedCutOutcome, ReleasePrivateCut,
    ReleasePrivateCutOutcome,
};
use crate::branches::{BranchStatus, BranchStore, MAINLINE_BRANCH_ID};
use crate::{StoreError, StoreResult};

fn read_derived_cut(
    connection: &Connection,
    derivation_id: &str,
) -> StoreResult<Option<FlowingDerivedCut>> {
    type DerivedRow = (
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        String,
    );
    let row: Option<DerivedRow> = connection
        .query_row(
            "SELECT derivation_id, target_branch_id, target_before_cut_id, \
                    target_after_cut_id, target_after_manifest_hash, witness_json, \
                    witness_digest, actor, recorded_at \
             FROM flowing_derived_cuts WHERE derivation_id = ?1",
            [derivation_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            derivation_id,
            target_branch_id,
            target_before_cut_id,
            target_after_cut_id,
            target_after_manifest_hash,
            witness_json,
            witness_digest,
            actor,
            recorded_at,
        )| {
            let witness = serde_json::from_str(&witness_json)?;
            if derived_cut_digest(&witness) != witness_digest
                || witness.target_branch_id() != target_branch_id
                || witness.target_before_cut_id() != target_before_cut_id.as_deref()
                || witness.target_after_cut_id() != target_after_cut_id
                || witness.target_after_manifest_hash() != target_after_manifest_hash
            {
                return Err(StoreError::Conflict(
                    "flowing derived-cut witness differs from its digest".into(),
                ));
            }
            Ok(FlowingDerivedCut {
                derivation_id,
                witness,
                witness_digest,
                actor,
                recorded_at,
            })
        },
    )
    .transpose()
}

fn read_pin(connection: &Connection, pin_id: &str) -> StoreResult<Option<PrivateCutPin>> {
    connection
        .query_row(
            "SELECT pin_id, twig_branch_id, cut_id, manifest_hash, principal, \
             retained_at, released_at, released_by, release_reason \
             FROM flowing_private_pins WHERE pin_id = ?1",
            params![pin_id],
            |row| {
                Ok(PrivateCutPin {
                    pin_id: row.get(0)?,
                    twig_branch_id: row.get(1)?,
                    cut_id: row.get(2)?,
                    manifest_hash: row.get(3)?,
                    principal: row.get(4)?,
                    retained_at: row.get(5)?,
                    released_at: row.get(6)?,
                    released_by: row.get(7)?,
                    release_reason: row.get(8)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn read_declaration(
    connection: &Connection,
    unit_id: &str,
) -> StoreResult<Option<ContributionDeclaration>> {
    connection
        .query_row(
            "SELECT unit_id, pin_id, source_branch_id, source_cut_id, \
             source_manifest_hash, principal, intent, read_basis_digest, \
             dependency_basis_digest, scope_digest, declared_at \
             FROM flowing_contributions WHERE unit_id = ?1",
            params![unit_id],
            |row| {
                Ok(ContributionDeclaration {
                    unit_id: row.get(0)?,
                    pin_id: row.get(1)?,
                    source_branch_id: row.get(2)?,
                    source_cut_id: row.get(3)?,
                    source_manifest_hash: row.get(4)?,
                    principal: row.get(5)?,
                    intent: row.get(6)?,
                    read_basis_digest: row.get(7)?,
                    dependency_basis_digest: row.get(8)?,
                    scope_digest: row.get(9)?,
                    declared_at: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn read_basis(connection: &Connection, unit_id: &str) -> StoreResult<Option<ContributionBasis>> {
    let row: Option<(String, String, String, String)> = connection
        .query_row(
            "SELECT unit_id, basis_digest, atoms_json, bound_at \
             FROM flowing_contribution_basis WHERE unit_id = ?1",
            params![unit_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    row.map(|(unit_id, basis_digest, atoms_json, bound_at)| {
        Ok(ContributionBasis {
            unit_id,
            basis_digest,
            atoms: serde_json::from_str(&atoms_json)?,
            bound_at,
        })
    })
    .transpose()
}

#[derive(Clone, Copy)]
enum HandoffLookup {
    Operation,
    Unit,
}

fn read_handoff(
    connection: &Connection,
    lookup: HandoffLookup,
    value: &str,
) -> StoreResult<Option<HandoffReceipt>> {
    let query = match lookup {
        HandoffLookup::Operation => {
            "SELECT op_id, unit_id, source_branch_id, source_cut_id, \
                     source_manifest_hash, source_basis_digest, target_branch_id, \
                     target_before_cut_id, target_after_cut_id, target_after_manifest_hash, \
                     effects_json, original_principal, actor, recorded_at \
                     FROM flowing_handoffs WHERE op_id = ?1"
        }
        HandoffLookup::Unit => {
            "SELECT op_id, unit_id, source_branch_id, source_cut_id, \
                       source_manifest_hash, source_basis_digest, target_branch_id, \
                       target_before_cut_id, target_after_cut_id, target_after_manifest_hash, \
                       effects_json, original_principal, actor, recorded_at \
                       FROM flowing_handoffs WHERE unit_id = ?1"
        }
    };
    let row: Option<(HandoffReceipt, String)> = connection
        .query_row(query, params![value], handoff_row)
        .optional()?;
    row.map(decode_handoff).transpose()
}

fn handoff_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(HandoffReceipt, String)> {
    Ok((
        HandoffReceipt {
            op_id: row.get(0)?,
            unit_id: row.get(1)?,
            source_branch_id: row.get(2)?,
            source_cut_id: row.get(3)?,
            source_manifest_hash: row.get(4)?,
            source_basis_digest: row.get(5)?,
            target_branch_id: row.get(6)?,
            target_before_cut_id: row.get(7)?,
            target_after_cut_id: row.get(8)?,
            target_after_manifest_hash: row.get(9)?,
            effects: Vec::new(),
            original_principal: row.get(11)?,
            actor: row.get(12)?,
            recorded_at: row.get(13)?,
        },
        row.get(10)?,
    ))
}

fn decode_handoff(
    (mut receipt, effects_json): (HandoffReceipt, String),
) -> StoreResult<HandoffReceipt> {
    receipt.effects = serde_json::from_str(&effects_json)?;
    Ok(receipt)
}

impl FlowingSources for BranchStore {
    fn pin_private_cut(&mut self, request: PinPrivateCut<'_>) -> StoreResult<PinPrivateCutOutcome> {
        if let Some(field) = missing_pin_field(request) {
            return Ok(PinPrivateCutOutcome::Invalid { field });
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_pin(&tx, request.pin_id)? {
            if existing.twig_branch_id != request.twig_branch_id
                || existing.cut_id != request.cut_id
                || existing.manifest_hash != request.manifest_hash
                || existing.principal != request.principal
                || existing.retained_at != request.retained_at
            {
                return Ok(PinPrivateCutOutcome::IdentityMismatch);
            }
            return Ok(if existing.released_at.is_some() {
                PinPrivateCutOutcome::Released
            } else {
                PinPrivateCutOutcome::Existing
            });
        }
        let Some(branch) = BranchStore::row_by_id(&tx, request.twig_branch_id)? else {
            return Ok(PinPrivateCutOutcome::BranchMissing);
        };
        if branch.status != BranchStatus::Active {
            return Ok(PinPrivateCutOutcome::BranchNotActive);
        }
        let cut: Option<(String, String)> = tx
            .query_row(
                "SELECT branch_id, manifest_hash FROM cuts WHERE cut_id = ?1",
                params![request.cut_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((branch_id, manifest_hash)) = cut else {
            return Ok(PinPrivateCutOutcome::CutMissing);
        };
        if branch_id != request.twig_branch_id || manifest_hash != request.manifest_hash {
            return Ok(PinPrivateCutOutcome::CutMismatch);
        }
        tx.execute(
            "INSERT INTO flowing_private_pins \
             (pin_id, twig_branch_id, cut_id, manifest_hash, principal, retained_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                request.pin_id,
                request.twig_branch_id,
                request.cut_id,
                request.manifest_hash,
                request.principal,
                request.retained_at,
            ],
        )?;
        tx.commit()?;
        Ok(PinPrivateCutOutcome::Pinned)
    }

    fn private_cut_pin(&self, pin_id: &str) -> StoreResult<Option<PrivateCutPin>> {
        read_pin(&self.connection, pin_id)
    }

    fn declare_contribution(
        &mut self,
        request: DeclareContribution<'_>,
    ) -> StoreResult<DeclareContributionOutcome> {
        if let Some(field) = missing_declaration_field(request) {
            return Ok(DeclareContributionOutcome::Invalid { field });
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_declaration(&tx, request.unit_id)? {
            return Ok(
                if existing.pin_id == request.pin_id
                    && existing.principal == request.principal
                    && existing.intent == request.intent
                    && existing.read_basis_digest == request.read_basis_digest
                    && existing.dependency_basis_digest == request.dependency_basis_digest
                    && existing.scope_digest == request.scope_digest
                    && existing.declared_at == request.declared_at
                {
                    DeclareContributionOutcome::Existing
                } else {
                    DeclareContributionOutcome::IdentityMismatch
                },
            );
        }
        let Some(pin) = read_pin(&tx, request.pin_id)? else {
            return Ok(DeclareContributionOutcome::PinMissing);
        };
        if pin.released_at.is_some() {
            return Ok(DeclareContributionOutcome::PinReleased);
        }
        if pin.principal != request.principal {
            return Ok(DeclareContributionOutcome::PrincipalMismatch);
        }
        tx.execute(
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, \
              source_manifest_hash, principal, intent, read_basis_digest, \
              dependency_basis_digest, scope_digest, declared_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                request.unit_id,
                request.pin_id,
                pin.twig_branch_id,
                pin.cut_id,
                pin.manifest_hash,
                request.principal,
                request.intent,
                request.read_basis_digest,
                request.dependency_basis_digest,
                request.scope_digest,
                request.declared_at,
            ],
        )?;
        tx.commit()?;
        Ok(DeclareContributionOutcome::Declared)
    }

    fn contribution_declaration(
        &self,
        unit_id: &str,
    ) -> StoreResult<Option<ContributionDeclaration>> {
        read_declaration(&self.connection, unit_id)
    }

    fn source_contributions(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<Vec<ContributionDeclaration>> {
        let mut statement = self.connection.prepare(
            "SELECT unit_id, pin_id, source_branch_id, source_cut_id, \
             source_manifest_hash, principal, intent, read_basis_digest, \
             dependency_basis_digest, scope_digest, declared_at \
             FROM flowing_contributions WHERE source_branch_id = ?1 ORDER BY unit_id",
        )?;
        let rows = statement
            .query_map([source_branch_id], |row| {
                Ok(ContributionDeclaration {
                    unit_id: row.get(0)?,
                    pin_id: row.get(1)?,
                    source_branch_id: row.get(2)?,
                    source_cut_id: row.get(3)?,
                    source_manifest_hash: row.get(4)?,
                    principal: row.get(5)?,
                    intent: row.get(6)?,
                    read_basis_digest: row.get(7)?,
                    dependency_basis_digest: row.get(8)?,
                    scope_digest: row.get(9)?,
                    declared_at: row.get(10)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn bind_contribution_basis(
        &mut self,
        request: BindContributionBasis<'_>,
    ) -> StoreResult<BindContributionBasisOutcome> {
        if let Some(field) = missing_basis_field(request) {
            return Ok(BindContributionBasisOutcome::Invalid { field });
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_basis(&tx, request.unit_id)? {
            return Ok(
                if existing.basis_digest == request.selection.digest()
                    && existing.atoms == request.selection.changes()
                    && existing.bound_at == request.bound_at
                {
                    BindContributionBasisOutcome::Existing
                } else {
                    BindContributionBasisOutcome::IdentityMismatch
                },
            );
        }
        let Some(unit) = read_declaration(&tx, request.unit_id)? else {
            return Ok(BindContributionBasisOutcome::UnitMissing);
        };
        let Some(pin) = read_pin(&tx, &unit.pin_id)? else {
            return Ok(BindContributionBasisOutcome::PinMissing);
        };
        if pin.released_at.is_some() {
            return Ok(BindContributionBasisOutcome::PinReleased);
        }
        if pin.pin_id != request.selection.pin_id()
            || pin.twig_branch_id != request.selection.source_branch_id()
            || pin.cut_id != request.selection.source_cut_id()
            || pin.manifest_hash != request.selection.source_manifest_hash()
            || unit.source_branch_id != request.selection.source_branch_id()
            || unit.source_cut_id != request.selection.source_cut_id()
            || unit.source_manifest_hash != request.selection.source_manifest_hash()
        {
            return Ok(BindContributionBasisOutcome::SelectionMismatch);
        }
        let pinned_cut: Option<(String, String)> = tx
            .query_row(
                "SELECT branch_id, manifest_hash FROM cuts WHERE cut_id = ?1",
                params![unit.source_cut_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((branch_id, manifest_hash)) = pinned_cut else {
            return Ok(BindContributionBasisOutcome::CutMissing);
        };
        if branch_id != unit.source_branch_id || manifest_hash != unit.source_manifest_hash {
            return Ok(BindContributionBasisOutcome::CutMismatch);
        }
        for atom in request.selection.changes() {
            let atom_cut: Option<(String, String)> = tx
                .query_row(
                    "SELECT branch_id, change_id FROM cuts WHERE cut_id = ?1",
                    params![atom.cut_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((atom_branch, atom_change)) = atom_cut else {
                return Ok(BindContributionBasisOutcome::CutMissing);
            };
            if atom_branch != unit.source_branch_id || atom_change != atom.change_id {
                return Ok(BindContributionBasisOutcome::CutMismatch);
            }
            let holder: Option<String> = tx
                .query_row(
                    "SELECT unit_id FROM flowing_source_atom_owners \
                     WHERE source_branch_id = ?1 AND source_cut_id = ?2 AND path = ?3",
                    params![unit.source_branch_id, atom.cut_id, atom.path],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(unit_id) = holder {
                return Ok(BindContributionBasisOutcome::AtomOwned {
                    unit_id,
                    cut_id: atom.cut_id.clone(),
                    path: atom.path.clone(),
                });
            }
        }
        tx.execute(
            "INSERT INTO flowing_contribution_basis \
             (unit_id, basis_digest, atoms_json, bound_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                request.unit_id,
                request.selection.digest(),
                serde_json::to_string(request.selection.changes())?,
                request.bound_at,
            ],
        )?;
        for atom in request.selection.changes() {
            tx.execute(
                "INSERT INTO flowing_source_atom_owners \
                 (source_branch_id, source_cut_id, path, unit_id) VALUES (?1, ?2, ?3, ?4)",
                params![
                    unit.source_branch_id,
                    atom.cut_id,
                    atom.path,
                    request.unit_id
                ],
            )?;
        }
        tx.commit()?;
        Ok(BindContributionBasisOutcome::Bound)
    }

    fn contribution_basis(&self, unit_id: &str) -> StoreResult<Option<ContributionBasis>> {
        read_basis(&self.connection, unit_id)
    }

    fn handoff_contribution(
        &mut self,
        request: HandoffContribution<'_>,
    ) -> StoreResult<HandoffContributionOutcome> {
        if let Some(field) = missing_handoff_field(request) {
            return Ok(HandoffContributionOutcome::Invalid { field });
        }
        let witness = request.witness;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_handoff(&tx, HandoffLookup::Operation, request.op_id)? {
            return Ok(
                if existing.unit_id == witness.unit_id()
                    && existing.source_basis_digest == witness.basis_digest()
                    && existing.target_branch_id == witness.target_branch_id()
                    && existing.target_before_cut_id.as_deref() == witness.target_before_cut_id()
                    && existing.target_after_cut_id == witness.target_after_cut_id()
                    && existing.target_after_manifest_hash == witness.target_after_manifest_hash()
                    && existing.effects == witness.effects()
                    && existing.actor == request.actor
                    && existing.recorded_at == request.recorded_at
                {
                    HandoffContributionOutcome::Existing(existing)
                } else {
                    HandoffContributionOutcome::IdentityMismatch
                },
            );
        }
        if read_handoff(&tx, HandoffLookup::Unit, witness.unit_id())?.is_some() {
            return Ok(HandoffContributionOutcome::AlreadyTransferred);
        }
        let Some(unit) = read_declaration(&tx, witness.unit_id())? else {
            return Ok(HandoffContributionOutcome::UnitMissing);
        };
        let Some(basis) = read_basis(&tx, witness.unit_id())? else {
            return Ok(HandoffContributionOutcome::BasisMissing);
        };
        if basis.basis_digest != witness.basis_digest() {
            return Ok(HandoffContributionOutcome::BasisMismatch);
        }
        let Some(pin) = read_pin(&tx, &unit.pin_id)? else {
            return Ok(HandoffContributionOutcome::PinMissing);
        };
        if pin.released_at.is_some() {
            return Ok(HandoffContributionOutcome::PinReleased);
        }
        let Some(source) = BranchStore::row_by_id(&tx, &unit.source_branch_id)? else {
            return Ok(HandoffContributionOutcome::SourceMissing);
        };
        if source.status != BranchStatus::Active {
            return Ok(HandoffContributionOutcome::SourceNotActive);
        }
        if witness.target_branch_id() == MAINLINE_BRANCH_ID {
            return Ok(HandoffContributionOutcome::TrunkRequiresGate);
        }
        let Some(target) = BranchStore::row_by_id(&tx, witness.target_branch_id())? else {
            return Ok(HandoffContributionOutcome::TargetMissing);
        };
        if target.status != BranchStatus::Active {
            return Ok(HandoffContributionOutcome::TargetNotActive);
        }
        if source.parent_branch_id.as_deref() != Some(witness.target_branch_id()) {
            return Ok(HandoffContributionOutcome::TargetNotParent);
        }
        let reservation: Option<String> = tx
            .query_row(
                "SELECT reservation_id FROM branch_head_reservations WHERE branch_id = ?1",
                params![witness.target_branch_id()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(holder) = reservation {
            return Ok(HandoffContributionOutcome::TargetReserved { holder });
        }
        if target.head_cut_id.as_deref() != witness.target_before_cut_id() {
            return Ok(HandoffContributionOutcome::TargetStale {
                current_head_cut_id: target.head_cut_id,
            });
        }
        let target_cut = BranchStore::cut_by_id(&tx, witness.target_after_cut_id())?;
        let Some(target_cut) = target_cut else {
            return Ok(HandoffContributionOutcome::TargetCutMissing);
        };
        if target_cut.branch_id != witness.target_branch_id()
            || target_cut.manifest_hash != witness.target_after_manifest_hash()
            || target_cut.parent_cut_id.as_deref() != witness.target_before_cut_id()
        {
            return Ok(HandoffContributionOutcome::TargetCutMismatch);
        }
        if target_cut.origin.as_deref()
            != Some(format!("transport:{}", unit.source_branch_id).as_str())
            || target_cut.actor.as_deref() != Some(request.actor)
        {
            return Ok(HandoffContributionOutcome::TargetCutAuthorshipMismatch);
        }
        if let Some(state) =
            crate::branches::flowing_fence::native::read_state(&tx, witness.target_branch_id())?
        {
            if crate::branches::flowing_fence::require_head_move(
                &state,
                witness.target_before_cut_id(),
                witness.target_after_cut_id(),
                witness.target_after_manifest_hash(),
                Some(&target_cut),
            )
            .is_err()
            {
                return Ok(HandoffContributionOutcome::TargetFenceRefused);
            }
        }
        let receipt = HandoffReceipt {
            op_id: request.op_id.to_owned(),
            unit_id: unit.unit_id,
            source_branch_id: unit.source_branch_id,
            source_cut_id: unit.source_cut_id,
            source_manifest_hash: unit.source_manifest_hash,
            source_basis_digest: basis.basis_digest,
            target_branch_id: witness.target_branch_id().to_owned(),
            target_before_cut_id: target.head_cut_id,
            target_after_cut_id: witness.target_after_cut_id().to_owned(),
            target_after_manifest_hash: witness.target_after_manifest_hash().to_owned(),
            effects: witness.effects().to_vec(),
            original_principal: unit.principal,
            actor: request.actor.to_owned(),
            recorded_at: request.recorded_at.to_owned(),
        };
        tx.execute(
            "INSERT INTO flowing_handoffs \
             (op_id, unit_id, source_branch_id, source_cut_id, source_manifest_hash, \
              source_basis_digest, target_branch_id, target_before_cut_id, target_after_cut_id, \
              target_after_manifest_hash, effects_json, original_principal, actor, recorded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                receipt.op_id,
                receipt.unit_id,
                receipt.source_branch_id,
                receipt.source_cut_id,
                receipt.source_manifest_hash,
                receipt.source_basis_digest,
                receipt.target_branch_id,
                receipt.target_before_cut_id,
                receipt.target_after_cut_id,
                receipt.target_after_manifest_hash,
                serde_json::to_string(&receipt.effects)?,
                receipt.original_principal,
                receipt.actor,
                receipt.recorded_at,
            ],
        )?;
        tx.execute(
            "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, updated_at = ?4 \
             WHERE branch_id = ?1",
            params![
                witness.target_branch_id(),
                witness.target_after_cut_id(),
                witness.target_after_manifest_hash(),
                request.recorded_at,
            ],
        )?;
        tx.commit()?;
        Ok(HandoffContributionOutcome::Transferred(receipt))
    }

    fn handoff_receipt(&self, op_id: &str) -> StoreResult<Option<HandoffReceipt>> {
        read_handoff(&self.connection, HandoffLookup::Operation, op_id)
    }

    fn contribution_handoff(&self, unit_id: &str) -> StoreResult<Option<HandoffReceipt>> {
        read_handoff(&self.connection, HandoffLookup::Unit, unit_id)
    }

    fn target_handoffs(&self, target_branch_id: &str) -> StoreResult<Vec<HandoffReceipt>> {
        let mut statement = self.connection.prepare(
            "SELECT op_id, unit_id, source_branch_id, source_cut_id, \
             source_manifest_hash, source_basis_digest, target_branch_id, \
             target_before_cut_id, target_after_cut_id, target_after_manifest_hash, \
             effects_json, original_principal, actor, recorded_at \
             FROM flowing_handoffs WHERE target_branch_id = ?1 ORDER BY op_id",
        )?;
        let receipts = statement
            .query_map([target_branch_id], handoff_row)?
            .map(|row| decode_handoff(row?))
            .collect();
        receipts
    }

    fn record_flowing_derived_cut(
        &mut self,
        request: RecordFlowingDerivedCut<'_>,
    ) -> StoreResult<RecordFlowingDerivedCutOutcome> {
        use RecordFlowingDerivedCutOutcome as R;
        if let Some(field) = missing_derived_cut_field(request) {
            return Ok(R::Invalid { field });
        }
        let witness = request.witness();
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_derived_cut(&tx, request.derivation_id())? {
            return Ok(
                if existing.witness == *witness
                    && existing.actor == request.actor()
                    && existing.recorded_at == request.recorded_at()
                {
                    R::Existing(existing)
                } else {
                    R::IdentityMismatch
                },
            );
        }
        let already_derived: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM flowing_derived_cuts WHERE target_after_cut_id = ?1)",
            [witness.target_after_cut_id()],
            |row| row.get(0),
        )?;
        if already_derived {
            return Ok(R::CutAlreadyDerived);
        }
        if witness.target_branch_id() == MAINLINE_BRANCH_ID {
            return Ok(R::TrunkRequiresGate);
        }
        let Some(target) = BranchStore::row_by_id(&tx, witness.target_branch_id())? else {
            return Ok(R::TargetMissing);
        };
        if target.status != BranchStatus::Active {
            return Ok(R::TargetNotActive);
        }
        let Some(cut) = BranchStore::cut_by_id(&tx, witness.target_after_cut_id())? else {
            return Ok(R::CutMissing);
        };
        if cut.branch_id != witness.target_branch_id()
            || cut.parent_cut_id.as_deref() != witness.target_before_cut_id()
            || cut.manifest_hash != witness.target_after_manifest_hash()
        {
            return Ok(R::CutMismatch);
        }
        if cut.origin.as_deref()
            != Some(format!("transport-batch:{}", request.derivation_id()).as_str())
            || cut.actor.as_deref() != Some(request.actor())
            || cut.recorded_at != request.recorded_at()
        {
            return Ok(R::CutAuthorshipMismatch);
        }
        for selected in witness.units() {
            let unit_id = selected.unit_id();
            let Some(unit) = read_declaration(&tx, unit_id)? else {
                return Ok(R::UnitMissing {
                    unit_id: unit_id.into(),
                });
            };
            let Some(basis) = read_basis(&tx, unit_id)? else {
                return Ok(R::BasisMissing {
                    unit_id: unit_id.into(),
                });
            };
            if unit.source_branch_id != selected.source_branch_id()
                || unit.source_cut_id != selected.source_cut_id()
                || basis.basis_digest != selected.basis_digest()
            {
                return Ok(R::BasisMismatch {
                    unit_id: unit_id.into(),
                });
            }
            let Some(pin) = read_pin(&tx, &unit.pin_id)? else {
                return Ok(R::PinMissing {
                    unit_id: unit_id.into(),
                });
            };
            if pin.released_at.is_some() {
                return Ok(R::PinReleased {
                    unit_id: unit_id.into(),
                });
            }
            let Some(source) = BranchStore::row_by_id(&tx, &unit.source_branch_id)? else {
                return Ok(R::SourceNotActive {
                    unit_id: unit_id.into(),
                });
            };
            if source.status != BranchStatus::Active {
                return Ok(R::SourceNotActive {
                    unit_id: unit_id.into(),
                });
            }
            if source.parent_branch_id.as_deref() != Some(witness.target_branch_id()) {
                return Ok(R::SourceNotParent {
                    unit_id: unit_id.into(),
                });
            }
        }
        let record = FlowingDerivedCut {
            derivation_id: request.derivation_id().into(),
            witness: witness.clone(),
            witness_digest: derived_cut_digest(witness),
            actor: request.actor().into(),
            recorded_at: request.recorded_at().into(),
        };
        tx.execute(
            "INSERT INTO flowing_derived_cuts \
             (derivation_id, target_after_cut_id, target_branch_id, target_before_cut_id, \
              target_after_manifest_hash, witness_json, witness_digest, actor, recorded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                record.derivation_id,
                witness.target_after_cut_id(),
                witness.target_branch_id(),
                witness.target_before_cut_id(),
                witness.target_after_manifest_hash(),
                serde_json::to_string(witness)?,
                record.witness_digest,
                record.actor,
                record.recorded_at,
            ],
        )?;
        tx.commit()?;
        Ok(R::Recorded(record))
    }

    fn flowing_derived_cut(&self, derivation_id: &str) -> StoreResult<Option<FlowingDerivedCut>> {
        read_derived_cut(&self.connection, derivation_id)
    }

    fn release_private_cut(
        &mut self,
        request: ReleasePrivateCut<'_>,
    ) -> StoreResult<ReleasePrivateCutOutcome> {
        if let Some(field) = missing_release_field(request) {
            return Ok(ReleasePrivateCutOutcome::Invalid { field });
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(pin) = read_pin(&tx, request.pin_id)? else {
            return Ok(ReleasePrivateCutOutcome::Missing);
        };
        if pin.released_at.is_some() {
            return Ok(ReleasePrivateCutOutcome::AlreadyReleased);
        }
        let declared: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM flowing_contributions AS unit \
             LEFT JOIN flowing_handoffs AS handoff ON handoff.unit_id = unit.unit_id \
             WHERE unit.pin_id = ?1 AND handoff.unit_id IS NULL)",
            params![request.pin_id],
            |row| row.get(0),
        )?;
        if declared {
            return Ok(ReleasePrivateCutOutcome::HasDeclaredUnit);
        }
        tx.execute(
            "UPDATE flowing_private_pins SET released_at = ?2, released_by = ?3, \
             release_reason = ?4 WHERE pin_id = ?1",
            params![
                request.pin_id,
                request.released_at,
                request.released_by,
                request.reason
            ],
        )?;
        tx.commit()?;
        Ok(ReleasePrivateCutOutcome::Released)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::branches::{Branches, CreateBranch, CutRecord, MAINLINE_BRANCH_ID};

    fn seed() -> BranchStore {
        let mut store = BranchStore::open_in_memory().expect("store");
        store.ensure_mainline("t0").expect("mainline");
        store
            .create_branch(CreateBranch {
                branch_id: "twig-1",
                name: None,
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .expect("twig");
        store
            .record_cut(CutRecord {
                cut_id: "cut-1",
                change_id: "change-1",
                branch_id: "twig-1",
                manifest_hash: "manifest-1",
                parent_cut_id: None,
                origin: Some("write:notes"),
                actor: Some("s:session-1"),
                intent: None,
                recorded_at: "t2",
            })
            .expect("cut");
        store
    }

    fn pin<'a>() -> PinPrivateCut<'a> {
        PinPrivateCut {
            pin_id: "pin-1",
            twig_branch_id: "twig-1",
            cut_id: "cut-1",
            manifest_hash: "manifest-1",
            principal: "s:session-1",
            retained_at: "t3",
        }
    }

    fn declaration<'a>() -> DeclareContribution<'a> {
        DeclareContribution {
            unit_id: "unit-1",
            pin_id: "pin-1",
            principal: "s:session-1",
            intent: "repair customer rule",
            read_basis_digest: "reads-1",
            dependency_basis_digest: "deps-1",
            scope_digest: "scope-1",
            declared_at: "t4",
        }
    }

    fn release<'a>() -> ReleasePrivateCut<'a> {
        ReleasePrivateCut {
            pin_id: "pin-1",
            released_by: "s:session-1",
            reason: "explicitly abandoned private draft",
            released_at: "t5",
        }
    }

    #[test]
    fn private_pin_survives_until_explicit_release_and_cannot_resurrect() {
        let mut store = seed();
        assert_eq!(
            store.pin_private_cut(pin()).unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        assert_eq!(
            store.pin_private_cut(pin()).unwrap(),
            PinPrivateCutOutcome::Existing
        );
        assert!(store.pinned_cuts("year-3000").unwrap().contains("cut-1"));
        assert_eq!(
            store
                .pin_private_cut(PinPrivateCut {
                    manifest_hash: "changed",
                    ..pin()
                })
                .unwrap(),
            PinPrivateCutOutcome::IdentityMismatch
        );
        assert_eq!(
            store.release_private_cut(release()).unwrap(),
            ReleasePrivateCutOutcome::Released
        );
        let released = store.private_cut_pin("pin-1").unwrap().unwrap();
        assert_eq!(released.released_by.as_deref(), Some("s:session-1"));
        assert_eq!(
            released.release_reason.as_deref(),
            Some("explicitly abandoned private draft")
        );
        assert!(!store.pinned_cuts("t6").unwrap().contains("cut-1"));
        assert_eq!(
            store.pin_private_cut(pin()).unwrap(),
            PinPrivateCutOutcome::Released
        );
        assert_eq!(
            store.declare_contribution(declaration()).unwrap(),
            DeclareContributionOutcome::PinReleased
        );
    }

    #[test]
    fn declaration_binds_exact_cut_and_prevents_pin_release() {
        let mut store = seed();
        assert_eq!(
            store
                .pin_private_cut(PinPrivateCut {
                    principal: " ",
                    ..pin()
                })
                .unwrap(),
            PinPrivateCutOutcome::Invalid { field: "principal" }
        );
        assert_eq!(
            store
                .pin_private_cut(PinPrivateCut {
                    cut_id: "absent",
                    ..pin()
                })
                .unwrap(),
            PinPrivateCutOutcome::CutMissing
        );
        assert_eq!(
            store
                .pin_private_cut(PinPrivateCut {
                    manifest_hash: "wrong",
                    ..pin()
                })
                .unwrap(),
            PinPrivateCutOutcome::CutMismatch
        );
        assert_eq!(
            store.pin_private_cut(pin()).unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        assert_eq!(
            store
                .declare_contribution(DeclareContribution {
                    principal: "different",
                    ..declaration()
                })
                .unwrap(),
            DeclareContributionOutcome::PrincipalMismatch
        );
        assert_eq!(
            store
                .declare_contribution(DeclareContribution {
                    intent: "",
                    ..declaration()
                })
                .unwrap(),
            DeclareContributionOutcome::Invalid { field: "intent" }
        );
        assert_eq!(
            store.declare_contribution(declaration()).unwrap(),
            DeclareContributionOutcome::Declared
        );
        assert_eq!(
            store.declare_contribution(declaration()).unwrap(),
            DeclareContributionOutcome::Existing
        );
        assert_eq!(
            store
                .declare_contribution(DeclareContribution {
                    intent: "different substance",
                    ..declaration()
                })
                .unwrap(),
            DeclareContributionOutcome::IdentityMismatch
        );
        let recorded = store.contribution_declaration("unit-1").unwrap().unwrap();
        assert_eq!(recorded.source_cut_id, "cut-1");
        assert_eq!(recorded.source_manifest_hash, "manifest-1");
        assert_eq!(recorded.principal, "s:session-1");
        assert_eq!(
            store.release_private_cut(release()).unwrap(),
            ReleasePrivateCutOutcome::HasDeclaredUnit
        );
        assert_eq!(
            store
                .release_private_cut(ReleasePrivateCut {
                    reason: "",
                    ..release()
                })
                .unwrap(),
            ReleasePrivateCutOutcome::Invalid { field: "reason" }
        );
        assert!(store.pinned_cuts("year-3000").unwrap().contains("cut-1"));
    }

    #[test]
    fn private_cut_survives_store_reopen() {
        let dir = crate::scratch::path("flowing-private-pin-reopen");
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("branches.sqlite");
        {
            let mut store = BranchStore::open(&path).expect("store");
            store.ensure_mainline("t0").expect("mainline");
            store
                .create_branch(CreateBranch {
                    branch_id: "twig-1",
                    name: None,
                    parent_branch_id: MAINLINE_BRANCH_ID,
                    at_cut: None,
                    created_at: "t1",
                    idempotency_key: None,
                })
                .expect("twig");
            store
                .record_cut(CutRecord {
                    cut_id: "cut-1",
                    change_id: "change-1",
                    branch_id: "twig-1",
                    manifest_hash: "manifest-1",
                    parent_cut_id: None,
                    origin: Some("write:notes"),
                    actor: Some("s:session-1"),
                    intent: None,
                    recorded_at: "t2",
                })
                .expect("cut");
            assert_eq!(
                store.pin_private_cut(pin()).unwrap(),
                PinPrivateCutOutcome::Pinned
            );
            assert_eq!(
                store.declare_contribution(declaration()).unwrap(),
                DeclareContributionOutcome::Declared
            );
        }
        let store = BranchStore::open(&path).expect("reopen");
        assert!(store.pinned_cuts("year-3000").unwrap().contains("cut-1"));
        assert_eq!(
            store
                .contribution_declaration("unit-1")
                .unwrap()
                .unwrap()
                .source_cut_id,
            "cut-1"
        );
        drop(store);
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
