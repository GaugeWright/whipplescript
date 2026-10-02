use super::DoBranches;
use crate::do_store::{as_opt_text, as_text, sql_err, text, DoSql, SqlValue};
use whipplescript_store::branches::flowing_sources::{
    derived_cut_digest, missing_basis_field, missing_declaration_field, missing_derived_cut_field,
    missing_handoff_field, missing_pin_field, missing_release_field, BindContributionBasis,
    BindContributionBasisOutcome, ContributionBasis, ContributionDeclaration, DeclareContribution,
    DeclareContributionOutcome, FlowingDerivedCut, FlowingSources, HandoffContribution,
    HandoffContributionOutcome, HandoffReceipt, PinPrivateCut, PinPrivateCutOutcome, PrivateCutPin,
    RecordFlowingDerivedCut, RecordFlowingDerivedCutOutcome, ReleasePrivateCut,
    ReleasePrivateCutOutcome,
};
use whipplescript_store::branches::{BranchStatus, Branches, MAINLINE_BRANCH_ID};
use whipplescript_store::{StoreError, StoreResult};

pub(super) fn exact_atomic<S: DoSql, T>(
    sql: &S,
    subject: &str,
    mut body: impl FnMut() -> StoreResult<T>,
) -> StoreResult<T> {
    let mut called = false;
    let mut result = None;
    sql.atomic(&mut || {
        if called {
            return Err(StoreError::fault(subject, "SQL host repeated atomic body"));
        }
        called = true;
        result = Some(body()?);
        Ok(())
    })?;
    result.ok_or_else(|| StoreError::fault(subject, "SQL host skipped atomic body"))
}

fn read_derived_cut<S: DoSql>(
    sql: &S,
    derivation_id: &str,
) -> StoreResult<Option<FlowingDerivedCut>> {
    let rows = sql
        .query(
            "SELECT derivation_id, target_branch_id, target_before_cut_id, \
                target_after_cut_id, target_after_manifest_hash, witness_json, \
                witness_digest, actor, recorded_at \
         FROM flowing_derived_cuts WHERE derivation_id = ?1",
            &[text(derivation_id)],
        )
        .map_err(sql_err)?;
    rows.first()
        .map(|row| {
            let witness = serde_json::from_str(&as_text(&row[5]))?;
            let witness_digest = as_text(&row[6]);
            if derived_cut_digest(&witness) != witness_digest
                || witness.target_branch_id() != as_text(&row[1])
                || witness.target_before_cut_id() != as_opt_text(&row[2]).as_deref()
                || witness.target_after_cut_id() != as_text(&row[3])
                || witness.target_after_manifest_hash() != as_text(&row[4])
            {
                return Err(StoreError::Conflict(
                    "flowing derived-cut witness differs from its digest or row".into(),
                ));
            }
            Ok(FlowingDerivedCut {
                derivation_id: as_text(&row[0]),
                witness,
                witness_digest,
                actor: as_text(&row[7]),
                recorded_at: as_text(&row[8]),
            })
        })
        .transpose()
}

fn read_pin<S: DoSql>(sql: &S, pin_id: &str) -> StoreResult<Option<PrivateCutPin>> {
    let rows = sql
        .query(
            "SELECT pin_id, twig_branch_id, cut_id, manifest_hash, principal, \
             retained_at, released_at, released_by, release_reason \
             FROM flowing_private_pins WHERE pin_id = ?1",
            &[text(pin_id)],
        )
        .map_err(sql_err)?;
    Ok(rows.first().map(|row| PrivateCutPin {
        pin_id: as_text(&row[0]),
        twig_branch_id: as_text(&row[1]),
        cut_id: as_text(&row[2]),
        manifest_hash: as_text(&row[3]),
        principal: as_text(&row[4]),
        retained_at: as_text(&row[5]),
        released_at: as_opt_text(&row[6]),
        released_by: as_opt_text(&row[7]),
        release_reason: as_opt_text(&row[8]),
    }))
}

fn read_declaration<S: DoSql>(
    sql: &S,
    unit_id: &str,
) -> StoreResult<Option<ContributionDeclaration>> {
    let rows = sql
        .query(
            "SELECT unit_id, pin_id, source_branch_id, source_cut_id, \
             source_manifest_hash, principal, intent, read_basis_digest, \
             dependency_basis_digest, scope_digest, declared_at \
             FROM flowing_contributions WHERE unit_id = ?1",
            &[text(unit_id)],
        )
        .map_err(sql_err)?;
    Ok(rows.first().map(|row| ContributionDeclaration {
        unit_id: as_text(&row[0]),
        pin_id: as_text(&row[1]),
        source_branch_id: as_text(&row[2]),
        source_cut_id: as_text(&row[3]),
        source_manifest_hash: as_text(&row[4]),
        principal: as_text(&row[5]),
        intent: as_text(&row[6]),
        read_basis_digest: as_text(&row[7]),
        dependency_basis_digest: as_text(&row[8]),
        scope_digest: as_text(&row[9]),
        declared_at: as_text(&row[10]),
    }))
}

fn read_basis<S: DoSql>(sql: &S, unit_id: &str) -> StoreResult<Option<ContributionBasis>> {
    let rows = sql
        .query(
            "SELECT unit_id, basis_digest, atoms_json, bound_at \
             FROM flowing_contribution_basis WHERE unit_id = ?1",
            &[text(unit_id)],
        )
        .map_err(sql_err)?;
    rows.first()
        .map(|row| {
            Ok(ContributionBasis {
                unit_id: as_text(&row[0]),
                basis_digest: as_text(&row[1]),
                atoms: serde_json::from_str(&as_text(&row[2]))?,
                bound_at: as_text(&row[3]),
            })
        })
        .transpose()
}

#[derive(Clone, Copy)]
enum HandoffLookup {
    Operation,
    Unit,
}

fn read_handoff<S: DoSql>(
    sql: &S,
    lookup: HandoffLookup,
    value: &str,
) -> StoreResult<Option<HandoffReceipt>> {
    let predicate = match lookup {
        HandoffLookup::Operation => "op_id = ?1",
        HandoffLookup::Unit => "unit_id = ?1",
    };
    let rows = sql
        .query(
            &format!(
                "SELECT op_id, unit_id, source_branch_id, source_cut_id, \
                 source_manifest_hash, source_basis_digest, target_branch_id, \
                 target_before_cut_id, target_after_cut_id, target_after_manifest_hash, \
                 effects_json, original_principal, actor, recorded_at \
                 FROM flowing_handoffs WHERE {predicate}"
            ),
            &[text(value)],
        )
        .map_err(sql_err)?;
    rows.first().map(|row| decode_handoff(row)).transpose()
}

fn decode_handoff(row: &[SqlValue]) -> StoreResult<HandoffReceipt> {
    Ok(HandoffReceipt {
        op_id: as_text(&row[0]),
        unit_id: as_text(&row[1]),
        source_branch_id: as_text(&row[2]),
        source_cut_id: as_text(&row[3]),
        source_manifest_hash: as_text(&row[4]),
        source_basis_digest: as_text(&row[5]),
        target_branch_id: as_text(&row[6]),
        target_before_cut_id: as_opt_text(&row[7]),
        target_after_cut_id: as_text(&row[8]),
        target_after_manifest_hash: as_text(&row[9]),
        effects: serde_json::from_str(&as_text(&row[10]))?,
        original_principal: as_text(&row[11]),
        actor: as_text(&row[12]),
        recorded_at: as_text(&row[13]),
    })
}

impl<S: DoSql> FlowingSources for DoBranches<S> {
    fn pin_private_cut(&mut self, request: PinPrivateCut<'_>) -> StoreResult<PinPrivateCutOutcome> {
        if let Some(field) = missing_pin_field(request) {
            return Ok(PinPrivateCutOutcome::Invalid { field });
        }
        exact_atomic(&self.sql, "flowing private pin", || {
            if let Some(existing) = read_pin(&self.sql, request.pin_id)? {
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
            let Some(branch) = self.row_by_id(request.twig_branch_id)? else {
                return Ok(PinPrivateCutOutcome::BranchMissing);
            };
            if branch.status != BranchStatus::Active {
                return Ok(PinPrivateCutOutcome::BranchNotActive);
            }
            let Some(cut) = self.get_cut(request.cut_id)? else {
                return Ok(PinPrivateCutOutcome::CutMissing);
            };
            if cut.branch_id != request.twig_branch_id || cut.manifest_hash != request.manifest_hash
            {
                return Ok(PinPrivateCutOutcome::CutMismatch);
            }
            self.sql
                .execute(
                    "INSERT INTO flowing_private_pins \
                     (pin_id, twig_branch_id, cut_id, manifest_hash, principal, retained_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    &[
                        text(request.pin_id),
                        text(request.twig_branch_id),
                        text(request.cut_id),
                        text(request.manifest_hash),
                        text(request.principal),
                        text(request.retained_at),
                    ],
                )
                .map_err(sql_err)?;
            Ok(PinPrivateCutOutcome::Pinned)
        })
    }

    fn private_cut_pin(&self, pin_id: &str) -> StoreResult<Option<PrivateCutPin>> {
        read_pin(&self.sql, pin_id)
    }

    fn declare_contribution(
        &mut self,
        request: DeclareContribution<'_>,
    ) -> StoreResult<DeclareContributionOutcome> {
        if let Some(field) = missing_declaration_field(request) {
            return Ok(DeclareContributionOutcome::Invalid { field });
        }
        exact_atomic(&self.sql, "flowing contribution declaration", || {
            if let Some(existing) = read_declaration(&self.sql, request.unit_id)? {
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
            let Some(pin) = read_pin(&self.sql, request.pin_id)? else {
                return Ok(DeclareContributionOutcome::PinMissing);
            };
            if pin.released_at.is_some() {
                return Ok(DeclareContributionOutcome::PinReleased);
            }
            if pin.principal != request.principal {
                return Ok(DeclareContributionOutcome::PrincipalMismatch);
            }
            self.sql
                .execute(
                    "INSERT INTO flowing_contributions \
                     (unit_id, pin_id, source_branch_id, source_cut_id, \
                      source_manifest_hash, principal, intent, read_basis_digest, \
                      dependency_basis_digest, scope_digest, declared_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    &[
                        text(request.unit_id),
                        text(request.pin_id),
                        text(&pin.twig_branch_id),
                        text(&pin.cut_id),
                        text(&pin.manifest_hash),
                        text(request.principal),
                        text(request.intent),
                        text(request.read_basis_digest),
                        text(request.dependency_basis_digest),
                        text(request.scope_digest),
                        text(request.declared_at),
                    ],
                )
                .map_err(sql_err)?;
            Ok(DeclareContributionOutcome::Declared)
        })
    }

    fn contribution_declaration(
        &self,
        unit_id: &str,
    ) -> StoreResult<Option<ContributionDeclaration>> {
        read_declaration(&self.sql, unit_id)
    }

    fn source_contributions(
        &self,
        source_branch_id: &str,
    ) -> StoreResult<Vec<ContributionDeclaration>> {
        let rows = self
            .sql
            .query(
                "SELECT unit_id, pin_id, source_branch_id, source_cut_id, \
             source_manifest_hash, principal, intent, read_basis_digest, \
             dependency_basis_digest, scope_digest, declared_at \
             FROM flowing_contributions WHERE source_branch_id = ?1 ORDER BY unit_id",
                &[text(source_branch_id)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| ContributionDeclaration {
                unit_id: as_text(&row[0]),
                pin_id: as_text(&row[1]),
                source_branch_id: as_text(&row[2]),
                source_cut_id: as_text(&row[3]),
                source_manifest_hash: as_text(&row[4]),
                principal: as_text(&row[5]),
                intent: as_text(&row[6]),
                read_basis_digest: as_text(&row[7]),
                dependency_basis_digest: as_text(&row[8]),
                scope_digest: as_text(&row[9]),
                declared_at: as_text(&row[10]),
            })
            .collect())
    }

    fn bind_contribution_basis(
        &mut self,
        request: BindContributionBasis<'_>,
    ) -> StoreResult<BindContributionBasisOutcome> {
        if let Some(field) = missing_basis_field(request) {
            return Ok(BindContributionBasisOutcome::Invalid { field });
        }
        exact_atomic(&self.sql, "flowing contribution basis", || {
            if let Some(existing) = read_basis(&self.sql, request.unit_id())? {
                return Ok(
                    if existing.basis_digest == request.selection().digest()
                        && existing.atoms == request.selection().changes()
                        && existing.bound_at == request.bound_at()
                    {
                        BindContributionBasisOutcome::Existing
                    } else {
                        BindContributionBasisOutcome::IdentityMismatch
                    },
                );
            }
            let Some(unit) = read_declaration(&self.sql, request.unit_id())? else {
                return Ok(BindContributionBasisOutcome::UnitMissing);
            };
            let Some(pin) = read_pin(&self.sql, &unit.pin_id)? else {
                return Ok(BindContributionBasisOutcome::PinMissing);
            };
            if pin.released_at.is_some() {
                return Ok(BindContributionBasisOutcome::PinReleased);
            }
            if pin.pin_id != request.selection().pin_id()
                || pin.twig_branch_id != request.selection().source_branch_id()
                || pin.cut_id != request.selection().source_cut_id()
                || pin.manifest_hash != request.selection().source_manifest_hash()
                || unit.source_branch_id != request.selection().source_branch_id()
                || unit.source_cut_id != request.selection().source_cut_id()
                || unit.source_manifest_hash != request.selection().source_manifest_hash()
            {
                return Ok(BindContributionBasisOutcome::SelectionMismatch);
            }
            let Some(cut) = self.get_cut(&unit.source_cut_id)? else {
                return Ok(BindContributionBasisOutcome::CutMissing);
            };
            if cut.branch_id != unit.source_branch_id
                || cut.manifest_hash != unit.source_manifest_hash
            {
                return Ok(BindContributionBasisOutcome::CutMismatch);
            }
            for atom in request.selection().changes() {
                let Some(atom_cut) = self.get_cut(&atom.cut_id)? else {
                    return Ok(BindContributionBasisOutcome::CutMissing);
                };
                if atom_cut.branch_id != unit.source_branch_id
                    || atom_cut.change_id != atom.change_id
                {
                    return Ok(BindContributionBasisOutcome::CutMismatch);
                }
                let rows = self
                    .sql
                    .query(
                        "SELECT unit_id FROM flowing_source_atom_owners \
                     WHERE source_branch_id = ?1 AND source_cut_id = ?2 AND path = ?3",
                        &[
                            text(&unit.source_branch_id),
                            text(&atom.cut_id),
                            text(&atom.path),
                        ],
                    )
                    .map_err(sql_err)?;
                if let Some(row) = rows.first() {
                    return Ok(BindContributionBasisOutcome::AtomOwned {
                        unit_id: as_text(&row[0]),
                        cut_id: atom.cut_id.clone(),
                        path: atom.path.clone(),
                    });
                }
            }
            self.sql
                .execute(
                    "INSERT INTO flowing_contribution_basis \
                 (unit_id, basis_digest, atoms_json, bound_at) VALUES (?1, ?2, ?3, ?4)",
                    &[
                        text(request.unit_id()),
                        text(request.selection().digest()),
                        text(&serde_json::to_string(request.selection().changes())?),
                        text(request.bound_at()),
                    ],
                )
                .map_err(sql_err)?;
            for atom in request.selection().changes() {
                self.sql
                    .execute(
                        "INSERT INTO flowing_source_atom_owners \
                     (source_branch_id, source_cut_id, path, unit_id) VALUES (?1, ?2, ?3, ?4)",
                        &[
                            text(&unit.source_branch_id),
                            text(&atom.cut_id),
                            text(&atom.path),
                            text(request.unit_id()),
                        ],
                    )
                    .map_err(sql_err)?;
            }
            Ok(BindContributionBasisOutcome::Bound)
        })
    }

    fn contribution_basis(&self, unit_id: &str) -> StoreResult<Option<ContributionBasis>> {
        read_basis(&self.sql, unit_id)
    }

    fn handoff_contribution(
        &mut self,
        request: HandoffContribution<'_>,
    ) -> StoreResult<HandoffContributionOutcome> {
        if let Some(field) = missing_handoff_field(request) {
            return Ok(HandoffContributionOutcome::Invalid { field });
        }
        let witness = request.witness();
        exact_atomic(&self.sql, "flowing contribution handoff", || {
            if let Some(existing) =
                read_handoff(&self.sql, HandoffLookup::Operation, request.op_id())?
            {
                return Ok(
                    if existing.unit_id == witness.unit_id()
                        && existing.source_basis_digest == witness.basis_digest()
                        && existing.target_branch_id == witness.target_branch_id()
                        && existing.target_before_cut_id.as_deref()
                            == witness.target_before_cut_id()
                        && existing.target_after_cut_id == witness.target_after_cut_id()
                        && existing.target_after_manifest_hash
                            == witness.target_after_manifest_hash()
                        && existing.effects == witness.effects()
                        && existing.actor == request.actor()
                        && existing.recorded_at == request.recorded_at()
                    {
                        HandoffContributionOutcome::Existing(existing)
                    } else {
                        HandoffContributionOutcome::IdentityMismatch
                    },
                );
            }
            if read_handoff(&self.sql, HandoffLookup::Unit, witness.unit_id())?.is_some() {
                return Ok(HandoffContributionOutcome::AlreadyTransferred);
            }
            let Some(unit) = read_declaration(&self.sql, witness.unit_id())? else {
                return Ok(HandoffContributionOutcome::UnitMissing);
            };
            let Some(basis) = read_basis(&self.sql, witness.unit_id())? else {
                return Ok(HandoffContributionOutcome::BasisMissing);
            };
            if basis.basis_digest != witness.basis_digest() {
                return Ok(HandoffContributionOutcome::BasisMismatch);
            }
            let Some(pin) = read_pin(&self.sql, &unit.pin_id)? else {
                return Ok(HandoffContributionOutcome::PinMissing);
            };
            if pin.released_at.is_some() {
                return Ok(HandoffContributionOutcome::PinReleased);
            }
            let Some(source) = self.row_by_id(&unit.source_branch_id)? else {
                return Ok(HandoffContributionOutcome::SourceMissing);
            };
            if source.status != BranchStatus::Active {
                return Ok(HandoffContributionOutcome::SourceNotActive);
            }
            if witness.target_branch_id() == MAINLINE_BRANCH_ID {
                return Ok(HandoffContributionOutcome::TrunkRequiresGate);
            }
            let Some(target) = self.row_by_id(witness.target_branch_id())? else {
                return Ok(HandoffContributionOutcome::TargetMissing);
            };
            if target.status != BranchStatus::Active {
                return Ok(HandoffContributionOutcome::TargetNotActive);
            }
            if source.parent_branch_id.as_deref() != Some(witness.target_branch_id()) {
                return Ok(HandoffContributionOutcome::TargetNotParent);
            }
            if let Some(holder) = self.head_reservation(witness.target_branch_id())? {
                return Ok(HandoffContributionOutcome::TargetReserved { holder });
            }
            if target.head_cut_id.as_deref() != witness.target_before_cut_id() {
                return Ok(HandoffContributionOutcome::TargetStale {
                    current_head_cut_id: target.head_cut_id,
                });
            }
            let Some(target_cut) = self.get_cut(witness.target_after_cut_id())? else {
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
                || target_cut.actor.as_deref() != Some(request.actor())
            {
                return Ok(HandoffContributionOutcome::TargetCutAuthorshipMismatch);
            }
            if let Some(state) =
                super::flowing_fence::read_state(&self.sql, witness.target_branch_id())?
            {
                if whipplescript_store::branches::flowing_fence::require_head_move(
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
                op_id: request.op_id().to_owned(),
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
                actor: request.actor().to_owned(),
                recorded_at: request.recorded_at().to_owned(),
            };
            self.sql
                .execute(
                    "INSERT INTO flowing_handoffs \
                     (op_id, unit_id, source_branch_id, source_cut_id, source_manifest_hash, \
                      source_basis_digest, target_branch_id, target_before_cut_id, target_after_cut_id, \
                      target_after_manifest_hash, effects_json, original_principal, actor, recorded_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                    &[
                        text(&receipt.op_id),
                        text(&receipt.unit_id),
                        text(&receipt.source_branch_id),
                        text(&receipt.source_cut_id),
                        text(&receipt.source_manifest_hash),
                        text(&receipt.source_basis_digest),
                        text(&receipt.target_branch_id),
                        receipt.target_before_cut_id.as_deref().map_or(SqlValue::Null, text),
                        text(&receipt.target_after_cut_id),
                        text(&receipt.target_after_manifest_hash),
                        text(&serde_json::to_string(&receipt.effects)?),
                        text(&receipt.original_principal),
                        text(&receipt.actor),
                        text(&receipt.recorded_at),
                    ],
                )
                .map_err(sql_err)?;
            self.sql
                .execute(
                    "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, updated_at = ?4 \
                     WHERE branch_id = ?1",
                    &[
                        text(witness.target_branch_id()),
                        text(witness.target_after_cut_id()),
                        text(witness.target_after_manifest_hash()),
                        text(request.recorded_at()),
                    ],
                )
                .map_err(sql_err)?;
            Ok(HandoffContributionOutcome::Transferred(receipt))
        })
    }

    fn handoff_receipt(&self, op_id: &str) -> StoreResult<Option<HandoffReceipt>> {
        read_handoff(&self.sql, HandoffLookup::Operation, op_id)
    }

    fn contribution_handoff(&self, unit_id: &str) -> StoreResult<Option<HandoffReceipt>> {
        read_handoff(&self.sql, HandoffLookup::Unit, unit_id)
    }

    fn target_handoffs(&self, target_branch_id: &str) -> StoreResult<Vec<HandoffReceipt>> {
        let rows = self
            .sql
            .query(
                "SELECT op_id, unit_id, source_branch_id, source_cut_id, \
                 source_manifest_hash, source_basis_digest, target_branch_id, \
                 target_before_cut_id, target_after_cut_id, target_after_manifest_hash, \
                 effects_json, original_principal, actor, recorded_at \
                 FROM flowing_handoffs WHERE target_branch_id = ?1 ORDER BY op_id",
                &[text(target_branch_id)],
            )
            .map_err(sql_err)?;
        rows.iter().map(|row| decode_handoff(row)).collect()
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
        exact_atomic(&self.sql, "flowing derived cut", || {
            if let Some(existing) = read_derived_cut(&self.sql, request.derivation_id())? {
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
            if !self
                .sql
                .query(
                    "SELECT 1 FROM flowing_derived_cuts WHERE target_after_cut_id = ?1",
                    &[text(witness.target_after_cut_id())],
                )
                .map_err(sql_err)?
                .is_empty()
            {
                return Ok(R::CutAlreadyDerived);
            }
            if witness.target_branch_id() == MAINLINE_BRANCH_ID {
                return Ok(R::TrunkRequiresGate);
            }
            let Some(target) = self.row_by_id(witness.target_branch_id())? else {
                return Ok(R::TargetMissing);
            };
            if target.status != BranchStatus::Active {
                return Ok(R::TargetNotActive);
            }
            let Some(cut) = self.get_cut(witness.target_after_cut_id())? else {
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
                let Some(unit) = read_declaration(&self.sql, unit_id)? else {
                    return Ok(R::UnitMissing {
                        unit_id: unit_id.into(),
                    });
                };
                let Some(basis) = read_basis(&self.sql, unit_id)? else {
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
                let Some(pin) = read_pin(&self.sql, &unit.pin_id)? else {
                    return Ok(R::PinMissing {
                        unit_id: unit_id.into(),
                    });
                };
                if pin.released_at.is_some() {
                    return Ok(R::PinReleased {
                        unit_id: unit_id.into(),
                    });
                }
                let Some(source) = self.row_by_id(&unit.source_branch_id)? else {
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
            self.sql
                .execute(
                    "INSERT INTO flowing_derived_cuts \
                 (derivation_id, target_after_cut_id, target_branch_id, target_before_cut_id, \
                  target_after_manifest_hash, witness_json, witness_digest, actor, recorded_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    &[
                        text(&record.derivation_id),
                        text(witness.target_after_cut_id()),
                        text(witness.target_branch_id()),
                        witness.target_before_cut_id().map_or(SqlValue::Null, text),
                        text(witness.target_after_manifest_hash()),
                        text(&serde_json::to_string(witness)?),
                        text(&record.witness_digest),
                        text(&record.actor),
                        text(&record.recorded_at),
                    ],
                )
                .map_err(sql_err)?;
            Ok(R::Recorded(record))
        })
    }

    fn flowing_derived_cut(&self, derivation_id: &str) -> StoreResult<Option<FlowingDerivedCut>> {
        read_derived_cut(&self.sql, derivation_id)
    }

    fn release_private_cut(
        &mut self,
        request: ReleasePrivateCut<'_>,
    ) -> StoreResult<ReleasePrivateCutOutcome> {
        if let Some(field) = missing_release_field(request) {
            return Ok(ReleasePrivateCutOutcome::Invalid { field });
        }
        exact_atomic(&self.sql, "flowing private pin release", || {
            let Some(pin) = read_pin(&self.sql, request.pin_id)? else {
                return Ok(ReleasePrivateCutOutcome::Missing);
            };
            if pin.released_at.is_some() {
                return Ok(ReleasePrivateCutOutcome::AlreadyReleased);
            }
            let referenced = self
                .sql
                .query(
                    "SELECT 1 FROM flowing_contributions AS unit \
                     LEFT JOIN flowing_handoffs AS handoff ON handoff.unit_id = unit.unit_id \
                     WHERE unit.pin_id = ?1 AND handoff.unit_id IS NULL LIMIT 1",
                    &[text(request.pin_id)],
                )
                .map_err(sql_err)?;
            if !referenced.is_empty() {
                return Ok(ReleasePrivateCutOutcome::HasDeclaredUnit);
            }
            self.sql
                .execute(
                    "UPDATE flowing_private_pins SET released_at = ?2, released_by = ?3, \
                     release_reason = ?4 WHERE pin_id = ?1",
                    &[
                        text(request.pin_id),
                        text(request.released_at),
                        text(request.released_by),
                        text(request.reason),
                    ],
                )
                .map_err(sql_err)?;
            Ok(ReleasePrivateCutOutcome::Released)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::do_store::test_support::RusqliteDoSql;
    use crate::do_store::SqlValue;
    use whipplescript_store::branches::{CreateBranch, CutRecord, MAINLINE_BRANCH_ID};

    #[test]
    fn hosted_mixed_derivation_retains_both_units_without_a_head_move() {
        use std::rc::Rc;

        use crate::do_branches::DoContentBlobs;
        use whipplescript_store::branches::flowing_sources::RecordFlowingDerivedCutOutcome as R;
        use whipplescript_store::content::ContentBlobs;
        use whipplescript_store::selection::parse;
        use whipplescript_store::vcs::{
            FlowingBatchTargetEffectsOutcome, FlowingSelectionOutcome, WorkspaceVcs,
        };

        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut vcs = WorkspaceVcs::from_parts(
            DoBranches::new(Rc::clone(&sql)).unwrap(),
            DoContentBlobs::new(Rc::clone(&sql)).unwrap(),
        );
        vcs.init("t0").unwrap();
        vcs.create_branch("branch", Some("feature"), MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.create_branch("twig", None, "branch", "t1").unwrap();
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .unwrap();
        vcs.write("twig", "b.txt", Some("B"), "twig-b", "t3")
            .unwrap();
        let mut branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        let mut selected_ids = Vec::new();
        for (unit_id, pin_id, cut_id, path) in [
            ("unit-a", "pin-a", "twig-a", "a.txt"),
            ("unit-b", "pin-b", "twig-b", "b.txt"),
        ] {
            let cut = branches.get_cut(cut_id).unwrap().unwrap();
            assert_eq!(
                branches
                    .pin_private_cut(PinPrivateCut {
                        pin_id,
                        twig_branch_id: "twig",
                        cut_id,
                        manifest_hash: &cut.manifest_hash,
                        principal: "s:author",
                        retained_at: "t4",
                    })
                    .unwrap(),
                PinPrivateCutOutcome::Pinned
            );
            assert_eq!(
                branches
                    .declare_contribution(DeclareContribution {
                        unit_id,
                        pin_id,
                        principal: "s:author",
                        intent: "mixed change",
                        read_basis_digest: "read",
                        dependency_basis_digest: "deps",
                        scope_digest: "scope",
                        declared_at: "t4",
                    })
                    .unwrap(),
                DeclareContributionOutcome::Declared
            );
            let FlowingSelectionOutcome::Selected(selection) = vcs
                .select_private_changes(pin_id, &parse(&format!("path({path})")).unwrap())
                .unwrap()
            else {
                panic!("source selection")
            };
            selected_ids.push((
                path.to_owned(),
                selection.changes()[0].after.clone().unwrap(),
            ));
            assert_eq!(
                vcs.bind_private_selection(unit_id, &selection, "t5")
                    .unwrap(),
                BindContributionBasisOutcome::Bound
            );
        }
        let content = DoContentBlobs::new(Rc::clone(&sql)).unwrap();
        let manifest_hash = content
            .put_text(
                &serde_json::to_string(
                    &selected_ids
                        .into_iter()
                        .collect::<std::collections::BTreeMap<_, _>>(),
                )
                .unwrap(),
            )
            .unwrap();
        branches
            .record_cut(CutRecord {
                cut_id: "batch-cut",
                change_id: "mixed-output",
                branch_id: "branch",
                manifest_hash: &manifest_hash,
                parent_cut_id: None,
                origin: Some("transport-batch:derive-1"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t6",
            })
            .unwrap();
        let FlowingBatchTargetEffectsOutcome::Verified(witness) = vcs
            .verify_private_batch_target_effects(&["unit-a", "unit-b"], "batch-cut")
            .unwrap()
        else {
            panic!("real mixed target")
        };
        let mut forged_json = serde_json::to_value(&witness).unwrap();
        forged_json["units"][1]["basis_digest"] = "wrong".into();
        let forged = serde_json::from_value(forged_json).unwrap();
        assert_eq!(
            vcs.record_private_batch_derivation("derive-forged", &forged, "mediator", "t6")
                .unwrap(),
            R::WitnessMismatch
        );
        assert!(branches
            .flowing_derived_cut("derive-forged")
            .unwrap()
            .is_none());
        let R::Recorded(record) = vcs
            .record_private_batch_derivation("derive-1", &witness, "mediator", "t6")
            .unwrap()
        else {
            panic!("hosted derivation")
        };
        assert_eq!(
            branches.flowing_derived_cut("derive-1").unwrap(),
            Some(record.clone())
        );
        assert_eq!(
            vcs.record_private_batch_derivation("derive-1", &witness, "mediator", "t6")
                .unwrap(),
            R::Existing(record)
        );
        assert!(branches
            .get_branch("branch")
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
        for unit_id in ["unit-a", "unit-b"] {
            assert!(branches.contribution_handoff(unit_id).unwrap().is_none());
        }
        sql.execute(
            "UPDATE flowing_derived_cuts SET witness_digest = 'wrong' WHERE derivation_id = ?1",
            &[text("derive-1")],
        )
        .unwrap();
        assert!(branches.flowing_derived_cut("derive-1").is_err());
    }

    #[test]
    fn hosted_flowing_writes_refuse_a_repeated_or_skipped_atomic_body() {
        struct BrokenSql {
            repeat: bool,
        }
        impl DoSql for BrokenSql {
            fn atomic(&self, body: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
                if self.repeat {
                    body()?;
                    body()
                } else {
                    Ok(())
                }
            }
            fn execute(&self, _: &str, _: &[SqlValue]) -> Result<u64, String> {
                panic!("atomic body never reaches SQL")
            }
            fn query(&self, _: &str, _: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
                panic!("atomic body never reaches SQL")
            }
        }

        let mut repeated_calls = 0;
        let error = exact_atomic(&BrokenSql { repeat: true }, "flowing test", || {
            repeated_calls += 1;
            Ok(())
        })
        .expect_err("repeated host callback must refuse");
        assert_eq!(repeated_calls, 1);
        assert!(format!("{error:?}").contains("SQL host repeated atomic body"));

        let mut skipped_calls = 0;
        let error = exact_atomic(&BrokenSql { repeat: false }, "flowing test", || {
            skipped_calls += 1;
            Ok(())
        })
        .expect_err("skipped host callback must refuse");
        assert_eq!(skipped_calls, 0);
        assert!(format!("{error:?}").contains("SQL host skipped atomic body"));
    }

    #[test]
    fn hosted_workspace_derives_selected_atoms_from_the_retained_cut() {
        use std::rc::Rc;

        use crate::do_branches::DoContentBlobs;
        use whipplescript_store::branches::flowing_sources::BindContributionBasisOutcome;
        use whipplescript_store::selection::parse;
        use whipplescript_store::vcs::{FlowingSelectionOutcome, WorkspaceVcs};

        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut vcs = WorkspaceVcs::from_parts(
            DoBranches::new(Rc::clone(&sql)).unwrap(),
            DoContentBlobs::new(Rc::clone(&sql)).unwrap(),
        );
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.write("twig", "a.txt", Some("A"), "c1", "t2").unwrap();
        let mut pins = DoBranches::new(Rc::clone(&sql)).unwrap();
        let cut = pins.get_cut("c1").unwrap().unwrap();
        assert_eq!(
            pins.pin_private_cut(PinPrivateCut {
                pin_id: "pin-1",
                twig_branch_id: "twig",
                cut_id: "c1",
                manifest_hash: &cut.manifest_hash,
                principal: "s:author",
                retained_at: "t3",
            })
            .unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        assert_eq!(
            pins.declare_contribution(DeclareContribution {
                unit_id: "unit-a",
                pin_id: "pin-1",
                principal: "s:author",
                intent: "customer change",
                read_basis_digest: "reads-1",
                dependency_basis_digest: "deps-1",
                scope_digest: "scope-a",
                declared_at: "t3",
            })
            .unwrap(),
            DeclareContributionOutcome::Declared
        );
        vcs.write("twig", "b.txt", Some("B"), "c2", "t4").unwrap();
        let FlowingSelectionOutcome::Selected(basis) = vcs
            .select_private_changes("pin-1", &parse("path(*)").unwrap())
            .unwrap()
        else {
            panic!("expected hosted source basis");
        };
        assert_eq!(basis.source_cut_id(), "c1");
        assert_eq!(basis.changes().len(), 1);
        assert_eq!(basis.changes()[0].path, "a.txt");
        assert_eq!(basis.changes()[0].cut_id, "c1");
        assert_eq!(
            vcs.bind_private_selection("unit-a", &basis, "t5").unwrap(),
            BindContributionBasisOutcome::Bound
        );
        assert_eq!(
            pins.contribution_basis("unit-a").unwrap().unwrap().atoms,
            basis.changes()
        );
        assert_eq!(
            vcs.bind_private_selection("unit-a", &basis, "t5").unwrap(),
            BindContributionBasisOutcome::Existing
        );
        assert_eq!(
            pins.declare_contribution(DeclareContribution {
                unit_id: "unit-duplicate",
                pin_id: "pin-1",
                principal: "s:author",
                intent: "second claim",
                read_basis_digest: "reads-1",
                dependency_basis_digest: "deps-1",
                scope_digest: "scope-duplicate",
                declared_at: "t6",
            })
            .unwrap(),
            DeclareContributionOutcome::Declared
        );
        assert_eq!(
            vcs.bind_private_selection("unit-duplicate", &basis, "t7")
                .unwrap(),
            BindContributionBasisOutcome::AtomOwned {
                unit_id: "unit-a".into(),
                cut_id: "c1".into(),
                path: "a.txt".into(),
            }
        );
        assert_eq!(pins.contribution_basis("unit-duplicate").unwrap(), None);
        assert_eq!(
            pins.pin_private_cut(PinPrivateCut {
                pin_id: "other-pin",
                twig_branch_id: "twig",
                cut_id: "c1",
                manifest_hash: &cut.manifest_hash,
                principal: "s:author",
                retained_at: "t6",
            })
            .unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        pins.declare_contribution(DeclareContribution {
            unit_id: "unit-other",
            pin_id: "other-pin",
            principal: "s:author",
            intent: "other cut",
            read_basis_digest: "reads-1",
            dependency_basis_digest: "deps-1",
            scope_digest: "scope-other",
            declared_at: "t6",
        })
        .unwrap();
        assert_eq!(
            vcs.bind_private_selection("unit-other", &basis, "t7")
                .unwrap(),
            BindContributionBasisOutcome::SelectionMismatch
        );
    }

    #[test]
    fn hosted_basis_binding_rolls_back_all_atom_owners_on_late_failure() {
        use std::rc::Rc;

        use crate::do_branches::DoContentBlobs;
        use whipplescript_store::selection::parse;
        use whipplescript_store::vcs::{FlowingSelectionOutcome, WorkspaceVcs};

        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut vcs = WorkspaceVcs::from_parts(
            DoBranches::new(Rc::clone(&sql)).unwrap(),
            DoContentBlobs::new(Rc::clone(&sql)).unwrap(),
        );
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.write("twig", "a.txt", Some("A"), "c1", "t2").unwrap();
        vcs.write("twig", "b.txt", Some("B"), "c2", "t3").unwrap();
        let mut pins = DoBranches::new(Rc::clone(&sql)).unwrap();
        let cut = pins.get_cut("c2").unwrap().unwrap();
        pins.pin_private_cut(PinPrivateCut {
            pin_id: "pin-both",
            twig_branch_id: "twig",
            cut_id: "c2",
            manifest_hash: &cut.manifest_hash,
            principal: "s:author",
            retained_at: "t4",
        })
        .unwrap();
        pins.declare_contribution(DeclareContribution {
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
            .select_private_changes("pin-both", &parse("path(*)").unwrap())
            .unwrap()
        else {
            panic!("select both")
        };
        assert_eq!(basis.changes().len(), 2);
        sql.execute(
            "CREATE TRIGGER fail_second_atom BEFORE INSERT ON flowing_source_atom_owners \
             WHEN NEW.path = 'b.txt' BEGIN SELECT RAISE(ABORT, 'late atom failure'); END",
            &[],
        )
        .unwrap();
        assert!(vcs
            .bind_private_selection("unit-both", &basis, "t6")
            .is_err());
        assert_eq!(pins.contribution_basis("unit-both").unwrap(), None);
        assert!(sql
            .query("SELECT unit_id FROM flowing_source_atom_owners", &[])
            .unwrap()
            .is_empty());
        sql.execute("DROP TRIGGER fail_second_atom", &[]).unwrap();
        assert_eq!(
            vcs.bind_private_selection("unit-both", &basis, "t6")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
    }

    #[test]
    fn hosted_direct_trunk_candidate_checks_actual_selected_content() {
        use std::rc::Rc;

        use crate::do_branches::DoContentBlobs;
        use whipplescript_store::content::ContentBlobs;
        use whipplescript_store::selection::parse;
        use whipplescript_store::vcs::{
            FlowingEffectDisposition, FlowingSelectionOutcome, FlowingTargetEffectsOutcome,
            WorkspaceVcs,
        };

        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut vcs = WorkspaceVcs::from_parts(
            DoBranches::new(Rc::clone(&sql)).expect("branches"),
            DoContentBlobs::new(Rc::clone(&sql)).expect("content"),
        );
        vcs.init("t0").expect("initialize");
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .expect("direct twig");
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .expect("source cut");
        let mut branches = DoBranches::new(Rc::clone(&sql)).expect("branches");
        let source_cut = branches.get_cut("twig-a").unwrap().unwrap();
        branches
            .pin_private_cut(PinPrivateCut {
                pin_id: "pin-a",
                twig_branch_id: "twig",
                cut_id: "twig-a",
                manifest_hash: &source_cut.manifest_hash,
                principal: "s:author",
                retained_at: "t3",
            })
            .expect("pin source");
        branches
            .declare_contribution(DeclareContribution {
                unit_id: "unit-a",
                pin_id: "pin-a",
                principal: "s:author",
                intent: "share one file",
                read_basis_digest: "reads-a",
                dependency_basis_digest: "deps-a",
                scope_digest: "scope-a",
                declared_at: "t3",
            })
            .expect("declare source");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-a", &parse("path(a.txt)").unwrap())
            .expect("select source")
        else {
            panic!("source selection must succeed")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a", &selection, "t4")
                .expect("bind source"),
            BindContributionBasisOutcome::Bound
        );
        vcs.write("twig", "b.txt", Some("later"), "twig-tail", "t5")
            .expect("unselected tail remains on twig");
        let body = DoContentBlobs::new(Rc::clone(&sql)).expect("content");
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .prepare_direct_trunk_candidate("unit-a", "trunk-exact", "coordinator", "t5")
            .expect("prepare candidate")
        else {
            panic!("trunk candidate should carry selected content")
        };
        assert_eq!(witness.target_branch_id(), MAINLINE_BRANCH_ID);
        assert_eq!(
            witness.effects()[0].disposition,
            FlowingEffectDisposition::Applied
        );
        assert_eq!(
            vcs.prepare_direct_trunk_candidate("unit-a", "trunk-exact", "coordinator", "t5")
                .expect("exact retry"),
            FlowingTargetEffectsOutcome::Verified(witness.clone())
        );

        let omitted = body.put_text("{}").expect("omitted candidate manifest");
        branches
            .record_cut(CutRecord {
                cut_id: "trunk-omitted",
                change_id: "candidate-omitted",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: &omitted,
                parent_cut_id: None,
                origin: Some("transport:twig"),
                actor: Some("coordinator"),
                intent: None,
                recorded_at: "t5",
            })
            .expect("omitted candidate cut");
        assert_eq!(
            vcs.verify_trunk_target_effects("unit-a", "trunk-omitted")
                .expect("verify omitted candidate"),
            FlowingTargetEffectsOutcome::OmittedEffect {
                path: "a.txt".into()
            }
        );
        assert!(branches
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());

        vcs.write(
            MAINLINE_BRANCH_ID,
            "a.txt",
            Some("A"),
            "trunk-existing",
            "t6",
        )
        .expect("fixture installs equivalent trunk content");
        let FlowingTargetEffectsOutcome::Verified(equivalent) = vcs
            .prepare_direct_trunk_candidate("unit-a", "trunk-existing", "coordinator", "t7")
            .expect("prepare metadata-only candidate")
        else {
            panic!("current trunk content should be equivalent")
        };
        assert_eq!(
            equivalent.effects()[0].disposition,
            FlowingEffectDisposition::Equivalent
        );
        assert_eq!(equivalent.target_before_cut_id(), Some("trunk-existing"));
        assert_eq!(equivalent.target_after_cut_id(), "trunk-existing");
    }

    #[test]
    fn hosted_direct_trunk_initial_noop_keeps_unit_owed() {
        use std::rc::Rc;

        use crate::do_branches::DoContentBlobs;
        use whipplescript_store::selection::parse;
        use whipplescript_store::vcs::{
            FlowingSelectionOutcome, FlowingTargetEffectsOutcome, WorkspaceVcs,
        };

        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut vcs = WorkspaceVcs::from_parts(
            DoBranches::new(Rc::clone(&sql)).unwrap(),
            DoContentBlobs::new(Rc::clone(&sql)).unwrap(),
        );
        vcs.init("t0").unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .unwrap();
        vcs.write("twig", "a.txt", None, "twig-undo", "t3").unwrap();
        let mut branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        let source_cut = branches.get_cut("twig-undo").unwrap().unwrap();
        branches
            .pin_private_cut(PinPrivateCut {
                pin_id: "pin-undo",
                twig_branch_id: "twig",
                cut_id: "twig-undo",
                manifest_hash: &source_cut.manifest_hash,
                principal: "s:author",
                retained_at: "t4",
            })
            .unwrap();
        branches
            .declare_contribution(DeclareContribution {
                unit_id: "unit-undo",
                pin_id: "pin-undo",
                principal: "s:author",
                intent: "undo the file",
                read_basis_digest: "reads-a",
                dependency_basis_digest: "deps-a",
                scope_digest: "scope-a",
                declared_at: "t4",
            })
            .unwrap();
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-undo", &parse("path(a.txt)").unwrap())
            .unwrap()
        else {
            panic!("write and undo must remain selected")
        };
        assert_eq!(selection.changes().len(), 2);
        assert_eq!(
            vcs.bind_private_selection("unit-undo", &selection, "t5")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        assert_eq!(
            vcs.prepare_direct_trunk_candidate("unit-undo", "first-cut", "coordinator", "t6")
                .unwrap(),
            FlowingTargetEffectsOutcome::InitialNoopNeedsGenesis
        );
        assert!(branches.get_cut("first-cut").unwrap().is_none());
        assert!(branches
            .contribution_declaration("unit-undo")
            .unwrap()
            .is_some());
        assert!(branches
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
    }

    #[test]
    fn hosted_handoff_accounts_consecutive_writes_as_one_target_effect() {
        use std::rc::Rc;

        use crate::do_branches::DoContentBlobs;
        use whipplescript_store::branches::flowing_fence::{
            FlowingFence, FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
        };
        use whipplescript_store::selection::parse;
        use whipplescript_store::vcs::{
            FlowingBranchLineageOutcome, FlowingSelectionOutcome, FlowingTargetEffectsOutcome,
            WorkspaceVcs,
        };

        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut vcs = WorkspaceVcs::from_parts(
            DoBranches::new(Rc::clone(&sql)).expect("branches"),
            DoContentBlobs::new(Rc::clone(&sql)).expect("content"),
        );
        vcs.init("t0").unwrap();
        vcs.create_branch("branch", Some("feature"), MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        let mut opening = DoBranches::new(Rc::clone(&sql)).unwrap();
        assert!(matches!(
            opening
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "branch".into(),
                    incarnation_id: "branch-inc".into(),
                    kind: FlowingSourceKind::Branch,
                    owner: "coordinator".into(),
                    opened_at: "t1".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        vcs.create_branch("twig", None, "branch", "t1").unwrap();
        assert!(matches!(
            opening
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t1".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .unwrap();
        vcs.write("twig", "a.txt", Some("B"), "twig-b", "t3")
            .unwrap();
        let mut branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        let source_cut = branches.get_cut("twig-b").unwrap().unwrap();
        assert_eq!(
            branches
                .pin_private_cut(PinPrivateCut {
                    pin_id: "pin-b",
                    twig_branch_id: "twig",
                    cut_id: "twig-b",
                    manifest_hash: &source_cut.manifest_hash,
                    principal: "s:author",
                    retained_at: "t4",
                })
                .unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        assert_eq!(
            branches
                .declare_contribution(DeclareContribution {
                    unit_id: "unit-b",
                    pin_id: "pin-b",
                    principal: "s:author",
                    intent: "two writes to one path",
                    read_basis_digest: "reads-b",
                    dependency_basis_digest: "deps-b",
                    scope_digest: "scope-b",
                    declared_at: "t4",
                })
                .unwrap(),
            DeclareContributionOutcome::Declared
        );
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-b", &parse("path(a.txt)").unwrap())
            .unwrap()
        else {
            panic!("select both writes");
        };
        assert_eq!(selection.changes().len(), 2);
        assert_eq!(
            vcs.bind_private_selection("unit-b", &selection, "t5")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        let expected = selection.changes()[1].after.as_ref().unwrap();
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .prepare_private_handoff_target("unit-b", "target-b", "mediator", "t6")
            .unwrap()
        else {
            panic!("planner derives the net source effect on the target");
        };
        assert_eq!(witness.effects().len(), 1);
        assert_eq!(witness.effects()[0].after.as_ref(), Some(expected));
        assert_eq!(
            witness.effects()[0].disposition,
            whipplescript_store::vcs::FlowingEffectDisposition::Applied
        );
        assert!(matches!(
            vcs.handoff_private_selection("op-b", &witness, "mediator", "t7")
                .unwrap(),
            HandoffContributionOutcome::Transferred(_)
        ));
        let receipt = branches.handoff_receipt("op-b").unwrap().unwrap();
        assert_eq!(branches.target_handoffs("branch").unwrap(), vec![receipt]);
        assert!(branches.target_handoffs("twig").unwrap().is_empty());
        let FlowingBranchLineageOutcome::Verified(lineage) =
            vcs.inspect_flowing_branch_lineage("branch").unwrap()
        else {
            panic!("the hosted cut and receipt must form one checked chain")
        };
        assert_eq!(lineage.head_cut_id(), Some("target-b"));
        assert_eq!(lineage.handoffs().len(), 1);
        sql.execute(
            "UPDATE flowing_handoffs SET effects_json = '[]' WHERE op_id = ?1",
            &[text("op-b")],
        )
        .unwrap();
        assert!(matches!(
            vcs.inspect_flowing_branch_lineage("branch").unwrap(),
            FlowingBranchLineageOutcome::ReceiptMismatch { op_id } if op_id == "op-b"
        ));
        sql.execute(
            "DELETE FROM flowing_handoffs WHERE op_id = ?1",
            &[text("op-b")],
        )
        .unwrap();
        assert!(matches!(
            vcs.inspect_flowing_branch_lineage("branch").unwrap(),
            FlowingBranchLineageOutcome::MissingReceipt { cut_id } if cut_id == "target-b"
        ));
    }

    #[test]
    fn hosted_handoff_refuses_a_disabled_flowing_target_without_moving_its_ref() {
        use std::rc::Rc;

        use crate::do_branches::DoContentBlobs;
        use whipplescript_store::branches::flowing_fence::{
            FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
            FlowingSourceKind, OpenFlowingSource,
        };
        use whipplescript_store::selection::parse;
        use whipplescript_store::vcs::{
            FlowingSelectionOutcome, FlowingTargetEffectsOutcome, WorkspaceVcs,
        };

        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut vcs = WorkspaceVcs::from_parts(
            DoBranches::new(Rc::clone(&sql)).unwrap(),
            DoContentBlobs::new(Rc::clone(&sql)).unwrap(),
        );
        vcs.init("t0").unwrap();
        vcs.create_branch("branch", Some("feature"), MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        let mut branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        branches
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "branch".into(),
                incarnation_id: "branch-inc".into(),
                kind: FlowingSourceKind::Branch,
                owner: "coordinator".into(),
                opened_at: "t1".into(),
            })
            .unwrap();
        vcs.create_branch("twig", None, "branch", "t1").unwrap();
        branches
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "twig".into(),
                incarnation_id: "twig-inc".into(),
                kind: FlowingSourceKind::Twig,
                owner: "coordinator".into(),
                opened_at: "t1".into(),
            })
            .unwrap();
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .unwrap();
        let source_cut = branches.get_cut("twig-a").unwrap().unwrap();
        branches
            .pin_private_cut(PinPrivateCut {
                pin_id: "pin-a",
                twig_branch_id: "twig",
                cut_id: "twig-a",
                manifest_hash: &source_cut.manifest_hash,
                principal: "s:author",
                retained_at: "t3",
            })
            .unwrap();
        branches
            .declare_contribution(DeclareContribution {
                unit_id: "unit-a",
                pin_id: "pin-a",
                principal: "s:author",
                intent: "selected work",
                read_basis_digest: "reads-a",
                dependency_basis_digest: "deps-a",
                scope_digest: "scope-a",
                declared_at: "t3",
            })
            .unwrap();
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-a", &parse("path(a.txt)").unwrap())
            .unwrap()
        else {
            panic!("source selection");
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a", &selection, "t4")
                .unwrap(),
            BindContributionBasisOutcome::Bound
        );
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .prepare_private_handoff_target("unit-a", "target-a", "mediator", "t5")
            .unwrap()
        else {
            panic!("prepared target");
        };
        let state = branches.flowing_source("branch").unwrap().unwrap();
        assert!(matches!(
            branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "disable".into(),
                    source_branch_id: "branch".into(),
                    incarnation_id: "branch-inc".into(),
                    expected_eligibility_epoch: state.eligibility_epoch,
                    expected_owner_epoch: state.owner_epoch,
                    actor: "coordinator".into(),
                    action: FlowingFenceAction::DisableAdmission,
                    recorded_at: "t5".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        assert_eq!(
            vcs.handoff_private_selection("handoff-a", &witness, "mediator", "t6")
                .unwrap(),
            HandoffContributionOutcome::TargetFenceRefused
        );
        assert!(branches.handoff_receipt("handoff-a").unwrap().is_none());
        assert!(branches
            .get_branch("branch")
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
    }

    #[test]
    fn hosted_handoff_rolls_back_receipt_and_ref_together() {
        use std::rc::Rc;

        use crate::do_branches::DoContentBlobs;
        use whipplescript_store::content::ContentBlobs;
        use whipplescript_store::selection::parse;
        use whipplescript_store::vcs::{
            FlowingSelectionOutcome, FlowingTargetEffectsOutcome, WorkspaceVcs,
        };

        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut vcs = WorkspaceVcs::from_parts(
            DoBranches::new(Rc::clone(&sql)).expect("branches"),
            DoContentBlobs::new(Rc::clone(&sql)).expect("content"),
        );
        vcs.init("t0").expect("initialize");
        vcs.create_branch("branch", None, MAINLINE_BRANCH_ID, "t1")
            .expect("target branch");
        vcs.create_branch("twig", None, "branch", "t1")
            .expect("source twig");
        vcs.write("twig", "a.txt", Some("A"), "twig-a", "t2")
            .expect("source cut");
        let mut branches = DoBranches::new(Rc::clone(&sql)).expect("branches");
        let source_cut = branches.get_cut("twig-a").expect("cut read").expect("cut");
        branches
            .pin_private_cut(PinPrivateCut {
                pin_id: "pin-a",
                twig_branch_id: "twig",
                cut_id: "twig-a",
                manifest_hash: &source_cut.manifest_hash,
                principal: "s:author",
                retained_at: "t3",
            })
            .expect("pin source");
        branches
            .declare_contribution(DeclareContribution {
                unit_id: "unit-a",
                pin_id: "pin-a",
                principal: "s:author",
                intent: "share one file",
                read_basis_digest: "reads-a",
                dependency_basis_digest: "deps-a",
                scope_digest: "scope-a",
                declared_at: "t3",
            })
            .expect("declare source");
        let FlowingSelectionOutcome::Selected(selection) = vcs
            .select_private_changes("pin-a", &parse("path(a.txt)").expect("selection"))
            .expect("select source")
        else {
            panic!("source selection must succeed")
        };
        assert_eq!(
            vcs.bind_private_selection("unit-a", &selection, "t4")
                .expect("bind source"),
            BindContributionBasisOutcome::Bound
        );
        let body = DoContentBlobs::new(Rc::clone(&sql)).expect("content");
        let manifest = body
            .put_text(&format!(
                r#"{{"a.txt":"{}"}}"#,
                selection.changes()[0]
                    .after
                    .as_deref()
                    .expect("source body")
            ))
            .expect("target manifest");
        branches
            .record_cut(CutRecord {
                cut_id: "target-a",
                change_id: "shared-unit-a",
                branch_id: "branch",
                manifest_hash: &manifest,
                parent_cut_id: None,
                origin: Some("transport:twig"),
                actor: Some("mediator"),
                intent: None,
                recorded_at: "t5",
            })
            .expect("target cut");
        let FlowingTargetEffectsOutcome::Verified(witness) = vcs
            .verify_private_target_effects("unit-a", "target-a")
            .expect("verify target")
        else {
            panic!("target must contain exact selected effect")
        };
        assert_eq!(
            vcs.handoff_private_selection("wrong-actor", &witness, "another", "t6")
                .expect("authorship refusal"),
            HandoffContributionOutcome::TargetCutAuthorshipMismatch
        );
        assert_eq!(branches.handoff_receipt("wrong-actor").unwrap(), None);
        sql.execute(
            "CREATE TRIGGER fail_handoff_head BEFORE UPDATE ON branches \
             WHEN NEW.branch_id = 'branch' BEGIN SELECT RAISE(ABORT, 'late head failure'); END",
            &[],
        )
        .expect("install failure");
        assert!(vcs
            .handoff_private_selection("op-a", &witness, "mediator", "t6")
            .is_err());
        assert_eq!(branches.handoff_receipt("op-a").expect("receipt"), None);
        assert_eq!(
            branches
                .get_branch("branch")
                .expect("target")
                .expect("branch")
                .head_cut_id,
            None
        );
        assert_eq!(
            branches
                .release_private_cut(ReleasePrivateCut {
                    pin_id: "pin-a",
                    released_by: "s:author",
                    reason: "premature",
                    released_at: "t7",
                })
                .expect("release check"),
            ReleasePrivateCutOutcome::HasDeclaredUnit
        );
        sql.execute("DROP TRIGGER fail_handoff_head", &[])
            .expect("remove failure");
        let HandoffContributionOutcome::Transferred(receipt) = vcs
            .handoff_private_selection("op-a", &witness, "mediator", "t6")
            .expect("handoff")
        else {
            panic!("handoff must succeed")
        };
        assert_eq!(receipt.source_cut_id, "twig-a");
        assert_eq!(receipt.target_after_cut_id, "target-a");
        assert_eq!(
            branches
                .get_branch("branch")
                .expect("target")
                .expect("branch")
                .head_cut_id,
            Some("target-a".into())
        );
        assert_eq!(
            branches
                .release_private_cut(ReleasePrivateCut {
                    pin_id: "pin-a",
                    released_by: "s:author",
                    reason: "branch holds unit",
                    released_at: "t7",
                })
                .expect("release pin"),
            ReleasePrivateCutOutcome::Released
        );
        let pinned = branches.pinned_cuts("year-3000").expect("pinned cuts");
        assert!(pinned.contains("twig-a"));
        assert!(pinned.contains("target-a"));
    }

    fn seed() -> DoBranches<RusqliteDoSql> {
        let sql = RusqliteDoSql::with_runtime_schema();
        let mut store = DoBranches::new(sql).expect("store");
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
    fn hosted_private_pin_and_declaration_keep_the_exact_cut() {
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
            store.pin_private_cut(pin()).unwrap(),
            PinPrivateCutOutcome::Pinned
        );
        assert_eq!(
            store.pin_private_cut(pin()).unwrap(),
            PinPrivateCutOutcome::Existing
        );
        assert_eq!(
            store
                .pin_private_cut(PinPrivateCut {
                    manifest_hash: "changed",
                    ..pin()
                })
                .unwrap(),
            PinPrivateCutOutcome::IdentityMismatch
        );
        assert!(store.pinned_cuts("year-3000").unwrap().contains("cut-1"));
        assert_eq!(
            store.declare_contribution(declaration()).unwrap(),
            DeclareContributionOutcome::Declared
        );
        assert_eq!(
            store
                .declare_contribution(DeclareContribution {
                    scope_digest: "",
                    ..declaration()
                })
                .unwrap(),
            DeclareContributionOutcome::Invalid {
                field: "scope_digest"
            }
        );
        assert_eq!(
            store.declare_contribution(declaration()).unwrap(),
            DeclareContributionOutcome::Existing
        );
        assert_eq!(
            store
                .source_contributions("twig-1")
                .expect("source inventory"),
            vec![store
                .contribution_declaration("unit-1")
                .expect("declaration read")
                .expect("declared unit")]
        );
        assert_eq!(
            store
                .declare_contribution(DeclareContribution {
                    read_basis_digest: "changed",
                    ..declaration()
                })
                .unwrap(),
            DeclareContributionOutcome::IdentityMismatch
        );
        let recorded = store.contribution_declaration("unit-1").unwrap().unwrap();
        assert_eq!(recorded.source_branch_id, "twig-1");
        assert_eq!(recorded.source_cut_id, "cut-1");
        assert_eq!(recorded.source_manifest_hash, "manifest-1");
        assert_eq!(
            store.release_private_cut(release()).unwrap(),
            ReleasePrivateCutOutcome::HasDeclaredUnit
        );
        assert!(store.pinned_cuts("year-3000").unwrap().contains("cut-1"));
    }

    #[test]
    fn hosted_explicit_release_cannot_revive_a_pin() {
        let mut store = seed();
        assert_eq!(
            store.pin_private_cut(pin()).unwrap(),
            PinPrivateCutOutcome::Pinned
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
}
