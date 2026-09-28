use std::collections::BTreeSet;

use super::flowing_fence;
use super::flowing_sources::exact_atomic;
use super::DoBranches;
use crate::do_store::{as_text, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_admission::{
    check_fence, validate_request, FlowingAdmissionOutcome, FlowingAdmissionReceipt,
    FlowingAdmissionRefusal, FlowingAdmissionRequest, FlowingAdmissions, FlowingUnitOutcome,
};
use whipplescript_store::branches::flowing_fence::FlowingSourceKind;
use whipplescript_store::branches::{
    BranchStatus, Branches, MAINLINE_BRANCH_ID, MAINLINE_GATE_LEASE,
};
use whipplescript_store::StoreResult;

fn read_receipt<S: DoSql>(sql: &S, op_id: &str) -> StoreResult<Option<FlowingAdmissionReceipt>> {
    sql.query(
        "SELECT receipt_json FROM flowing_admissions WHERE op_id = ?1",
        &[text(op_id)],
    )
    .map_err(sql_err)?
    .first()
    .map(|row| serde_json::from_str(&as_text(&row[0])).map_err(Into::into))
    .transpose()
}

impl<S: DoSql> DoBranches<S> {
    fn flowing_ancestor(&self, older: &str, newer: &str) -> StoreResult<bool> {
        let mut cursor = Some(newer.to_owned());
        let mut visited = BTreeSet::new();
        while let Some(id) = cursor {
            if !visited.insert(id.clone()) {
                return Ok(false);
            }
            if id == older {
                return Ok(true);
            }
            cursor = self.get_cut(&id)?.and_then(|cut| cut.parent_cut_id);
        }
        Ok(false)
    }
}

impl<S: DoSql> FlowingAdmissions for DoBranches<S> {
    fn admit_flowing_prefix(
        &mut self,
        request: &FlowingAdmissionRequest,
    ) -> StoreResult<FlowingAdmissionOutcome> {
        use FlowingAdmissionOutcome::{Admitted, Existing, Refused};
        use FlowingAdmissionRefusal as R;

        if let Err(refusal) = validate_request(request) {
            return Ok(Refused(refusal));
        }
        exact_atomic(&self.sql, "flowing trunk admission", || {
            if let Some(existing) = read_receipt(&self.sql, &request.op_id)? {
                return Ok(if existing.request == *request {
                    Existing(existing)
                } else {
                    Refused(R::IdentityMismatch)
                });
            }
            let Some(source) = self.row_by_id(&request.source_branch_id)? else {
                return Ok(Refused(R::SourceMissing));
            };
            if source.status != BranchStatus::Active {
                return Ok(Refused(R::SourceNotActive));
            }
            if source.parent_branch_id.as_deref() != Some(MAINLINE_BRANCH_ID) {
                return Ok(Refused(R::SourceNotTrunkChild));
            }
            let Some(fence) = flowing_fence::read_state(&self.sql, &request.source_branch_id)?
            else {
                return Ok(Refused(R::SourceMissing));
            };
            if fence.kind != FlowingSourceKind::Twig {
                return Ok(Refused(R::SourceNotDirectTwig));
            }
            if let Err(refusal) = check_fence(&fence, request) {
                return Ok(Refused(refusal));
            }
            let Some(selected_cut) = self.get_cut(&request.source_cut_id)? else {
                return Ok(Refused(R::SourceCutMissing));
            };
            if selected_cut.branch_id != request.source_branch_id
                || selected_cut.manifest_hash != request.source_manifest_hash
            {
                return Ok(Refused(R::SourceCutMismatch));
            }
            let Some(source_head) = source.head_cut_id.as_deref() else {
                return Ok(Refused(R::SourceCutNotRetained));
            };
            if !self.flowing_ancestor(&request.source_cut_id, source_head)? {
                return Ok(Refused(R::SourceCutNotRetained));
            }

            let Some(trunk) = self.row_by_id(MAINLINE_BRANCH_ID)? else {
                return Ok(Refused(R::TrunkMissing));
            };
            if trunk.status != BranchStatus::Active {
                return Ok(Refused(R::TrunkNotActive));
            }
            let reservation = self.head_reservation(MAINLINE_BRANCH_ID)?;
            if reservation
                .as_deref()
                .is_some_and(|holder| holder != MAINLINE_GATE_LEASE)
            {
                return Ok(Refused(R::TrunkReserved));
            }
            if trunk.head_cut_id != request.expected_trunk_cut_id {
                return Ok(Refused(R::TrunkStale {
                    current: trunk.head_cut_id,
                }));
            }
            let Some(candidate) = self.get_cut(&request.candidate_cut_id)? else {
                return Ok(Refused(R::CandidateMissing));
            };
            let same_cut =
                request.expected_trunk_cut_id.as_deref() == Some(request.candidate_cut_id.as_str());
            let has_applied = request
                .units
                .iter()
                .any(|unit| unit.outcome == FlowingUnitOutcome::Applied);
            let expected_origin = format!("transport:{}", request.source_branch_id);
            if candidate.branch_id != MAINLINE_BRANCH_ID
                || candidate.manifest_hash != request.candidate_manifest_hash
                || (!same_cut
                    && candidate.parent_cut_id.as_deref()
                        != request.expected_trunk_cut_id.as_deref())
                || (!same_cut
                    && (candidate.origin.as_deref() != Some(expected_origin.as_str())
                        || candidate.actor.as_deref() != Some(request.coordinator.as_str())))
                || same_cut == has_applied
            {
                return Ok(Refused(R::CandidateMismatch));
            }

            for unit in &request.units {
                let declarations = self
                    .sql
                    .query(
                        "SELECT pin_id, source_branch_id, source_cut_id, principal, intent \
                         FROM flowing_contributions WHERE unit_id = ?1",
                        &[text(&unit.unit_id)],
                    )
                    .map_err(sql_err)?;
                let Some(declaration) = declarations.first() else {
                    return Ok(Refused(R::UnitMissing {
                        unit_id: unit.unit_id.clone(),
                    }));
                };
                let pin_id = as_text(&declaration[0]);
                let declared_branch = as_text(&declaration[1]);
                let declared_cut = as_text(&declaration[2]);
                let principal = as_text(&declaration[3]);
                let intent = as_text(&declaration[4]);
                let bases = self
                    .sql
                    .query(
                        "SELECT basis_digest FROM flowing_contribution_basis WHERE unit_id = ?1",
                        &[text(&unit.unit_id)],
                    )
                    .map_err(sql_err)?;
                let Some(basis) = bases.first() else {
                    return Ok(Refused(R::UnitBasisMissing {
                        unit_id: unit.unit_id.clone(),
                    }));
                };
                if as_text(&basis[0]) != unit.basis_digest
                    || principal != unit.principal
                    || intent != unit.intent
                {
                    return Ok(Refused(R::UnitBasisMismatch {
                        unit_id: unit.unit_id.clone(),
                    }));
                }
                let handoffs = self
                    .sql
                    .query(
                        "SELECT target_branch_id, target_after_cut_id \
                         FROM flowing_handoffs WHERE unit_id = ?1",
                        &[text(&unit.unit_id)],
                    )
                    .map_err(sql_err)?;
                if !handoffs.is_empty() {
                    return Ok(Refused(R::UnverifiedLineage {
                        unit_id: unit.unit_id.clone(),
                    }));
                }
                let (holder, holder_cut) = handoffs.first().map_or_else(
                    || (declared_branch, declared_cut),
                    |handoff| (as_text(&handoff[0]), as_text(&handoff[1])),
                );
                if handoffs.is_empty() {
                    let pins = self
                        .sql
                        .query(
                            "SELECT released_at FROM flowing_private_pins WHERE pin_id = ?1",
                            &[text(&pin_id)],
                        )
                        .map_err(sql_err)?;
                    let Some(pin) = pins.first() else {
                        return Ok(Refused(R::UnitPinMissing {
                            unit_id: unit.unit_id.clone(),
                        }));
                    };
                    if !matches!(pin[0], crate::do_store::SqlValue::Null) {
                        return Ok(Refused(R::UnitPinReleased {
                            unit_id: unit.unit_id.clone(),
                        }));
                    }
                }
                if holder != request.source_branch_id
                    || !self.flowing_ancestor(&holder_cut, &request.source_cut_id)?
                {
                    return Ok(Refused(R::UnitNotHeldBySource {
                        unit_id: unit.unit_id.clone(),
                    }));
                }
                if !self
                    .sql
                    .query(
                        "SELECT op_id FROM flowing_admitted_units WHERE unit_id = ?1",
                        &[text(&unit.unit_id)],
                    )
                    .map_err(sql_err)?
                    .is_empty()
                {
                    return Ok(Refused(R::UnitAlreadyAdmitted {
                        unit_id: unit.unit_id.clone(),
                    }));
                }
            }

            let receipt = FlowingAdmissionReceipt {
                request: request.clone(),
            };
            self.sql
                .execute(
                    "INSERT INTO flowing_admissions (op_id, receipt_json) VALUES (?1, ?2)",
                    &[
                        text(&request.op_id),
                        text(&serde_json::to_string(&receipt)?),
                    ],
                )
                .map_err(sql_err)?;
            for unit in &request.units {
                self.sql
                    .execute(
                        "INSERT INTO flowing_admitted_units (unit_id, op_id) VALUES (?1, ?2)",
                        &[text(&unit.unit_id), text(&request.op_id)],
                    )
                    .map_err(sql_err)?;
            }
            if !same_cut {
                self.sql
                    .execute(
                        "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, \
                         updated_at = ?4 WHERE branch_id = ?1",
                        &[
                            text(MAINLINE_BRANCH_ID),
                            text(&request.candidate_cut_id),
                            text(&request.candidate_manifest_hash),
                            text(&request.recorded_at),
                        ],
                    )
                    .map_err(sql_err)?;
            }
            Ok(Admitted(receipt))
        })
    }

    fn flowing_admission_receipt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingAdmissionReceipt>> {
        read_receipt(&self.sql, op_id)
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::do_store::test_support::RusqliteDoSql;
    use whipplescript_store::branches::flowing_admission::FlowingSelectedUnit;
    use whipplescript_store::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
    };
    use whipplescript_store::branches::{CreateBranch, CutRecord};

    type Sql = Rc<RusqliteDoSql>;

    fn fixture() -> (Sql, DoBranches<Sql>) {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut store = DoBranches::new(sql.clone()).unwrap();
        store.ensure_mainline("t0").unwrap();
        store
            .create_branch(CreateBranch {
                branch_id: "twig",
                name: None,
                parent_branch_id: MAINLINE_BRANCH_ID,
                at_cut: None,
                created_at: "t1",
                idempotency_key: None,
            })
            .unwrap();
        assert!(matches!(
            store
                .open_flowing_source(&OpenFlowingSource {
                    source_branch_id: "twig".into(),
                    incarnation_id: "inc".into(),
                    kind: FlowingSourceKind::Twig,
                    owner: "coordinator".into(),
                    opened_at: "t1".into(),
                })
                .unwrap(),
            OpenFlowingSourceOutcome::Opened(_)
        ));
        store
            .record_cut(CutRecord {
                cut_id: "source",
                change_id: "change",
                branch_id: "twig",
                manifest_hash: "source-manifest",
                parent_cut_id: None,
                origin: None,
                actor: Some("author"),
                intent: Some("change"),
                recorded_at: "t2",
            })
            .unwrap();
        store
            .advance_head("twig", None, "source", "source-manifest", "t2")
            .unwrap();
        store
            .record_cut(CutRecord {
                cut_id: "candidate",
                change_id: "integrated",
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: "candidate-manifest",
                parent_cut_id: None,
                origin: Some("transport:twig"),
                actor: Some("coordinator"),
                intent: Some("change"),
                recorded_at: "t3",
            })
            .unwrap();
        for statement in [
            "INSERT INTO flowing_private_pins \
             (pin_id, twig_branch_id, cut_id, manifest_hash, principal, retained_at) \
             VALUES ('pin', 'twig', 'source', 'source-manifest', 'author', 't2')",
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, \
              scope_digest, declared_at) \
             VALUES ('unit-a', 'pin', 'twig', 'source', 'source-manifest', \
                     'author', 'change', 'reads', 'deps', 'scope', 't2')",
            "INSERT INTO flowing_contributions \
             (unit_id, pin_id, source_branch_id, source_cut_id, source_manifest_hash, \
              principal, intent, read_basis_digest, dependency_basis_digest, \
              scope_digest, declared_at) \
             VALUES ('unit-b', 'pin', 'twig', 'source', 'source-manifest', \
                     'author', 'change', 'reads', 'deps', 'scope', 't2')",
            "INSERT INTO flowing_contribution_basis (unit_id, basis_digest, atoms_json, bound_at) \
             VALUES ('unit-a', 'basis-a', '[]', 't2')",
            "INSERT INTO flowing_contribution_basis (unit_id, basis_digest, atoms_json, bound_at) \
             VALUES ('unit-b', 'basis-b', '[]', 't2')",
        ] {
            sql.execute(statement, &[]).unwrap();
        }
        (sql, store)
    }

    fn request(unit_id: &str, op_id: &str) -> FlowingAdmissionRequest {
        FlowingAdmissionRequest {
            op_id: op_id.into(),
            certificate_handle: "certificate-a".into(),
            source_branch_id: "twig".into(),
            source_incarnation_id: "inc".into(),
            source_cut_id: "source".into(),
            source_manifest_hash: "source-manifest".into(),
            expected_eligibility_epoch: 0,
            expected_owner_epoch: 0,
            coordinator: "coordinator".into(),
            expected_trunk_cut_id: None,
            candidate_cut_id: "candidate".into(),
            candidate_manifest_hash: "candidate-manifest".into(),
            units: vec![FlowingSelectedUnit {
                unit_id: unit_id.into(),
                basis_digest: format!("basis-{}", unit_id.strip_prefix("unit-").unwrap()),
                principal: "author".into(),
                intent: "change".into(),
                outcome: FlowingUnitOutcome::Applied,
            }],
            recorded_at: "t4".into(),
        }
    }

    #[test]
    fn hosted_ref_entry_orders_hold_cas_noop_and_duplicate_unit() {
        let (_, mut store) = fixture();
        let hold = FlowingFenceTransition {
            op_id: "hold".into(),
            source_branch_id: "twig".into(),
            incarnation_id: "inc".into(),
            expected_eligibility_epoch: 0,
            expected_owner_epoch: 0,
            actor: "coordinator".into(),
            action: FlowingFenceAction::Hold,
            recorded_at: "t3".into(),
        };
        assert!(matches!(
            store.transition_flowing_source(&hold).unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        let mut first = request("unit-a", "admission-a");
        first.expected_eligibility_epoch = 1;
        assert_eq!(
            store.admit_flowing_prefix(&first).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::Held)
        );
        store
            .transition_flowing_source(&FlowingFenceTransition {
                op_id: "release".into(),
                expected_eligibility_epoch: 1,
                action: FlowingFenceAction::ReleaseHold,
                ..hold
            })
            .unwrap();
        first.expected_eligibility_epoch = 2;
        let FlowingAdmissionOutcome::Admitted(receipt) =
            store.admit_flowing_prefix(&first).unwrap()
        else {
            panic!("hosted prefix should admit")
        };
        assert_eq!(
            store.admit_flowing_prefix(&first).unwrap(),
            FlowingAdmissionOutcome::Existing(receipt.clone())
        );
        assert_eq!(
            store.flowing_admission_receipt("admission-a").unwrap(),
            Some(receipt)
        );
        let mut competing = first.clone();
        competing.op_id = "admission-b".into();
        competing.expected_trunk_cut_id = Some("candidate".into());
        competing.units[0].outcome = FlowingUnitOutcome::Equivalent;
        assert!(matches!(
            store.admit_flowing_prefix(&competing).unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::UnitAlreadyAdmitted { .. })
        ));
        let mut no_op = request("unit-b", "admission-c");
        no_op.expected_eligibility_epoch = 2;
        no_op.expected_trunk_cut_id = Some("candidate".into());
        no_op.units[0].outcome = FlowingUnitOutcome::Equivalent;
        assert!(matches!(
            store.admit_flowing_prefix(&no_op).unwrap(),
            FlowingAdmissionOutcome::Admitted(_)
        ));
        assert_eq!(
            store
                .get_branch(MAINLINE_BRANCH_ID)
                .unwrap()
                .unwrap()
                .head_cut_id,
            Some("candidate".into())
        );
    }

    #[test]
    fn hosted_failed_unit_write_rolls_back_trunk_and_receipt() {
        let (sql, mut store) = fixture();
        sql.execute(
            "CREATE TRIGGER reject_admitted_unit BEFORE INSERT ON flowing_admitted_units \
             BEGIN SELECT RAISE(ABORT, 'injected refusal'); END",
            &[],
        )
        .unwrap();
        assert!(store
            .admit_flowing_prefix(&request("unit-a", "admission-a"))
            .is_err());
        assert!(store
            .flowing_admission_receipt("admission-a")
            .unwrap()
            .is_none());
        assert!(store
            .get_branch(MAINLINE_BRANCH_ID)
            .unwrap()
            .unwrap()
            .head_cut_id
            .is_none());
    }

    #[test]
    fn hosted_handoff_is_not_admitted_without_lineage_policy() {
        let (sql, mut store) = fixture();
        sql.execute(
            "INSERT INTO flowing_handoffs \
             (op_id, unit_id, source_branch_id, source_cut_id, source_manifest_hash, \
              source_basis_digest, target_branch_id, target_after_cut_id, \
              target_after_manifest_hash, effects_json, original_principal, actor, recorded_at) \
             VALUES ('handoff', 'unit-a', 'twig', 'source', 'source-manifest', \
                     'basis-a', 'branch', 'branch-cut', 'branch-manifest', '[]', \
                     'author', 'coordinator', 't3')",
            &[],
        )
        .unwrap();
        assert!(matches!(
            store
                .admit_flowing_prefix(&request("unit-a", "admission-a"))
                .unwrap(),
            FlowingAdmissionOutcome::Refused(FlowingAdmissionRefusal::UnverifiedLineage { .. })
        ));
        assert!(store
            .flowing_admission_receipt("admission-a")
            .unwrap()
            .is_none());
    }
}
