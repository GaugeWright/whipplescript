use std::collections::BTreeSet;

use super::{flowing_fence, flowing_sources::exact_atomic, DoBranches};
use crate::do_store::{as_opt_text, as_text, opt_text, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_abandonment::{
    check_current, digest, AbandonUnitState, CommitFlowingAbandonment, FlowingAbandonmentOutcome,
    FlowingAbandonmentReceipt, FlowingAbandonmentRefusal, FlowingAbandonments,
};
use whipplescript_store::branches::flowing_admission::FlowingAdmissions;
use whipplescript_store::branches::flowing_parking::FlowingParking;
use whipplescript_store::branches::flowing_sources::FlowingSources;
use whipplescript_store::branches::write_commit::{INSERT_CUT, INSERT_OP};
use whipplescript_store::branches::{Branches, OpBranchDelta, OpBranchState};
use whipplescript_store::{StoreError, StoreResult};

fn read_receipt<S: DoSql>(
    sql: &S,
    predicate: &str,
    value: &str,
) -> StoreResult<Option<FlowingAbandonmentReceipt>> {
    let rows = sql
        .query(
            &format!(
                "SELECT op_id, after_cut_id, witness_json, witness_digest \
                  FROM flowing_abandonments WHERE {predicate} = ?1"
            ),
            &[text(value)],
        )
        .map_err(sql_err)?;
    rows.first()
        .map(|row| {
            let receipt: FlowingAbandonmentReceipt = serde_json::from_str(&as_text(&row[2]))?;
            if receipt.op_id != as_text(&row[0])
                || receipt.after_cut_id != as_text(&row[1])
                || digest(&receipt) != as_text(&row[3])
            {
                return Err(StoreError::Conflict(
                    "flowing abandonment receipt differs from its row or digest".into(),
                ));
            }
            let cuts = sql.query(
            "SELECT branch_id, manifest_hash, parent_cut_id, origin FROM cuts WHERE cut_id = ?1",
            &[text(&receipt.after_cut_id)],
        ).map_err(sql_err)?;
            if !cuts.first().is_some_and(|cut| {
                as_text(&cut[0]) == receipt.source_branch_id
                    && as_text(&cut[1]) == receipt.after_manifest_hash
                    && as_opt_text(&cut[2]) == receipt.branch_point_cut_id
                    && as_opt_text(&cut[3]).as_deref() == Some("flowing:abandon")
            }) {
                return Err(StoreError::Conflict(
                    "flowing abandonment receipt lost its exact cut".into(),
                ));
            }
            let expected: BTreeSet<&str> =
                receipt.units.iter().map(|unit| unit.unit_id()).collect();
            let indexed = sql
                .query(
                    "SELECT unit_id FROM flowing_abandoned_units WHERE op_id = ?1",
                    &[text(&receipt.op_id)],
                )
                .map_err(sql_err)?;
            let actual: BTreeSet<String> = indexed.iter().map(|row| as_text(&row[0])).collect();
            if expected.is_empty()
                || expected.len() != receipt.units.len()
                || expected != actual.iter().map(String::as_str).collect()
            {
                return Err(StoreError::Conflict(
                    "flowing abandonment receipt differs from unit dispositions".into(),
                ));
            }
            Ok(receipt)
        })
        .transpose()
}

impl<S: DoSql> FlowingAbandonments for DoBranches<S> {
    fn commit_flowing_abandonment(
        &mut self,
        request: CommitFlowingAbandonment<'_>,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<FlowingAbandonmentOutcome> {
        use FlowingAbandonmentOutcome as O;
        use FlowingAbandonmentRefusal as R;
        let receipt = request.receipt();
        exact_atomic(&self.sql, "flowing abandonment", || {
            if let Some(existing) = read_receipt(&self.sql, "op_id", &receipt.op_id)? {
                if existing == receipt {
                    return Ok(O::Existing(existing));
                }
                // MUTATION-SUCCESS-EXPR: Ok(O::Existing(existing))
                return Ok(O::Refused(R::IdentityMismatch));
            }
            if self.get_cut(&receipt.after_cut_id)?.is_some() {
                // MUTATION-SUCCESS-EXPR: Ok(O::Committed(receipt.clone()))
                return Ok(O::Refused(R::CutAlreadyRecorded));
            }
            if !self
                .sql
                .query(
                    "SELECT op_id FROM ops WHERE op_id = ?1",
                    &[text(&receipt.op_id)],
                )
                .map_err(sql_err)?
                .is_empty()
            {
                // MUTATION-SUCCESS-EXPR: Ok(O::Committed(receipt.clone()))
                return Ok(O::Refused(R::OperationAlreadyRecorded));
            }
            let source = self.row_by_id(&receipt.source_branch_id)?;
            let fence = flowing_fence::read_state(&self.sql, &receipt.source_branch_id)?;
            let reserved = self.head_reservation(&receipt.source_branch_id)?.is_some();
            let mut units = Vec::new();
            for declaration in self.source_contributions(&receipt.source_branch_id)? {
                if let Some(op_id) = self.abandoned_unit_operation(&declaration.unit_id)? {
                    let prior = self.flowing_abandonment_receipt(&op_id)?.ok_or_else(|| {
                        StoreError::Conflict("abandoned flowing unit lost its receipt".into())
                    })?;
                    if prior.source_branch_id != receipt.source_branch_id
                        || !prior
                            .units
                            .iter()
                            .any(|root| root.unit_id() == declaration.unit_id)
                    {
                        return Err(StoreError::Conflict(
                            "abandoned unit differs from its source receipt".into(),
                        ));
                    }
                    continue;
                }
                units.push(AbandonUnitState {
                    basis: self.contribution_basis(&declaration.unit_id)?,
                    pin: self.private_cut_pin(&declaration.pin_id)?,
                    handed_off: self.contribution_handoff(&declaration.unit_id)?.is_some(),
                    admitted: self
                        .admitted_unit_operation(&declaration.unit_id)?
                        .is_some(),
                    parked: self.parked_flowing_unit(&declaration.unit_id)?.is_some(),
                    abandoned: false,
                    declaration,
                });
            }
            let after =
                match check_current(&receipt, source.clone(), fence.clone(), reserved, &units) {
                    Ok(after) => after,
                    Err(refusal) => return Ok(O::Refused(refusal)),
                };
            let old = source.expect("validated source exists");
            let deltas = serde_json::to_string(&[OpBranchDelta {
                branch_id: receipt.source_branch_id.clone(),
                before: Some(OpBranchState::of(&old)),
                after: OpBranchState::of(&after),
            }])?;
            check()?;
            self.sql
                .execute(
                    INSERT_CUT,
                    &[
                        text(&receipt.after_cut_id),
                        text(&receipt.after_cut_id),
                        text(&receipt.source_branch_id),
                        text(&receipt.after_manifest_hash),
                        opt_text(receipt.branch_point_cut_id.as_deref()),
                        text("flowing:abandon"),
                        text(&receipt.actor),
                        opt_text(None),
                        text(&receipt.recorded_at),
                    ],
                )
                .map_err(sql_err)?;
            let cut = self.get_cut(&receipt.after_cut_id)?;
            whipplescript_store::branches::flowing_fence::require_head_move(
                &fence.expect("validated revision exists"),
                Some(&receipt.before_cut_id),
                &receipt.after_cut_id,
                &receipt.after_manifest_hash,
                cut.as_ref(),
            )?;
            self.sql.execute(
                "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, updated_at = ?4 \
                 WHERE branch_id = ?1",
                &[
                    text(&receipt.source_branch_id), text(&receipt.after_cut_id),
                    text(&receipt.after_manifest_hash), text(&receipt.recorded_at),
                ],
            ).map_err(sql_err)?;
            self.sql
                .execute(
                    INSERT_OP,
                    &[
                        text(&receipt.op_id),
                        text("flowing_abandonment"),
                        text(&deltas),
                        text("flowing:abandon"),
                        text(&receipt.recorded_at),
                    ],
                )
                .map_err(sql_err)?;
            self.sql.execute(
                "INSERT INTO flowing_abandonments (op_id, after_cut_id, witness_json, witness_digest) \
                 VALUES (?1, ?2, ?3, ?4)",
                &[
                    text(&receipt.op_id), text(&receipt.after_cut_id),
                    text(&serde_json::to_string(&receipt)?), text(&digest(&receipt)),
                ],
            ).map_err(sql_err)?;
            for unit in &receipt.units {
                self.sql
                    .execute(
                        "INSERT INTO flowing_abandoned_units (unit_id, op_id) VALUES (?1, ?2)",
                        &[text(unit.unit_id()), text(&receipt.op_id)],
                    )
                    .map_err(sql_err)?;
            }
            Ok(O::Committed(receipt.clone()))
        })
    }

    fn flowing_abandonment_receipt(
        &self,
        op_id: &str,
    ) -> StoreResult<Option<FlowingAbandonmentReceipt>> {
        read_receipt(&self.sql, "op_id", op_id)
    }

    fn flowing_abandonment_for_cut(
        &self,
        after_cut_id: &str,
    ) -> StoreResult<Option<FlowingAbandonmentReceipt>> {
        read_receipt(&self.sql, "after_cut_id", after_cut_id)
    }

    fn abandoned_unit_operation(&self, unit_id: &str) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query(
                "SELECT op_id FROM flowing_abandoned_units WHERE unit_id = ?1",
                &[text(unit_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::do_branches::DoContentBlobs;
    use crate::do_store::test_support::RusqliteDoSql;
    use whipplescript_store::branches::flowing_close_roster::{
        FlowingCloseRosterReader, FlowingCloseUnitState,
    };
    use whipplescript_store::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource,
    };
    use whipplescript_store::branches::flowing_sources::{
        DeclareContribution, PinPrivateCut, ReleasePrivateCut, ReleasePrivateCutOutcome,
    };
    use whipplescript_store::branches::MAINLINE_BRANCH_ID;
    use whipplescript_store::selection;
    use whipplescript_store::vcs::flowing_abandonment::WholeTwigAbandonmentOutcome;
    use whipplescript_store::vcs::{FlowingSelectionOutcome, WorkspaceVcs};

    type HostedVcs = WorkspaceVcs<DoBranches<Rc<RusqliteDoSql>>, DoContentBlobs<Rc<RusqliteDoSql>>>;

    fn bound_write(
        sql: &Rc<RusqliteDoSql>,
        vcs: &mut HostedVcs,
        path: &str,
        cut_id: &str,
        unit_id: &str,
    ) {
        vcs.write("twig", path, Some(unit_id), cut_id, "t2")
            .unwrap();
        let mut branches = DoBranches::new(Rc::clone(sql)).unwrap();
        let cut = branches.get_cut(cut_id).unwrap().unwrap();
        let pin_id = format!("pin-{unit_id}");
        branches
            .pin_private_cut(PinPrivateCut {
                pin_id: &pin_id,
                twig_branch_id: "twig",
                cut_id,
                manifest_hash: &cut.manifest_hash,
                principal: "s:author",
                retained_at: "t3",
            })
            .unwrap();
        branches
            .declare_contribution(DeclareContribution {
                unit_id,
                pin_id: &pin_id,
                principal: "s:author",
                intent: "hosted abandonment fixture",
                read_basis_digest: "read",
                dependency_basis_digest: "deps",
                scope_digest: unit_id,
                declared_at: "t3",
            })
            .unwrap();
        let FlowingSelectionOutcome::Selected(selected) = vcs
            .select_private_changes(
                &pin_id,
                &selection::parse(&format!("change({cut_id})")).unwrap(),
            )
            .unwrap()
        else {
            panic!("selected");
        };
        vcs.bind_private_selection(unit_id, &selected, "t3")
            .unwrap();
    }

    fn fixture() -> (Rc<RusqliteDoSql>, HostedVcs) {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let mut vcs = WorkspaceVcs::from_parts(
            DoBranches::new(Rc::clone(&sql)).unwrap(),
            DoContentBlobs::new(Rc::clone(&sql)).unwrap(),
        );
        vcs.init("t0").unwrap();
        vcs.write(MAINLINE_BRANCH_ID, "base.txt", Some("base"), "base", "t1")
            .unwrap();
        vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
            .unwrap();
        DoBranches::new(Rc::clone(&sql))
            .unwrap()
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "twig".into(),
                incarnation_id: "twig-inc-1".into(),
                kind: FlowingSourceKind::Twig,
                owner: "s:author".into(),
                opened_at: "t1".into(),
            })
            .unwrap();
        bound_write(&sql, &mut vcs, "a.txt", "cut-a", "unit-a");
        bound_write(&sql, &mut vcs, "b.txt", "cut-b", "unit-b");
        (sql, vcs)
    }

    fn begin(sql: &Rc<RusqliteDoSql>) {
        assert!(matches!(
            DoBranches::new(Rc::clone(sql))
                .unwrap()
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "begin-abandon".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc-1".into(),
                    expected_eligibility_epoch: 0,
                    expected_owner_epoch: 0,
                    actor: "s:author".into(),
                    action: FlowingFenceAction::BeginRevision {
                        before_cut_id: Some("cut-b".into()),
                        after_cut_id: "abandoned".into(),
                    },
                    recorded_at: "t5".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
    }

    #[test]
    fn hosted_abandonment_commits_both_units_and_retries_exactly() {
        let (sql, mut vcs) = fixture();
        let WholeTwigAbandonmentOutcome::Prepared(plan) =
            vcs.prepare_whole_twig_abandonment("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin(&sql);
        let FlowingAbandonmentOutcome::Committed(receipt) = vcs
            .commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap()
        else {
            panic!("committed");
        };
        let mut branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        assert_eq!(receipt.units.len(), 2);
        let host = vcs
            .read_abandonment_evidence("abandon-op")
            .unwrap()
            .expect("hosted disposition evidence");
        assert_eq!(host.units.len(), 2);
        assert_eq!(host.after_cut_id, "abandoned");
        assert_eq!(
            whipplescript_store::vcs::flowing_abandonment::FlowingHostAbandonmentEvidenceV1::decode(
                &serde_json::to_vec(&host).unwrap()
            )
            .unwrap(),
            host
        );
        let close_roster = branches.flowing_close_roster("twig").unwrap().unwrap();
        assert_eq!(close_roster.units.len(), 2);
        assert!(close_roster.units.iter().all(|unit| matches!(
            &unit.state,
            FlowingCloseUnitState::Abandoned { op_id } if op_id == "abandon-op"
        )));
        assert_eq!(
            branches
                .abandoned_unit_operation("unit-a")
                .unwrap()
                .as_deref(),
            Some("abandon-op")
        );
        assert_eq!(
            branches
                .abandoned_unit_operation("unit-b")
                .unwrap()
                .as_deref(),
            Some("abandon-op")
        );
        assert_eq!(
            branches
                .get_branch("twig")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("abandoned")
        );
        assert_eq!(
            branches.flowing_abandonment_for_cut("abandoned").unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || panic!("retry cannot repeat authority check"),
            )
            .unwrap(),
            FlowingAbandonmentOutcome::Existing(receipt.clone())
        );
        assert_eq!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "changed-time",
                &mut || panic!("mismatched retry must refuse before final check"),
            )
            .unwrap(),
            FlowingAbandonmentOutcome::Refused(FlowingAbandonmentRefusal::IdentityMismatch)
        );
        let mut branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        assert_eq!(
            branches
                .release_private_cut(ReleasePrivateCut {
                    pin_id: "pin-unit-a",
                    released_by: "s:author",
                    reason: "unit abandoned under exact disposition",
                    released_at: "t7",
                })
                .unwrap(),
            ReleasePrivateCutOutcome::Released
        );
        assert_eq!(
            branches.flowing_abandonment_receipt("abandon-op").unwrap(),
            Some(receipt)
        );
    }

    #[test]
    fn hosted_abandonment_closes_with_retained_disposition_evidence() {
        use whipplescript_store::branches::flowing_close_host::{
            read_close_evidence, FlowingHostCloseDispositionV1, FlowingHostCloseEvidenceV1,
            FLOWING_CLOSE_EVIDENCE_V2,
        };
        use whipplescript_store::branches::flowing_final_close::{
            FinalCloseFlowingSource, FlowingFinalClose, FlowingFinalCloseOutcome,
            FlowingFinalCloseRefusal,
        };

        let (sql, mut vcs) = fixture();
        let WholeTwigAbandonmentOutcome::Prepared(plan) =
            vcs.prepare_whole_twig_abandonment("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin(&sql);
        assert!(matches!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap(),
            FlowingAbandonmentOutcome::Committed(_)
        ));
        let mut branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        for unit_id in ["unit-a", "unit-b"] {
            assert_eq!(
                branches
                    .release_private_cut(ReleasePrivateCut {
                        pin_id: &format!("pin-{unit_id}"),
                        released_by: "s:author",
                        reason: "unit abandoned under exact disposition",
                        released_at: "t7",
                    })
                    .unwrap(),
                ReleasePrivateCutOutcome::Released
            );
        }
        for (op_id, action) in [
            (
                "finish-abandon",
                FlowingFenceAction::FinishRevision {
                    begin_op_id: "begin-abandon".into(),
                },
            ),
            ("request-close", FlowingFenceAction::RequestClose),
            ("disable", FlowingFenceAction::DisableAdmission),
        ] {
            let fence = branches.flowing_source("twig").unwrap().unwrap();
            let transition = branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: op_id.into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: fence.incarnation_id,
                    expected_eligibility_epoch: fence.eligibility_epoch,
                    expected_owner_epoch: fence.owner_epoch,
                    actor: "s:author".into(),
                    action,
                    recorded_at: "t8".into(),
                })
                .unwrap();
            assert!(
                matches!(transition, FlowingFenceOutcome::Applied(_)),
                "{transition:?}"
            );
        }
        let roster = branches.flowing_close_roster("twig").unwrap().unwrap();
        let request = FinalCloseFlowingSource {
            op_id: "final-close".into(),
            source_branch_id: "twig".into(),
            source_incarnation_id: roster.source_fence.incarnation_id.clone(),
            expected_eligibility_epoch: roster.source_fence.eligibility_epoch,
            expected_owner_epoch: roster.source_fence.owner_epoch,
            expected_roster_digest: roster.digest().unwrap(),
            actor: "s:author".into(),
            recorded_at: "t9".into(),
        };
        let original = branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap()
            .unwrap();
        let mut wrong_incarnation = original.clone();
        wrong_incarnation.source_incarnation_id = "other-incarnation".into();
        sql.execute(
            "UPDATE flowing_abandonments SET witness_json = ?1, witness_digest = ?2 \
             WHERE op_id = 'abandon-op'",
            &[
                text(&serde_json::to_string(&wrong_incarnation).unwrap()),
                text(&digest(&wrong_incarnation)),
            ],
        )
        .unwrap();
        assert_eq!(
            branches.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                unit_id: "unit-a".into(),
            })
        );
        let mut extra_value = serde_json::to_value(&original).unwrap();
        let mut extra_unit = extra_value["units"][0].clone();
        extra_unit["unit_id"] = "unit-z".into();
        extra_value["units"]
            .as_array_mut()
            .unwrap()
            .push(extra_unit);
        let extra: FlowingAbandonmentReceipt = serde_json::from_value(extra_value).unwrap();
        sql.execute(
            "UPDATE flowing_abandonments SET witness_json = ?1, witness_digest = ?2 \
             WHERE op_id = 'abandon-op'",
            &[
                text(&serde_json::to_string(&extra).unwrap()),
                text(&digest(&extra)),
            ],
        )
        .unwrap();
        sql.execute(
            "INSERT INTO flowing_abandoned_units (unit_id, op_id) VALUES ('unit-z', 'abandon-op')",
            &[],
        )
        .unwrap();
        assert_eq!(
            branches.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Refused(FlowingFinalCloseRefusal::UnitReceiptMismatch {
                unit_id: "unit-z".into(),
            })
        );
        sql.execute(
            "DELETE FROM flowing_abandoned_units WHERE unit_id = 'unit-z'",
            &[],
        )
        .unwrap();
        sql.execute(
            "UPDATE flowing_abandonments SET witness_json = ?1, witness_digest = ?2 \
             WHERE op_id = 'abandon-op'",
            &[
                text(&serde_json::to_string(&original).unwrap()),
                text(&digest(&original)),
            ],
        )
        .unwrap();
        let outcome = branches.final_close_flowing_source(&request).unwrap();
        let FlowingFinalCloseOutcome::Closed(receipt) = outcome else {
            panic!("exact abandonment dispositions close the hosted source: {outcome:?}");
        };
        assert_eq!(receipt.unit_evidence.abandonments.len(), 1);
        assert_eq!(receipt.unit_evidence.abandonments[0].units.len(), 2);
        let host = read_close_evidence(&branches, "twig").unwrap().unwrap();
        assert_eq!(host.schema, FLOWING_CLOSE_EVIDENCE_V2);
        assert_eq!(
            FlowingHostCloseEvidenceV1::decode(&serde_json::to_vec(&host).unwrap()).unwrap(),
            host
        );
        assert!(host.units.iter().all(|unit| matches!(
            &unit.disposition,
            FlowingHostCloseDispositionV1::Abandoned { operation_id, .. }
                if operation_id == "abandon-op"
        )));
        assert_eq!(
            branches.final_close_flowing_source(&request).unwrap(),
            FlowingFinalCloseOutcome::Existing(receipt)
        );
    }

    #[test]
    fn hosted_abandonment_reader_refuses_changed_digest_cut_and_unit_index() {
        let (sql, mut vcs) = fixture();
        let WholeTwigAbandonmentOutcome::Prepared(plan) =
            vcs.prepare_whole_twig_abandonment("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin(&sql);
        let FlowingAbandonmentOutcome::Committed(receipt) = vcs
            .commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap()
        else {
            panic!("committed");
        };
        let branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        assert_eq!(
            branches.flowing_abandonment_receipt("abandon-op").unwrap(),
            Some(receipt.clone())
        );

        sql.execute(
            "UPDATE flowing_abandonments SET witness_digest = 'wrong' WHERE op_id = 'abandon-op'",
            &[],
        )
        .unwrap();
        let error = branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap_err();
        assert!(format!("{error:?}").contains("receipt differs from its row or digest"));
        sql.execute(
            "UPDATE flowing_abandonments SET witness_digest = ?1 WHERE op_id = 'abandon-op'",
            &[text(&digest(&receipt))],
        )
        .unwrap();

        sql.execute(
            "UPDATE cuts SET origin = 'write:forged' WHERE cut_id = 'abandoned'",
            &[],
        )
        .unwrap();
        let error = branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap_err();
        assert!(format!("{error:?}").contains("receipt lost its exact cut"));
        sql.execute(
            "UPDATE cuts SET origin = 'flowing:abandon' WHERE cut_id = 'abandoned'",
            &[],
        )
        .unwrap();

        sql.execute(
            "DELETE FROM flowing_abandoned_units WHERE unit_id = 'unit-b'",
            &[],
        )
        .unwrap();
        let error = branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap_err();
        assert!(format!("{error:?}").contains("receipt differs from unit dispositions"));
    }

    #[test]
    fn hosted_abandonment_refuses_reused_cut_and_unrelated_operation_id() {
        let (sql, mut vcs) = fixture();
        let WholeTwigAbandonmentOutcome::Prepared(plan) =
            vcs.prepare_whole_twig_abandonment("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin(&sql);
        assert_eq!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "cut-b",
                "s:author",
                "t6",
                &mut || panic!("reused cut must refuse before the final check"),
            )
            .unwrap(),
            FlowingAbandonmentOutcome::Refused(FlowingAbandonmentRefusal::CutAlreadyRecorded)
        );
        sql.execute(
            INSERT_OP,
            &[
                text("abandon-op"),
                text("unrelated"),
                text("[]"),
                opt_text(None),
                text("t5"),
            ],
        )
        .unwrap();
        assert_eq!(
            vcs.commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || panic!("operation collision must refuse before the final check"),
            )
            .unwrap(),
            FlowingAbandonmentOutcome::Refused(FlowingAbandonmentRefusal::OperationAlreadyRecorded)
        );
    }

    #[test]
    fn hosted_abandonment_refuses_a_dangling_prior_unit_disposition() {
        let (sql, mut vcs) = fixture();
        let WholeTwigAbandonmentOutcome::Prepared(plan) =
            vcs.prepare_whole_twig_abandonment("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin(&sql);
        sql.execute(
            "INSERT INTO flowing_abandoned_units (unit_id, op_id) VALUES ('unit-a', 'lost-op')",
            &[],
        )
        .unwrap();
        let error = vcs
            .commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || panic!("dangling disposition must refuse before the final check"),
            )
            .unwrap_err();
        assert!(format!("{error:?}").contains("abandoned flowing unit lost its receipt"));
        assert_eq!(
            DoBranches::new(Rc::clone(&sql))
                .unwrap()
                .get_branch("twig")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("cut-b")
        );
    }

    #[test]
    fn hosted_abandonment_refuses_a_prior_unit_receipt_from_another_source() {
        let (sql, mut vcs) = fixture();
        let WholeTwigAbandonmentOutcome::Prepared(first) =
            vcs.prepare_whole_twig_abandonment("twig").unwrap()
        else {
            panic!("first plan");
        };
        begin(&sql);
        let FlowingAbandonmentOutcome::Committed(mut prior) = vcs
            .commit_prepared_whole_twig_abandonment(
                &first,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap()
        else {
            panic!("first disposition");
        };
        prior.source_branch_id = "another-source".into();
        sql.execute(
            "UPDATE flowing_abandonments SET witness_json = ?1, witness_digest = ?2 \
             WHERE op_id = 'abandon-op'",
            &[
                text(&serde_json::to_string(&prior).unwrap()),
                text(&digest(&prior)),
            ],
        )
        .unwrap();
        sql.execute(
            "UPDATE cuts SET branch_id = 'another-source' WHERE cut_id = 'abandoned'",
            &[],
        )
        .unwrap();
        let error = vcs
            .commit_prepared_whole_twig_abandonment(
                &first,
                "abandon-again",
                "begin-abandon",
                "abandoned-again",
                "s:author",
                "t9",
                &mut || panic!("foreign receipt must refuse before the final check"),
            )
            .unwrap_err();
        assert!(format!("{error:?}").contains("abandoned unit differs from its source receipt"));
    }

    #[test]
    fn hosted_abandonment_can_dispose_a_new_unit_after_a_verified_prior_cut() {
        let (sql, mut vcs) = fixture();
        let WholeTwigAbandonmentOutcome::Prepared(first) =
            vcs.prepare_whole_twig_abandonment("twig").unwrap()
        else {
            panic!("first plan");
        };
        begin(&sql);
        let FlowingAbandonmentOutcome::Committed(_prior) = vcs
            .commit_prepared_whole_twig_abandonment(
                &first,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap()
        else {
            panic!("first disposition");
        };
        assert!(matches!(
            DoBranches::new(Rc::clone(&sql))
                .unwrap()
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "finish-abandon".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc-1".into(),
                    expected_eligibility_epoch: 1,
                    expected_owner_epoch: 0,
                    actor: "s:author".into(),
                    action: FlowingFenceAction::FinishRevision {
                        begin_op_id: "begin-abandon".into(),
                    },
                    recorded_at: "t7".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        bound_write(&sql, &mut vcs, "c.txt", "cut-c", "unit-c");
        let WholeTwigAbandonmentOutcome::Prepared(second) =
            vcs.prepare_whole_twig_abandonment("twig").unwrap()
        else {
            panic!("second plan");
        };
        assert!(matches!(
            DoBranches::new(Rc::clone(&sql))
                .unwrap()
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "begin-abandon-again".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc-1".into(),
                    expected_eligibility_epoch: second.source_eligibility_epoch(),
                    expected_owner_epoch: second.source_owner_epoch(),
                    actor: "s:author".into(),
                    action: FlowingFenceAction::BeginRevision {
                        before_cut_id: Some("cut-c".into()),
                        after_cut_id: "abandoned-again".into(),
                    },
                    recorded_at: "t8".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        let FlowingAbandonmentOutcome::Committed(receipt) = vcs
            .commit_prepared_whole_twig_abandonment(
                &second,
                "abandon-again",
                "begin-abandon-again",
                "abandoned-again",
                "s:author",
                "t9",
                &mut || Ok(()),
            )
            .unwrap()
        else {
            panic!("second disposition");
        };
        assert_eq!(receipt.units.len(), 1);
        assert_eq!(receipt.units[0].unit_id(), "unit-c");
        let whipplescript_store::vcs::flowing_abandonment::FlowingAbandonmentLineageOutcome::Verified(lineage) =
            vcs.verify_flowing_abandonment_lineage("abandoned-again").unwrap()
        else {
            panic!("both historical cuts verify");
        };
        assert_eq!(lineage.source_atoms().len(), 1);
        assert_eq!(lineage.source_atoms()[0].cut_id, "cut-c");
    }

    #[test]
    fn hosted_late_disposition_insert_failure_rolls_back_head_cut_and_all_units() {
        let (sql, mut vcs) = fixture();
        let WholeTwigAbandonmentOutcome::Prepared(plan) =
            vcs.prepare_whole_twig_abandonment("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin(&sql);
        sql.execute(
            "CREATE TRIGGER fail_second_abandonment_unit BEFORE INSERT ON flowing_abandoned_units \
             WHEN NEW.unit_id = 'unit-b' BEGIN SELECT RAISE(ABORT, 'injected disposition failure'); END",
            &[],
        ).unwrap();
        assert!(vcs
            .commit_prepared_whole_twig_abandonment(
                &plan,
                "abandon-op",
                "begin-abandon",
                "abandoned",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .is_err());
        let branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        assert_eq!(
            branches
                .get_branch("twig")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("cut-b")
        );
        assert!(branches.get_cut("abandoned").unwrap().is_none());
        assert!(branches
            .flowing_abandonment_receipt("abandon-op")
            .unwrap()
            .is_none());
        assert!(branches
            .abandoned_unit_operation("unit-a")
            .unwrap()
            .is_none());
        assert!(branches
            .abandoned_unit_operation("unit-b")
            .unwrap()
            .is_none());
    }
}
