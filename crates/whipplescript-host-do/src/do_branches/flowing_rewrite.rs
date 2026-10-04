use super::{flowing_fence, flowing_sources::exact_atomic, DoBranches};
use crate::do_store::{as_text, opt_text, sql_err, text, DoSql};
use whipplescript_store::branches::flowing_admission::FlowingAdmissions;
use whipplescript_store::branches::flowing_rewrite::{
    check_current, digest, CommitFlowingRewrite, FlowingRewriteOutcome, FlowingRewriteReceipt,
    FlowingRewriteRefusal, FlowingRewrites, RewriteUnitState,
};
use whipplescript_store::branches::flowing_sources::FlowingSources;
use whipplescript_store::branches::write_commit::{INSERT_CUT, INSERT_OP};
use whipplescript_store::branches::{Branches, OpBranchDelta, OpBranchState};
use whipplescript_store::{StoreError, StoreResult};

fn read_receipt<S: DoSql>(
    sql: &S,
    predicate: &str,
    value: &str,
) -> StoreResult<Option<FlowingRewriteReceipt>> {
    let rows = sql
        .query(
            &format!(
                "SELECT op_id, after_cut_id, witness_json, witness_digest \
                 FROM flowing_rewrites WHERE {predicate} = ?1"
            ),
            &[text(value)],
        )
        .map_err(sql_err)?;
    rows.first()
        .map(|row| {
            let receipt: FlowingRewriteReceipt = serde_json::from_str(&as_text(&row[2]))?;
            if receipt.op_id != as_text(&row[0])
                || receipt.after_cut_id != as_text(&row[1])
                || digest(&receipt) != as_text(&row[3])
            {
                return Err(StoreError::Conflict(
                    "flowing rewrite receipt differs from its row or digest".into(),
                ));
            }
            Ok(receipt)
        })
        .transpose()
}

impl<S: DoSql> FlowingRewrites for DoBranches<S> {
    fn commit_flowing_rewrite(
        &mut self,
        request: CommitFlowingRewrite<'_>,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<FlowingRewriteOutcome> {
        use FlowingRewriteOutcome as O;
        use FlowingRewriteRefusal as R;
        let receipt = request.receipt();
        exact_atomic(&self.sql, "flowing rewrite", || {
            if let Some(existing) = read_receipt(&self.sql, "op_id", &receipt.op_id)? {
                if existing == receipt {
                    return Ok(O::Existing(existing));
                }
                // MUTATION-SUCCESS-EXPR: Ok(O::Existing(existing))
                return Ok(O::Refused(R::IdentityMismatch));
            }
            if self.get_cut(&receipt.after_cut_id)?.is_some() {
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
                return Ok(O::Refused(R::OperationAlreadyRecorded));
            }
            let source = self.row_by_id(&receipt.source_branch_id)?;
            let parent = self.row_by_id(&receipt.parent_branch_id)?;
            let fence = flowing_fence::read_state(&self.sql, &receipt.source_branch_id)?;
            let reserved = self.head_reservation(&receipt.source_branch_id)?.is_some();
            let mut units = Vec::new();
            for declaration in self.source_contributions(&receipt.source_branch_id)? {
                units.push(RewriteUnitState {
                    basis: self.contribution_basis(&declaration.unit_id)?,
                    pin: self.private_cut_pin(&declaration.pin_id)?,
                    handed_off: self.contribution_handoff(&declaration.unit_id)?.is_some(),
                    admitted: self
                        .admitted_unit_operation(&declaration.unit_id)?
                        .is_some(),
                    declaration,
                });
            }
            let after = match check_current(
                &receipt,
                source.clone(),
                parent,
                fence.clone(),
                reserved,
                &units,
            ) {
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
                        opt_text(receipt.parent_head_cut_id.as_deref()),
                        text("flowing:rebase"),
                        text(&receipt.actor),
                        opt_text(None),
                        text(&receipt.recorded_at),
                    ],
                )
                .map_err(sql_err)?;
            let cut = self.get_cut(&receipt.after_cut_id)?;
            whipplescript_store::branches::flowing_fence::require_head_move(
                &fence.expect("validated revision exists"),
                Some(&receipt.old_head_cut_id),
                &receipt.after_cut_id,
                &receipt.after_manifest_hash,
                cut.as_ref(),
            )?;
            self.sql
                .execute(
                    "UPDATE branches SET branch_point_cut_id = ?2, branch_point_manifest_hash = ?3, \
                     head_cut_id = ?4, head_manifest_hash = ?5, updated_at = ?6 WHERE branch_id = ?1",
                    &[
                        text(&receipt.source_branch_id),
                        opt_text(receipt.parent_head_cut_id.as_deref()),
                        opt_text(receipt.parent_head_manifest_hash.as_deref()),
                        text(&receipt.after_cut_id),
                        text(&receipt.after_manifest_hash),
                        text(&receipt.recorded_at),
                    ],
                )
                .map_err(sql_err)?;
            self.sql
                .execute(
                    INSERT_OP,
                    &[
                        text(&receipt.op_id),
                        text("flowing_rewrite"),
                        text(&deltas),
                        text("flowing:rebase"),
                        text(&receipt.recorded_at),
                    ],
                )
                .map_err(sql_err)?;
            self.sql
                .execute(
                    "INSERT INTO flowing_rewrites (op_id, after_cut_id, witness_json, witness_digest) \
                     VALUES (?1, ?2, ?3, ?4)",
                    &[
                        text(&receipt.op_id),
                        text(&receipt.after_cut_id),
                        text(&serde_json::to_string(&receipt)?),
                        text(&digest(&receipt)),
                    ],
                )
                .map_err(sql_err)?;
            Ok(O::Committed(receipt.clone()))
        })
    }

    fn flowing_rewrite_receipt(&self, op_id: &str) -> StoreResult<Option<FlowingRewriteReceipt>> {
        read_receipt(&self.sql, "op_id", op_id)
    }

    fn flowing_rewrite_for_cut(&self, cut_id: &str) -> StoreResult<Option<FlowingRewriteReceipt>> {
        read_receipt(&self.sql, "after_cut_id", cut_id)
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;
    use crate::do_branches::DoContentBlobs;
    use crate::do_store::test_support::RusqliteDoSql;
    use whipplescript_store::branches::flowing_fence::{
        FlowingFence, FlowingFenceAction, FlowingFenceOutcome, FlowingFenceTransition,
        FlowingSourceKind, OpenFlowingSource,
    };
    use whipplescript_store::branches::flowing_sources::{DeclareContribution, PinPrivateCut};
    use whipplescript_store::branches::MAINLINE_BRANCH_ID;
    use whipplescript_store::selection;
    use whipplescript_store::vcs::flowing_rewrite::{
        CurrentFlowingRewritePrefixOutcome, CurrentFlowingRewriteRosterOutcome,
        FlowingDisjointRebaseOutcome, FlowingRewriteLineageOutcome,
    };
    use whipplescript_store::vcs::{FlowingSelectionOutcome, WorkspaceVcs};

    type HostedVcs = WorkspaceVcs<DoBranches<Rc<RusqliteDoSql>>, DoContentBlobs<Rc<RusqliteDoSql>>>;

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
        let mut branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        branches
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "twig".into(),
                incarnation_id: "twig-inc-1".into(),
                kind: FlowingSourceKind::Twig,
                owner: "s:author".into(),
                opened_at: "t1".into(),
            })
            .unwrap();
        vcs.write("twig", "a.txt", Some("A"), "cut-a", "t2")
            .unwrap();
        let cut = branches.get_cut("cut-a").unwrap().unwrap();
        branches
            .pin_private_cut(PinPrivateCut {
                pin_id: "pin-a",
                twig_branch_id: "twig",
                cut_id: "cut-a",
                manifest_hash: &cut.manifest_hash,
                principal: "s:author",
                retained_at: "t3",
            })
            .unwrap();
        branches
            .declare_contribution(DeclareContribution {
                unit_id: "unit-a",
                pin_id: "pin-a",
                principal: "s:author",
                intent: "hosted rewrite",
                read_basis_digest: "read",
                dependency_basis_digest: "deps",
                scope_digest: "scope",
                declared_at: "t3",
            })
            .unwrap();
        let FlowingSelectionOutcome::Selected(selected) = vcs
            .select_private_changes("pin-a", &selection::parse("path(a.txt)").unwrap())
            .unwrap()
        else {
            panic!("selected");
        };
        vcs.bind_private_selection("unit-a", &selected, "t3")
            .unwrap();
        vcs.write(
            MAINLINE_BRANCH_ID,
            "parent.txt",
            Some("parent"),
            "parent-next",
            "t4",
        )
        .unwrap();
        (sql, vcs)
    }

    fn begin(sql: &Rc<RusqliteDoSql>) {
        let mut branches = DoBranches::new(Rc::clone(sql)).unwrap();
        assert!(matches!(
            branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "begin-rewrite".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: "twig-inc-1".into(),
                    expected_eligibility_epoch: 0,
                    expected_owner_epoch: 0,
                    actor: "s:author".into(),
                    action: FlowingFenceAction::BeginRevision {
                        before_cut_id: Some("cut-a".into()),
                        after_cut_id: "rebased".into(),
                    },
                    recorded_at: "t5".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
    }

    #[test]
    fn hosted_rewrite_commits_exact_roots_and_retries_without_rechecking() {
        let (sql, mut vcs) = fixture();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin(&sql);
        let committed = vcs
            .commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap();
        let FlowingRewriteOutcome::Committed(receipt) = committed else {
            panic!("committed");
        };
        let branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        assert_eq!(
            branches
                .get_branch("twig")
                .unwrap()
                .unwrap()
                .branch_point_cut_id
                .as_deref(),
            Some("parent-next")
        );
        assert_eq!(
            branches
                .get_branch("twig")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref(),
            Some("rebased")
        );
        assert_eq!(
            branches.flowing_rewrite_for_cut("rebased").unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(receipt.roots[0].unit_id(), "unit-a");
        let FlowingRewriteLineageOutcome::Verified(lineage) =
            vcs.verify_flowing_rewrite_lineage("rebased").unwrap()
        else {
            panic!("hosted rewrite lineage verified");
        };
        assert_eq!(lineage.receipt(), &receipt);
        assert_eq!(lineage.source_atoms()[0].cut_id, "cut-a");
        assert_eq!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || panic!("exact retry should not recheck"),
            )
            .unwrap(),
            FlowingRewriteOutcome::Existing(receipt)
        );
        assert_eq!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "different-time",
                &mut || panic!("changed retry must refuse"),
            )
            .unwrap(),
            FlowingRewriteOutcome::Refused(FlowingRewriteRefusal::IdentityMismatch),
        );
        assert_eq!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-2",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || panic!("cut collision must refuse"),
            )
            .unwrap(),
            FlowingRewriteOutcome::Refused(FlowingRewriteRefusal::CutAlreadyRecorded),
        );
    }

    #[test]
    fn hosted_current_rewrite_prefix_survives_a_later_write() {
        let (sql, mut vcs) = fixture();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin(&sql);
        assert!(matches!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap(),
            FlowingRewriteOutcome::Committed(_)
        ));
        assert_eq!(
            vcs.verify_current_flowing_rewrite_prefix("twig", "rebased")
                .unwrap(),
            CurrentFlowingRewritePrefixOutcome::SourceNotReady
        );
        let mut branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        let fence = branches.flowing_source("twig").unwrap().unwrap();
        assert!(matches!(
            branches
                .transition_flowing_source(&FlowingFenceTransition {
                    op_id: "finish-rewrite".into(),
                    source_branch_id: "twig".into(),
                    incarnation_id: fence.incarnation_id,
                    expected_eligibility_epoch: fence.eligibility_epoch,
                    expected_owner_epoch: fence.owner_epoch,
                    actor: "s:author".into(),
                    action: FlowingFenceAction::FinishRevision {
                        begin_op_id: "begin-rewrite".into(),
                    },
                    recorded_at: "t7".into(),
                })
                .unwrap(),
            FlowingFenceOutcome::Applied(_)
        ));
        vcs.write("twig", "later.txt", Some("tail"), "later-cut", "t8")
            .unwrap();
        let CurrentFlowingRewritePrefixOutcome::Verified(prefix) = vcs
            .verify_current_flowing_rewrite_prefix("twig", "rebased")
            .unwrap()
        else {
            panic!("active hosted source keeps the verified rewrite and later tail");
        };
        assert_eq!(prefix.lineage().receipt().roots.len(), 1);
        assert_eq!(prefix.tail_atoms().len(), 1);
        assert_eq!(prefix.tail_atoms()[0].cut_id, "later-cut");
        assert_eq!(
            vcs.verify_current_flowing_rewrite_roster("twig", "rebased")
                .unwrap(),
            CurrentFlowingRewriteRosterOutcome::IncompleteRoster
        );
        let cut = branches.get_cut("later-cut").unwrap().unwrap();
        branches
            .pin_private_cut(PinPrivateCut {
                pin_id: "pin-tail",
                twig_branch_id: "twig",
                cut_id: "later-cut",
                manifest_hash: &cut.manifest_hash,
                principal: "s:author",
                retained_at: "t9",
            })
            .unwrap();
        branches
            .declare_contribution(DeclareContribution {
                unit_id: "unit-tail",
                pin_id: "pin-tail",
                principal: "s:author",
                intent: "hosted tail",
                read_basis_digest: "read",
                dependency_basis_digest: "deps",
                scope_digest: "tail",
                declared_at: "t9",
            })
            .unwrap();
        let FlowingSelectionOutcome::Selected(selected) = vcs
            .select_private_changes("pin-tail", &selection::parse("change(later-cut)").unwrap())
            .unwrap()
        else {
            panic!("later write can be selected after the rewrite");
        };
        vcs.bind_private_selection("unit-tail", &selected, "t9")
            .unwrap();
        let CurrentFlowingRewriteRosterOutcome::Verified(roster) = vcs
            .verify_current_flowing_rewrite_roster("twig", "rebased")
            .unwrap()
        else {
            panic!("hosted source roster verifies old roots and later tail");
        };
        assert_eq!(
            roster
                .units()
                .iter()
                .map(|unit| unit.unit_id.as_str())
                .collect::<Vec<_>>(),
            ["unit-a", "unit-tail"]
        );
        assert!(!roster.units()[1].from_rewrite);
    }

    #[test]
    fn hosted_rewrite_refuses_reused_operation_id_and_corrupt_receipt() {
        let (sql, mut vcs) = fixture();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin(&sql);
        assert_eq!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "op-parent-next",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || panic!("operation collision must refuse"),
            )
            .unwrap(),
            FlowingRewriteOutcome::Refused(FlowingRewriteRefusal::OperationAlreadyRecorded),
        );
        assert!(
            vcs.get_branch("twig")
                .unwrap()
                .unwrap()
                .head_cut_id
                .as_deref()
                == Some("cut-a")
        );
        assert!(matches!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap(),
            FlowingRewriteOutcome::Committed(_)
        ));
        sql.execute(
            "UPDATE flowing_rewrites SET witness_digest = 'sha256:corrupt' WHERE op_id = ?1",
            &[text("rewrite-1")],
        )
        .unwrap();
        let branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        assert!(branches.flowing_rewrite_receipt("rewrite-1").is_err());
        assert!(branches.flowing_rewrite_for_cut("rebased").is_err());
    }

    #[test]
    fn hosted_rewrite_late_sql_failure_rolls_back_cut_ref_and_receipt() {
        let (sql, mut vcs) = fixture();
        let FlowingDisjointRebaseOutcome::Prepared(plan) =
            vcs.prepare_disjoint_flowing_rebase("twig").unwrap()
        else {
            panic!("prepared");
        };
        begin(&sql);
        let before = vcs.get_branch("twig").unwrap().unwrap();
        sql.execute(
            "CREATE TRIGGER fail_flowing_rewrite BEFORE INSERT ON flowing_rewrites \
             BEGIN SELECT RAISE(ABORT, 'injected rewrite failure'); END",
            &[],
        )
        .unwrap();
        assert!(vcs
            .commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .is_err());
        let branches = DoBranches::new(Rc::clone(&sql)).unwrap();
        assert_eq!(vcs.get_branch("twig").unwrap().unwrap(), before);
        assert!(branches.get_cut("rebased").unwrap().is_none());
        assert!(branches
            .flowing_rewrite_receipt("rewrite-1")
            .unwrap()
            .is_none());
        sql.execute("DROP TRIGGER fail_flowing_rewrite", &[])
            .unwrap();
        assert!(matches!(
            vcs.commit_prepared_disjoint_flowing_rebase(
                &plan,
                "rewrite-1",
                "begin-rewrite",
                "rebased",
                "s:author",
                "t6",
                &mut || Ok(()),
            )
            .unwrap(),
            FlowingRewriteOutcome::Committed(_)
        ));
    }
}
