use super::*;
use crate::do_store::{test_support::RusqliteDoSql, tests::FaultySql};
use whipplescript_store::branches::write_commit::conformance;

#[test]
fn hosted_authority_obeys_retained_publication() {
    whipplescript_store::content::publication::conformance::check(|| {
        DoContentBlobs::new(RusqliteDoSql::with_runtime_schema()).expect("content authority")
    });
}

#[test]
fn hosted_retained_publication_rolls_back_every_sql_boundary() {
    use std::rc::Rc;
    let mut refused = 0;
    let mut completed = false;
    for fail_at in 1..24 {
        let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
        let content = DoContentBlobs::new(sql.clone()).expect("content");
        let payload = content.put_text("retained payload").expect("prepare");
        let manifest = content.put_text("prepared manifest").expect("prepare");
        let mut branches = DoBranches::new(sql.clone()).expect("branches");
        let before = branches.ensure_mainline("t0").expect("init");
        let injected = Rc::new(FaultySql::new(sql, fail_at));
        let content = DoContentBlobs {
            sql: injected.clone(),
            external: None,
            threshold_bytes: crate::DEFAULT_TIER_THRESHOLD_BYTES,
        };
        let mut branches = DoBranches {
            sql: injected.clone(),
        };
        let reference = whipplescript_store::branches::write_evidence::WriteEvidenceRef {
            schema_ref: "fixture.result.v1".into(),
            label_ref: "private".into(),
            content_hash: payload.clone(),
        };
        let mut cut = conformance::cut("candidate", None);
        cut.manifest_hash = &manifest;
        let outcome = content.publish_retained(&[payload.clone(), manifest.clone()], || {
            branches.commit_write_with_evidence(cut, Some(&reference))
        });
        injected.disarm();
        if let Ok(AdvanceOutcome::Advanced(_)) = outcome {
            assert_eq!(
                branches.write_evidence("candidate").expect("evidence"),
                Some(reference)
            );
            completed = true;
            break;
        }
        assert!(outcome.is_err(), "{fail_at}: SQL failure must propagate");
        refused += 1;
        assert_eq!(
            branches.get_branch(MAINLINE_BRANCH_ID).expect("branch"),
            Some(before)
        );
        assert!(branches.get_cut("candidate").expect("cut").is_none());
        assert!(branches.get_op("op-candidate").expect("op").is_none());
        assert!(branches
            .write_evidence("candidate")
            .expect("evidence")
            .is_none());
        assert_eq!(
            content
                .get(&payload)
                .expect("durable preparation")
                .as_deref(),
            Some(&b"retained payload"[..])
        );
    }
    assert!(completed);
    assert_eq!(
        refused, 8,
        "two availability reads and all six branch publication statements"
    );
}

#[test]
fn a_sql_host_cannot_invoke_retained_publication_twice() {
    use std::rc::Rc;
    struct Repeated(Rc<RusqliteDoSql>);
    impl DoSql for Repeated {
        fn atomic(&self, body: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
            self.0.atomic(&mut || {
                body()?;
                body()
            })
        }
        fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
            self.0.execute(sql, params)
        }
        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            self.0.query(sql, params)
        }
    }
    let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
    let content = DoContentBlobs::new(sql.clone()).expect("content");
    let id = content.put_text("prepared").expect("prepare");
    let mut branches = DoBranches::new(sql.clone()).expect("branches");
    let before = branches.ensure_mainline("t0").expect("init");
    let broken = DoContentBlobs {
        sql: Repeated(sql),
        external: None,
        threshold_bytes: crate::DEFAULT_TIER_THRESHOLD_BYTES,
    };
    let error = broken
        .publish_retained(std::slice::from_ref(&id), || {
            branches.commit_write(conformance::cut("candidate", None))
        })
        .expect_err("duplicate callback");
    assert!(format!("{error:?}").contains("SQL host repeated retained publication"));
    assert_eq!(
        branches.get_branch(MAINLINE_BRANCH_ID).expect("branch"),
        Some(before)
    );
    assert!(branches.get_cut("candidate").expect("cut").is_none());
    assert!(branches.get_op("op-candidate").expect("op").is_none());
    assert_eq!(
        broken.get(&id).expect("durable preparation").as_deref(),
        Some(&b"prepared"[..])
    );
}

#[test]
fn hosted_write_commit_conformance() {
    conformance::check(&mut DoBranches::new(RusqliteDoSql::with_runtime_schema()).unwrap());
}

#[test]
fn hosted_write_commit_rolls_back_every_sql_boundary() {
    let mut reached_success = false;
    let mut refused = 0;
    for fail_at in 1..20 {
        let sql = RusqliteDoSql::with_runtime_schema();
        let mut branches = DoBranches::new(sql).unwrap();
        let before = branches.ensure_mainline("t0").unwrap();
        let mut injected = DoBranches {
            sql: FaultySql::new(branches.sql, fail_at),
        };
        let outcome = injected.commit_write(conformance::cut("first", None));
        injected.sql.disarm();
        if let Ok(AdvanceOutcome::Advanced(_)) = outcome {
            assert!(injected.get_cut("first").unwrap().is_some());
            assert!(injected.get_op("op-first").unwrap().is_some());
            reached_success = true;
            break;
        }
        assert!(outcome.is_err(), "injected SQL failure must propagate");
        refused += 1;
        assert_eq!(
            injected.get_branch(MAINLINE_BRANCH_ID).unwrap(),
            Some(before),
            "failure {fail_at}"
        );
        assert!(
            injected.get_cut("first").unwrap().is_none(),
            "failure {fail_at}"
        );
        assert!(
            injected.get_op("op-first").unwrap().is_none(),
            "failure {fail_at}"
        );
        assert!(matches!(
            injected
                .commit_write(conformance::cut("first", None))
                .unwrap(),
            AdvanceOutcome::Advanced(_)
        ));
    }
    assert!(reached_success);
    assert_eq!(
        refused, 5,
        "both reads and all three mutations must be exercised"
    );
}

#[test]
fn hosted_versioned_save_binding() {
    whipplescript_store::vcs_file_save::conformance::check(|| {
        super::compose_vcs(&RusqliteDoSql::with_runtime_schema()).expect("hosted workspace")
    });
}

#[test]
fn hosted_write_evidence_conformance() {
    whipplescript_store::branches::write_evidence::conformance::check(
        &mut DoBranches::new(RusqliteDoSql::with_runtime_schema()).expect("branches"),
    );
}

#[test]
fn hosted_write_evidence_rolls_back_every_sql_boundary() {
    let mut reached_success = false;
    let mut refused = 0;
    for fail_at in 1..24 {
        let sql = RusqliteDoSql::with_runtime_schema();
        let mut branches = DoBranches::new(sql).expect("branches");
        let before = branches.ensure_mainline("t0").expect("init");
        let mut injected = DoBranches {
            sql: FaultySql::new(branches.sql, fail_at),
        };
        let evidence = whipplescript_store::branches::write_evidence::conformance::reference();
        let outcome =
            injected.commit_write_with_evidence(conformance::cut("first", None), Some(&evidence));
        injected.sql.disarm();
        if let Ok(AdvanceOutcome::Advanced(_)) = outcome {
            assert_eq!(
                injected.write_evidence("first").expect("evidence"),
                Some(evidence)
            );
            reached_success = true;
            break;
        }
        assert!(outcome.is_err());
        refused += 1;
        assert_eq!(
            injected.get_branch(MAINLINE_BRANCH_ID).expect("branch"),
            Some(before)
        );
        assert!(injected.get_cut("first").expect("cut").is_none());
        assert!(injected.get_op("op-first").expect("op").is_none());
        assert!(injected
            .write_evidence("first")
            .expect("evidence")
            .is_none());
        assert!(matches!(
            injected
                .commit_write_with_evidence(conformance::cut("first", None), Some(&evidence))
                .expect("safe commit"),
            AdvanceOutcome::Advanced(_)
        ));
    }
    assert!(reached_success);
    assert_eq!(
        refused, 6,
        "two reads and all four writes must be exercised"
    );
}

#[test]
fn hosted_scoped_save_adapter_preserves_original_evidence() {
    whipplescript_store::vcs_file_save::scoped_conformance::check(|| {
        super::compose_vcs(&RusqliteDoSql::with_runtime_schema()).expect("hosted workspace")
    });
}
