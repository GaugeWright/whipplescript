use super::*;
use crate::do_store::{test_support::RusqliteDoSql, tests::FaultySql};
use whipplescript_store::branches::write_commit::conformance;

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
