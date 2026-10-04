use super::*;
use crate::vcs::tests::{vcs, TempVcs};
use std::cell::Cell;

fn setup() -> TempVcs {
    let mut vcs = vcs();
    vcs.init("t0").unwrap();
    vcs.write(
        MAINLINE_BRANCH_ID,
        "patient.txt",
        Some("baseline"),
        "main-1",
        "t1",
    )
    .unwrap();
    vcs.create_branch("office", None, MAINLINE_BRANCH_ID, "t2")
        .unwrap();
    vcs.write(
        "office",
        "patient.txt",
        Some("staff result"),
        "office-1",
        "t3",
    )
    .unwrap();
    vcs.write(
        MAINLINE_BRANCH_ID,
        "colleague.txt",
        Some("colleague result"),
        "main-2",
        "t4",
    )
    .unwrap();
    vcs
}
fn prepare(vcs: &NativeWorkspaceVcs) -> PreparedRecordedSettlement {
    vcs.prepare_recorded_settlement(
        "office",
        "office-1",
        &[],
        "settlement",
        "staff:alice",
        "original-http-command",
        "t5",
        &mut || Ok(()),
    )
    .unwrap()
}
// The gate retains only the concrete temporary paths, not a second owner handle.
struct TestGate {
    paths: Vec<std::path::PathBuf>,
    mode: &'static str,
}
impl MainlineGate for TestGate {
    fn prepare(
        &mut self,
        base: Option<&str>,
        cut: &str,
        capture: &crate::norm_commands::NormArtifactCapture<'_>,
    ) -> StoreResult<GateVerdict> {
        assert!(base.is_some());
        assert!(capture(cut)?.files().contains_key("patient.txt"));
        for path in &self.paths {
            let connection = rusqlite::Connection::open(path).unwrap();
            connection.busy_timeout(std::time::Duration::ZERO).unwrap();
            assert!(
                connection.execute_batch("BEGIN IMMEDIATE").is_err(),
                "writer escaped gate"
            );
        }
        if self.mode == "refuse" {
            Ok(GateVerdict::Refuse(GateRefusal {
                reason: "fixture refusal".into(),
                detail: serde_json::Value::Null,
            }))
        } else {
            Ok(GateVerdict::Admit)
        }
    }
    fn commit(&mut self, advance: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<GateCommit> {
        match self.mode {
            "stale" => Ok(GateCommit::Stale {
                changed: "fixture stale".into(),
            }),
            "omit" => Ok(GateCommit::Committed),
            _ => {
                advance()?;
                if self.mode == "twice" {
                    advance()?;
                }
                if matches!(
                    self.mode,
                    "lost-cut" | "lost-op" | "lost-source" | "lost-target"
                ) {
                    let connection = rusqlite::Connection::open(&self.paths[0])?;
                    connection.execute(
                        match self.mode {
                            "lost-cut" => "DELETE FROM cuts WHERE cut_id='settlement'",
                            "lost-op" => "DELETE FROM ops WHERE op_id='op-settlement'",
                            "lost-source" => "DELETE FROM branches WHERE branch_id='office'",
                            _ => "DELETE FROM branches WHERE branch_id='main'",
                        },
                        [],
                    )?;
                }
                if self.mode == "tamper-op" {
                    let connection = rusqlite::Connection::open(&self.paths[0])?;
                    connection.execute(
                        "UPDATE ops SET kind='substituted' WHERE op_id='op-settlement'",
                        [],
                    )?;
                }
                if self.mode == "bad-stale" {
                    return Ok(GateCommit::Stale {
                        changed: "invalid stale after commit".into(),
                    });
                }
                Ok(GateCommit::Committed)
            }
        }
    }
}
fn gate(vcs: &TempVcs, mode: &'static str) -> TestGate {
    TestGate {
        paths: vec![
            vcs.dir.join("branches.sqlite"),
            vcs.dir.join("content.sqlite"),
        ],
        mode,
    }
}

#[test]
fn recorded_settlement_matches_merge_keeping_without_an_intermediate_rebase() {
    let vcs = setup();
    let before = vcs.branches.list_branches(None).unwrap();
    let prepared = prepare(&vcs);
    assert_eq!(vcs.branches.list_branches(None).unwrap(), before);
    let RecordedSettlementOutcome::Applied(receipt) = vcs
        .apply_prepared_recorded_settlement(&prepared, &mut || Ok(()), &mut gate(&vcs, "admit"))
        .unwrap()
    else {
        panic!("not applied")
    };
    assert_eq!(
        vcs.read(MAINLINE_BRANCH_ID, "patient.txt")
            .unwrap()
            .as_deref(),
        Some("staff result")
    );
    assert_eq!(
        vcs.read(MAINLINE_BRANCH_ID, "colleague.txt")
            .unwrap()
            .as_deref(),
        Some("colleague result")
    );
    assert_eq!(receipt.cut().actor.as_deref(), Some("staff:alice"));
    assert_eq!(
        receipt.cut().intent.as_deref(),
        Some("original-http-command")
    );
    assert_eq!(receipt.cut().change_id, "office-1");
    assert_eq!(receipt.operation().kind, "merge-keep");
    assert_eq!(receipt.operation().deltas.len(), 2);
    let source = vcs.get_branch("office").unwrap().unwrap();
    assert_eq!(source.head_cut_id.as_deref(), Some("settlement"));
    assert_eq!(source.branch_point_cut_id, source.head_cut_id);
    assert!(vcs.get_cut("settlement-rebase").unwrap().is_none());
    vcs.publish_recorded_settlement(&receipt, |_, _| {
        for path in &gate(&vcs, "admit").paths {
            let independent = rusqlite::Connection::open(path).unwrap();
            independent.busy_timeout(std::time::Duration::ZERO).unwrap();
            assert!(independent.execute_batch("BEGIN IMMEDIATE").is_err());
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn recorded_settlement_gate_refusal_staleness_or_omitted_commit_moves_nothing() {
    for mode in ["refuse", "stale", "omit"] {
        let vcs = setup();
        let before = vcs.branches.list_branches(None).unwrap();
        let prepared = prepare(&vcs);
        let result = vcs.apply_prepared_recorded_settlement(
            &prepared,
            &mut || Ok(()),
            &mut gate(&vcs, mode),
        );
        match mode {
            "refuse" => assert!(matches!(
                result,
                Ok(RecordedSettlementOutcome::GateRefused(_))
            )),
            "stale" => assert!(matches!(
                result,
                Ok(RecordedSettlementOutcome::GateStale { .. })
            )),
            _ => assert!(
                matches!(result, Err(StoreError::Conflict(reason)) if reason == "recorded settlement operation unavailable")
            ),
        }
        assert_eq!(vcs.branches.list_branches(None).unwrap(), before);
        assert!(vcs.get_cut("settlement").unwrap().is_none());
        assert!(vcs.get_op("op-settlement").unwrap().is_none());
    }
}

#[test]
fn recorded_settlement_original_check_refuses_at_every_native_commit_boundary() {
    for denied in 1..=4 {
        let vcs = setup();
        let before = vcs.branches.list_branches(None).unwrap();
        let prepared = prepare(&vcs);
        let calls = Cell::new(0);
        assert!(vcs
            .apply_prepared_recorded_settlement(
                &prepared,
                &mut || {
                    calls.set(calls.get() + 1);
                    if calls.get() == denied {
                        Err(StoreError::Conflict("original ended".into()))
                    } else {
                        Ok(())
                    }
                },
                &mut gate(&vcs, "admit")
            )
            .is_err());
        assert_eq!(calls.get(), denied);
        assert_eq!(vcs.branches.list_branches(None).unwrap(), before);
        assert!(vcs.get_cut("settlement").unwrap().is_none());
        assert!(vcs.get_op("op-settlement").unwrap().is_none());
    }
}

#[test]
fn recorded_settlement_changed_inputs_or_lost_payloads_refuse_before_heads_move() {
    for change in [
        "target",
        "source",
        "retarget",
        "base-payload",
        "candidate",
        "cut",
        "reservation",
        "receipt-collision",
    ] {
        let mut vcs = setup();
        let prepared = prepare(&vcs);
        match change {
            "target" => {
                vcs.write(MAINLINE_BRANCH_ID, "new.txt", Some("new"), "main-3", "t6")
                    .unwrap();
            }
            "source" => {
                vcs.write("office", "new.txt", Some("new"), "office-2", "t6")
                    .unwrap();
            }
            "retarget" => {
                vcs.create_branch("other", None, MAINLINE_BRANCH_ID, "t6")
                    .unwrap();
                vcs.branches
                    .retarget_branch("office", "other", "t7")
                    .unwrap();
            }
            "base-payload" => {
                let body = vcs.cut_manifest("main-1").unwrap().unwrap()["patient.txt"].clone();
                vcs.content.erase(&body, "t6").unwrap();
            }
            "candidate" => {
                vcs.content.erase(&prepared.manifest_hash, "t6").unwrap();
            }
            "cut" => {
                let db = rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).unwrap();
                db.execute("DELETE FROM cuts WHERE cut_id='main-1'", [])
                    .unwrap();
            }
            "reservation" => {
                vcs.branches
                    .reserve_head("office", "other-owner", "t6")
                    .unwrap();
            }
            _ => {
                vcs.branches
                    .record_op("op-settlement", "collision", &[], None, "t6")
                    .unwrap();
            }
        }
        let before = vcs.branches.list_branches(None).unwrap();
        assert!(
            vcs.apply_prepared_recorded_settlement(
                &prepared,
                &mut || Ok(()),
                &mut gate(&vcs, "admit")
            )
            .is_err(),
            "{change}"
        );
        assert_eq!(
            vcs.branches.list_branches(None).unwrap(),
            before,
            "{change}"
        );
        assert!(vcs.get_cut("settlement").unwrap().is_none());
    }
}

#[test]
fn recorded_settlement_conflict_or_missing_meaning_cannot_prepare() {
    let mut vcs = setup();
    vcs.write(
        MAINLINE_BRANCH_ID,
        "patient.txt",
        Some("different result"),
        "main-3",
        "t5",
    )
    .unwrap();
    let result = vcs.prepare_recorded_settlement(
        "office",
        "office-1",
        &[],
        "settlement",
        "staff",
        "command",
        "t6",
        &mut || Ok(()),
    );
    assert!(
        matches!(result, Err(StoreError::Conflict(reason)) if reason == "recorded settlement requires a clean original candidate")
    );
    let vcs = setup();
    assert!(vcs
        .prepare_recorded_settlement(
            "office",
            "office-1",
            &[],
            "settlement",
            "",
            "command",
            "t6",
            &mut || Ok(())
        )
        .is_err());
    assert!(vcs
        .prepare_recorded_settlement(
            "office",
            "office-1",
            &["missing-original-evidence".into()],
            "settlement",
            "staff",
            "command",
            "t6",
            &mut || Ok(())
        )
        .is_err());
}

#[test]
fn recorded_settlement_later_embedding_failure_leaves_original_native_receipt() {
    let vcs = setup();
    let prepared = prepare(&vcs);
    let RecordedSettlementOutcome::Applied(receipt) = vcs
        .apply_prepared_recorded_settlement(&prepared, &mut || Ok(()), &mut gate(&vcs, "admit"))
        .unwrap()
    else {
        panic!("not applied")
    };
    let result: StoreResult<()> = vcs.publish_recorded_settlement(&receipt, |_, _| {
        Err(StoreError::Conflict("embedding authority ended".into()))
    });
    assert!(result.is_err());
    assert_eq!(
        vcs.get_cut("settlement").unwrap().as_ref(),
        Some(receipt.cut())
    );
    assert_eq!(
        vcs.get_op("op-settlement").unwrap().as_ref(),
        Some(receipt.operation())
    );
}

#[test]
fn recorded_settlement_publisher_refuses_changed_or_missing_exact_native_evidence() {
    for change in ["op", "cut", "head", "payload"] {
        let mut vcs = setup();
        let prepared = prepare(&vcs);
        let RecordedSettlementOutcome::Applied(receipt) = vcs
            .apply_prepared_recorded_settlement(&prepared, &mut || Ok(()), &mut gate(&vcs, "admit"))
            .unwrap()
        else {
            panic!("not applied")
        };
        match change {
            "head" => {
                vcs.write("office", "later.txt", Some("later"), "office-2", "t6")
                    .unwrap();
            }
            "payload" => {
                vcs.content.erase(&receipt.cut.manifest_hash, "t6").unwrap();
            }
            _ => {
                let db = rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).unwrap();
                db.execute(
                    if change == "op" {
                        "DELETE FROM ops WHERE op_id='op-settlement'"
                    } else {
                        "DELETE FROM cuts WHERE cut_id='settlement'"
                    },
                    [],
                )
                .unwrap();
            }
        }
        let result = vcs.publish_recorded_settlement(&receipt, |_, _| Ok(()));
        if change == "payload" {
            assert!(result.is_err());
        } else {
            assert!(
                matches!(result, Err(StoreError::Conflict(reason)) if reason == "recorded settlement evidence changed before publication"),
                "{change}"
            );
        }
    }
}

#[test]
fn recorded_settlement_recovery_never_reapplies_or_borrows_fresh_meaning() {
    let vcs = setup();
    let prepared = prepare(&vcs);
    let RecordedSettlementOutcome::Applied(applied) = vcs
        .apply_prepared_recorded_settlement(&prepared, &mut || Ok(()), &mut gate(&vcs, "admit"))
        .unwrap()
    else {
        panic!("not applied")
    };
    let before = vcs.branches.list_branches(None).unwrap();
    let recovered = vcs
        .recover_recorded_settlement(
            "office",
            "office-1",
            &[],
            "settlement",
            "staff:alice",
            "original-http-command",
            &mut || Ok(()),
        )
        .unwrap();
    assert_eq!(recovered.cut(), applied.cut());
    assert_eq!(recovered.operation(), applied.operation());
    assert_eq!(vcs.branches.list_branches(None).unwrap(), before);
    for (actor, intent, head) in [
        ("another-staff", "original-http-command", "office-1"),
        ("staff:alice", "new-http-command", "office-1"),
        ("staff:alice", "original-http-command", "main-1"),
    ] {
        let result = vcs.recover_recorded_settlement(
            "office",
            head,
            &[],
            "settlement",
            actor,
            intent,
            &mut || Ok(()),
        );
        let expected = if head == "office-1" {
            "original recorded settlement recovery meaning differs"
        } else {
            "original recorded settlement recovery operation differs"
        };
        assert!(matches!(result, Err(StoreError::Conflict(reason)) if reason == expected));
    }
    assert!(vcs
        .recover_recorded_settlement(
            "office",
            "office-1",
            &[],
            "settlement",
            "staff:alice",
            "original-http-command",
            &mut || Err(StoreError::Conflict("original expired".into()))
        )
        .is_err());
    let calls = Cell::new(0);
    assert!(vcs
        .recover_recorded_settlement(
            "office",
            "office-1",
            &[],
            "settlement",
            "staff:alice",
            "original-http-command",
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err(StoreError::Conflict(
                        "original expired at publication".into(),
                    ))
                } else {
                    Ok(())
                }
            }
        )
        .is_err());
    let db = rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).unwrap();
    db.execute("DELETE FROM ops WHERE op_id='op-settlement'", [])
        .unwrap();
    assert!(vcs
        .recover_recorded_settlement(
            "office",
            "office-1",
            &[],
            "settlement",
            "staff:alice",
            "original-http-command",
            &mut || Ok(())
        )
        .is_err());
}

#[test]
fn recorded_settlement_no_change_still_leaves_one_synchronized_receipt() {
    let mut vcs = setup();
    vcs.write(
        "office",
        "patient.txt",
        Some("baseline"),
        "office-noop",
        "t5",
    )
    .unwrap();
    let prepared = vcs
        .prepare_recorded_settlement(
            "office",
            "office-noop",
            &[],
            "settlement",
            "staff:alice",
            "original-http-command",
            "t6",
            &mut || Ok(()),
        )
        .unwrap();
    let RecordedSettlementOutcome::Applied(receipt) = vcs
        .apply_prepared_recorded_settlement(&prepared, &mut || Ok(()), &mut gate(&vcs, "admit"))
        .unwrap()
    else {
        panic!("not applied")
    };
    assert_eq!(
        vcs.read("office", "colleague.txt").unwrap().as_deref(),
        Some("colleague result")
    );
    assert_eq!(receipt.cut.change_id, "office-noop");
}

#[test]
fn recorded_settlement_changed_resolution_memory_cannot_replace_prepared_candidate() {
    let mut vcs = setup();
    vcs.write(
        MAINLINE_BRANCH_ID,
        "patient.txt",
        Some("conflicting main result"),
        "main-3",
        "t5",
    )
    .unwrap();
    let key = crate::branches::ConflictRow::triple_key(
        Some(&crate::stable_hash_bytes_hex(b"baseline")),
        Some(&crate::stable_hash_bytes_hex(b"staff result")),
        Some(&crate::stable_hash_bytes_hex(b"conflicting main result")),
    );
    let first = vcs.content.put_text("first remembered resolution").unwrap();
    vcs.branches
        .record_resolution_memory(&key, &first, "t6")
        .unwrap();
    let prepared = prepare(&vcs);
    let second = vcs
        .content
        .put_text("changed remembered resolution")
        .unwrap();
    // Resolution memory is first-wins. Alter the stored row directly to
    // exercise changed native evidence rather than pretending retry replaces it.
    let db = rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).unwrap();
    assert_eq!(
        db.execute(
            "UPDATE resolution_memory SET resolution=?2 WHERE triple_key=?1",
            rusqlite::params![key, second]
        )
        .unwrap(),
        1
    );
    let before = vcs.branches.list_branches(None).unwrap();
    let result =
        vcs.apply_prepared_recorded_settlement(&prepared, &mut || Ok(()), &mut gate(&vcs, "admit"));
    assert!(
        matches!(result, Err(StoreError::Conflict(reason)) if reason=="prepared recorded settlement candidate changed")
    );
    assert_eq!(vcs.branches.list_branches(None).unwrap(), before);
    assert!(vcs.get_cut("settlement").unwrap().is_none());
}

#[test]
fn recorded_settlement_gate_cannot_substitute_an_operation_or_claim_staleness_after_commit() {
    for mode in ["tamper-op", "bad-stale"] {
        let vcs = setup();
        let prepared = prepare(&vcs);
        let result = vcs.apply_prepared_recorded_settlement(
            &prepared,
            &mut || Ok(()),
            &mut gate(&vcs, mode),
        );
        let expected = if mode == "tamper-op" {
            "recorded settlement differs from its original operation"
        } else {
            "recorded settlement gate reported stale after committing"
        };
        assert!(
            matches!(result, Err(StoreError::Conflict(reason)) if reason == expected),
            "{mode}"
        );
        // Native commit already happened: the error must not pretend rollback.
        assert!(vcs.get_cut("settlement").unwrap().is_some());
        assert!(vcs.get_op("op-settlement").unwrap().is_some());
    }
}

#[test]
fn recorded_settlement_holds_both_writers_at_the_first_transaction_access_check() {
    let vcs = setup();
    let prepared = prepare(&vcs);
    let calls = Cell::new(0);
    let result = vcs
        .apply_prepared_recorded_settlement(
            &prepared,
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() > 1 {
                    for path in &gate(&vcs, "admit").paths {
                        let independent = rusqlite::Connection::open(path).unwrap();
                        independent.busy_timeout(std::time::Duration::ZERO).unwrap();
                        assert!(
                            independent.execute_batch("BEGIN IMMEDIATE").is_err(),
                            "writer escaped before native mutation"
                        );
                    }
                }
                Ok(())
            },
            &mut gate(&vcs, "admit"),
        )
        .unwrap();
    assert!(matches!(result, RecordedSettlementOutcome::Applied(_)));
    assert_eq!(calls.get(), 4);
}

#[test]
fn recorded_settlement_repeated_gate_commit_or_lost_receipt_cannot_report_success() {
    for (mode, expected) in [
        ("twice", "recorded settlement gate invoked commit twice"),
        ("lost-cut", "recorded settlement cut unavailable"),
        ("lost-op", "recorded settlement operation unavailable"),
        ("lost-source", "recorded settlement source unavailable"),
        ("lost-target", "recorded settlement target unavailable"),
    ] {
        let vcs = setup();
        let prepared = prepare(&vcs);
        let result = vcs.apply_prepared_recorded_settlement(
            &prepared,
            &mut || Ok(()),
            &mut gate(&vcs, mode),
        );
        assert!(
            matches!(result, Err(StoreError::Conflict(reason)) if reason == expected),
            "{mode}"
        );
        // These faults happen after native commit, never claim rollback.
        assert!(vcs.get_op("op-settlement").unwrap().is_some() || mode == "lost-op");
    }
}

#[test]
fn recorded_settlement_disappearing_rows_roll_back_the_complete_transaction() {
    for branch in ["office", "main"] {
        let vcs = setup();
        let prepared = prepare(&vcs);
        let before = vcs.branches.list_branches(None).unwrap();
        let db = rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).unwrap();
        db.execute_batch(&format!("CREATE TRIGGER lost_merge_row AFTER UPDATE ON branches WHEN NEW.branch_id='{branch}' BEGIN DELETE FROM branches WHERE branch_id='{branch}'; END")).unwrap();
        let expected = if branch == "office" {
            "recorded settlement source disappeared"
        } else {
            "recorded settlement target disappeared"
        };
        let result = vcs.apply_prepared_recorded_settlement(
            &prepared,
            &mut || Ok(()),
            &mut gate(&vcs, "admit"),
        );
        assert!(
            matches!(result, Err(StoreError::Conflict(reason)) if reason == expected),
            "{branch}"
        );
        assert_eq!(vcs.branches.list_branches(None).unwrap(), before);
        assert!(vcs.get_cut("settlement").unwrap().is_none());
        assert!(vcs.get_op("op-settlement").unwrap().is_none());
    }
}

#[test]
fn recorded_settlement_recovery_requires_complete_original_cut_coordinates() {
    for change in ["cut", "coordinate"] {
        let vcs = setup();
        let prepared = prepare(&vcs);
        assert!(matches!(
            vcs.apply_prepared_recorded_settlement(
                &prepared,
                &mut || Ok(()),
                &mut gate(&vcs, "admit")
            )
            .unwrap(),
            RecordedSettlementOutcome::Applied(_)
        ));
        let db = rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).unwrap();
        let expected = if change == "cut" {
            assert_eq!(
                db.execute(
                    "UPDATE cuts SET change_id='substituted' WHERE cut_id='office-1'",
                    []
                )
                .unwrap(),
                1
            );
            "original recorded settlement recovery cut differs"
        } else {
            let mut op = vcs.get_op("op-settlement").unwrap().unwrap();
            op.deltas[1].before.as_mut().unwrap().head_manifest_hash = None;
            assert_eq!(
                db.execute(
                    "UPDATE ops SET deltas=?1 WHERE op_id='op-settlement'",
                    rusqlite::params![serde_json::to_string(&op.deltas).unwrap()]
                )
                .unwrap(),
                1
            );
            "original recorded settlement recovery coordinate is incomplete"
        };
        let result = vcs.recover_recorded_settlement(
            "office",
            "office-1",
            &[],
            "settlement",
            "staff:alice",
            "original-http-command",
            &mut || Ok(()),
        );
        assert!(
            matches!(result, Err(StoreError::Conflict(reason)) if reason == expected),
            "{change}"
        );
    }
}
