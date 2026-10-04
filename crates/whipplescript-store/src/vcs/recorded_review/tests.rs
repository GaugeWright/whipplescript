use super::*;
use crate::vcs::tests::vcs;
use std::cell::Cell;

fn setup() -> crate::vcs::tests::TempVcs {
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
    vcs
}

#[test]
fn recorded_review_preserves_native_probe_and_writes_nothing() {
    let vcs = setup();
    let before = vcs.branches.list_branches(None).unwrap();
    let calls = Cell::new(0);
    let result = vcs
        .publish_recorded_merge_review(
            "office",
            "office-1",
            &[],
            &mut || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            |review, _| {
                assert_eq!(review.head_cut_id, "office-1");
                assert_eq!(review.target_cut_id.as_deref(), Some("main-1"));
                assert_eq!(review.branch_point_cut_id.as_deref(), Some("main-1"));
                assert_eq!(
                    review.outcome,
                    RecordedMergeOutcome::Clean {
                        changed_paths: vec!["patient.txt".into()]
                    }
                );
                assert_eq!(review.diff.len(), 1);
                assert!(!review.diff[0].payload_unavailable);
                Ok("published")
            },
        )
        .unwrap();
    assert_eq!(result, "published");
    assert_eq!(calls.get(), 3);
    assert_eq!(vcs.branches.list_branches(None).unwrap(), before);
}

#[test]
fn recorded_review_holds_both_actual_native_writers_through_publication() {
    let vcs = setup();
    vcs.publish_recorded_merge_review("office", "office-1", &[], &mut || Ok(()), |_, _| {
        for name in ["branches.sqlite", "content.sqlite"] {
            let independent = rusqlite::Connection::open(vcs.dir.join(name)).unwrap();
            independent.busy_timeout(std::time::Duration::ZERO).unwrap();
            assert!(
                independent.execute_batch("BEGIN IMMEDIATE").is_err(),
                "{name} writer escaped"
            );
        }
        Ok(())
    })
    .unwrap();
}

#[test]
fn recorded_review_original_authority_refuses_before_observation_and_publication() {
    for denied_call in 1..=3 {
        let vcs = setup();
        let calls = Cell::new(0);
        let published = Cell::new(false);
        let result = vcs.publish_recorded_merge_review(
            "office",
            "office-1",
            &[],
            &mut || {
                calls.set(calls.get() + 1);
                if calls.get() == denied_call {
                    Err(StoreError::Conflict("original authority ended".into()))
                } else {
                    Ok(())
                }
            },
            |_, _| {
                published.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!published.get());
    }
}

#[test]
fn recorded_review_missing_unchanged_payload_or_original_evidence_cannot_publish() {
    for original in [false, true] {
        let vcs = setup();
        let retained = if original {
            vec!["missing-original-descriptor".into()]
        } else {
            let id = vcs.cut_manifest("main-1").unwrap().unwrap()["patient.txt"].clone();
            vcs.content.erase(&id, "t4").unwrap();
            vec![]
        };
        let result: StoreResult<()> = vcs.publish_recorded_merge_review(
            "office",
            "office-1",
            &retained,
            &mut || Ok(()),
            |_, _| panic!("unavailable evidence published"),
        );
        assert!(result.is_err());
    }
}

#[test]
fn recorded_review_opens_only_current_existing_authorities() {
    let vcs = setup();
    let branches = vcs.dir.join("branches.sqlite");
    let content = vcs.dir.join("content.sqlite");
    NativeWorkspaceVcs::open_for_recorded_review(&branches, &content).unwrap();
    let missing = vcs.dir.join("missing.sqlite");
    assert!(NativeWorkspaceVcs::open_for_recorded_review(&missing, &content).is_err());
    assert!(!missing.exists());
    let db = rusqlite::Connection::open(&branches).unwrap();
    db.execute("DELETE FROM schema_migrations", []).unwrap();
    assert!(matches!(
        NativeWorkspaceVcs::open_for_recorded_review(&branches, &content),
        Err(StoreError::UnsupportedVersion { .. })
    ));
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn recorded_review_readonly_branch_snapshot_is_not_a_writer_fence() {
    let vcs = setup();
    let reader = NativeWorkspaceVcs::from_parts(
        BranchStore::open_read_only(vcs.dir.join("branches.sqlite")).unwrap(),
        ContentStore::open_for_retained_publication(vcs.dir.join("content.sqlite")).unwrap(),
    );
    let result: StoreResult<()> =
        reader.publish_recorded_merge_review("office", "office-1", &[], &mut || Ok(()), |_, _| {
            panic!("read-only branch published")
        });
    assert!(matches!(result, Err(StoreError::Conflict(reason))
        if reason == "recorded review requires a writable branch authority"));
}

fn blob_count(vcs: &crate::vcs::tests::TempVcs) -> i64 {
    rusqlite::Connection::open(vcs.dir.join("content.sqlite"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM content_blobs", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn recorded_review_reuses_text_source_and_resolution_refinement_without_preparation() {
    struct Certified;
    impl SourceMerger for Certified {
        fn merge_source(&self, _: Option<&str>, _: &str, _: &str) -> SourceMergeVerdict {
            SourceMergeVerdict::Certified {
                merged: "certified composed source".into(),
            }
        }
    }
    for case in ["text", "source", "conflict", "remembered", "erased-memory"] {
        let mut vcs = vcs();
        vcs.init("t0").unwrap();
        let path = if case == "source" {
            "draft.whip"
        } else {
            "draft.txt"
        };
        let base = "The quick brown fox jumps over the lazy dog tonight.";
        let ours = "The swift brown fox jumps over the lazy dog tonight.";
        let theirs = if case == "text" {
            "The quick brown fox jumps over the lazy cat tonight."
        } else {
            "The speedy brown fox jumps over the lazy dog tonight."
        };
        vcs.write(MAINLINE_BRANCH_ID, path, Some(base), "base", "t1")
            .unwrap();
        vcs.create_branch("office", None, MAINLINE_BRANCH_ID, "t2")
            .unwrap();
        vcs.write("office", path, Some(ours), "result", "t3")
            .unwrap();
        vcs.write(MAINLINE_BRANCH_ID, path, Some(theirs), "target", "t4")
            .unwrap();
        if case == "source" {
            vcs.set_source_merger(Box::new(Certified));
        }
        if case == "remembered" || case == "erased-memory" {
            let payload = vcs.content.put_text("remembered resolution").unwrap();
            let key = crate::branches::ConflictRow::triple_key(
                Some(&crate::stable_hash_bytes_hex(base.as_bytes())),
                Some(&crate::stable_hash_bytes_hex(ours.as_bytes())),
                Some(&crate::stable_hash_bytes_hex(theirs.as_bytes())),
            );
            vcs.branches
                .record_resolution_memory(&key, &payload, "t5")
                .unwrap();
            if case == "erased-memory" {
                vcs.content.erase(&payload, "t6").unwrap();
            }
        }
        let before = blob_count(&vcs);
        let review = vcs
            .publish_recorded_merge_review("office", "result", &[], &mut || Ok(()), |review, _| {
                Ok(review.clone())
            })
            .unwrap();
        assert_eq!(blob_count(&vcs), before, "{case} wrote candidate content");
        let legacy = vcs.merge_probe("office").unwrap();
        match (review.outcome, legacy) {
            (
                RecordedMergeOutcome::Clean { changed_paths },
                MergeProbeOutcome::Clean {
                    changed_paths: expected,
                    ..
                },
            ) => {
                assert_eq!(changed_paths, expected);
                assert!(matches!(case, "text" | "source" | "remembered"));
            }
            (
                RecordedMergeOutcome::Conflicted { conflicts },
                MergeProbeOutcome::Conflicted {
                    conflicts: expected,
                },
            ) => {
                assert_eq!(conflicts, expected);
                assert!(matches!(case, "conflict" | "erased-memory"));
            }
            other => panic!("{case}: review changed native outcome: {other:?}"),
        }
    }
}

#[test]
fn recorded_review_refuses_missing_or_corrupt_coordinates() {
    let mutations = [
        (
            "DELETE FROM branches WHERE branch_id = 'office'",
            "recorded review branch unavailable",
        ),
        (
            "UPDATE branches SET parent_branch_id = NULL WHERE branch_id = 'office'",
            "recorded review parent unavailable",
        ),
        (
            "UPDATE branches SET status = 'discarded' WHERE branch_id = 'office'",
            "recorded review requires the active original head and parent",
        ),
        (
            "UPDATE branches SET status = 'discarded' WHERE branch_id = 'main'",
            "recorded review requires the active original head and parent",
        ),
        (
            "UPDATE branches SET head_cut_id = 'different' WHERE branch_id = 'office'",
            "recorded review requires the active original head and parent",
        ),
        (
            "DELETE FROM cuts WHERE cut_id = 'main-1'",
            "recorded review cut unavailable",
        ),
        (
            "UPDATE cuts SET manifest_hash = 'substituted' WHERE cut_id = 'office-1'",
            "recorded review head differs from its cut",
        ),
        (
            "UPDATE branches SET head_manifest_hash = NULL WHERE branch_id = 'office'",
            "recorded review coordinate is incomplete",
        ),
    ];
    for (mutation, expected) in mutations {
        let vcs = setup();
        let db = rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).unwrap();
        assert_eq!(
            db.execute(mutation, []).unwrap(),
            1,
            "mutation missed its target"
        );
        let result: StoreResult<()> =
            vcs.publish_recorded_merge_review("office", "office-1", &[], &mut || Ok(()), |_, _| {
                panic!("corrupt coordinates published: {mutation}")
            });
        assert!(
            matches!(result, Err(StoreError::Conflict(reason)) if reason == expected),
            "{mutation}"
        );
    }
}

#[test]
fn recorded_review_refuses_changes_between_capture_and_both_fences() {
    for mutation in [
        "UPDATE branches SET updated_at = 'different' WHERE branch_id = 'office'",
        "UPDATE branches SET updated_at = 'different' WHERE branch_id = 'main'",
        "UPDATE cuts SET actor = 'substituted' WHERE cut_id = 'office-1'",
        "DELETE FROM cuts WHERE cut_id = 'main-1'",
    ] {
        let vcs = setup();
        let inputs = vcs
            .capture_recorded_merge_inputs("office", "office-1", &[])
            .unwrap();
        let db = rusqlite::Connection::open(vcs.dir.join("branches.sqlite")).unwrap();
        assert_eq!(
            db.execute(mutation, []).unwrap(),
            1,
            "mutation did not exercise its target"
        );
        let result: StoreResult<()> =
            vcs.publish_recorded_merge_inputs(inputs, Some(&mut || Ok(())), |_, _| {
                panic!("changed original inputs published: {mutation}")
            });
        assert!(matches!(result, Err(StoreError::Conflict(reason))
            if reason == "recorded review inputs changed before publication"));
    }
}

#[test]
fn recorded_review_retains_unchanged_comparison_payloads_and_rollback_releases_fences() {
    let mut vcs = setup();
    vcs.write(
        MAINLINE_BRANCH_ID,
        "unchanged.txt",
        Some("target only data"),
        "main-2",
        "t4",
    )
    .unwrap();
    let inputs = vcs
        .capture_recorded_merge_inputs("office", "office-1", &[])
        .unwrap();
    let id = vcs.cut_manifest("main-2").unwrap().unwrap()["unchanged.txt"].clone();
    vcs.content.erase(&id, "t5").unwrap();
    let result: StoreResult<()> =
        vcs.publish_recorded_merge_inputs(inputs, Some(&mut || Ok(())), |_, _| {
            panic!("unavailable unchanged comparison input published")
        });
    assert!(result.is_err());
    let ready = setup();
    let result: StoreResult<()> =
        ready.publish_recorded_merge_review("office", "office-1", &[], &mut || Ok(()), |_, _| {
            Err(StoreError::Conflict("product publication refused".into()))
        });
    assert!(
        matches!(result, Err(StoreError::Conflict(reason)) if reason == "product publication refused")
    );
    for name in ["branches.sqlite", "content.sqlite"] {
        let independent = rusqlite::Connection::open(ready.dir.join(name)).unwrap();
        independent.busy_timeout(std::time::Duration::ZERO).unwrap();
        independent
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .unwrap();
    }
}

#[test]
fn recorded_review_reports_converged_content_and_an_empty_recorded_parent() {
    let mut vcs = setup();
    vcs.write(
        MAINLINE_BRANCH_ID,
        "patient.txt",
        Some("staff result"),
        "main-2",
        "t4",
    )
    .unwrap();
    vcs.publish_recorded_merge_review("office", "office-1", &[], &mut || Ok(()), |review, _| {
        assert_eq!(review.outcome, RecordedMergeOutcome::UpToDate);
        assert!(review.diff.is_empty());
        Ok(())
    })
    .unwrap();
    let mut empty = crate::vcs::tests::vcs();
    empty.init("t0").unwrap();
    empty
        .create_branch("office", None, MAINLINE_BRANCH_ID, "t1")
        .unwrap();
    empty
        .write(
            "office",
            "patient.txt",
            Some("first result"),
            "office-1",
            "t2",
        )
        .unwrap();
    empty
        .publish_recorded_merge_review("office", "office-1", &[], &mut || Ok(()), |review, _| {
            assert!(review.target_cut_id.is_none());
            assert!(review.branch_point_cut_id.is_none());
            assert!(matches!(review.outcome, RecordedMergeOutcome::Clean { .. }));
            Ok(())
        })
        .unwrap();
}

#[test]
fn prepared_recorded_review_publishes_after_borrowed_check_ends() {
    struct OriginalProductWriter {
        checked: Cell<bool>,
    }
    impl OriginalProductWriter {
        fn check(&self) -> StoreResult<()> {
            self.checked.set(true);
            Ok(())
        }
        fn commit(self) -> StoreResult<()> {
            assert!(self.checked.get());
            Ok(())
        }
    }
    let vcs = setup();
    let original = OriginalProductWriter {
        checked: Cell::new(false),
    };
    let prepared = vcs
        .prepare_recorded_merge_review("office", "office-1", &[], &mut || original.check())
        .unwrap();
    vcs.publish_prepared_recorded_merge_review(&prepared, |review, _| {
        assert_eq!(review, prepared.review());
        original.commit()
    })
    .unwrap();
}

#[test]
fn prepared_recorded_review_cannot_replace_its_original_judgment() {
    let mut vcs = setup();
    vcs.write(
        MAINLINE_BRANCH_ID,
        "patient.txt",
        Some("conflicting main result"),
        "main-2",
        "t4",
    )
    .unwrap();
    let prepared = vcs
        .prepare_recorded_merge_review("office", "office-1", &[], &mut || Ok(()))
        .unwrap();
    assert!(matches!(
        prepared.review().outcome,
        RecordedMergeOutcome::Conflicted { .. }
    ));
    let key = crate::branches::ConflictRow::triple_key(
        Some(&crate::stable_hash_bytes_hex(b"baseline")),
        Some(&crate::stable_hash_bytes_hex(b"staff result")),
        Some(&crate::stable_hash_bytes_hex(b"conflicting main result")),
    );
    let payload = vcs.content.put_text("later remembered resolution").unwrap();
    vcs.branches
        .record_resolution_memory(&key, &payload, "t5")
        .unwrap();
    let result: StoreResult<()> = vcs.publish_prepared_recorded_merge_review(&prepared, |_, _| {
        panic!("changed prepared review published")
    });
    assert!(matches!(result, Err(StoreError::Conflict(reason))
        if reason == "prepared recorded merge review changed before publication"));
}
