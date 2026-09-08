use super::conformance::{binding, context, seed, DRAFT};
use super::*;
use crate::branches::MAINLINE_BRANCH_ID;
use crate::vcs::NativeWorkspaceVcs;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "whip-save-recovery-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("fixture");
        Self(path)
    }
    fn open(&self) -> NativeWorkspaceVcs {
        NativeWorkspaceVcs::open(
            self.0.join("branches.sqlite"),
            self.0.join("content.sqlite"),
        )
        .expect("workspace")
    }
    fn branches(&self) -> Connection {
        Connection::open(self.0.join("branches.sqlite")).expect("branch fault connection")
    }
    fn content(&self) -> Connection {
        Connection::open(self.0.join("content.sqlite")).expect("content fault connection")
    }
    fn saved(
        &self,
    ) -> (
        VersionedSaveFileStore<crate::branches::BranchStore, crate::content::ContentStore>,
        RecoveredSave,
    ) {
        let mut workspace = self.open();
        seed(&mut workspace);
        let files = VersionedSaveFileStore::new(workspace, binding(DRAFT)).expect("binding");
        files
            .write_text_with_context(Path::new(SAVE_OUTPUT_PATH), DRAFT, context())
            .expect("save");
        let result = files
            .recover_result(&SaveAttempt::from(context()))
            .expect("recover")
            .expect("committed");
        (files, result)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn committed_save_result_survives_collection_and_reopen_but_not_explicit_erasure() {
    let fixture = Fixture::new();
    let (files, result) = fixture.saved();
    drop(files);
    let mut reopened = fixture.open();
    let orphan = reopened
        .content_store()
        .put("uncommitted candidate result")
        .expect("prepare orphan");
    reopened
        .write(
            MAINLINE_BRANCH_ID,
            "docs/test.txt",
            Some("later head"),
            "later",
            "t3",
        )
        .expect("advance");
    reopened.purge_unreachable("t3").expect("collect");
    assert!(reopened
        .content_store()
        .get(&orphan)
        .expect("orphan")
        .is_none());
    let attempt = SaveAttempt::from(context());
    let expected = SaveResultBinding::from(&binding(DRAFT));
    let recovered = read_committed_save(&reopened, &expected, &attempt)
        .expect("lookup after collection")
        .expect("retained");
    assert_eq!(recovered.receipt_json, result.receipt_json);
    assert_eq!(recovered.accepted_content, DRAFT);
    reopened
        .content_store()
        .erase(&result.reference.content_hash, "t4")
        .expect("erase result");
    assert!(read_committed_save(&reopened, &expected, &attempt)
        .expect_err("no invented reconstruction")
        .to_string()
        .contains("result content is unavailable or erased"));
    assert!(reopened
        .get_cut(&save_cut_id(&attempt.instance_id, &attempt.effect_id))
        .expect("cut")
        .is_some());
}

#[test]
fn recovery_refuses_every_broken_cut_result_link() {
    for fault in [
        "orphan-reference",
        "missing-reference",
        "wrong-label",
        "wrong-schema",
        "wrong-actor",
        "wrong-branch",
        "wrong-intent",
        "wrong-origin",
        "missing-operation",
        "wrong-operation",
        "wrong-digest",
        "wrong-binding",
        "conflict-receipt",
        "wrong-body-hash",
        "missing-body",
        "absent-path",
    ] {
        let fixture = Fixture::new();
        let (files, result) = fixture.saved();
        let attempt = SaveAttempt::from(context());
        let cut = save_cut_id(&attempt.instance_id, &attempt.effect_id);
        let connection = fixture.branches();
        let expected = match fault {
            "orphan-reference" => {
                connection
                    .execute("DELETE FROM cuts WHERE cut_id = ?1", [&cut])
                    .expect("fault");
                "reference has no committed cut"
            }
            "missing-reference" => {
                connection
                    .execute("DELETE FROM cut_evidence WHERE cut_id = ?1", [&cut])
                    .expect("fault");
                "result reference is unavailable"
            }
            "wrong-label" => {
                connection
                    .execute(
                        "UPDATE cut_evidence SET label_ref = 'elsewhere' WHERE cut_id = ?1",
                        [&cut],
                    )
                    .expect("fault");
                "does not bind the requested scope and attempt"
            }
            "wrong-schema" => {
                connection
                    .execute(
                        "UPDATE cut_evidence SET schema_ref = 'future' WHERE cut_id = ?1",
                        [&cut],
                    )
                    .expect("fault");
                "does not bind the requested scope and attempt"
            }
            "wrong-actor" => {
                connection
                    .execute("UPDATE cuts SET actor = 'other' WHERE cut_id = ?1", [&cut])
                    .expect("fault");
                "does not bind the requested scope and attempt"
            }
            "wrong-branch" => {
                connection
                    .execute(
                        "UPDATE cuts SET branch_id = 'other' WHERE cut_id = ?1",
                        [&cut],
                    )
                    .expect("fault");
                "does not bind the requested scope and attempt"
            }
            "wrong-intent" => {
                let mut other = attempt.clone();
                other.run_id = "other".into();
                connection
                    .execute(
                        "UPDATE cuts SET intent = ?1 WHERE cut_id = ?2",
                        params![serde_json::to_string(&other).expect("intent"), cut],
                    )
                    .expect("fault");
                "does not bind the requested scope and attempt"
            }
            "wrong-origin" => {
                connection
                    .execute(
                        "UPDATE cuts SET origin = 'write:other' WHERE cut_id = ?1",
                        [&cut],
                    )
                    .expect("fault");
                "does not bind the requested scope and attempt"
            }
            "missing-operation" => {
                connection
                    .execute("DELETE FROM ops WHERE op_id = ?1", [format!("op-{cut}")])
                    .expect("fault");
                "operation is unavailable"
            }
            "wrong-operation" => {
                connection
                    .execute(
                        "UPDATE ops SET kind = 'other' WHERE op_id = ?1",
                        [format!("op-{cut}")],
                    )
                    .expect("fault");
                "operation differs from its cut"
            }
            "wrong-digest" => {
                fixture
                    .content()
                    .execute(
                        "UPDATE content_blobs SET body = '{}' WHERE id = ?1",
                        [&result.reference.content_hash],
                    )
                    .expect("fault");
                "result content does not match its hash"
            }
            "absent-path" => {
                let empty = files
                    .workspace
                    .borrow()
                    .content_store()
                    .put("{}")
                    .expect("empty manifest");
                let op_id = format!("op-{cut}");
                let mut op = files
                    .workspace
                    .borrow()
                    .get_op(&op_id)
                    .expect("op")
                    .expect("committed op");
                op.deltas[0].after.head_manifest_hash = Some(empty.clone());
                connection
                    .execute(
                        "UPDATE cuts SET manifest_hash = ?1 WHERE cut_id = ?2",
                        params![empty, cut],
                    )
                    .expect("fault");
                connection
                    .execute(
                        "UPDATE ops SET deltas = ?1 WHERE op_id = ?2",
                        params![serde_json::to_string(&op.deltas).expect("deltas"), op_id],
                    )
                    .expect("fault");
                "committed save body is unavailable"
            }
            "missing-body" => {
                files
                    .workspace
                    .borrow()
                    .content_store()
                    .erase(&crate::stable_hash_hex(DRAFT), "t3")
                    .expect("erase accepted body");
                "save evidence content is unavailable or erased"
            }
            _ => {
                let mut receipt = result.receipt.clone();
                let diagnostic = match fault {
                    "wrong-binding" => {
                        receipt.base_cut_id = "other-base".into();
                        "differs from the immutable binding"
                    }
                    "conflict-receipt" => {
                        receipt.result = SaveResult::Conflicted {
                            head_cut_id: None,
                            head_content: None,
                            pieces: vec![],
                        };
                        "a conflict cannot be a committed save result"
                    }
                    _ => {
                        let SaveResult::Written {
                            accepted_content_hash,
                            ..
                        } = &mut receipt.result
                        else {
                            panic!("written");
                        };
                        *accepted_content_hash = "other".into();
                        "body differs from its recorded result"
                    }
                };
                let hash = files
                    .workspace
                    .borrow()
                    .content_store()
                    .put(&serde_json::to_string(&receipt).expect("changed receipt"))
                    .expect("store changed evidence");
                connection
                    .execute(
                        "UPDATE cut_evidence SET content_hash = ?1 WHERE cut_id = ?2",
                        params![hash, cut],
                    )
                    .expect("fault");
                diagnostic
            }
        };
        let error = files.recover_result(&attempt).expect_err(fault);
        assert!(error.to_string().contains(expected), "{fault}: {error}");
    }
}

#[test]
fn a_disappearing_commit_cannot_be_acknowledged_as_a_successful_save() {
    let fixture = Fixture::new();
    let mut workspace = fixture.open();
    seed(&mut workspace);
    // Deliberately violate the storage contract after its final insert. This
    // is a negative control for the post-commit observation, not a supported
    // database configuration or a claim to repair a corrupted database.
    fixture.branches().execute_batch("CREATE TRIGGER lose_commit AFTER INSERT ON cut_evidence BEGIN DELETE FROM cut_evidence WHERE cut_id = NEW.cut_id; DELETE FROM cuts WHERE cut_id = NEW.cut_id; END").expect("lost commit fault");
    let files = VersionedSaveFileStore::new(workspace, binding(DRAFT)).expect("binding");
    let failure = files
        .write_text_with_context(Path::new(SAVE_OUTPUT_PATH), DRAFT, context())
        .expect_err("no retained commit");
    assert!(failure
        .error
        .to_string()
        .contains("accepted save cut is unavailable"));
}

#[test]
fn recovery_requires_the_original_binding_and_attempt_and_preserves_legacy_limits() {
    let fixture = Fixture::new();
    let (files, _) = fixture.saved();
    let attempt = SaveAttempt::from(context());
    for field in [
        "branch",
        "path",
        "base",
        "draft",
        "principal",
        "label",
        "run",
        "event",
    ] {
        let mut expected = SaveResultBinding::from(&binding(DRAFT));
        let mut changed = attempt.clone();
        match field {
            "branch" => expected.branch_id = "other".into(),
            "path" => expected.path = "other".into(),
            "base" => expected.base_cut_id = "other".into(),
            "draft" => expected.draft_hash = "other".into(),
            "principal" => expected.executing_principal = "other".into(),
            "label" => expected.evidence_label = "other".into(),
            "run" => changed.run_id = "other".into(),
            _ => changed.started_event_id = "other".into(),
        }
        assert!(
            read_committed_save(&files.workspace.borrow(), &expected, &changed).is_err(),
            "{field}"
        );
    }
    let absent = SaveAttempt {
        effect_id: "never-dispatched".into(),
        ..attempt.clone()
    };
    assert!(files
        .recover_result(&absent)
        .expect("no cut observed")
        .is_none());
    let legacy = SaveAttempt {
        effect_id: "legacy".into(),
        ..attempt
    };
    files
        .workspace
        .borrow_mut()
        .write(
            MAINLINE_BRANCH_ID,
            "docs/test.txt",
            Some(DRAFT),
            &save_cut_id(&legacy.instance_id, &legacy.effect_id),
            "t2",
        )
        .expect("legacy write");
    assert!(files
        .recover_result(&legacy)
        .expect_err("legacy cut has no saved result")
        .to_string()
        .contains("result reference is unavailable"));
}
