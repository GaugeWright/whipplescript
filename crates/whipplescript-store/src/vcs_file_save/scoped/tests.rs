use super::*;

#[test]
fn scoped_save_receipt_codec_preserves_constraints() {
    let mut receipt = ScopedSaveReceipt {
        protocol: SCOPED_SAVE_RECEIPT_SCHEMA.into(),
        binding: SaveResultBinding::from(&super::super::conformance::binding("draft")),
        attempt: SaveAttempt::from(super::super::conformance::context()),
        result: SaveResult::Conflicted {
            head_cut_id: None,
            head_content: None,
            pieces: vec![],
        },
        resolution_scope: conformance::scope(),
        observations: vec![ResolutionLookup {
            triple_key: "rks1|fixture".into(),
            observed: ResolutionObservation::Missing,
            payload_use: ResolutionPayloadUse::NotRead,
        }],
    };
    receipt.validate().unwrap();
    let value = serde_json::to_value(&receipt).unwrap();
    for pointer in [
        "",
        "/binding",
        "/attempt",
        "/result",
        "/resolution_scope",
        "/observations/0",
        "/observations/0/observed",
    ] {
        let mut changed = value.clone();
        changed
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("new_constraint".into(), true.into());
        assert!(
            serde_json::from_value::<ScopedSaveReceipt>(changed).is_err(),
            "{pointer}"
        );
    }
    for field in ["authority", "resource", "compartment"] {
        let mut changed = value.clone();
        changed["resolution_scope"][field] = " ".into();
        assert!(serde_json::from_value::<ScopedSaveReceipt>(changed).is_err());
    }
    receipt.protocol = SAVE_RECEIPT_SCHEMA.into();
    assert!(receipt.validate().is_err());
    receipt.protocol = SCOPED_SAVE_RECEIPT_SCHEMA.into();
    for use_ in [
        ResolutionPayloadUse::Applied,
        ResolutionPayloadUse::Unavailable,
        ResolutionPayloadUse::NonText,
    ] {
        receipt.observations[0].payload_use = use_;
        assert!(receipt.validate().is_err());
    }
    receipt.observations[0].payload_use = ResolutionPayloadUse::NotRead;
    receipt.result = SaveResult::Written {
        cut_id: "cut".into(),
        parent_cut_id: None,
        operation_id: "op-cut".into(),
        accepted_content_hash: "hash".into(),
    };
    assert!(receipt.validate().is_err());
}

#[cfg(feature = "native")]
#[test]
fn native_scoped_save_adapter_preserves_original_evidence() {
    conformance::check(|| {
        WorkspaceVcs::from_parts(
            crate::branches::BranchStore::open_in_memory().unwrap(),
            crate::content::ContentStore::open(":memory:").unwrap(),
        )
    });
}

#[test]
fn scoped_save_builder_refuses_a_different_candidate_scope() {
    use crate::vcs::{SaveCommitPlan, SaveResultEvidenceBuilder};
    let binding = super::super::conformance::binding("draft");
    let attempt = SaveAttempt::from(super::super::conformance::context());
    let scope = conformance::scope();
    let other =
        ResolutionMemoryScope::new("other".into(), "resource/path".into(), "compartment".into())
            .unwrap();
    let builder = recovery::SaveEvidenceBuilder {
        binding: &binding,
        attempt: &attempt,
        resolution_scope: Some(&scope),
    };
    let mut plan = SaveCommitPlan {
        branch_id: &binding.branch_id,
        path: &binding.path,
        base_cut_id: &binding.base_cut_id,
        parent_cut_id: Some(&binding.base_cut_id),
        cut_id: "candidate",
        draft: &binding.draft,
        accepted: &binding.draft,
        pieces: None,
        resolution_scope: Some(&scope),
        resolution_observations: &[],
    };
    builder.prepare(&plan).expect("actual bound candidate");
    for changed in [None, Some(&other)] {
        plan.resolution_scope = changed;
        let error = builder
            .prepare(&plan)
            .expect_err("cannot mislabel a candidate's knowledge scope");
        assert!(
            matches!(error, crate::StoreError::Conflict(ref message) if message.contains("scope"))
        );
    }
}

#[cfg(feature = "native")]
#[test]
fn scoped_save_authorizes_exact_versions_before_reading_their_bodies() {
    use crate::content::{ContentBlobs, ContentStore};
    use crate::{StoreError, StoreResult};
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};
    struct ObservedContent {
        inner: ContentStore,
        reads: Arc<Mutex<BTreeSet<String>>>,
    }
    impl ContentBlobs for ObservedContent {
        fn put(&self, bytes: &[u8]) -> StoreResult<String> {
            self.inner.put(bytes)
        }
        fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
            self.reads.lock().unwrap().insert(id.into());
            self.inner.get(id)
        }
        fn cached_read_available(&self, id: &str) -> StoreResult<bool> {
            self.inner.cached_read_available(id)
        }
        fn publish_retained<T>(
            &self,
            ids: &[String],
            publish: impl FnOnce() -> StoreResult<T>,
        ) -> StoreResult<T> {
            self.inner.publish_retained(ids, publish)
        }
    }
    crate::content::conformance::run_suite(|| ObservedContent {
        inner: ContentStore::open(":memory:").unwrap(),
        reads: Arc::new(Mutex::new(BTreeSet::new())),
    })
    .expect("the read observer preserves the content-store contract");
    for refused_cut in [None, Some("base"), Some("head")] {
        let reads = Arc::new(Mutex::new(BTreeSet::new()));
        let content = ObservedContent {
            inner: ContentStore::open(":memory:").unwrap(),
            reads: reads.clone(),
        };
        let mut workspace = WorkspaceVcs::from_parts(
            crate::branches::BranchStore::open_in_memory().unwrap(),
            content,
        );
        workspace.init("t0").unwrap();
        workspace
            .write("main", "docs/test.txt", Some("private base"), "base", "t1")
            .unwrap();
        if refused_cut == Some("head") {
            workspace
                .write("main", "docs/test.txt", Some("private head"), "head", "t2")
                .unwrap();
        }
        reads.lock().unwrap().clear();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let checks = observed.clone();
        let files = VersionedSaveFileStore::new_in_resolution_scope(
            workspace,
            super::super::conformance::binding("draft"),
            conformance::scope(),
            Arc::new(move |branch: &str, path: &str, cut: &str| {
                checks
                    .lock()
                    .unwrap()
                    .push((branch.to_owned(), path.to_owned(), cut.to_owned()));
                if Some(cut) == refused_cut {
                    return Err(StoreError::Conflict("retained version refused".into()));
                }
                Ok(())
            }),
        )
        .unwrap();
        let result = files.write_text_with_context(
            Path::new(SAVE_OUTPUT_PATH),
            "draft",
            super::super::conformance::context(),
        );
        if let Some(cut) = refused_cut {
            let failure = result.expect_err("refused input must not be read or committed");
            assert!(failure
                .error
                .to_string()
                .contains("retained version refused"));
            assert!(failure.evidence.is_none());
            let body = if cut == "base" {
                "private base"
            } else {
                "private head"
            };
            assert!(
                !reads
                    .lock()
                    .unwrap()
                    .contains(&crate::stable_hash_hex(body)),
                "denied body was read"
            );
            let workspace = files.workspace.borrow();
            let context = super::super::conformance::context();
            assert!(workspace
                .get_cut(&save_cut_id(context.instance_id, context.effect_id))
                .unwrap()
                .is_none());
        } else {
            result.expect("authorized versions remain writable");
            assert!(reads
                .lock()
                .unwrap()
                .contains(&crate::stable_hash_hex("private base")));
        }
        let checks = observed.lock().unwrap();
        assert!(!checks.is_empty());
        assert!(checks
            .iter()
            .all(|(branch, path, _)| branch == "main" && path == "docs/test.txt"));
    }
}

#[cfg(feature = "native")]
#[test]
fn scoped_save_reauthorizes_a_head_that_wins_the_first_cas_race() {
    use crate::content::{ContentBlobs, ContentStore};
    use crate::{StoreError, StoreResult};
    use std::sync::atomic::{AtomicBool, Ordering};
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = Scratch(crate::scratch::path("whipple-save-authority-race"));
    std::fs::create_dir(&dir.0).unwrap();
    let branches = dir.0.join("branches.sqlite");
    let content = dir.0.join("content.sqlite");
    let mut workspace = WorkspaceVcs::open(&branches, &content).unwrap();
    workspace.init("t0").unwrap();
    workspace
        .write("main", "docs/test.txt", Some("base"), "base", "t1")
        .unwrap();
    let raced = AtomicBool::new(false);
    let authorize = |branch: &str, path: &str, cut: &str| -> StoreResult<()> {
        assert_eq!((branch, path), ("main", "docs/test.txt"));
        // Fault injection: another connection wins after this candidate has
        // captured its head. The next candidate must authorize that new head.
        if !raced.swap(true, Ordering::SeqCst) {
            let mut competitor = WorkspaceVcs::open(&branches, &content).unwrap();
            competitor
                .write("main", path, Some("private head"), "competitor", "t2")
                .unwrap();
            // A read before authorization now gives an erasure error, so a
            // late check cannot accidentally satisfy the intended assertion.
            ContentStore::open(&content)
                .unwrap()
                .erase(&crate::stable_hash_hex("private head"), "t3")
                .unwrap();
        }
        if cut == "competitor" {
            return Err(StoreError::Conflict(
                "new head authorization refused".into(),
            ));
        }
        Ok(())
    };
    let error = workspace
        .save_with_authorized_versions_in_resolution_scope(
            &conformance::scope(),
            "main",
            "docs/test.txt",
            "draft",
            "base",
            "saved",
            "t4",
            None,
            &authorize,
        )
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("new head authorization refused"),
        "{error:?}"
    );
    assert!(workspace.get_cut("saved").unwrap().is_none());
    assert_eq!(
        workspace
            .get_branch("main")
            .unwrap()
            .unwrap()
            .head_cut_id
            .as_deref(),
        Some("competitor")
    );
}
