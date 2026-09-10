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
