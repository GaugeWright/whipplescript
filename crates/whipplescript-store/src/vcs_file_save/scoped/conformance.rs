use super::*;
use crate::branches::MAINLINE_BRANCH_ID;
use crate::vcs::resolution_recording::conformance::resolution;

pub fn scope() -> ResolutionMemoryScope {
    ResolutionMemoryScope::new(
        "authority".into(),
        "resource/path".into(),
        "compartment".into(),
    )
    .expect("scope")
}

pub fn check<B: Branches, C: ContentBlobs>(mut make: impl FnMut() -> WorkspaceVcs<B, C>) {
    for mode in ["plain", "remembered", "missing", "foreign"] {
        let mut workspace = make();
        workspace.init("t0").expect("workspace");
        workspace.set_actor(Some("human".into()));
        workspace.set_intent(Some("human correction".into()));
        workspace
            .write(
                MAINLINE_BRANCH_ID,
                "docs/test.txt",
                Some("dog"),
                "base",
                "t0",
            )
            .expect("base");
        if mode != "plain" {
            workspace
                .write(
                    MAINLINE_BRANCH_ID,
                    "docs/test.txt",
                    Some("tiger"),
                    "head",
                    "t1",
                )
                .expect("head");
        }
        let knowledge_scope = if mode == "foreign" {
            ResolutionMemoryScope::new("authority".into(), "resource/path".into(), "private".into())
                .expect("other")
        } else {
            scope()
        };
        if mode != "missing" {
            workspace
                .record_region_resolutions_in_scope(
                    &knowledge_scope,
                    "original-human-resolution",
                    &[resolution("remembered correction")],
                    "t2",
                )
                .expect("knowledge");
        }
        let binding = super::super::conformance::binding("lion");
        let expected = SaveResultBinding::from(&binding);
        let attempt = SaveAttempt::from(super::super::conformance::context());
        let files = VersionedSaveFileStore::new_in_resolution_scope(workspace, binding, scope())
            .expect("adapter");
        let result = files.write_text_with_context(
            Path::new(SAVE_OUTPUT_PATH),
            "lion",
            super::super::conformance::context(),
        );
        let evidence = match mode {
            "plain" | "remembered" => result.expect("applied").evidence.expect("evidence"),
            _ => result
                .expect_err("unresolved")
                .evidence
                .expect("conflict evidence"),
        };
        assert_eq!(evidence.schema_ref, SCOPED_SAVE_RECEIPT_SCHEMA);
        let receipt: ScopedSaveReceipt =
            serde_json::from_str(&evidence.content).expect("strict receipt");
        receipt.validate().expect("consistent observations");
        assert_eq!(receipt.binding, expected);
        assert_eq!(receipt.resolution_scope, scope());
        assert_eq!(receipt.attempt, attempt);
        assert!(
            serde_json::from_str::<SaveReceipt>(&evidence.content).is_err(),
            "v1 cannot discard v2 constraints"
        );
        if mode == "plain" {
            assert!(matches!(receipt.result, SaveResult::Written { .. }));
            assert!(receipt.observations.is_empty());
        } else {
            assert!(!receipt.observations.is_empty(), "{mode}");
            let observed = &receipt.observations[0];
            if mode == "remembered" {
                assert_eq!(observed.payload_use, ResolutionPayloadUse::Applied);
                assert!(
                    matches!(&observed.observed, ResolutionObservation::Recorded { origin, .. }
                    if origin.operation_id == "original-human-resolution")
                );
                assert!(matches!(receipt.result, SaveResult::Merged { .. }));
            } else {
                assert_eq!(observed.payload_use, ResolutionPayloadUse::NotRead);
                assert_eq!(observed.observed, ResolutionObservation::Missing);
                assert!(matches!(receipt.result, SaveResult::Conflicted { .. }));
            }
        }
        assert!(
            files.recover_result(&attempt).is_err(),
            "legacy recovery must refuse scoped adapter"
        );
        let recovered = files
            .recover_scoped_result(&attempt)
            .expect("recovery query");
        if mode == "plain" || mode == "remembered" {
            let recovered = recovered.expect("committed original");
            assert_eq!(recovered.receipt, receipt);
            assert_eq!(recovered.receipt_json, evidence.content);
            assert_eq!(
                recovered.accepted_content,
                if mode == "plain" {
                    "lion"
                } else {
                    "remembered correction"
                }
            );
            let workspace = files.workspace.borrow();
            assert!(read_committed_save(&workspace, &expected, &attempt).is_err());
            for changed in [
                ResolutionMemoryScope::new(
                    "other".into(),
                    "resource/path".into(),
                    "compartment".into(),
                )
                .expect("changed scope"),
                ResolutionMemoryScope::new(
                    "authority".into(),
                    "other".into(),
                    "compartment".into(),
                )
                .expect("changed scope"),
                ResolutionMemoryScope::new(
                    "authority".into(),
                    "resource/path".into(),
                    "other".into(),
                )
                .expect("changed scope"),
            ] {
                assert!(
                    read_committed_scoped_save(&workspace, &expected, &changed, &attempt).is_err()
                );
            }
            let mut wrong = expected.clone();
            wrong.evidence_label = "other".into();
            assert!(read_committed_scoped_save(&workspace, &wrong, &scope(), &attempt).is_err());
        } else {
            assert!(
                recovered.is_none(),
                "conflict cannot invent a committed cut"
            );
        }
    }
    for scoped in [false, true] {
        let mut workspace = make();
        super::super::conformance::seed(&mut workspace);
        let mut binding = super::super::conformance::binding(super::super::conformance::DRAFT);
        binding.branch_id = "missing-branch".into();
        let files = if scoped {
            VersionedSaveFileStore::new_in_resolution_scope(workspace, binding, scope())
        } else {
            VersionedSaveFileStore::new(workspace, binding)
        }
        .expect("confined descriptor");
        let failure = files
            .write_text_with_context(
                Path::new(SAVE_OUTPUT_PATH),
                super::super::conformance::DRAFT,
                super::super::conformance::context(),
            )
            .expect_err("a missing branch cannot acknowledge a save");
        assert!(failure
            .error
            .to_string()
            .contains("versioned save refused: BranchMissing"));
        assert!(
            failure.evidence.is_none(),
            "no fabricated saved or conflict receipt"
        );
        let context = super::super::conformance::context();
        assert!(files
            .workspace
            .borrow()
            .get_cut(&save_cut_id(context.instance_id, context.effect_id))
            .expect("cut lookup")
            .is_none());
    }
    let mut workspace = make();
    super::super::conformance::seed(&mut workspace);
    let files = VersionedSaveFileStore::new(
        workspace,
        super::super::conformance::binding(super::super::conformance::DRAFT),
    )
    .expect("legacy binding");
    assert!(files
        .recover_scoped_result(&SaveAttempt::from(super::super::conformance::context()))
        .is_err());
}
