use super::*;
use whipplescript_store::branches::{BranchStore, MAINLINE_BRANCH_ID};
use whipplescript_store::content::ContentStore;
use whipplescript_store::files::{FileStore, FileWriteContext};
use whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope;
use whipplescript_store::vcs_file_save::{
    read_committed_scoped_save, VersionedSaveBinding, VersionedSaveFileStore, SAVE_OUTPUT_PATH,
};

#[test]
fn absent_save_targets_cannot_supply_application_proof_to_either_reader() {
    for scoped in [false, true] {
        let mut workspace = WorkspaceVcs::from_parts(
            BranchStore::open(":memory:").expect("branches"),
            ContentStore::open(":memory:").expect("content"),
        );
        workspace.init("t0").expect("target");
        workspace
            .write(MAINLINE_BRANCH_ID, "test.txt", Some("base"), "base", "t0")
            .expect("base");
        let binding = VersionedSaveBinding {
            branch_id: MAINLINE_BRANCH_ID.into(),
            path: "test.txt".into(),
            base_cut_id: "base".into(),
            draft: "draft".into(),
            draft_hash: whipplescript_store::stable_hash_hex("draft"),
            input_label: "private".into(),
            executing_principal: "actor".into(),
            evidence_label: "private".into(),
            recorded_at: "t1".into(),
        };
        let scope =
            ResolutionMemoryScope::new("authority".into(), "test.txt".into(), "private".into())
                .expect("scope");
        let context = FileWriteContext {
            instance_id: "instance",
            effect_id: "save",
            run_id: "run",
            started_event_id: "started",
        };
        let attempt = SaveAttempt::from(context);
        let expected = SaveResultBinding::from(&binding);
        let absent = if scoped {
            read_committed_scoped_save(&workspace, &expected, &scope, &attempt)
                .expect("scoped read")
                .map(|saved| saved.receipt_json)
        } else {
            read_committed_save(&workspace, &expected, &attempt)
                .expect("legacy read")
                .map(|saved| saved.receipt_json)
        };
        let error = require_committed_target(absent)
            .expect_err("an absent target cannot settle a dispatch");
        assert!(format!("{error:?}").contains("versioned save target has no committed result"));
        let files = if scoped {
            VersionedSaveFileStore::new_in_resolution_scope(workspace, binding, scope)
        } else {
            VersionedSaveFileStore::new(workspace, binding)
        }
        .expect("adapter");
        let accepted = files
            .write_text_with_context(std::path::Path::new(SAVE_OUTPUT_PATH), "draft", context)
            .expect("commit");
        let actual = if scoped {
            files
                .recover_scoped_result(&attempt)
                .expect("scoped read")
                .map(|saved| saved.receipt_json)
        } else {
            files
                .recover_result(&attempt)
                .expect("legacy read")
                .map(|saved| saved.receipt_json)
        };
        assert_eq!(
            require_committed_target(actual).expect("original committed proof"),
            accepted.evidence.expect("committed receipt").content
        );
    }
}
