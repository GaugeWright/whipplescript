use super::*;
use crate::branches::MAINLINE_BRANCH_ID;
use crate::content::ContentStore;
use crate::text_merge::{MergePiece, TextMergeConfig, TextMergeOutcome};
use crate::vcs::NativeWorkspaceVcs;
use std::cell::RefCell;

struct Directory(std::path::PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn fixture() -> (Directory, NativeWorkspaceVcs) {
    let root = std::env::temp_dir().join(format!(
        "resolution-observations-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("fixture root");
    let mut vcs =
        NativeWorkspaceVcs::open(root.join("branches.sqlite"), root.join("content.sqlite"))
            .expect("workspace");
    vcs.init("t0").expect("init");
    vcs.set_actor(Some("human".into()));
    vcs.set_intent(Some("knowledge".into()));
    (Directory(root), vcs)
}
fn scope() -> ResolutionMemoryScope {
    ResolutionMemoryScope::new("issuer".into(), "target".into(), "compartment".into())
        .expect("scope")
}

/// Deliberately inject a concurrent event during result preparation. A real
/// builder is pure; this fixture schedules the race at the exact candidate.
struct Race {
    fire: RefCell<Option<Box<dyn FnOnce()>>>,
    candidates: RefCell<Vec<serde_json::Value>>,
}
impl SaveResultEvidenceBuilder for Race {
    fn prepare(
        &self,
        plan: &crate::vcs::SaveCommitPlan<'_>,
    ) -> StoreResult<crate::files::FileWriteEvidence> {
        self.candidates
            .borrow_mut()
            .push(serde_json::to_value(plan.resolution_observations)?);
        if let Some(fire) = self.fire.borrow_mut().take() {
            fire();
        }
        conformance::Evidence.prepare(plan)
    }
}

#[cfg(test)]
#[test]
fn resolution_observations_belong_only_to_the_winning_save_candidate() {
    let (dir, mut vcs) = fixture();
    let scope = scope();
    let first = crate::vcs::resolution_recording::conformance::resolution("first remembered value");
    let second = RegionResolution {
        ours_text: "panther".into(),
        resolution_text: "second remembered value".into(),
        ..first.clone()
    };
    vcs.record_region_resolutions_in_scope(&scope, "first-origin", &[first], "t1")
        .expect("first knowledge");
    vcs.record_region_resolutions_in_scope(&scope, "second-origin", &[second], "t2")
        .expect("second knowledge");
    vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some("dog"), "base", "t3")
        .expect("base");
    vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some("tiger"), "head", "t4")
        .expect("head");
    let mut competitor =
        NativeWorkspaceVcs::open(dir.0.join("branches.sqlite"), dir.0.join("content.sqlite"))
            .expect("competing connection");
    let builder = Race {
        fire: RefCell::new(Some(Box::new(move || {
            competitor
                .write(MAINLINE_BRANCH_ID, "a.txt", Some("panther"), "raced", "t5")
                .expect("move head");
        }))),
        candidates: RefCell::new(Vec::new()),
    };
    let saved = vcs
        .save_with_base_in_resolution_scope(
            &scope,
            MAINLINE_BRANCH_ID,
            "a.txt",
            "lion",
            "base",
            "save",
            "t6",
            Some(&builder),
        )
        .expect("save after race");
    assert_eq!(builder.candidates.borrow().len(), 2);
    assert_eq!(
        saved.observations.len(),
        1,
        "discarded candidate cannot contaminate winning evidence"
    );
    assert_eq!(
        serde_json::to_value(&saved.observations).expect("snapshot"),
        builder.candidates.borrow()[1]
    );
    assert_eq!(
        serde_json::to_value(&saved.observations).expect("snapshot")[0]["observed"]["origin"]
            ["operation_id"],
        "second-origin"
    );
    assert!(
        matches!(saved.outcome, SaveWithBaseOutcome::Merged { ref merged, .. } if merged == "second remembered value")
    );
    let reference = vcs
        .write_evidence("save")
        .expect("reference")
        .expect("committed evidence");
    let body = vcs
        .content_store()
        .get_text(&reference.content_hash)
        .expect("read")
        .text()
        .expect("text");
    let evidence: serde_json::Value = serde_json::from_str(&body).expect("result");
    assert_eq!(evidence["observations"], builder.candidates.borrow()[1]);
    assert_eq!(evidence["parent"], "raced");
}

#[cfg(test)]
#[test]
fn resolution_input_erased_before_publication_cannot_enter_a_saved_cut() {
    let (dir, mut vcs) = fixture();
    let scope = scope();
    let prefix = (0..30).map(|n| format!("prefix{n} ")).collect::<String>();
    let suffix = (0..30).map(|n| format!(" suffix{n}")).collect::<String>();
    let base = format!("{prefix}dog{suffix}");
    let head = format!("{prefix}tiger{suffix}");
    let draft = format!("{prefix}lion{suffix}");
    let TextMergeOutcome::Conflicted { pieces } =
        crate::text_merge::text_merge(&base, &head, &draft, &TextMergeConfig::from_env())
    else {
        panic!("fixture must conflict")
    };
    assert!(
        pieces
            .iter()
            .any(|piece| matches!(piece, MergePiece::Merged { .. })),
        "fixture needs unchanged surrounding text"
    );
    let resolutions: Vec<_> = pieces
        .iter()
        .filter_map(|piece| match piece {
            MergePiece::Conflict {
                base_text,
                ours_text,
                theirs_text,
            } => Some(RegionResolution {
                base_text: base_text.clone(),
                ours_text: ours_text.clone(),
                theirs_text: theirs_text.clone(),
                resolution_text: "remembered-region".into(),
            }),
            _ => None,
        })
        .collect();
    let receipt = vcs
        .record_region_resolutions_in_scope(&scope, "origin", &resolutions, "t1")
        .expect("remember");
    let id = receipt.outcomes[0].resolution.clone();
    vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some(&base), "base", "t2")
        .expect("base");
    vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some(&head), "head", "t3")
        .expect("head");
    let eraser = ContentStore::open(dir.0.join("content.sqlite")).expect("erasing connection");
    let builder = Race {
        fire: RefCell::new(Some(Box::new(move || {
            eraser.erase(&id, "t4").expect("erase input before commit");
        }))),
        candidates: RefCell::new(Vec::new()),
    };
    let outcome = vcs
        .save_with_base_in_resolution_scope(
            &scope,
            MAINLINE_BRANCH_ID,
            "a.txt",
            &draft,
            "base",
            "save",
            "t5",
            Some(&builder),
        )
        .expect("lost input becomes an honest conflict");
    assert!(matches!(
        outcome.outcome,
        SaveWithBaseOutcome::Conflicted { .. }
    ));
    assert!(vcs.get_cut("save").expect("no published cut").is_none());
    assert!(vcs
        .write_evidence("save")
        .expect("no false saved result")
        .is_none());
    assert_eq!(
        vcs.read_at_cut("head", "a.txt").expect("original head"),
        Some(head)
    );
    assert!(outcome
        .observations
        .iter()
        .all(|lookup| lookup.payload_use == ResolutionPayloadUse::Unavailable));
}

#[cfg(test)]
#[test]
fn native_resolution_observation_verifies_the_consumed_bytes() {
    let (dir, mut vcs) = fixture();
    let connection =
        rusqlite::Connection::open(dir.0.join("content.sqlite")).expect("fault injection");
    conformance::check_content_identity(&mut vcs, |id| {
        connection
            .execute(
                "UPDATE content_blobs SET body = 'forged value', byte_len = 12 WHERE id = ?1",
                [id],
            )
            .expect("corrupt stored bytes");
    });
}
