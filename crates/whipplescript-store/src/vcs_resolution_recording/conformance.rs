//! The same independently bound operation runs on actual native and DO stores.
use super::*;
use crate::branches::MAINLINE_BRANCH_ID;
use crate::content::EraseOutcome;

pub fn input(body: &str) -> String {
    serde_json::to_string(
        &ResolutionRecordingInput::new(vec![RegionResolution {
            base_text: "dog".into(),
            ours_text: "tiger".into(),
            theirs_text: "lion".into(),
            resolution_text: body.into(),
        }])
        .expect("input"),
    )
    .expect("json")
}
pub fn scope() -> ResolutionMemoryScope {
    ResolutionMemoryScope::new("home".into(), "target/path-grant".into(), "private".into())
        .expect("scope")
}
pub fn binding(body: &str) -> ResolutionRecordingBinding {
    ResolutionRecordingBinding::prepare(
        body,
        "protected-input",
        scope(),
        "knowledge-1",
        "human:recorder",
        "admitted-correction",
        "t1",
    )
    .expect("binding")
}
pub fn check<B: Branches, C: ContentBlobs>(mut workspace: WorkspaceVcs<B, C>) {
    workspace.init("t0").expect("workspace");
    let head = workspace
        .get_branch(MAINLINE_BRANCH_ID)
        .expect("branch")
        .expect("mainline")
        .head_cut_id;
    workspace.set_actor(Some("unrelated ambient actor".into()));
    workspace.set_intent(Some("unrelated ambient intent".into()));
    let body = input("liger");
    let binding = binding(&body);
    let input_hash = workspace
        .content_store()
        .put_text(&body)
        .expect("fixture retained input");
    assert_eq!(input_hash, binding.input_hash());
    assert!(read_committed_resolution_recording(&workspace, &binding)
        .expect("observation")
        .is_none());
    let mut target =
        BoundResolutionRecording::new(workspace, binding.clone(), &body).expect("actual binding");
    assert_eq!(target.binding(), &binding);
    let first = target.record().expect("record");
    assert_eq!(&first.request, binding.batch());
    assert!(first.outcomes.iter().all(|entry| entry.inserted));
    assert_eq!(first.request.actor, "human:recorder");
    assert_eq!(first.request.intent, "admitted-correction");
    assert_eq!(
        target
            .workspace
            .get_branch(MAINLINE_BRANCH_ID)
            .expect("branch")
            .expect("mainline")
            .head_cut_id,
        head
    );
    assert_eq!(target.record().expect("same request"), first);
    assert_eq!(
        read_committed_resolution_recording(&target.workspace, &binding).expect("read receipt"),
        Some(first.clone())
    );
    // Recording evidence survives loss of both the original input and its
    // remembered payload. A repeated delivery cannot resurrect either body.
    for hash in [&input_hash, &first.request.entries[0].resolution] {
        assert!(matches!(
            target
                .workspace
                .content_store()
                .erase(hash, "t2")
                .expect("erase"),
            EraseOutcome::Erased { .. }
        ));
    }
    assert_eq!(
        read_committed_resolution_recording(&target.workspace, &binding)
            .expect("historical receipt"),
        Some(first.clone())
    );
    assert_eq!(target.record().expect("receipt before preparation"), first);
    assert!(target
        .workspace
        .content_store()
        .get(&input_hash)
        .expect("input erased")
        .is_none());
    assert!(target
        .workspace
        .content_store()
        .get(&first.request.entries[0].resolution)
        .expect("resolution erased")
        .is_none());
    let changed_body = input("different correction");
    let changed = ResolutionRecordingBinding::prepare(
        &changed_body,
        "protected-input",
        scope(),
        "knowledge-1",
        "human:recorder",
        "admitted-correction",
        "t1",
    )
    .expect("changed input");
    assert!(read_committed_resolution_recording(&target.workspace, &changed).is_err());
    let mut target = BoundResolutionRecording::new(target.workspace, changed, &changed_body)
        .expect("different valid descriptor");
    assert!(target.record().is_err());
    assert!(target
        .workspace
        .content_store()
        .get(&crate::stable_hash_hex("different correction"))
        .expect("no losing preparation")
        .is_none());
    // A genuinely new action observes first-wins outcomes; it does not claim
    // the old actor's insertions or reinterpret its own losing body as winner.
    let next = ResolutionRecordingBinding::prepare(
        &changed_body,
        "protected-input",
        scope(),
        "knowledge-2",
        "agent:recorder",
        "new admitted correction",
        "t3",
    )
    .expect("next action");
    let mut target =
        BoundResolutionRecording::new(target.workspace, next, &changed_body).expect("new binding");
    let later = target.record().expect("observe existing winners");
    assert_eq!(later.request.actor, "agent:recorder");
    assert!(later
        .outcomes
        .iter()
        .all(|entry| !entry.inserted && entry.resolution == first.outcomes[0].resolution));
    assert_eq!(
        read_committed_resolution_recording(&target.workspace, &binding)
            .expect("original attribution"),
        Some(first)
    );
}
