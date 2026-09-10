use super::*;
use crate::branches::MAINLINE_BRANCH_ID;
use crate::text_merge::{MergePiece, Provenance};
use crate::vcs::resolution_recording::conformance::resolution;

fn scope(authority: &str, resource: &str, compartment: &str) -> ResolutionMemoryScope {
    ResolutionMemoryScope::new(authority.into(), resource.into(), compartment.into())
        .expect("complete scope")
}

pub fn check<B: Branches, C: ContentBlobs>(vcs: &mut WorkspaceVcs<B, C>) {
    for fields in [
        ["", "target", "label"],
        ["issuer", "  ", "label"],
        ["issuer", "target", "\n"],
    ] {
        let error =
            ResolutionMemoryScope::new(fields[0].into(), fields[1].into(), fields[2].into())
                .expect_err("incomplete scopes cannot name legacy or public memory");
        assert!(matches!(error, StoreError::Conflict(_)));
    }
    assert_ne!(
        scope("a|b", "c", "d").key("triple").expect("framed key"),
        scope("a", "b|c", "d")
            .key("triple")
            .expect("different framed key"),
    );
    vcs.init("t0").expect("workspace");
    vcs.set_actor(Some("human-1".into()));
    vcs.set_intent(Some("resolution-intent".into()));
    vcs.record_region_resolutions_recorded("legacy", &[resolution("legacy private text")], "t1")
        .expect("legacy knowledge remains available only to legacy callers");
    let private = scope("issuer", "private-target", "private-compartment");
    let remembered = vcs
        .record_region_resolutions_in_scope(
            &private,
            "private-knowledge",
            &[resolution("private scoped text")],
            "t2",
        )
        .expect("private knowledge");
    let public = scope("issuer", "public-target", "public-compartment");
    vcs.write(
        MAINLINE_BRANCH_ID,
        "targets/public/a.txt",
        Some("dog"),
        "base",
        "t3",
    )
    .expect("base");
    vcs.write(
        MAINLINE_BRANCH_ID,
        "targets/public/a.txt",
        Some("tiger"),
        "head",
        "t4",
    )
    .expect("head");
    // Isolate each namespace component, including a weaker/different policy for
    // the same resource. Delimiter-looking strings must not alias either.
    let misses = [
        public.clone(),
        scope("other-issuer", "private-target", "private-compartment"),
        scope("issuer", "other-target", "private-compartment"),
        scope("issuer", "private-target", "public-compartment"),
    ];
    for (index, other) in misses.iter().enumerate() {
        let outcome = vcs
            .save_with_base_in_resolution_scope(
                other,
                MAINLINE_BRANCH_ID,
                "targets/public/a.txt",
                "lion",
                "base",
                &format!("refused-{index}"),
                "t5",
                None,
            )
            .expect("ordinary unresolved conflict");
        assert!(
            matches!(outcome.outcome, SaveWithBaseOutcome::Conflicted { ref pieces, .. }
            if pieces.iter().any(|piece| matches!(piece, MergePiece::Conflict { .. })))
        );
        assert!(vcs
            .get_cut(&format!("refused-{index}"))
            .expect("cut lookup")
            .is_none());
    }
    // A changed scope under the original operation cannot attach to an old
    // receipt, even if all other request fields match.
    let error = vcs
        .record_region_resolutions_in_scope(
            &public,
            "private-knowledge",
            &[resolution("private scoped text")],
            "t2",
        )
        .expect_err("scope is part of retry meaning");
    assert!(matches!(error, StoreError::Conflict(_)));
    assert_eq!(
        vcs.resolution_receipt("private-knowledge")
            .expect("receipt"),
        Some(remembered.clone())
    );

    // Human -> agent reuse works inside the admitted compartment and never
    // reattributes the first winner to its later observer.
    vcs.set_actor(Some("agent-2".into()));
    vcs.set_intent(Some("agent-intent".into()));
    let observed = vcs
        .record_region_resolutions_in_scope(
            &private,
            "agent-knowledge",
            &[resolution("later suggestion")],
            "t6",
        )
        .expect("observe first winner");
    for (first, later) in remembered.outcomes.iter().zip(&observed.outcomes) {
        assert_eq!(first.resolution, later.resolution);
        assert!(first.inserted);
        assert!(!later.inserted);
    }
    // Give the public target its own first winner: the private and legacy rows
    // cannot prevent it being inserted, and the save must use this value.
    let public_receipt = vcs
        .record_region_resolutions_in_scope(
            &public,
            "public-knowledge",
            &[resolution("public scoped text")],
            "t7",
        )
        .expect("public knowledge");
    assert!(public_receipt.outcomes.iter().all(|entry| entry.inserted));
    let outcome = vcs
        .save_with_base_in_resolution_scope(
            &public,
            MAINLINE_BRANCH_ID,
            "targets/public/a.txt",
            "lion",
            "base",
            "public-save",
            "t8",
            None,
        )
        .expect("public save");
    assert!(
        matches!(outcome.outcome, SaveWithBaseOutcome::Merged { ref merged, ref pieces, .. }
        if merged == "public scoped text" && pieces.iter().any(|piece|
            matches!(piece, MergePiece::Merged { provenance: Provenance::Resolved, .. })))
    );
    assert_eq!(
        vcs.read_at_cut("public-save", "targets/public/a.txt")
            .expect("accepted content"),
        Some("public scoped text".into())
    );

    // Reversed sides share one compartment, and erasure leaves an honest
    // conflict. Use a second path so previous saves cannot short-circuit merge.
    vcs.write(
        MAINLINE_BRANCH_ID,
        "b.txt",
        Some("dog"),
        "reverse-base",
        "t9",
    )
    .expect("base");
    vcs.write(
        MAINLINE_BRANCH_ID,
        "b.txt",
        Some("lion"),
        "reverse-head",
        "t10",
    )
    .expect("head");
    let reverse = vcs
        .save_with_base_in_resolution_scope(
            &private,
            MAINLINE_BRANCH_ID,
            "b.txt",
            "tiger",
            "reverse-base",
            "reverse-save",
            "t11",
            None,
        )
        .expect("reverse save");
    assert!(
        matches!(reverse.outcome, SaveWithBaseOutcome::Merged { ref merged, .. } if merged == "private scoped text")
    );
    vcs.content_store()
        .erase(&remembered.outcomes[0].resolution, "t12")
        .expect("erase");
    vcs.write(
        MAINLINE_BRANCH_ID,
        "c.txt",
        Some("dog"),
        "erased-base",
        "t13",
    )
    .expect("base");
    vcs.write(
        MAINLINE_BRANCH_ID,
        "c.txt",
        Some("tiger"),
        "erased-head",
        "t14",
    )
    .expect("head");
    let erased = vcs
        .save_with_base_in_resolution_scope(
            &private,
            MAINLINE_BRANCH_ID,
            "c.txt",
            "lion",
            "erased-base",
            "erased-save",
            "t15",
            None,
        )
        .expect("erased memory is unavailable");
    assert!(matches!(
        erased.outcome,
        SaveWithBaseOutcome::Conflicted { .. }
    ));
}

pub struct Evidence;
impl SaveResultEvidenceBuilder for Evidence {
    fn prepare(
        &self,
        plan: &super::super::SaveCommitPlan<'_>,
    ) -> StoreResult<crate::files::FileWriteEvidence> {
        Ok(crate::files::FileWriteEvidence {
            schema_ref: "resolution-observation-fixture.v1".into(),
            label_ref: "fixture-compartment".into(),
            content: serde_json::to_string(&serde_json::json!({
                "scope": plan.resolution_scope,
                "observations": plan.resolution_observations,
                "parent": plan.parent_cut_id,
                "accepted": plan.accepted,
            }))?,
        })
    }
}

pub fn check_observations<B: Branches, C: ContentBlobs>(vcs: &mut WorkspaceVcs<B, C>) {
    use crate::branches::resolution_origin::ResolutionObservation;
    vcs.init("t0").expect("workspace");
    vcs.set_actor(Some("human".into()));
    vcs.set_intent(Some("settle conflict".into()));
    let unknown_scope = scope("issuer", "target", "old-policy");
    let known_scope = scope("issuer", "target", "admitted-policy");
    let key =
        WorkspaceVcs::<B, C>::region_key_in_scope(Some(&unknown_scope), "dog", "tiger", "lion")
            .expect("key");
    let old_hash = vcs
        .content_store()
        .put_text("unindexed knowledge")
        .expect("payload");
    vcs.branches
        .record_resolution_memory(&key, &old_hash, "t0")
        .expect("unindexed row");
    vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some("dog"), "base", "t1")
        .expect("base");
    vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some("tiger"), "head", "t2")
        .expect("head");
    let unknown = vcs
        .save_with_base_in_resolution_scope(
            &unknown_scope,
            MAINLINE_BRANCH_ID,
            "a.txt",
            "lion",
            "base",
            "unknown",
            "t3",
            Some(&Evidence),
        )
        .expect("unknown origin cannot be applied");
    assert!(matches!(
        unknown.outcome,
        SaveWithBaseOutcome::Conflicted { .. }
    ));
    assert_eq!(
        unknown.observations,
        vec![ResolutionLookup {
            triple_key: key,
            observed: ResolutionObservation::OriginUnavailable {
                content_hash: old_hash
            },
            payload_use: ResolutionPayloadUse::NotRead,
        }]
    );
    let receipt = vcs
        .record_region_resolutions_in_scope(
            &known_scope,
            "knowledge",
            &[resolution("accepted knowledge")],
            "t4",
        )
        .expect("record");
    vcs.set_actor(Some("agent".into()));
    let saved = vcs
        .save_with_base_in_resolution_scope(
            &known_scope,
            MAINLINE_BRANCH_ID,
            "a.txt",
            "lion",
            "base",
            "save",
            "t5",
            Some(&Evidence),
        )
        .expect("save");
    assert!(matches!(saved.outcome, SaveWithBaseOutcome::Merged { .. }));
    assert_eq!(saved.observations.len(), 1);
    assert_eq!(
        saved.observations[0].payload_use,
        ResolutionPayloadUse::Applied
    );
    assert_eq!(
        saved.observations[0].triple_key,
        receipt.outcomes[0].triple_key
    );
    assert_eq!(
        saved.observations[0].observed,
        ResolutionObservation::Recorded {
            content_hash: receipt.outcomes[0].resolution.clone(),
            origin: crate::branches::resolution_origin::ResolutionOrigin {
                operation_id: "knowledge".into(),
                receipt_hash: receipt.encode().expect("digest").1,
                outcome_index: 0,
            },
        }
    );
    let evidence = vcs
        .write_evidence("save")
        .expect("reference")
        .expect("committed evidence");
    let json = vcs
        .content_store()
        .get_text(&evidence.content_hash)
        .expect("body")
        .text()
        .expect("text");
    let document: serde_json::Value = serde_json::from_str(&json).expect("evidence");
    assert_eq!(
        document["observations"],
        serde_json::to_value(&saved.observations).expect("observations")
    );
    assert_eq!(
        document["scope"],
        serde_json::to_value(&known_scope).expect("scope")
    );
    assert_eq!(
        vcs.get_cut("save")
            .expect("cut")
            .expect("saved")
            .actor
            .as_deref(),
        Some("agent")
    );
    let plain = vcs
        .save_with_base_in_resolution_scope(
            &known_scope,
            MAINLINE_BRANCH_ID,
            "a.txt",
            "plain change",
            "save",
            "plain",
            "t6",
            Some(&Evidence),
        )
        .expect("plain save");
    assert!(matches!(plain.outcome, SaveWithBaseOutcome::Written { .. }));
    assert!(plain.observations.is_empty());

    vcs.write(MAINLINE_BRANCH_ID, "b.txt", Some("dog"), "base2", "t7")
        .expect("base");
    vcs.write(MAINLINE_BRANCH_ID, "b.txt", Some("tiger"), "head2", "t8")
        .expect("head");
    vcs.content_store()
        .erase(&receipt.outcomes[0].resolution, "t9")
        .expect("erase");
    let erased = vcs
        .save_with_base_in_resolution_scope(
            &known_scope,
            MAINLINE_BRANCH_ID,
            "b.txt",
            "lion",
            "base2",
            "erased",
            "t10",
            None,
        )
        .expect("unavailable");
    assert!(matches!(
        erased.outcome,
        SaveWithBaseOutcome::Conflicted { .. }
    ));
    assert_eq!(
        erased.observations[0].observed,
        saved.observations[0].observed
    );
    assert_eq!(
        erased.observations[0].payload_use,
        ResolutionPayloadUse::Unavailable
    );
    assert!(vcs
        .write_evidence("erased")
        .expect("no committed evidence")
        .is_none());
    let missing = vcs
        .save_with_base_in_resolution_scope(
            &known_scope,
            MAINLINE_BRANCH_ID,
            "b.txt",
            "zebra",
            "base2",
            "missing",
            "t13",
            None,
        )
        .expect("missing knowledge");
    assert_eq!(
        missing.observations[0].observed,
        ResolutionObservation::Missing
    );
    assert_eq!(
        missing.observations[0].payload_use,
        ResolutionPayloadUse::NotRead
    );
}

/// Byte-backed stores must distinguish non-text input from a missing value.
/// The current DO text store refuses a binary put before this operation.
pub fn check_binary_observation<B: Branches, C: ContentBlobs>(vcs: &mut WorkspaceVcs<B, C>) {
    use crate::branches::resolution_batch::{ResolutionMemoryBatch, ResolutionMemoryEntry};
    vcs.init("t0").expect("workspace");
    let known_scope = scope("issuer", "target", "admitted-policy");
    vcs.write(MAINLINE_BRANCH_ID, "b.txt", Some("dog"), "base2", "t7")
        .expect("base");
    vcs.write(MAINLINE_BRANCH_ID, "b.txt", Some("tiger"), "head2", "t8")
        .expect("head");
    let binary = vcs.content_store().put(&[0xff, 0xfe]).expect("binary body");
    let binary_key =
        WorkspaceVcs::<B, C>::region_key_in_scope(Some(&known_scope), "dog", "tiger", "leopard")
            .expect("key");
    vcs.branches
        .record_resolution_batch(&ResolutionMemoryBatch {
            operation_id: "binary-knowledge".into(),
            actor: "human".into(),
            intent: "binary fixture".into(),
            recorded_at: "t11".into(),
            entries: vec![ResolutionMemoryEntry {
                triple_key: binary_key,
                resolution: binary,
            }],
        })
        .expect("typed non-text knowledge");
    let non_text = vcs
        .save_with_base_in_resolution_scope(
            &known_scope,
            MAINLINE_BRANCH_ID,
            "b.txt",
            "leopard",
            "base2",
            "binary",
            "t12",
            None,
        )
        .expect("non-text conflict");
    assert!(matches!(
        non_text.outcome,
        SaveWithBaseOutcome::Conflicted { .. }
    ));
    assert_eq!(
        non_text.observations[0].payload_use,
        ResolutionPayloadUse::NonText
    );
}

pub fn check_content_identity<B: Branches, C: ContentBlobs>(
    vcs: &mut WorkspaceVcs<B, C>,
    corrupt: impl FnOnce(&str),
) {
    vcs.init("t0").expect("workspace");
    vcs.set_actor(Some("human".into()));
    vcs.set_intent(Some("knowledge".into()));
    let scope = scope("issuer", "target", "compartment");
    let receipt = vcs
        .record_region_resolutions_in_scope(
            &scope,
            "knowledge",
            &[resolution("original resolution")],
            "t1",
        )
        .expect("remember");
    vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some("dog"), "base", "t2")
        .expect("base");
    vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some("tiger"), "head", "t3")
        .expect("head");
    corrupt(&receipt.outcomes[0].resolution);
    let error = vcs
        .save_with_base_in_resolution_scope(
            &scope,
            MAINLINE_BRANCH_ID,
            "a.txt",
            "lion",
            "base",
            "save",
            "t4",
            Some(&Evidence),
        )
        .expect_err("a reference cannot attest different bytes");
    assert!(matches!(error, StoreError::ContentMismatch { .. }));
    assert!(vcs.get_cut("save").expect("no saved cut").is_none());
    assert!(vcs
        .write_evidence("save")
        .expect("no invented evidence")
        .is_none());
}
