use super::*;
use crate::branches::MAINLINE_BRANCH_ID;
use crate::content::{BlobStatus, EraseOutcome};
use crate::vcs::{SaveWithBaseOutcome, VcsWriteOutcome};
use crate::StoreError;

pub fn resolution(body: &str) -> RegionResolution {
    RegionResolution {
        base_text: "dog".into(),
        ours_text: "tiger".into(),
        theirs_text: "lion".into(),
        resolution_text: body.into(),
    }
}

pub fn check<B: Branches, C: ContentBlobs>(vcs: &mut WorkspaceVcs<B, C>) {
    let resolved = resolution("liger");
    let hash = crate::chunking::content_hash_hex(b"liger");
    for missing in ["actor", "intent"] {
        vcs.set_actor((missing != "actor").then(|| "person-1".into()));
        vcs.set_intent((missing != "intent").then(|| "intent-1".into()));
        let error = vcs
            .record_region_resolutions_recorded(
                "knowledge-1",
                std::slice::from_ref(&resolved),
                "t1",
            )
            .expect_err("missing attribution");
        assert!(matches!(error, StoreError::Conflict(_)));
        assert_eq!(
            vcs.content_store().get(&hash).expect("no preparation"),
            None
        );
        assert_eq!(
            vcs.resolution_receipt("knowledge-1").expect("no effect"),
            None
        );
    }
    vcs.set_actor(Some("person-1".into()));
    vcs.set_intent(Some("intent-1".into()));
    let receipt = vcs
        .record_region_resolutions_recorded("knowledge-1", std::slice::from_ref(&resolved), "t1")
        .expect("record");
    assert_eq!(receipt.request.actor, "person-1");
    assert_eq!(receipt.request.intent, "intent-1");
    assert_eq!(receipt.request.entries.len(), 2);
    for (requested, accepted) in receipt.request.entries.iter().zip(&receipt.outcomes) {
        assert_eq!(requested.triple_key, accepted.triple_key);
        assert_eq!(requested.resolution, accepted.resolution);
        assert!(accepted.inserted);
    }
    assert_ne!(
        receipt.outcomes[0].triple_key,
        receipt.outcomes[1].triple_key
    );
    for entry in &receipt.outcomes {
        assert_eq!(entry.resolution, hash);
    }
    assert_eq!(
        vcs.resolution_receipt("knowledge-1").expect("read"),
        Some(receipt.clone())
    );

    // A save can still conflict elsewhere; its failure cannot erase knowledge.
    vcs.init("t2").expect("init");
    assert!(matches!(
        vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some("base\n"), "base", "t2")
            .expect("base"),
        VcsWriteOutcome::Written { .. }
    ));
    vcs.write(MAINLINE_BRANCH_ID, "a.txt", Some("head\n"), "head", "t3")
        .expect("head");
    assert!(matches!(
        vcs.save_with_base(
            MAINLINE_BRANCH_ID,
            "a.txt",
            "draft\n",
            "base",
            &[],
            "save",
            "t4"
        )
        .expect("conflict"),
        SaveWithBaseOutcome::Conflicted { .. }
    ));
    assert_eq!(
        vcs.resolution_receipt("knowledge-1")
            .expect("independent outcome"),
        Some(receipt.clone())
    );

    // A different effect can propose another body; both side orientations still
    // report the original winner, and the losing request retains its identity.
    vcs.set_actor(Some("agent-2".into()));
    let later = vcs
        .record_region_resolutions_recorded("knowledge-2", &[resolution("different")], "t5")
        .expect("later resolution");
    for (old, observed) in receipt.outcomes.iter().zip(&later.outcomes) {
        assert_eq!(old.triple_key, observed.triple_key);
        assert_eq!(old.resolution, observed.resolution);
        assert!(
            !observed.inserted,
            "observing a winner must not claim authorship"
        );
    }
    assert_ne!(
        later.request.entries[0].resolution,
        later.outcomes[0].resolution
    );
    let error = vcs
        .record_region_resolutions_recorded("knowledge-1", &[resolution("new body")], "t1")
        .expect_err("changed retry");
    assert!(matches!(error, StoreError::Conflict(_)));
    assert_eq!(
        vcs.content_store()
            .get(&crate::chunking::content_hash_hex(b"new body"))
            .expect("no preparation on changed retry"),
        None
    );

    assert!(matches!(
        vcs.content_store().erase(&hash, "t6").expect("erase"),
        EraseOutcome::Erased { .. }
    ));
    vcs.set_actor(Some("person-1".into()));
    assert_eq!(
        vcs.record_region_resolutions_recorded("knowledge-1", &[resolved], "t1")
            .expect("recover erased receipt"),
        receipt
    );
    assert!(matches!(
        vcs.content_store().status(&hash).expect("still erased"),
        BlobStatus::Erased { .. }
    ));
    assert_eq!(
        vcs.content_store().get(&hash).expect("no resurrection"),
        None
    );
}
