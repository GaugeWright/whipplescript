//! The same immutable-version observations on native and hosted storage.
use super::*;

pub fn check<B: Branches, C: ContentBlobs>(mut make: impl FnMut() -> WorkspaceVcs<B, C>) {
    let mut vcs = make();
    vcs.init("t0").expect("init");
    let budget = NonZeroUsize::new(8).expect("budget");
    // Legacy flat roots remain readable without rewriting recorded history.
    let legacy_body = vcs
        .content
        .put_text("legacy body")
        .expect("retained-version conformance fixture");
    let legacy_root = vcs
        .content
        .put_text(
            &serde_json::to_string(&std::collections::BTreeMap::from([(
                "legacy.txt",
                legacy_body,
            )]))
            .expect("retained-version conformance fixture"),
        )
        .expect("retained-version conformance fixture");
    vcs.branches
        .record_cut(crate::branches::CutRecord {
            cut_id: "legacy",
            change_id: "legacy",
            branch_id: "main",
            manifest_hash: &legacy_root,
            parent_cut_id: None,
            origin: Some("write:legacy.txt"),
            actor: None,
            intent: None,
            recorded_at: "t0",
        })
        .expect("retained-version conformance fixture");
    assert_eq!(
        vcs.read_at_cut("legacy", "legacy.txt")
            .expect("retained-version conformance fixture")
            .as_deref(),
        Some("legacy body")
    );
    assert_eq!(
        vcs.read_at_cut("legacy", "absent.txt")
            .expect("retained-version conformance fixture"),
        None
    );
    assert_eq!(
        vcs.file_version_origin("legacy", "legacy.txt", budget)
            .expect("retained-version conformance fixture")
            .source,
        FileVersionSource::Write {
            cut_id: "legacy".into(),
            evidence: None
        }
    );
    vcs.content
        .erase(&legacy_root, "t0")
        .expect("retained-version conformance fixture");
    let unavailable = vcs
        .read_at_cut("legacy", "absent.txt")
        .expect_err("a missing manifest cannot establish an absent path");
    assert!(
        matches!(&unavailable, StoreError::Conflict(reason)
        if reason == "retained manifest is unavailable"),
        "missing history is distinct from corrupt retained bytes: {unavailable:?}"
    );

    assert!(vcs
        .file_version_origin("missing", "note.txt", budget)
        .is_err());
    vcs.write("main", "note.txt", Some("original"), "first", "t1")
        .expect("write");
    assert_eq!(
        vcs.read_at_cut("first", "note.txt")
            .expect("retained-version conformance fixture")
            .as_deref(),
        Some("original")
    );
    assert_eq!(
        vcs.read_at_cut("first", "absent.txt")
            .expect("retained-version conformance fixture"),
        None
    );
    assert_eq!(
        vcs.file_version_origin("first", "absent.txt", budget)
            .expect("retained-version conformance fixture")
            .source,
        FileVersionSource::Absent
    );
    let original = vcs
        .file_version_origin("first", "note.txt", budget)
        .expect("original metadata");
    assert_eq!(
        original.content_hash.as_deref(),
        Some(crate::stable_hash_hex("original").as_str())
    );
    assert_eq!(
        original.source,
        FileVersionSource::Write {
            cut_id: "first".into(),
            evidence: None
        }
    );
    vcs.write("main", "other.txt", Some("other"), "other", "t2")
        .expect("other file");
    let inherited = vcs
        .file_version_origin("other", "note.txt", budget)
        .expect("inherited metadata");
    assert_eq!(inherited.cut_id, "other");
    assert_eq!(inherited.source, original.source);
    let exhausted = vcs
        .file_version_origin(
            "other",
            "note.txt",
            NonZeroUsize::new(1).expect("one-hop budget"),
        )
        .expect_err("the original write lies outside this budget");
    assert!(
        matches!(&exhausted, StoreError::Conflict(reason)
        if reason == "file version provenance exceeds the observation budget"),
        "budget exhaustion must be diagnosable: {exhausted:?}"
    );
    let evidence = WriteEvidenceRef {
        schema_ref: "result.v1".into(),
        label_ref: "restricted".into(),
        content_hash: vcs
            .content
            .put_text("receipt")
            .expect("retained-version conformance fixture"),
    };
    let row = vcs
        .branches
        .get_branch("main")
        .expect("retained-version conformance fixture")
        .expect("retained-version conformance fixture");
    vcs.write_from_with_evidence(
        row,
        "note.txt",
        Some("original"),
        "same-bytes",
        "t3",
        Some(&evidence),
        &[],
    )
    .expect("retained-version conformance fixture");
    assert_eq!(
        vcs.file_version_origin("same-bytes", "note.txt", budget)
            .expect("retained-version conformance fixture")
            .source,
        FileVersionSource::Write {
            cut_id: "same-bytes".into(),
            evidence: Some(evidence)
        }
    );
    vcs.write("main", "note.txt", Some("changed"), "changed", "t4")
        .expect("retained-version conformance fixture");
    vcs.restore("main", "first", "restored", "t5", &mut Ungoverned)
        .expect("retained-version conformance fixture");
    assert_eq!(
        vcs.file_version_origin("restored", "note.txt", budget)
            .expect("retained-version conformance fixture")
            .source,
        FileVersionSource::Opaque {
            cut_id: "restored".into()
        }
    );
    // Metadata discovery must not load file bodies: the source remains visible
    // after erasure, while an actual exact-version body read refuses.
    vcs.content
        .erase(&crate::stable_hash_hex("original"), "t6")
        .expect("retained-version conformance fixture");
    assert_eq!(
        vcs.file_version_origin("other", "note.txt", budget)
            .expect("retained-version conformance fixture")
            .source,
        original.source
    );
    assert!(vcs.read_at_cut("first", "note.txt").is_err());
    let manifest = vcs
        .get_cut("first")
        .expect("retained-version conformance fixture")
        .expect("retained-version conformance fixture")
        .manifest_hash;
    vcs.content
        .erase(&manifest, "t7")
        .expect("retained-version conformance fixture");
    for path in ["note.txt", "absent.txt"] {
        assert!(
            vcs.file_version_origin("first", path, budget).is_err(),
            "erased manifest cannot establish presence or absence"
        );
        assert!(
            vcs.read_at_cut("first", path).is_err(),
            "erased manifest is not an absent file"
        );
    }
}

/// These observations carry no norm ledger, so nothing gates the mainline.
struct Ungoverned;

impl crate::vcs::MainlineGate for Ungoverned {
    fn prepare(
        &mut self,
        _base_cut: Option<&str>,
        _proposed_cut: &str,
        _artifacts: &crate::norm_commands::NormArtifactCapture<'_>,
    ) -> crate::StoreResult<crate::vcs::GateVerdict> {
        Ok(crate::vcs::GateVerdict::Admit)
    }
    fn commit(
        &mut self,
        advance: &mut dyn FnMut() -> crate::StoreResult<()>,
    ) -> crate::StoreResult<crate::vcs::GateCommit> {
        advance()?;
        Ok(crate::vcs::GateCommit::Committed)
    }
}
