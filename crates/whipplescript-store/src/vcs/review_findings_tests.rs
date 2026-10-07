//! Content-anchored findings, approvals and read/diff over real native review
//! revisions (`source_review_findings`). Lives under `vcs` for its fixtures.

use super::*;
use crate::branches::flowing_fence::{
    FlowingFence, FlowingSourceKind, OpenFlowingSource, OpenFlowingSourceOutcome,
};
use crate::branches::flowing_sources::{
    BindContributionBasisOutcome, DeclareContribution, DeclareContributionOutcome, FlowingSources,
    PinPrivateCut, PinPrivateCutOutcome,
};
use crate::branches::{BranchStore, MAINLINE_BRANCH_ID};
use crate::content::{ContentStore, TextBlob};
use crate::diff::DiffKind;
use crate::source_review::{ReviewError, ReviewStore};
use crate::source_review_findings::{EvidenceState, NewFinding};
use crate::source_review_native::NativeUpload;

type Vcs = WorkspaceVcs<BranchStore, ContentStore>;

const A1: &str = "alpha\nbeta\n";
const A2: &str = "alpha\nBETA\n";

/// Three units on one twig: `a.txt`, then `b.txt`, then a change to `a.txt`.
fn twig() -> Vcs {
    let mut vcs = WorkspaceVcs::from_parts(
        BranchStore::open_in_memory().expect("branches"),
        ContentStore::open(":memory:").expect("content"),
    );
    vcs.init("t0").expect("init");
    vcs.create_branch("twig", None, MAINLINE_BRANCH_ID, "t1")
        .expect("twig");
    assert!(matches!(
        vcs.branches
            .open_flowing_source(&OpenFlowingSource {
                source_branch_id: "twig".into(),
                incarnation_id: "inc-1".into(),
                kind: FlowingSourceKind::Twig,
                owner: "coordinator".into(),
                opened_at: "t1".into(),
            })
            .expect("open source"),
        OpenFlowingSourceOutcome::Opened(_)
    ));
    for (path, body, cut, unit) in [
        ("a.txt", A1, "twig-a", "unit-a"),
        ("b.txt", "bee\n", "twig-b", "unit-b"),
        ("a.txt", A2, "twig-c", "unit-c"),
    ] {
        bind_unit(&mut vcs, path, body, cut, unit);
    }
    vcs
}

fn bind_unit(vcs: &mut Vcs, path: &str, body: &str, cut_id: &str, unit_id: &str) {
    vcs.write("twig", path, Some(body), cut_id, "t2")
        .expect("write");
    let manifest_hash = vcs
        .branches
        .get_cut(cut_id)
        .expect("cut")
        .expect("cut exists")
        .manifest_hash;
    let pin_id = format!("pin-{unit_id}");
    assert_eq!(
        vcs.branches
            .pin_private_cut(PinPrivateCut {
                pin_id: &pin_id,
                twig_branch_id: "twig",
                cut_id,
                manifest_hash: &manifest_hash,
                principal: "s:author",
                retained_at: "t3",
            })
            .expect("pin"),
        PinPrivateCutOutcome::Pinned
    );
    assert_eq!(
        vcs.branches
            .declare_contribution(DeclareContribution {
                unit_id,
                pin_id: &pin_id,
                principal: "s:author",
                intent: "change",
                read_basis_digest: "reads",
                dependency_basis_digest: "deps",
                scope_digest: unit_id,
                declared_at: "t4",
            })
            .expect("declare"),
        DeclareContributionOutcome::Declared
    );
    let FlowingSelectionOutcome::Selected(selection) = vcs
        .select_private_changes(
            &pin_id,
            &crate::selection::parse(&format!("change({cut_id})")).expect("parse"),
        )
        .expect("select")
    else {
        panic!("selection")
    };
    assert_eq!(
        vcs.bind_private_selection(unit_id, &selection, "t5")
            .expect("bind"),
        BindContributionBasisOutcome::Bound
    );
}

fn reviews(path: &str) -> ReviewStore {
    let mut reviews = ReviewStore::open(path).expect("reviews");
    reviews
        .create_native_contribution("review-a", "s:author", "change", MAINLINE_BRANCH_ID, &[])
        .expect("contribution");
    reviews
}

/// Revision `n` selects the first `n` units, at their last cut.
fn upload(vcs: &Vcs, reviews: &mut ReviewStore, n: usize) -> i64 {
    let units = ["unit-a", "unit-b", "unit-c"];
    let cuts = ["twig-a", "twig-b", "twig-c"];
    reviews
        .upload_native_revision(
            &vcs.branches,
            NativeUpload {
                contribution_id: "review-a",
                upload_id: &format!("upload-{n}"),
                actor: "s:author",
                source_branch_id: "twig",
                source_cut_id: cuts[n - 1],
                unit_ids: &units[..n],
            },
        )
        .expect("upload")
        .sequence
}

fn digest(vcs: &Vcs, cut: &str, path: &str) -> String {
    vcs.cut_manifest(cut).expect("manifest").expect("cut")[path].clone()
}

fn finding<'a>(id: &'a str, sequence: i64, path: &'a str, blob: &'a str) -> NewFinding<'a> {
    NewFinding {
        contribution_id: "review-a",
        finding_id: id,
        sequence,
        actor: "s:reviewer",
        path,
        blob_digest: blob,
        start_line: 2,
        end_line: 2,
        body: "name this",
    }
}

fn error_text<T: std::fmt::Debug>(result: Result<T, ReviewError>) -> String {
    format!("{:?}", result.expect_err("refused"))
}

#[test]
fn findings_survive_new_revisions_and_go_stale_only_when_their_content_changes() {
    let vcs = twig();
    let mut reviews = reviews(":memory:");
    assert_eq!(upload(&vcs, &mut reviews, 1), 1);
    let a1 = digest(&vcs, "twig-a", "a.txt");
    reviews
        .record_finding(&vcs, finding("on-a", 1, "a.txt", &a1))
        .expect("finding on a");
    assert_eq!(upload(&vcs, &mut reviews, 2), 2);
    let b = digest(&vcs, "twig-b", "b.txt");
    reviews
        .record_finding(
            &vcs,
            NewFinding {
                start_line: 1,
                end_line: 1,
                ..finding("on-b", 2, "b.txt", &b)
            },
        )
        .expect("finding on b");
    let views = reviews.findings(&vcs, "review-a").unwrap();
    assert!(views
        .iter()
        .all(|view| view.state == EvidenceState::Current));

    assert_eq!(upload(&vcs, &mut reviews, 3), 3);
    let views = reviews.findings(&vcs, "review-a").unwrap();
    assert_eq!(views.len(), 2, "a new revision keeps the discussion");
    assert_eq!(views[0].finding.finding_id, "on-a");
    assert_eq!(views[0].state, EvidenceState::Stale { latest_sequence: 3 });
    assert_eq!(views[1].finding.finding_id, "on-b");
    assert_eq!(views[1].state, EvidenceState::Current);

    let old = reviews.revision_file(&vcs, "review-a", 1, "a.txt").unwrap();
    assert_eq!(
        (old.blob_digest.as_str(), old.body),
        (a1.as_str(), TextBlob::Text(A1.into()))
    );
    let new = reviews.revision_file(&vcs, "review-a", 3, "a.txt").unwrap();
    assert_eq!(new.body, TextBlob::Text(A2.into()));
    assert!(
        error_text(reviews.revision_file(&vcs, "review-a", 1, "b.txt"))
            .contains("b.txt in revision review-a/1")
    );

    let diff = reviews.diff_revisions(&vcs, "review-a", 1, 3, 3).unwrap();
    let kinds: Vec<_> = diff.iter().map(|e| (e.path.as_str(), e.kind)).collect();
    assert_eq!(
        kinds,
        [("a.txt", DiffKind::Modified), ("b.txt", DiffKind::Added)]
    );
    assert!(diff[0].to_unified().contains("+BETA"));
    assert!(reviews
        .diff_revisions(&vcs, "review-a", 2, 2, 3)
        .unwrap()
        .is_empty());
    assert!(
        error_text(reviews.diff_revisions(&vcs, "review-a", 1, 4, 3))
            .contains("native revision review-a/4")
    );
}

#[test]
fn approvals_bind_one_revision_and_stale_approvals_are_refused() {
    let vcs = twig();
    let mut reviews = reviews(":memory:");
    upload(&vcs, &mut reviews, 1);
    let approval = reviews
        .record_approval("review-a", "ok-1", 1, "s:reviewer")
        .unwrap();
    assert_eq!(
        reviews.current_approvals("review-a", 1).unwrap(),
        vec![approval.clone()]
    );

    upload(&vcs, &mut reviews, 2);
    assert!(error_text(reviews.current_approvals("review-a", 1))
        .contains("approvals of revision 1 are stale at revision 2"));
    assert!(
        error_text(reviews.record_approval("review-a", "ok-late", 1, "s:reviewer"))
            .contains("revision 1 is superseded by revision 2")
    );
    assert_eq!(
        reviews
            .record_approval("review-a", "ok-1", 1, "s:reviewer")
            .unwrap(),
        approval,
        "an identical retry returns the original record"
    );
    assert!(reviews.current_approvals("review-a", 2).unwrap().is_empty());
    reviews
        .record_approval("review-a", "ok-2", 2, "s:reviewer")
        .unwrap();
    assert_eq!(reviews.current_approvals("review-a", 2).unwrap().len(), 1);
}

#[test]
fn duplicate_uploads_and_records_are_idempotent_and_reuse_is_refused() {
    let vcs = twig();
    let mut reviews = reviews(":memory:");
    upload(&vcs, &mut reviews, 1);
    let a1 = digest(&vcs, "twig-a", "a.txt");
    let first = reviews
        .record_finding(&vcs, finding("on-a", 1, "a.txt", &a1))
        .unwrap();
    reviews
        .record_approval("review-a", "ok-1", 1, "s:reviewer")
        .unwrap();

    assert_eq!(upload(&vcs, &mut reviews, 1), 1, "duplicate upload");
    assert_eq!(reviews.latest_native_sequence("review-a").unwrap(), 1);
    assert_eq!(reviews.current_approvals("review-a", 1).unwrap().len(), 1);
    assert_eq!(
        reviews
            .record_finding(&vcs, finding("on-a", 1, "a.txt", &a1))
            .unwrap(),
        first
    );
    let views = reviews.findings(&vcs, "review-a").unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].state, EvidenceState::Current);

    assert!(error_text(reviews.record_finding(
        &vcs,
        NewFinding {
            body: "something else",
            ..finding("on-a", 1, "a.txt", &a1)
        }
    ))
    .contains("finding id already names another finding"));
    assert!(
        error_text(reviews.record_approval("review-a", "ok-1", 1, "s:other"))
            .contains("approval id already names another approval")
    );
}

#[test]
fn findings_and_approvals_survive_restart() {
    let dir = crate::scratch::path("review-findings-restart");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("reviews.sqlite");
    let path = path.to_str().unwrap();
    let vcs = twig();
    let a1 = digest(&vcs, "twig-a", "a.txt");
    {
        let mut reviews = reviews(path);
        upload(&vcs, &mut reviews, 1);
        reviews
            .record_finding(&vcs, finding("on-a", 1, "a.txt", &a1))
            .unwrap();
        reviews
            .record_approval("review-a", "ok-1", 1, "s:reviewer")
            .unwrap();
    }
    let mut reopened = ReviewStore::open(path).unwrap();
    let views = reopened.findings(&vcs, "review-a").unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].finding.anchor.blob_digest, a1);
    assert_eq!(reopened.current_approvals("review-a", 1).unwrap().len(), 1);
    upload(&vcs, &mut reopened, 2);
    drop(reopened);
    let reopened = ReviewStore::open(path).unwrap();
    assert!(error_text(reopened.current_approvals("review-a", 1)).contains("stale"));
    assert_eq!(
        reopened.findings(&vcs, "review-a").unwrap()[0].state,
        EvidenceState::Current
    );
    drop(reopened);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn old_revisions_and_their_evidence_cannot_be_mutated_or_repointed() {
    let vcs = twig();
    let mut reviews = reviews(":memory:");
    upload(&vcs, &mut reviews, 1);
    upload(&vcs, &mut reviews, 2);
    let a1 = digest(&vcs, "twig-a", "a.txt");
    let b = digest(&vcs, "twig-b", "b.txt");
    reviews
        .record_finding(&vcs, finding("on-a", 1, "a.txt", &a1))
        .unwrap();
    reviews
        .record_approval("review-a", "ok-2", 2, "s:reviewer")
        .unwrap();
    let db = &reviews.connection;
    for (sql, message) in [
        (
            "UPDATE native_revisions SET upload_id='moved' WHERE sequence=1",
            "native review revisions are append-only",
        ),
        (
            "DELETE FROM native_revisions WHERE sequence=1",
            "native review revisions are append-only",
        ),
        (
            "UPDATE review_findings SET blob_digest='other'",
            "review findings are append-only",
        ),
        (
            "DELETE FROM review_findings",
            "review findings are append-only",
        ),
        (
            "UPDATE review_approvals SET actor='other'",
            "review approvals are append-only",
        ),
        (
            "DELETE FROM review_approvals",
            "review approvals are append-only",
        ),
    ] {
        let error = db.execute(sql, []).expect_err(sql).to_string();
        assert!(error.contains(message), "{sql}: {error}");
    }

    // Out-of-band corruption that bypasses the store is detected on read.
    db.execute_batch(
        "DROP TRIGGER review_findings_no_update;
         DROP TRIGGER review_approvals_no_update;
         DROP TRIGGER native_revisions_no_update;",
    )
    .unwrap();
    db.execute("UPDATE review_findings SET blob_digest=?1", [&b])
        .unwrap();
    assert!(error_text(reviews.findings(&vcs, "review-a"))
        .contains("finding on-a no longer matches its revision's content"));
    db.execute("UPDATE review_findings SET blob_digest=?1", [&a1])
        .unwrap();
    db.execute("UPDATE review_approvals SET manifest_hash='other'", [])
        .unwrap();
    assert!(error_text(reviews.current_approvals("review-a", 2))
        .contains("approval no longer matches its revision's content"));

    let revision_one = vcs
        .branches
        .get_cut("twig-a")
        .unwrap()
        .unwrap()
        .manifest_hash;
    let revision_two = vcs
        .branches
        .get_cut("twig-b")
        .unwrap()
        .unwrap()
        .manifest_hash;
    db.execute(
        "UPDATE native_revisions SET revision_json=replace(revision_json, ?1, ?2) WHERE sequence=1",
        [&revision_one, &revision_two],
    )
    .unwrap();
    assert!(
        error_text(reviews.revision_file(&vcs, "review-a", 1, "a.txt"))
            .contains("revision disagrees with its recorded source cut")
    );
}

#[test]
fn anchors_must_name_text_the_revision_actually_holds() {
    let vcs = twig();
    let mut reviews = reviews(":memory:");
    assert!(
        error_text(reviews.latest_native_sequence("review-a")).contains("revisions of review-a")
    );
    upload(&vcs, &mut reviews, 2);
    let a1 = digest(&vcs, "twig-a", "a.txt");
    let b = digest(&vcs, "twig-b", "b.txt");
    for (request, message) in [
        (finding("bad id!", 1, "a.txt", &a1), "invalid finding id"),
        (
            NewFinding {
                body: " ",
                ..finding("f", 1, "a.txt", &a1)
            },
            "finding actor and body are required",
        ),
        (
            NewFinding {
                actor: "",
                ..finding("f", 1, "a.txt", &a1)
            },
            "finding actor and body are required",
        ),
        (
            finding("f", 1, "a.txt", &b),
            "finding anchor is not the revision's content at that path",
        ),
        (
            finding("f", 1, "c.txt", &b),
            "finding anchor is not the revision's content at that path",
        ),
        (
            NewFinding {
                start_line: 0,
                ..finding("f", 1, "a.txt", &a1)
            },
            "finding line range is outside the anchored content",
        ),
        (
            NewFinding {
                end_line: 1,
                ..finding("f", 1, "a.txt", &a1)
            },
            "finding line range is outside the anchored content",
        ),
        (
            NewFinding {
                end_line: 3,
                ..finding("f", 1, "a.txt", &a1)
            },
            "finding line range is outside the anchored content",
        ),
        (finding("f", 9, "a.txt", &a1), "native revision review-a/9"),
    ] {
        let error = error_text(reviews.record_finding(&vcs, request));
        assert!(error.contains(message), "{message}: {error}");
    }
    assert!(reviews.findings(&vcs, "review-a").unwrap().is_empty());
    for (id, actor, message) in [
        ("bad id!", "s:reviewer", "invalid approval id"),
        ("ok", " ", "approval actor is required"),
    ] {
        assert!(error_text(reviews.record_approval("review-a", id, 2, actor)).contains(message));
    }

    reviews
        .create_contribution("git-a", "s:author", "change", "refs/heads/main", &[])
        .unwrap();
    assert!(
        error_text(reviews.record_approval("git-a", "ok", 1, "s:reviewer"))
            .contains("content anchors need a native contribution")
    );
}

#[test]
fn a_line_anchor_needs_readable_text() {
    struct HidesAnchorText {
        inner: ContentStore,
        absent: String,
    }
    impl ContentBlobs for HidesAnchorText {
        fn put(&self, _: &[u8]) -> StoreResult<String> {
            panic!("anchoring must not write content")
        }
        fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
            if id == self.absent {
                Ok(None)
            } else {
                self.inner.get(id)
            }
        }
    }
    let vcs = twig();
    let mut reviews = reviews(":memory:");
    upload(&vcs, &mut reviews, 1);
    let a1 = digest(&vcs, "twig-a", "a.txt");
    let dir = crate::scratch::path("review-findings-hidden");
    std::fs::create_dir_all(&dir).unwrap();
    let branch_path = dir.join("branches.sqlite");
    vcs.branches
        .test_connection()
        .execute("VACUUM INTO ?1", [branch_path.to_str().unwrap()])
        .unwrap();
    let observer = WorkspaceVcs::from_parts(
        BranchStore::open_read_only(&branch_path).unwrap(),
        HidesAnchorText {
            inner: vcs.content,
            absent: a1.clone(),
        },
    );
    assert!(
        error_text(reviews.record_finding(&observer, finding("f", 1, "a.txt", &a1)))
            .contains("a line anchor needs readable text content")
    );
    drop(observer);
    std::fs::remove_dir_all(dir).unwrap();
}
