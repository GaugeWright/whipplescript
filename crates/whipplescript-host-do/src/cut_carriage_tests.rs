//! FB-6 on the hosted runtime: a cut a native Home ships is recorded by a
//! durable-object peer by content, and a line the peer writes against it comes
//! back to the Home as a recorded candidate. Neither side moves a ref.

use std::rc::Rc;

use crate::do_branches::compose_vcs;
use crate::do_store::test_support::RusqliteDoSql;
use whipplescript_store::vcs::cut_carriage::{CarriageOutcome, CarriedCut, CarriedKind};
use whipplescript_store::vcs::NativeWorkspaceVcs;

fn wire(carried: &CarriedCut) -> CarriedCut {
    serde_json::from_str(&serde_json::to_string(carried).expect("encode")).expect("decode")
}

type Refs = Vec<(String, Option<String>, Option<String>)>;

fn refs_of<
    B: whipplescript_store::branches::Branches,
    C: whipplescript_store::content::ContentBlobs,
>(
    vcs: &whipplescript_store::vcs::WorkspaceVcs<B, C>,
) -> Refs {
    vcs.list_branches(None)
        .expect("branches")
        .into_iter()
        .map(|row| (row.branch_id, row.head_cut_id, row.head_manifest_hash))
        .collect()
}

#[test]
fn a_native_home_and_a_hosted_peer_carry_cuts_both_ways_by_content() {
    let dir = std::env::temp_dir().join(format!(
        "do-carriage-home-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let mut home =
        NativeWorkspaceVcs::open(dir.join("branches.sqlite"), dir.join("content.sqlite"))
            .expect("home");
    home.init("t0").expect("init");
    home.create_branch("work", None, "main", "t1")
        .expect("branch");
    home.write("work", "a.whip", Some("flow a {}\n"), "h1", "t2")
        .expect("write");
    home.write("work", "notes.md", Some("home notes"), "h2", "t3")
        .expect("write");
    let (prefix, _) = home
        .export_carried_prefix("h1", "h2", "t4")
        .expect("prefix");
    let (cut, sent) = home.export_carried_cut("h2", "t5").expect("cut");

    let sql = Rc::new(RusqliteDoSql::in_memory());
    let mut peer = compose_vcs(&sql).expect("compose");
    peer.init("p0").expect("init");
    let peer_refs = refs_of(&peer);

    let received = peer
        .record_carried_cut(&wire(&cut), "p1")
        .expect("record cut")
        .receipt()
        .clone();
    assert_eq!(received.digest, sent.digest);
    assert!(matches!(
        peer.record_carried_cut(&wire(&prefix), "p2")
            .expect("record prefix"),
        CarriageOutcome::Recorded(_)
    ));
    assert!(matches!(
        peer.record_carried_cut(&wire(&cut), "p3")
            .expect("duplicate"),
        CarriageOutcome::AlreadyRecorded(_)
    ));
    assert_eq!(refs_of(&peer), peer_refs, "the peer's refs are untouched");

    let mut tampered = wire(&cut);
    for blob in &mut tampered.blobs {
        blob.body = blob.body.as_ref().map(|body| format!("{body} tampered"));
    }
    let error = peer
        .record_carried_cut(&tampered, "p4")
        .expect_err("a tampered body is refused on the hosted peer");
    assert!(
        format!("{error:?}").contains("ContentMismatch"),
        "{error:?}"
    );

    // The peer writes a twig on the carried content and returns it.
    let base = peer.carried_head_manifest(&received.digest).expect("head");
    peer.create_branch("twig", None, "main", "p1")
        .expect("twig");
    peer.import_diff("twig", &base, &[], "p_base", "p2")
        .expect("seed");
    peer.write("twig", "notes.md", Some("peer notes"), "p1c", "p3")
        .expect("write");
    let (line, _) = peer
        .export_peer_line("twig", "p_base", &received.digest, "p5")
        .expect("line");
    assert_eq!(line.header.kind, CarriedKind::PeerLine);

    let home_refs = refs_of(&home);
    let candidate = home
        .receive_peer_line(&wire(&line), "t6")
        .expect("receive")
        .receipt()
        .clone();
    assert_eq!(refs_of(&home), home_refs, "the Home's refs are untouched");
    let files = home
        .carried_head_manifest(&candidate.digest)
        .expect("candidate");
    assert_eq!(
        home.content_store()
            .get(&files["notes.md"])
            .expect("get")
            .as_deref(),
        Some(&b"peer notes"[..])
    );
    assert_eq!(
        home.read("work", "notes.md").expect("read").as_deref(),
        Some("home notes")
    );
    let _ = std::fs::remove_dir_all(&dir);
}
