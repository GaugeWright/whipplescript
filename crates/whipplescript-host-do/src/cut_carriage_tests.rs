//! FB-6 on the hosted runtime: a cut a native Home ships is recorded by a
//! durable-object peer by content, and a line the peer writes against it comes
//! back to the Home as a recorded candidate. Neither side moves a ref.

use std::rc::Rc;

use crate::do_branches::{compose_vcs, DoBranches};
use crate::do_store::{test_support::RusqliteDoSql, DoSql};
use whipplescript_store::branches::carried_cuts::{
    CarriageDirection, CarriedCutRow, CarriedCuts, SeedCarriedTwig, SeedCarriedTwigOutcome,
};
use whipplescript_store::branches::Branches;
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

    // Receipt moves no ref; the peer's local twig, cut and seed receipt move
    // together, then a retry after a simulated crash returns that receipt.
    let seeded = peer
        .seed_peer_twig(
            &received.digest,
            "twig",
            None,
            "p_base",
            "agent:peer",
            "turn:one",
            "p2",
        )
        .expect("seed");
    let SeedCarriedTwigOutcome::Seeded(seed_receipt) = seeded else {
        panic!("first seed must publish")
    };
    assert_eq!(seed_receipt.carriage_digest, received.digest);
    drop(peer);
    let mut peer = compose_vcs(&sql).expect("reopen peer after seed");
    assert_eq!(
        peer.seed_peer_twig(
            &received.digest,
            "twig",
            None,
            "p_base",
            "agent:peer",
            "turn:one",
            "p2-retry"
        )
        .expect("retry"),
        SeedCarriedTwigOutcome::AlreadySeeded(seed_receipt)
    );
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

#[test]
fn hosted_seed_rolls_back_twig_and_cut_when_its_receipt_fails() {
    let dir = std::env::temp_dir().join(format!(
        "do-carriage-seed-rollback-{}-{}",
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
    let (carried, _) = home.export_carried_cut("h1", "t3").expect("export");
    let sql = Rc::new(RusqliteDoSql::in_memory());
    let mut peer = compose_vcs(&sql).expect("peer");
    peer.init("p0").expect("init");
    peer.record_carried_cut(&wire(&carried), "p1")
        .expect("receive");
    sql.execute(
        "CREATE TRIGGER fail_seed_receipt BEFORE INSERT ON ops \
         WHEN NEW.kind = 'carried-seed' BEGIN SELECT RAISE(FAIL, 'injected receipt failure'); END",
        &[],
    )
    .expect("install fault");
    assert!(peer
        .seed_peer_twig(
            &carried.digest,
            "twig",
            None,
            "p-seed",
            "agent:peer",
            "turn:one",
            "p2"
        )
        .is_err());
    assert!(peer.get_branch("twig").expect("twig").is_none());
    assert!(peer.get_cut("p-seed").expect("cut").is_none());
    assert!(peer.get_op("op-p-seed").expect("op").is_none());
    sql.execute("DROP TRIGGER fail_seed_receipt", &[])
        .expect("remove fault");
    assert!(matches!(
        peer.seed_peer_twig(
            &carried.digest,
            "twig",
            None,
            "p-seed",
            "agent:peer",
            "turn:one",
            "p3"
        )
        .expect("retry after rollback"),
        SeedCarriedTwigOutcome::Seeded(_)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hosted_seed_backend_refuses_incomplete_or_stale_custody() {
    let sql = Rc::new(RusqliteDoSql::in_memory());
    let mut peer = compose_vcs(&sql).expect("peer");
    peer.init("p0").expect("mainline");
    let mut branches = DoBranches::observe(sql.clone());
    let request = SeedCarriedTwig {
        twig_branch_id: "twig",
        expected_parent_cut_id: None,
        seed_cut_id: "seed",
        carriage_digest: "received",
        head_manifest_hash: "manifest",
        actor: "agent:peer",
        intent: "turn:one",
        recorded_at: "p1",
    };
    let refused = |result: whipplescript_store::StoreResult<SeedCarriedTwigOutcome>, text: &str| {
        let error = result.expect_err("backend must refuse");
        assert!(format!("{error:?}").contains(text), "{error:?}");
    };

    refused(branches.seed_carried_twig(request), "no received carriage");
    branches
        .record_carriage(&CarriedCutRow {
            digest: "received".into(),
            record_id: "header".into(),
            kind: "cut".into(),
            direction: CarriageDirection::Received,
            step_manifest_hashes: vec!["manifest".into()],
            recorded_at: "p0".into(),
        })
        .expect("record backend carriage");
    refused(
        branches.seed_carried_twig(SeedCarriedTwig {
            head_manifest_hash: "other",
            ..request
        }),
        "does not match a received cut or prefix",
    );
    sql.execute(
        "UPDATE branches SET head_cut_id = 'later' WHERE branch_id = 'main'",
        &[],
    )
    .expect("move mainline");
    refused(branches.seed_carried_twig(request), "stale local parent");
    assert!(branches.get_branch("twig").expect("twig").is_none());

    let empty_sql = Rc::new(RusqliteDoSql::in_memory());
    let mut empty = DoBranches::new(empty_sql).expect("schema without mainline");
    empty
        .record_carriage(&CarriedCutRow {
            digest: "received".into(),
            record_id: "header".into(),
            kind: "cut".into(),
            direction: CarriageDirection::Received,
            step_manifest_hashes: vec!["manifest".into()],
            recorded_at: "p0".into(),
        })
        .expect("record backend carriage");
    refused(empty.seed_carried_twig(request), "no local mainline");
}

#[test]
fn hosted_seed_backend_refuses_a_branch_lost_during_the_transaction() {
    let sql = Rc::new(RusqliteDoSql::in_memory());
    let mut peer = compose_vcs(&sql).expect("peer");
    peer.init("p0").expect("mainline");
    let mut branches = DoBranches::observe(sql.clone());
    branches
        .record_carriage(&CarriedCutRow {
            digest: "received".into(),
            record_id: "header".into(),
            kind: "cut".into(),
            direction: CarriageDirection::Received,
            step_manifest_hashes: vec!["manifest".into()],
            recorded_at: "p0".into(),
        })
        .expect("record backend carriage");
    sql.execute(
        "CREATE TRIGGER lose_seed_branch AFTER INSERT ON branches \
         WHEN NEW.branch_id = 'twig' BEGIN DELETE FROM branches WHERE branch_id = 'twig'; END",
        &[],
    )
    .expect("inject branch loss");
    let error = branches
        .seed_carried_twig(SeedCarriedTwig {
            twig_branch_id: "twig",
            expected_parent_cut_id: None,
            seed_cut_id: "seed",
            carriage_digest: "received",
            head_manifest_hash: "manifest",
            actor: "agent:peer",
            intent: "turn:one",
            recorded_at: "p1",
        })
        .expect_err("deleted branch must refuse");
    assert!(
        format!("{error:?}").contains("branch disappeared"),
        "{error:?}"
    );
    assert!(branches.get_branch("twig").expect("twig").is_none());
    assert!(branches.get_cut("seed").expect("cut").is_none());
    assert!(branches.get_op("op-seed").expect("op").is_none());
}
