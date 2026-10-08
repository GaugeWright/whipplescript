use super::*;
use crate::chunking::ChunkingConfig;
use crate::vcs::NativeWorkspaceVcs;

fn vcs(tag: &str) -> NativeWorkspaceVcs {
    let dir = crate::scratch::path(&format!("whipplescript-carriage-{tag}"));
    let mut vcs = NativeWorkspaceVcs::open(dir.join("branches.sqlite"), dir.join("content.sqlite"))
        .expect("open vcs");
    vcs.init("t0").expect("init");
    vcs
}

/// Every ref a store holds: branch ids with their heads. A carriage moves none.
fn refs(vcs: &NativeWorkspaceVcs) -> Vec<(String, Option<String>, Option<String>)> {
    vcs.list_branches(None)
        .expect("branches")
        .into_iter()
        .map(|row| (row.branch_id, row.head_cut_id, row.head_manifest_hash))
        .collect()
}

/// A Home with a branch of three cuts: `h1`, `h2`, `h3`.
fn seeded_home(tag: &str) -> NativeWorkspaceVcs {
    let mut home = vcs(tag);
    home.create_branch("work", None, "main", "t1")
        .expect("branch");
    home.write("work", "a.md", Some("first"), "h1", "t2")
        .expect("write");
    home.write("work", "b.md", Some("second"), "h2", "t3")
        .expect("write");
    home.write("work", "a.md", Some("first, revised"), "h3", "t4")
        .expect("write");
    home
}

fn wire(carried: &CarriedCut) -> CarriedCut {
    serde_json::from_str(&serde_json::to_string(carried).expect("encode")).expect("decode")
}

fn refused<T: std::fmt::Debug>(result: StoreResult<T>, words: &str) {
    let error = result.expect_err(&format!("must be refused: {words}"));
    let text = format!("{error:?}");
    assert!(text.contains(words), "expected `{words}` in {text}");
    match &error {
        StoreError::Conflict(message) => assert!(
            message.starts_with("carried cut refused: "),
            "a refusal must say it is a carried-cut refusal: {message}"
        ),
        other => panic!("a refusal must be a Conflict, got {other:?}"),
    }
}

/// A peer holding the Home's `h3` and a twig seeded with exactly that content,
/// cut `p_base`, then one more cut.
fn peer_with_line(
    home: &mut NativeWorkspaceVcs,
    tag: &str,
) -> (NativeWorkspaceVcs, CarriedReceipt, CarriedCut) {
    let (carried, _) = home.export_carried_cut("h3", "t5").expect("export");
    let mut peer = vcs(tag);
    let received = peer
        .record_carried_cut(&wire(&carried), "p0")
        .expect("record")
        .receipt()
        .clone();
    let base = peer.carried_head_manifest(&received.digest).expect("head");
    peer.create_branch("twig", None, "main", "p1")
        .expect("twig");
    peer.import_diff("twig", &base, &[], "p_base", "p2")
        .expect("seed the twig with the carried content");
    peer.write("twig", "c.md", Some("written on the peer"), "p_c1", "p3")
        .expect("write");
    (peer, received, carried)
}

#[test]
fn a_carried_base_erased_after_receipt_cannot_seed_or_authorize_a_returned_line() {
    let mut home = seeded_home("erased-base-home");
    let (mut peer, received, carried) = peer_with_line(&mut home, "erased-base-peer");
    let base_id = peer
        .carried_head_manifest(&received.digest)
        .expect("verified base")
        .get("a.md")
        .expect("base file")
        .clone();
    peer.content_store()
        .erase(&base_id, "p4")
        .expect("erase carried body");

    refused(
        peer.carried_head_manifest(&received.digest),
        "carried content",
    );
    refused(
        peer.record_carried_cut(&wire(&carried), "p5"),
        "carried content",
    );
    refused(
        peer.export_peer_line("twig", "p_base", &received.digest, "p6"),
        "carried content",
    );
}

#[test]
fn an_erased_earlier_prefix_step_refuses_the_whole_recorded_carriage() {
    let mut home = seeded_home("erased-prefix-home");
    let first_id = home
        .cut_manifest("h1")
        .expect("manifest")
        .expect("first cut")
        .get("a.md")
        .expect("first body")
        .clone();
    let (prefix, _) = home
        .export_carried_prefix("h1", "h3", "t5")
        .expect("export prefix");
    let mut peer = vcs("erased-prefix-peer");
    let received = peer
        .record_carried_cut(&wire(&prefix), "p0")
        .expect("record prefix")
        .receipt()
        .clone();
    assert_eq!(
        peer.verified_carried_steps(&received.digest)
            .expect("all steps")
            .len(),
        3
    );
    peer.content_store()
        .erase(&first_id, "p1")
        .expect("erase earlier-only body");
    assert_ne!(
        prefix.header.steps.last().expect("head").get("a.md"),
        Some(&first_id),
        "the erased body is absent from the head"
    );
    refused(
        peer.verified_carried_steps(&received.digest),
        "carried content",
    );
    refused(
        peer.carried_head_manifest(&received.digest),
        "carried content",
    );
}

#[test]
fn a_cut_round_trips_by_content_and_moves_no_peer_ref() {
    let mut home = seeded_home("cut-home");
    let (carried, sent) = home.export_carried_cut("h2", "t5").expect("export");
    assert_eq!(carried.header.kind, CarriedKind::Cut);
    assert_eq!(carried.header.steps.len(), 1);
    assert_eq!(carried.provenance.host_cut_ids, vec!["h2".to_owned()]);
    assert_eq!(sent.direction, CarriageDirection::Sent);

    let mut peer = vcs("cut-peer");
    let before = refs(&peer);
    let outcome = peer
        .record_carried_cut(&wire(&carried), "p0")
        .expect("record");
    let CarriageOutcome::Recorded(receipt) = &outcome else {
        panic!("first record is Recorded: {outcome:?}");
    };
    assert_eq!(
        receipt.digest, sent.digest,
        "both sides key it by one digest"
    );
    assert_eq!(receipt.direction, CarriageDirection::Received);
    assert_eq!(refs(&peer), before, "recording a carriage moves no ref");
    assert!(
        peer.get_cut("h2").expect("cut").is_none(),
        "the Home's cut id names nothing on the peer"
    );

    let files = peer.carried_head_manifest(&receipt.digest).expect("head");
    assert_eq!(files, home.cut_manifest("h2").expect("m").expect("cut"));
    for id in files.values() {
        assert_eq!(
            peer.content_store().get(id).expect("get"),
            home.content_store().get(id).expect("get"),
        );
    }
    assert_eq!(
        peer.load_manifest(Some(&receipt.head_manifest_hash))
            .expect("manifest"),
        files,
        "the peer can materialize the carried head from its own manifest root"
    );

    let again = peer
        .record_carried_cut(&wire(&carried), "p1")
        .expect("re-record");
    assert_eq!(again, CarriageOutcome::AlreadyRecorded(receipt.clone()));
    assert_eq!(refs(&peer), before);
    assert!(matches!(
        home.export_carried_cut("h2", "t6").expect("re-export"),
        (
            _,
            CarriedReceipt {
                direction: CarriageDirection::Sent,
                ..
            }
        )
    ));
}

#[test]
fn a_recorded_carriage_survives_the_content_collector() {
    let mut home = seeded_home("collect-home");
    let (carried, _) = home
        .export_carried_prefix("h1", "h3", "t5")
        .expect("export");
    let mut peer = vcs("collect-peer");
    let receipt = peer
        .record_carried_cut(&carried, "p0")
        .expect("record")
        .receipt()
        .clone();
    peer.purge_unreachable("p1").expect("collect");
    let (row, header) = peer.recorded_carriage(&receipt.digest).expect("still held");
    assert_eq!(row.step_manifest_hashes.len(), 3);
    for (step, hash) in header.steps.iter().zip(&row.step_manifest_hashes) {
        assert_eq!(&peer.load_manifest(Some(hash)).expect("manifest"), step);
        for id in step.values() {
            assert!(peer.content_store().get(id).expect("get").is_some());
        }
    }
    home.purge_unreachable("t6").expect("collect");
    home.recorded_carriage(&receipt.digest)
        .expect("the Home keeps what it sent");
}

#[test]
fn the_digest_is_content_not_cut_identity() {
    let mut home = seeded_home("identity-home");
    let mut other = seeded_home("identity-other");
    let (here, _) = home.export_carried_cut("h3", "t5").expect("export");
    let (there, _) = other.export_carried_cut("h3", "t5").expect("export");
    assert_eq!(
        here.digest, there.digest,
        "the same content is the same carriage"
    );

    let mut renamed = vcs("identity-renamed");
    renamed
        .create_branch("w", None, "main", "t1")
        .expect("branch");
    renamed
        .write("w", "a.md", Some("first, revised"), "x1", "t2")
        .expect("write");
    renamed
        .write("w", "b.md", Some("second"), "x2", "t3")
        .expect("write");
    let (renamed_carried, _) = renamed.export_carried_cut("x2", "t4").expect("export");
    assert_eq!(
        renamed_carried.digest, here.digest,
        "different cut ids and history, same files: same digest"
    );
    assert_ne!(renamed_carried.provenance, here.provenance);
}

#[test]
fn a_prefix_carries_its_base_and_every_cut_in_order() {
    let mut home = seeded_home("prefix-home");
    let (carried, _) = home
        .export_carried_prefix("h1", "h3", "t5")
        .expect("export");
    assert_eq!(carried.header.kind, CarriedKind::Prefix);
    assert_eq!(carried.header.steps.len(), 3);
    for (step, cut) in carried.header.steps.iter().zip(["h1", "h2", "h3"]) {
        assert_eq!(step, &home.cut_manifest(cut).expect("m").expect("cut"));
    }

    let mut peer = vcs("prefix-peer");
    let before = refs(&peer);
    let receipt = peer
        .record_carried_cut(&wire(&carried), "p0")
        .expect("record")
        .receipt()
        .clone();
    assert_eq!(refs(&peer), before);
    assert_eq!(
        peer.load_manifest(Some(&receipt.head_manifest_hash))
            .expect("manifest"),
        home.cut_manifest("h3").expect("m").expect("cut")
    );

    refused(
        home.export_carried_prefix("h2", "h2", "t6"),
        "a prefix needs at least one cut after its base",
    );
    refused(
        home.export_carried_prefix("h3", "h1", "t6"),
        "does not descend from",
    );
    refused(home.export_carried_cut("nope", "t6"), "is not recorded");
}

#[test]
fn a_tampered_carriage_is_refused_and_writes_nothing() {
    let mut home = seeded_home("tamper-home");
    let (carried, sent) = home.export_carried_cut("h3", "t5").expect("export");
    let mut peer = vcs("tamper-peer");
    let before = refs(&peer);

    // A body swapped under its own id.
    let mut body = carried.clone();
    body.blobs[0].body = Some("attacker bytes".to_owned());
    // A step that names other content, digest left as declared.
    let mut step = carried.clone();
    let path = step.header.steps[0].keys().next().cloned().expect("a path");
    step.header.steps[0].insert(path, "0000".to_owned());
    // A file renamed: shape is fine, but the declared digest no longer names it.
    let mut renamed = carried.clone();
    let id = renamed.header.steps[0].remove("a.md").expect("a.md");
    renamed.header.steps[0].insert("c.md".to_owned(), id);
    // A body and its id replaced consistently, the step and digest re-derived,
    // but the SHA-256 the header binds left alone.
    let mut forged = carried.clone();
    let forged_id = crate::stable_hash_bytes_hex(b"forged");
    let old_id = forged.header.steps[0]
        .insert("a.md".to_owned(), forged_id.clone())
        .expect("a.md");
    let digest = forged.header.file_digests.remove(&old_id).expect("bound");
    forged.header.file_digests.insert(forged_id.clone(), digest);
    for blob in &mut forged.blobs {
        if blob.id == old_id {
            blob.id = forged_id.clone();
            blob.body = Some("forged".to_owned());
            blob.byte_len = 6;
        }
    }
    forged.digest = forged.header.digest().expect("digest");
    // A blob nobody references.
    let mut extra = carried.clone();
    let mut stray = extra.blobs[0].clone();
    stray.id = crate::stable_hash_bytes_hex(b"stray");
    stray.body = Some("stray".to_owned());
    extra.blobs.push(stray);
    // A blob withheld.
    let mut missing = carried.clone();
    missing.blobs.pop();
    // A blob carried twice.
    let mut twice = carried.clone();
    twice.blobs.push(twice.blobs[0].clone());
    // A blob that carries nothing.
    let mut empty = carried.clone();
    empty.blobs[0].body = None;
    // A blob marked as omitted, as a delta bundle would.
    let mut omitted = carried.clone();
    omitted.blobs[0].body = None;
    omitted.blobs[0].omitted = true;

    for (name, bad, words) in [
        ("body", body, "ContentMismatch"),
        ("step", step, "do not cover exactly"),
        (
            "renamed",
            renamed,
            "does not hash to the digest it declares",
        ),
        ("forged", forged, "not the bytes the digest names"),
        ("extra", extra, "carries blobs no step reaches"),
        ("missing", missing, "is not carried"),
        ("twice", twice, "is carried twice"),
        ("empty", empty, "carries no body"),
        ("omitted", omitted, "travels without its bytes"),
    ] {
        let error = peer
            .record_carried_cut(&bad, "p0")
            .expect_err(&format!("{name} must be refused"));
        let text = format!("{error:?}");
        assert!(text.contains(words), "{name}: {text}");
    }
    assert_eq!(refs(&peer), before);
    assert!(
        peer.content_store()
            .get(&sent.record_id)
            .expect("get")
            .is_none(),
        "no refused carriage left a record"
    );
    assert!(peer.branches.carriage(&sent.digest).expect("row").is_none());
    assert!(matches!(
        peer.record_carried_cut(&carried, "p1")
            .expect("the honest one"),
        CarriageOutcome::Recorded(_)
    ));
}

#[test]
fn a_header_out_of_shape_is_refused_by_name() {
    let mut home = seeded_home("shape-home");
    let (cut, _) = home.export_carried_cut("h3", "t5").expect("export");
    let (prefix, _) = home
        .export_carried_prefix("h2", "h3", "t5")
        .expect("export");
    let mut peer = vcs("shape-peer");

    let mut format = cut.clone();
    format.header.format = "whipplescript.carried-cut.v0".to_owned();
    let mut none = cut.clone();
    none.header.steps.clear();
    let mut two = prefix.clone();
    two.header.kind = CarriedKind::Cut;
    let mut one = cut.clone();
    one.header.kind = CarriedKind::Prefix;
    let mut based = cut.clone();
    based.header.base = Some("a base".to_owned());

    for (bad, words) in [
        (format, "unknown format"),
        (none, "it carries no step"),
        (two, "a cut carries exactly one step and no base"),
        (one, "a prefix carries its base and at least one cut"),
        (based, "a cut carries exactly one step and no base"),
    ] {
        refused(peer.record_carried_cut(&bad, "p0"), words);
    }
    let mut unbased = cut.clone();
    unbased.header.kind = CarriedKind::PeerLine;
    refused(
        home.receive_peer_line(&unbased, "t6"),
        "a peer line names the carriage it was written against",
    );
}

#[test]
fn chunked_content_travels_as_structure_and_is_checked_whole() {
    let config = ChunkingConfig {
        whole_blob_threshold: 256,
        min_size: 64,
        avg_size: 256,
        max_size: 1024,
    };
    let mut home = vcs("chunk-home");
    home.create_branch("work", None, "main", "t1")
        .expect("branch");
    let big = "0123456789abcdef-".repeat(600);
    let root = home
        .content_store()
        .put_chunked(&big, &config)
        .expect("chunk");
    let mut changed = BTreeMap::new();
    changed.insert("big.dat".to_owned(), root.clone());
    home.import_diff("work", &changed, &[], "c1", "t2")
        .expect("diff");
    let (carried, _) = home.export_carried_cut("c1", "t3").expect("export");
    let root_at = carried
        .blobs
        .iter()
        .position(|blob| blob.id == root)
        .expect("root entry");

    let mut peer = vcs("chunk-peer");
    let receipt = peer
        .record_carried_cut(&wire(&carried), "p0")
        .expect("record")
        .receipt()
        .clone();
    let files = peer.carried_head_manifest(&receipt.digest).expect("head");
    assert_eq!(
        peer.content_store().get(&files["big.dat"]).expect("get"),
        Some(big.as_bytes().to_vec()),
        "the peer re-links the root and reads it whole"
    );

    let fresh = |tag: &str| vcs(&format!("chunk-peer-{tag}"));
    let mut oversize = carried.clone();
    oversize.blobs[root_at].byte_len = 300 * 1024 * 1024;
    refused(
        fresh("oversize").record_carried_cut(&oversize, "p0"),
        "over the",
    );
    let mut reordered = carried.clone();
    reordered.blobs[root_at]
        .chunk_ids
        .as_mut()
        .expect("chunks")
        .reverse();
    refused(
        fresh("reordered").record_carried_cut(&reordered, "p0"),
        "does not match its chunk list",
    );
    let mut short = carried.clone();
    short.blobs[root_at].byte_len -= 1;
    refused(
        fresh("short").record_carried_cut(&short, "p0"),
        "reassembles to a different size",
    );
    let mut chunkless = carried.clone();
    let first_chunk = chunkless.blobs[root_at].chunk_ids.as_ref().expect("chunks")[0].clone();
    chunkless.blobs.retain(|blob| blob.id != first_chunk);
    refused(
        fresh("chunkless").record_carried_cut(&chunkless, "p0"),
        "is not carried",
    );
    let mut doubled = carried.clone();
    doubled.blobs.push(doubled.blobs[root_at].clone());
    refused(
        fresh("doubled").record_carried_cut(&doubled, "p0"),
        "is carried twice",
    );
}

#[test]
fn erased_content_neither_leaves_nor_returns() {
    let mut home = seeded_home("erase-home");
    let (carried, _) = home.export_carried_cut("h3", "t5").expect("export");
    home.erase_path("work", "b.md", "t6")
        .expect("erase")
        .expect("path");
    refused(
        home.export_carried_cut("h3", "t7"),
        "a check cannot run on content that is gone",
    );

    let mut peer = vcs("erase-peer");
    peer.create_branch("local", None, "main", "p1")
        .expect("branch");
    peer.write("local", "b.md", Some("second"), "l1", "p2")
        .expect("write");
    peer.erase_path("local", "b.md", "p3")
        .expect("erase")
        .expect("path");
    refused(
        peer.record_carried_cut(&carried, "p4"),
        "refusing resurrection",
    );
}

#[test]
fn a_peer_line_returns_as_a_candidate_without_moving_a_home_ref() {
    let mut home = seeded_home("line-home");
    let (mut peer, received, _) = peer_with_line(&mut home, "line-peer");
    peer.write("twig", "a.md", Some("revised on the peer"), "p_c2", "p4")
        .expect("write");
    let (line, _) = peer
        .export_peer_line("twig", "p_base", &received.digest, "p5")
        .expect("export line");
    assert_eq!(line.header.kind, CarriedKind::PeerLine);
    assert_eq!(line.header.steps.len(), 2, "only the cuts after the base");
    assert_eq!(line.header.base.as_deref(), Some(received.digest.as_str()));

    let before = refs(&home);
    let outcome = home.receive_peer_line(&wire(&line), "t6").expect("receive");
    let CarriageOutcome::Recorded(candidate) = &outcome else {
        panic!("first receipt records: {outcome:?}");
    };
    assert_eq!(refs(&home), before, "a returned line moves no Home ref");
    assert_eq!(candidate.kind, CarriedKind::PeerLine);
    let head = home
        .carried_head_manifest(&candidate.digest)
        .expect("candidate head");
    assert_eq!(
        home.content_store()
            .get(&head["c.md"])
            .expect("get")
            .as_deref(),
        Some(&b"written on the peer"[..])
    );
    assert_eq!(
        home.read("work", "a.md").expect("read").as_deref(),
        Some("first, revised"),
        "the Home's line still reads its own content"
    );
    assert!(matches!(
        home.receive_peer_line(&wire(&line), "t7").expect("again"),
        CarriageOutcome::AlreadyRecorded(_)
    ));
    assert_eq!(refs(&home), before);
}

#[test]
fn a_returned_line_refuses_when_its_sent_base_was_erased_at_home() {
    let mut home = seeded_home("lost-return-base-home");
    let (mut peer, received, carried) = peer_with_line(&mut home, "lost-return-base-peer");
    let base_id = carried.header.steps[0]["a.md"].clone();
    let (mut line, _) = peer
        .export_peer_line("twig", "p_base", &received.digest, "p4")
        .expect("return line");
    // A peer may return a line whose first cut removes a base-only file. Make
    // that valid wire shape here so this receiver test works with both the
    // legacy local seed and the later authenticated peer seed.
    for step in &mut line.header.steps {
        step.remove("a.md");
    }
    line.header.file_digests.remove(&base_id);
    line.blobs.retain(|blob| blob.id != base_id);
    line.digest = line.header.digest().expect("changed line digest");
    assert!(
        !line.header.file_digests.contains_key(&base_id),
        "the returned line cannot independently verify the removed base file"
    );
    home.content_store()
        .erase(&base_id, "t6")
        .expect("erase Home base");
    let before = refs(&home);
    refused(
        home.receive_peer_line(&wire(&line), "t7"),
        "carried content",
    );
    assert_eq!(refs(&home), before);
    refused(
        home.recorded_carriage(&line.digest),
        "was not recorded by this store",
    );
}

#[test]
fn a_returned_line_cannot_publish_after_its_base_is_erased_during_registration() {
    let dir = crate::scratch::path("whipplescript-carriage-racing-return-base-home");
    let branch_path = dir.join("branches.sqlite");
    let content_path = dir.join("content.sqlite");
    let mut home = NativeWorkspaceVcs::open(&branch_path, &content_path).expect("open");
    home.init("t0").expect("init");
    home.create_branch("work", None, "main", "t1")
        .expect("branch");
    home.write("work", "a.md", Some("first"), "h1", "t2")
        .expect("write");
    home.write("work", "b.md", Some("second"), "h2", "t3")
        .expect("write");
    home.write("work", "a.md", Some("first, revised"), "h3", "t4")
        .expect("write");
    let (mut peer, received, carried) = peer_with_line(&mut home, "racing-return-base-peer");
    let base_id = carried.header.steps[0]["a.md"].clone();
    let (mut line, _) = peer
        .export_peer_line("twig", "p_base", &received.digest, "p4")
        .expect("return line");
    for step in &mut line.header.steps {
        step.remove("a.md");
    }
    line.header.file_digests.remove(&base_id);
    line.blobs.retain(|blob| blob.id != base_id);
    line.digest = line.header.digest().expect("changed line digest");
    drop(home);

    let mut home = WorkspaceVcs::from_parts(
        crate::branches::BranchStore::open(&branch_path).expect("branches"),
        CollectedBeforePublication {
            inner: crate::content::ContentStore::open(&content_path).expect("content"),
            branch_path,
            content_path,
            collect: std::cell::Cell::new(false),
            erase_before_publish: std::cell::RefCell::new(Some(base_id.clone())),
            aliased_read: None,
            retained: Default::default(),
        },
    );
    let error = home
        .receive_peer_line(&wire(&line), "t7")
        .expect_err("erasure after the initial base read must prevent publication");
    assert!(
        home.content.retained.borrow().contains(&base_id),
        "the sent base is included in the publication exclusion: {error:?}"
    );
    assert!(
        home.branches
            .carriage(&line.digest)
            .expect("registry")
            .is_none(),
        "no returned-line receipt may name the lost base"
    );
}

#[test]
fn a_peer_line_must_be_written_against_what_this_home_supplied() {
    let mut home = seeded_home("supplied-home");
    let (mut peer, received, carried) = peer_with_line(&mut home, "supplied-peer");
    peer.write("twig", "z.md", Some("later"), "p_later", "p4")
        .expect("write");

    refused(
        peer.export_peer_line("twig", "p_c1", &received.digest, "p5"),
        "does not hold the carriage the line names as its base",
    );
    refused(
        peer.export_peer_line("twig", "p_later", &received.digest, "p5"),
        "the line has no cut after its base",
    );
    refused(
        peer.export_peer_line("nobody", "p_base", &received.digest, "p5"),
        "does not exist",
    );
    refused(
        peer.export_peer_line("twig", "h3", &received.digest, "p5"),
        "does not descend from",
    );
    refused(
        peer.export_peer_line("twig", "p_base", "no such digest", "p5"),
        "was not recorded by this store",
    );
    let (line, _) = peer
        .export_peer_line("twig", "p_base", &received.digest, "p5")
        .expect("line");

    // A Home that never sent the base.
    let mut stranger = vcs("supplied-stranger");
    let before = refs(&stranger);
    refused(
        stranger.receive_peer_line(&line, "s1"),
        "was not recorded by this store",
    );
    assert_eq!(refs(&stranger), before);

    // A base this store received rather than sent is not one it supplied.
    refused(
        peer.receive_peer_line(&line, "p6"),
        "a peer line's base is a carriage this Home sent",
    );
    // A peer line names a carriage the peer received, not one it sent.
    peer.create_branch("own", None, "main", "p7").expect("own");
    peer.write("own", "o.md", Some("own"), "o1", "p8")
        .expect("write");
    peer.write("own", "o.md", Some("own, again"), "o2", "p9")
        .expect("write");
    let (_, own) = peer.export_carried_cut("o1", "p10").expect("own export");
    refused(
        peer.export_peer_line("own", "o1", &own.digest, "p11"),
        "written against a carriage the peer received",
    );

    // Each door takes only its own direction.
    refused(
        home.receive_peer_line(&carried, "t8"),
        "only a peer line returns to a Home",
    );
    refused(
        peer.record_carried_cut(&line, "p12"),
        "received by its Home, not recorded on a peer",
    );
    // A store that sent a carriage does not also record it as received.
    refused(
        home.record_carried_cut(&carried, "t9"),
        "this store already sent carriage",
    );
}

#[test]
fn a_registry_row_must_name_the_header_it_was_recorded_with() {
    let mut home = seeded_home("row-home");
    let (carried, sent) = home.export_carried_cut("h3", "t5").expect("export");
    let row = |digest: &str, record_id: &str| CarriedCutRow {
        digest: digest.to_owned(),
        record_id: record_id.to_owned(),
        kind: "cut".to_owned(),
        direction: CarriageDirection::Sent,
        step_manifest_hashes: vec![sent.head_manifest_hash.clone()],
        recorded_at: "t6".to_owned(),
    };
    // A row naming another blob than its header.
    let other = home.content_store().put(b"not a header").expect("put");
    home.branches
        .record_carriage(&row("wrong-header", &other))
        .expect("row");
    refused(
        home.recorded_carriage("wrong-header"),
        "is not the carriage",
    );
    // A row naming a header the store does not hold.
    home.branches
        .record_carriage(&row("lost-header", "0123456789abcdef"))
        .expect("row");
    refused(home.recorded_carriage("lost-header"), "has lost its header");
    let pretty_header = serde_json::to_vec_pretty(&carried.header).expect("pretty header");
    let pretty_digest = sha256_hex(&pretty_header);
    let pretty_record = home
        .content_store()
        .put(&pretty_header)
        .expect("put pretty");
    home.branches
        .record_carriage(&row(&pretty_digest, &pretty_record))
        .expect("pretty row");
    refused(
        home.recorded_carriage(&pretty_digest),
        "noncanonical header",
    );
    assert_eq!(
        home.recorded_carriage(&carried.digest)
            .expect("the honest row")
            .1,
        carried.header
    );

    home.branches
        .test_connection()
        .execute(
            "UPDATE carried_cuts SET kind = 'prefix' WHERE digest = ?1",
            rusqlite::params![carried.digest],
        )
        .expect("corrupt kind");
    refused(
        home.recorded_carriage(&carried.digest),
        "mismatched registry kind",
    );
    refused(
        home.export_carried_cut("h3", "t7"),
        "mismatched registry kind",
    );
    home.branches
        .test_connection()
        .execute(
            "UPDATE carried_cuts SET kind = 'cut' WHERE digest = ?1",
            rusqlite::params![carried.digest],
        )
        .expect("restore kind");

    home.branches
        .test_connection()
        .execute(
            "DELETE FROM carried_cut_steps WHERE digest = ?1",
            rusqlite::params![carried.digest],
        )
        .expect("remove retained step");
    refused(
        home.carried_head_manifest(&carried.digest),
        "incomplete step registry",
    );
    home.branches
        .test_connection()
        .execute(
            "INSERT INTO carried_cut_steps (digest, step, manifest_hash) VALUES (?1, 0, ?2)",
            rusqlite::params![carried.digest, sent.head_manifest_hash],
        )
        .expect("restore retained step");

    let other_manifest = home
        .branches
        .get_cut("h1")
        .expect("read earlier cut")
        .expect("earlier cut")
        .manifest_hash;
    home.branches
        .test_connection()
        .execute(
            "UPDATE carried_cut_steps SET manifest_hash = ?2 WHERE digest = ?1",
            rusqlite::params![carried.digest, other_manifest],
        )
        .expect("mispoint retained step");
    refused(
        home.recorded_carriage(&carried.digest),
        "mismatched retained step",
    );

    let mut peer = vcs("row-peer");
    peer.record_carried_cut(&wire(&carried), "p1")
        .expect("record on peer");
    peer.branches
        .test_connection()
        .execute(
            "UPDATE carried_cuts SET kind = 'prefix' WHERE digest = ?1",
            rusqlite::params![carried.digest],
        )
        .expect("corrupt received kind");
    refused(
        peer.record_carried_cut(&wire(&carried), "p2"),
        "mismatched registry kind",
    );
}

/// A content authority whose collector, on another native connection, runs
/// in the window between the carriage's content writes and its registry row:
/// exactly when the row is about to be published under the retention fence.
struct CollectedBeforePublication {
    inner: crate::content::ContentStore,
    branch_path: std::path::PathBuf,
    content_path: std::path::PathBuf,
    collect: std::cell::Cell<bool>,
    erase_before_publish: std::cell::RefCell<Option<String>>,
    aliased_read: Option<(String, Vec<u8>)>,
    retained: std::cell::RefCell<Vec<String>>,
}

impl ContentBlobs for CollectedBeforePublication {
    fn put(&self, body: &[u8]) -> StoreResult<String> {
        self.inner.put(body)
    }
    fn put_unerased(&self, body: &[u8]) -> StoreResult<String> {
        self.inner.put_unerased(body)
    }
    fn put_chunk_root(
        &self,
        root_id: &str,
        chunk_ids: &[String],
        byte_len: u64,
    ) -> StoreResult<()> {
        self.inner.put_chunk_root(root_id, chunk_ids, byte_len)
    }
    fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
        if let Some((alias, body)) = &self.aliased_read {
            if alias == id {
                return Ok(Some(body.clone()));
            }
        }
        self.inner.get(id)
    }
    fn status(&self, id: &str) -> StoreResult<crate::content::BlobStatus> {
        self.inner.status(id)
    }
    fn publish_retained<T>(
        &self,
        ids: &[String],
        publish: impl FnOnce() -> StoreResult<T>,
    ) -> StoreResult<T> {
        *self.retained.borrow_mut() = ids.to_vec();
        if let Some(id) = self.erase_before_publish.borrow_mut().take() {
            crate::content::ContentStore::open(&self.content_path)?
                .erase(&id, "competing erasure")?;
        }
        if self.collect.replace(false) {
            let mut other =
                NativeWorkspaceVcs::open(&self.branch_path, &self.content_path).expect("open");
            other.purge_unreachable("race").expect("collect");
        }
        self.inner.publish_retained(ids, publish)
    }
}

fn racing_peer(
    tag: &str,
) -> WorkspaceVcs<crate::branches::BranchStore, CollectedBeforePublication> {
    let dir = crate::scratch::path(&format!("whipplescript-carriage-{tag}"));
    let branch_path = dir.join("branches.sqlite");
    let content_path = dir.join("content.sqlite");
    NativeWorkspaceVcs::open(&branch_path, &content_path)
        .expect("open vcs")
        .init("t0")
        .expect("init");
    WorkspaceVcs::from_parts(
        crate::branches::BranchStore::open(&branch_path).expect("branches"),
        CollectedBeforePublication {
            inner: crate::content::ContentStore::open(&content_path).expect("content"),
            branch_path,
            content_path,
            collect: std::cell::Cell::new(true),
            erase_before_publish: Default::default(),
            aliased_read: None,
            retained: Default::default(),
        },
    )
}

#[test]
fn a_received_carriage_refuses_bytes_aliased_under_a_shorter_local_id() {
    let mut home = seeded_home("aliased-home");
    let (carried, _) = home.export_carried_cut("h3", "t5").expect("export");
    let mut peer = racing_peer("aliased-peer");
    peer.content.collect.set(false);
    let id = carried
        .header
        .file_digests
        .keys()
        .next()
        .expect("carried file")
        .clone();
    peer.content.aliased_read = Some((id, b"different retained bytes".to_vec()));
    refused(
        peer.record_carried_cut(&wire(&carried), "p1"),
        "differs from the carriage",
    );
    assert!(
        peer.branches
            .carriage(&carried.digest)
            .expect("registry")
            .is_none(),
        "no carriage row is published for bytes the receiver cannot verify"
    );
}

#[test]
fn an_export_refuses_a_header_aliased_under_a_shorter_local_id() {
    let mut reference = seeded_home("aliased-header-reference");
    let (carried, _) = reference.export_carried_cut("h3", "t5").expect("reference");
    let header_id = crate::chunking::content_hash_hex(
        &carried.header.canonical_bytes().expect("canonical header"),
    );

    let dir = crate::scratch::path("whipplescript-carriage-aliased-header-export");
    let branch_path = dir.join("branches.sqlite");
    let content_path = dir.join("content.sqlite");
    let mut native = NativeWorkspaceVcs::open(&branch_path, &content_path).expect("open");
    native.init("t0").expect("init");
    native
        .create_branch("work", None, "main", "t1")
        .expect("branch");
    native
        .write("work", "a.md", Some("first"), "h1", "t2")
        .expect("write");
    native
        .write("work", "b.md", Some("second"), "h2", "t3")
        .expect("write");
    native
        .write("work", "a.md", Some("first, revised"), "h3", "t4")
        .expect("write");
    drop(native);
    let mut home = WorkspaceVcs::from_parts(
        crate::branches::BranchStore::open(&branch_path).expect("branches"),
        CollectedBeforePublication {
            inner: crate::content::ContentStore::open(&content_path).expect("content"),
            branch_path,
            content_path,
            collect: std::cell::Cell::new(false),
            erase_before_publish: Default::default(),
            aliased_read: None,
            retained: Default::default(),
        },
    );
    home.content.collect.set(false);
    home.content.aliased_read = Some((header_id, b"different retained header".to_vec()));
    refused(
        home.export_carried_cut("h3", "t5"),
        "stored header differs from the carriage",
    );
    assert!(
        home.branches
            .carriage(&carried.digest)
            .expect("registry")
            .is_none(),
        "the sender cannot register a carriage whose local header differs"
    );
}

#[test]
fn a_collector_between_content_and_registry_refuses_the_receipt() {
    let mut home = seeded_home("fence-home");
    let (carried, _) = home
        .export_carried_prefix("h1", "h3", "t5")
        .expect("export");
    let mut peer = racing_peer("fence-peer");
    assert!(
        peer.record_carried_cut(&wire(&carried), "p0").is_err(),
        "a receipt whose content was collected before its row must not register"
    );
    assert!(
        !peer.content.collect.get(),
        "the collector ran in the window"
    );
    assert!(
        peer.branches
            .carriage(&carried.digest)
            .expect("read")
            .is_none(),
        "no registry row names collected content"
    );

    // Unraced, the same carriage records, and the fence covered every id the
    // row reaches: the header, every carried file, and each step's manifest.
    let receipt = peer
        .record_carried_cut(&wire(&carried), "p1")
        .expect("record")
        .receipt()
        .clone();
    let retained = peer.content.retained.borrow().clone();
    let (row, header) = peer.recorded_carriage(&receipt.digest).expect("held");
    assert!(retained.contains(&row.record_id), "the header is retained");
    for id in header.file_digests.keys() {
        assert!(retained.contains(id), "carried file `{id}` is retained");
    }
    for hash in &row.step_manifest_hashes {
        assert!(
            retained.contains(hash),
            "step manifest `{hash}` is retained"
        );
    }
}

#[test]
fn a_collector_before_an_export_registers_refuses_the_sent_row() {
    let dir = crate::scratch::path("whipplescript-carriage-fence-export");
    let branch_path = dir.join("branches.sqlite");
    let content_path = dir.join("content.sqlite");
    {
        let mut seed = NativeWorkspaceVcs::open(&branch_path, &content_path).expect("open");
        seed.init("t0").expect("init");
        seed.create_branch("work", None, "main", "t1")
            .expect("branch");
        seed.write("work", "a.md", Some("first"), "h1", "t2")
            .expect("write");
    }
    let mut home = WorkspaceVcs::from_parts(
        crate::branches::BranchStore::open(&branch_path).expect("branches"),
        CollectedBeforePublication {
            inner: crate::content::ContentStore::open(&content_path).expect("content"),
            branch_path,
            content_path,
            collect: std::cell::Cell::new(true),
            erase_before_publish: Default::default(),
            aliased_read: None,
            retained: Default::default(),
        },
    );
    let refused = home.export_carried_cut("h1", "t3");
    assert!(
        refused.is_err(),
        "an export whose header was collected must not register"
    );
    let (carried, sent) = home.export_carried_cut("h1", "t4").expect("export");
    assert!(home.content.retained.borrow().contains(
        &home
            .recorded_carriage(&sent.digest)
            .expect("held")
            .0
            .record_id
    ));
    assert_eq!(carried.digest, sent.digest);
}

/// The racing double is the real native authority when it does not race, so
/// the content contract holds for it like any other.
#[test]
fn the_racing_double_satisfies_the_content_contract() {
    let counter = std::cell::Cell::new(0);
    crate::content::conformance::run_suite(|| {
        counter.set(counter.get() + 1);
        let dir = crate::scratch::path(&format!(
            "whipplescript-carriage-conformance-{}",
            counter.get()
        ));
        let content_path = dir.join("content.sqlite");
        CollectedBeforePublication {
            inner: crate::content::ContentStore::open(&content_path).expect("content"),
            branch_path: dir.join("branches.sqlite"),
            content_path,
            collect: std::cell::Cell::new(false),
            erase_before_publish: Default::default(),
            aliased_read: None,
            retained: Default::default(),
        }
    })
    .expect("content conformance");
}
