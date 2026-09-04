//! Receipt-schema test emitter. Operates only on in-memory or synthetic
//! temporary fixture stores; it accepts no user-store path or credentials.
#[path = "../tests/support/receipt_fixture.rs"]
mod receipt_fixture;

use receipt_fixture::{expected, Fixture};
use serde_json::{json, Value};
use whipplescript_store::vcs::{BoundaryPromotionOutcome, NativeWorkspaceVcs};
use whipplescript_store::workstreams::{
    fork_at_cut_and_admit, BoundaryReservation, ExactForkDestination, WorkstreamStore, Workstreams,
};

fn report(reports: &mut Vec<Value>, label: &str, receipt: impl serde::Serialize) {
    reports.push(json!({"label": label, "receipt": receipt}));
}

fn main() {
    let mut reports = Vec::new();
    let mut streams =
        WorkstreamStore::open(":memory:").expect("synthetic receipt fixture operation succeeds");
    let mut vcs = NativeWorkspaceVcs::open(":memory:", ":memory:")
        .expect("synthetic receipt fixture operation succeeds");
    vcs.init("t0")
        .expect("synthetic receipt fixture operation succeeds");
    vcs.write("main", "base", Some("base"), "main-1", "t1")
        .expect("synthetic receipt fixture operation succeeds");
    vcs.create_branch("line", None, "main", "t1")
        .expect("synthetic receipt fixture operation succeeds");
    vcs.write("line", "work", Some("work"), "line-1", "t2")
        .expect("synthetic receipt fixture operation succeeds");
    vcs.create_branch("chat", None, "main", "t1")
        .expect("synthetic receipt fixture operation succeeds");
    vcs.bind_instance("parent", "chat", "t1")
        .expect("synthetic receipt fixture operation succeeds");
    vcs.write("chat", "draft", Some("draft"), "chat-1", "t2")
        .expect("synthetic receipt fixture operation succeeds");
    report(
        &mut reports,
        "fresh-main-home",
        streams
            .home_receipt("chat")
            .expect("synthetic receipt fixture operation succeeds"),
    );
    streams
        .create_stream("ws", None, "line", "t2", None)
        .expect("synthetic receipt fixture operation succeeds");
    streams
        .join("chat", "ws", "t2")
        .expect("synthetic receipt fixture operation succeeds");
    report(
        &mut reports,
        "fresh-named-home",
        streams
            .home_receipt("chat")
            .expect("synthetic receipt fixture operation succeeds"),
    );
    let fork = fork_at_cut_and_admit(
        &mut streams,
        &mut vcs,
        "parent",
        "chat-1",
        "child",
        "chat-child",
        None,
        ExactForkDestination::Workstream("ws"),
        "t3",
    )
    .expect("synthetic receipt fixture operation succeeds");
    report(&mut reports, "fresh-fork", fork.receipt());
    streams
        .reserve_boundary(
            "ws",
            BoundaryReservation {
                reservation_id: "reservation",
                expected_line_cut: "line-1",
                expected_main_cut: "main-1",
                proposed_main_cut: "main-2",
                at: "t4",
            },
        )
        .expect("synthetic receipt fixture operation succeeds");
    report(
        &mut reports,
        "fresh-reserved",
        streams
            .get_stream("ws")
            .expect("synthetic receipt fixture operation succeeds")
            .expect("synthetic receipt fixture operation succeeds")
            .boundary_receipt("workspace")
            .expect("synthetic receipt fixture operation succeeds"),
    );
    vcs.reserve_branch_head("line", "reservation", "t4")
        .expect("synthetic receipt fixture operation succeeds");
    let promoted = vcs
        .promote_line_exact(
            "line",
            "reservation",
            Some("line-1"),
            Some("main-1"),
            "main-2",
            "t5",
        )
        .expect("synthetic receipt fixture operation succeeds");
    let BoundaryPromotionOutcome::Promoted {
        ref_position,
        ref_receipt_handle,
        ..
    } = promoted
    else {
        panic!("{promoted:?}")
    };
    streams
        .record_ref_advanced("ws", "reservation", ref_position, &ref_receipt_handle, "t5")
        .expect("synthetic receipt fixture operation succeeds");
    report(
        &mut reports,
        "fresh-ref-advanced",
        streams
            .get_stream("ws")
            .expect("synthetic receipt fixture operation succeeds")
            .expect("synthetic receipt fixture operation succeeds")
            .boundary_receipt("workspace")
            .expect("synthetic receipt fixture operation succeeds"),
    );
    streams
        .close_promoted("ws", "reservation", "t6")
        .expect("synthetic receipt fixture operation succeeds");
    report(
        &mut reports,
        "fresh-archived",
        streams
            .get_stream("ws")
            .expect("synthetic receipt fixture operation succeeds")
            .expect("synthetic receipt fixture operation succeeds")
            .boundary_receipt("workspace")
            .expect("synthetic receipt fixture operation succeeds"),
    );
    let refused = fork_at_cut_and_admit(
        &mut streams,
        &mut vcs,
        "parent",
        "chat-1",
        "late",
        "chat-late",
        None,
        ExactForkDestination::Workstream("ws"),
        "t7",
    )
    .expect("synthetic receipt fixture operation succeeds");
    report(&mut reports, "fresh-closed-home-refusal", refused.receipt());

    for (case, file) in [
        ("fork", "source-home.json"),
        ("fork", "fork.json"),
        ("archived", "boundary.json"),
        ("landed", "boundary.json"),
    ] {
        report(
            &mut reports,
            &format!("retained-{case}-{file}"),
            expected(case, file),
        );
    }
    let fixture = Fixture::load("fork");
    let (mut old_streams, mut old_vcs) = fixture.open();
    report(
        &mut reports,
        "upgraded-home",
        old_streams
            .home_receipt("chat")
            .expect("synthetic receipt fixture operation succeeds"),
    );
    let retried = fork_at_cut_and_admit(
        &mut old_streams,
        &mut old_vcs,
        "parent",
        "chat-1",
        "child",
        "chat-child",
        None,
        ExactForkDestination::Workstream("ws"),
        "after-upgrade",
    )
    .expect("synthetic receipt fixture operation succeeds");
    report(&mut reports, "upgraded-fork", retried.receipt());
    let archived = Fixture::load("archived");
    let (archived_streams, _archived_vcs) = archived.open();
    report(
        &mut reports,
        "upgraded-archived",
        archived_streams
            .get_stream("ws")
            .expect("synthetic receipt fixture operation succeeds")
            .expect("synthetic receipt fixture operation succeeds")
            .boundary_receipt("workspace")
            .expect("synthetic receipt fixture operation succeeds"),
    );
    println!(
        "{}",
        serde_json::to_string(&reports).expect("synthetic receipt fixture operation succeeds")
    );
}
