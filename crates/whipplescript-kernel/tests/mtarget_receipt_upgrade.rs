#![cfg(feature = "native")]
#[path = "../../whipplescript-store/tests/support/receipt_fixture.rs"]
mod receipt_fixture;

use receipt_fixture::{expected, Fixture};
use whipplescript_kernel::effect_handlers::{
    run_reserved_boundary_promotion_generic, BoundaryRunOutcome, PromoteDoorRequest,
    SingleWriterSerialization,
};
use whipplescript_store::workstreams::{StreamStatus, Workstreams};

#[test]
fn old_post_cas_store_closes_forward_without_another_main_write() {
    let fixture = Fixture::load("landed");
    rusqlite::Connection::open(fixture.0.join("branches.sqlite"))
        .expect("legacy post-CAS fixture closes without a second Main write")
        .execute_batch(
            "CREATE TRIGGER forbid_second_main_cas BEFORE UPDATE ON branches
            WHEN OLD.branch_id = 'main' BEGIN SELECT RAISE(FAIL, 'second Main CAS'); END;",
        )
        .expect("legacy post-CAS fixture closes without a second Main write");
    for _ in 0..2 {
        let (mut streams, mut vcs) = fixture.open();
        let result = run_reserved_boundary_promotion_generic(
            &mut streams,
            &mut vcs,
            &PromoteDoorRequest {
                stream_id: "ws",
                reservation_id: "unused-new-token",
                proposed_main: "unused-new-cut",
                at: "t4",
                receipt_scope: "workspace",
            },
            &mut SingleWriterSerialization,
        )
        .expect("legacy post-CAS fixture closes without a second Main write");
        let BoundaryRunOutcome::Promoted { receipt, .. } = result else {
            panic!("{result:?}")
        };
        assert_eq!(
            serde_json::to_value(receipt)
                .expect("legacy post-CAS fixture closes without a second Main write"),
            expected("archived", "boundary.json")
        );
        assert_eq!(
            streams
                .get_stream("ws")
                .expect("legacy post-CAS fixture closes without a second Main write")
                .expect("legacy post-CAS fixture closes without a second Main write")
                .status,
            StreamStatus::Archived
        );
        assert_eq!(
            vcs.get_branch("main")
                .expect("legacy post-CAS fixture closes without a second Main write")
                .expect("legacy post-CAS fixture closes without a second Main write")
                .head_cut_id
                .as_deref(),
            Some("main-2")
        );
        assert_eq!(
            vcs.branch_head_reservation("line")
                .expect("legacy post-CAS fixture closes without a second Main write"),
            None
        );
        assert!(vcs
            .get_cut("unused-new-cut")
            .expect("legacy post-CAS fixture closes without a second Main write")
            .is_none());
    }
}
