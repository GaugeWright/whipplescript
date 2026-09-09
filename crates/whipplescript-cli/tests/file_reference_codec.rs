//! Run the kernel-owned reference boundary fixture on both actual stores.
use whipplescript_host_do::do_store::{test_support::RusqliteDoSql, DoSqliteStore};
pub use whipplescript_kernel::{effect_handlers, RuntimeKernel};
use whipplescript_store::native_stores::NativeStores;
#[path = "../../whipplescript-kernel/src/effect_handlers/reference_conformance.rs"]
mod reference_conformance;

#[test]
fn reference_codec_preserves_boundaries_on_both_runtime_stores() {
    reference_conformance::check(|| {
        NativeStores::open_in_memory().expect("native reference fixture")
    });
    reference_conformance::check(|| DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()));
}
