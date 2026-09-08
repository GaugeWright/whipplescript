//! The kernel-owned reconciliation journey against both actual SQL stores.
use whipplescript_host_do::do_store::{test_support::RusqliteDoSql, DoSqliteStore};
use whipplescript_kernel::effect_reconciliation::conformance::journey;
use whipplescript_store::native_stores::NativeStores;

#[test]
fn authenticated_reconciliation_has_human_agent_and_native_do_parity() {
    let mut outcomes = Vec::new();
    for actor in ["person:1", "agent:1"] {
        outcomes.push(journey(NativeStores::open_in_memory().unwrap(), actor));
        outcomes.push(journey(
            DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
            actor,
        ));
    }
    assert!(outcomes.windows(2).all(|pair| pair[0] == pair[1]));
}
