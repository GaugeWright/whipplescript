//! A host that is not the CLI can seed the std package manifests.
//!
//! Since 0.2.2 the admission gate is real for `std.files` and friends: an
//! effect whose capability rows were never seeded blocks as
//! `blocked_by_capability`. The manifests therefore have to be reachable from
//! the library, not only the binary — otherwise an embedding host either
//! cannot run governed effects or reimplements the seeding and drifts, which
//! is exactly what the library surface exists to prevent.

use whipplescript::std_manifests::{register_all, EMBEDDED_STD_MANIFESTS};
use whipplescript_store::SqliteStore;

fn store() -> SqliteStore {
    SqliteStore::open_in_memory().expect("opens")
}

#[test]
fn the_manifests_are_reachable_from_the_library() {
    assert!(
        !EMBEDDED_STD_MANIFESTS.is_empty(),
        "a host needs the manifest set to seed a store",
    );
    assert!(
        EMBEDDED_STD_MANIFESTS
            .iter()
            .any(|(name, _)| *name == "std.files"),
        "std.files is the one a workflow reading a file store needs",
    );
}

#[test]
fn a_host_can_seed_a_store_and_repeat_it() {
    let store = store();
    register_all(&store).expect("seeds");
    // Idempotent: every write is ON CONFLICT DO UPDATE, so a host that seeds on
    // every open does not accumulate or fail.
    register_all(&store).expect("re-seeds");
}

#[test]
fn every_shipped_manifest_registers() {
    // One bad manifest would otherwise surface as a mid-run capability block
    // rather than at seed time.
    let store = store();
    for (name, json) in EMBEDDED_STD_MANIFESTS {
        store
            .register_package_manifest(json)
            .unwrap_or_else(|error| panic!("`{name}` failed to register: {error:?}"));
    }
}
