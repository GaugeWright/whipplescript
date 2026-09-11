//! Storage variants for governed tracker conformance, not a product host.
use std::{path::Path, sync::Arc};
use whipplescript_store::{
    coordination::CoordinationStore,
    items::WorkItemStore,
    native_stores::NativeStores,
    payload_protection::{PayloadCodec, PayloadProtection},
    SqliteStore, StoreResult,
};

// Deliberately reversible fixture encoding. This tests native codec dispatch
// and exact coordinates, not cryptographic strength or a host's key custody.
struct CoordinateCodec;
impl PayloadCodec for CoordinateCodec {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> StoreResult<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            aad,
            plaintext.iter().map(|byte| byte ^ 93).collect::<Vec<_>>(),
        ))?)
    }

    fn open(&self, aad: &[u8], ciphertext: &[u8]) -> StoreResult<Vec<u8>> {
        let (coordinate, encoded): (Vec<u8>, Vec<u8>) = serde_json::from_slice(ciphertext)?;
        assert_eq!(
            coordinate, aad,
            "governed fixture changed payload coordinates"
        );
        Ok(encoded.iter().map(|byte| byte ^ 93).collect())
    }

    fn retain(&self, publish: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
        publish()
    }
}

fn protection() -> PayloadProtection {
    PayloadProtection::new("tracker-conformance", Arc::new(CoordinateCodec))
        .expect("fixture protection domain")
}

pub(super) fn memory(protected: bool) -> NativeStores {
    if !protected {
        return NativeStores::open_in_memory().expect("plain fixture stores");
    }
    NativeStores {
        runtime: SqliteStore::open_in_memory_protected(protection())
            .expect("protected fixture runtime"),
        items: WorkItemStore::open_in_memory_protected(protection())
            .expect("protected fixture tracker"),
        coord: CoordinationStore::open_in_memory_protected(protection())
            .expect("protected fixture coordination"),
        frontier: None,
    }
}

pub(super) fn create(root: &Path, protected: bool) -> NativeStores {
    if !protected {
        return NativeStores::open(
            root.join("runtime.sqlite"),
            root.join("coord.sqlite"),
            root.join("items.sqlite"),
        )
        .expect("fixture store operation");
    }
    NativeStores {
        runtime: SqliteStore::create_protected(root.join("runtime.sqlite"), protection())
            .expect("create protected fixture runtime"),
        items: WorkItemStore::create_protected(root.join("items.sqlite"), protection())
            .expect("create protected fixture tracker"),
        coord: CoordinationStore::create_protected(root.join("coord.sqlite"), protection())
            .expect("create protected fixture coordination"),
        frontier: None,
    }
}

pub(super) fn reopen(root: &Path, protected: bool) -> NativeStores {
    if !protected {
        return NativeStores::open_existing(
            root.join("runtime.sqlite"),
            root.join("coord.sqlite"),
            root.join("items.sqlite"),
        )
        .expect("fixture store operation");
    }
    NativeStores {
        runtime: SqliteStore::open_existing_protected(root.join("runtime.sqlite"), protection())
            .expect("reopen protected fixture store"),
        items: WorkItemStore::open_existing_protected(root.join("items.sqlite"), protection())
            .expect("reopen protected fixture store"),
        coord: CoordinationStore::open_existing_protected(root.join("coord.sqlite"), protection())
            .expect("reopen protected fixture coordination"),
        frontier: None,
    }
}

/// Inspect the real files, including live WAL copies. Logical decoded reads
/// are asserted by the caller; this checks that those bytes did not also escape
/// into the underlying runtime, tracker, or otherwise unused coordination store.
pub(super) fn assert_sealed(root: &Path, protected: bool) {
    if !protected {
        return;
    }
    let mut files = 0;
    for entry in std::fs::read_dir(root).expect("list native fixture files") {
        let path = entry.expect("native fixture file").path();
        let bytes = std::fs::read(&path).expect("read native fixture bytes");
        files += 1;
        for canary in [
            "PRIVATE_TASK_BODY",
            "Self-reported completion",
            "Instructions",
        ] {
            assert!(
                !bytes
                    .windows(canary.len())
                    .any(|window| window == canary.as_bytes()),
                "private payload {canary:?} escaped into {}",
                path.display(),
            );
        }
    }
    assert!(files >= 3, "fixture must inspect the actual native stores");
}
