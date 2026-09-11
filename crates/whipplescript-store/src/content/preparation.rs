//! Derived preparation cannot restore an erased identity. The content owner
//! serializes its ledger check and byte preparation; reference publication is
//! a separate operation after this preparation commits.
use super::ContentBlobs;
use crate::{StoreError, StoreResult};

pub fn require_unerased(erased: bool) -> StoreResult<()> {
    if erased {
        return Err(StoreError::Conflict(
            "derived content identity was erased".into(),
        ));
    }
    Ok(())
}

#[cfg(feature = "native")]
pub(super) fn native_prepare(store: &super::ContentStore, body: &[u8]) -> StoreResult<String> {
    let transaction = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    let id = crate::stable_hash_bytes_hex(body);
    require_unerased(store.erased_byte_len(&id)?.is_some())?;
    let prepared = store.put(body)?;
    transaction.commit()?;
    Ok(prepared)
}

/// Run against actual authorities supporting preparation and erasure. A
/// backend declining the capability does not pass this positive contract.
pub mod conformance {
    use super::*;
    pub fn check<C: ContentBlobs>(make: impl Fn() -> C) {
        let store = make();
        let body = b"exact derived bytes\n";
        let id = store.put_unerased(body).expect("prepare");
        assert_eq!(id, crate::stable_hash_bytes_hex(body));
        assert_eq!(store.put_unerased(body).expect("retry"), id);
        assert_eq!(
            store.get(&id).expect("read").as_deref(),
            Some(body.as_slice())
        );
        store
            .publish_retained(std::slice::from_ref(&id), || Ok(()))
            .expect("publish");
        assert!(matches!(
            store.erase(&id, "erase").expect("erase"),
            super::super::EraseOutcome::Erased { .. }
        ));
        assert!(
            store.put_unerased(body).is_err(),
            "derived preparation must not recreate an erased input"
        );
        assert!(store.get(&id).expect("still erased").is_none());
        // A raw copy cannot override ledger authority for derived preparation.
        store.put(body).expect("ordinary raw put");
        assert!(
            store.put_unerased(body).is_err(),
            "live bytes cannot erase historical tombstones"
        );
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::super::ContentStore;
    use super::*;
    #[test]
    fn native_preparation_preserves_erasure_under_replay_and_reopen() {
        conformance::check(|| ContentStore::open(":memory:").unwrap());
        let path = std::env::temp_dir().join(format!(
            "whipple-input-preparation-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let body = b"saved-source input";
        let store = ContentStore::open(&path).unwrap();
        let id = store.put_unerased(body).unwrap();
        store.erase(&id, "erase").unwrap();
        drop(store);
        let store = ContentStore::open(&path).unwrap();
        assert!(store.put_unerased(body).is_err());
        assert!(store.get(&id).unwrap().is_none());
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn unsupported_preparation_refuses_without_using_ordinary_put() {
        struct Unsupported {
            inner: ContentStore,
            calls: std::cell::Cell<usize>,
        }
        impl ContentBlobs for Unsupported {
            fn put(&self, body: &[u8]) -> StoreResult<String> {
                self.calls.set(self.calls.get() + 1);
                self.inner.put(body)
            }
            fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
                self.calls.set(self.calls.get() + 1);
                self.inner.get(id)
            }
        }
        let make = || Unsupported {
            inner: ContentStore::open(":memory:").unwrap(),
            calls: Default::default(),
        };
        super::super::conformance::run_suite(make).unwrap();
        let unsupported = make();
        assert!(unsupported.put_unerased(b"input").is_err());
        assert_eq!(
            unsupported.calls.get(),
            0,
            "ordinary storage is no atomic fallback"
        );
    }
}
