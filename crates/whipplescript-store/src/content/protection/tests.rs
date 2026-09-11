use super::*;
use crate::payload_protection::PayloadCodec;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, RwLock,
};

// A reversible test codec, not a cryptographic implementation. It records and
// checks the AAD contract; production cryptography and keys belong to the host.
struct Codec {
    available: AtomicBool,
    retention: RwLock<()>,
    key: u8,
}
impl Codec {
    fn new(key: u8) -> Arc<Self> {
        Arc::new(Self {
            available: AtomicBool::new(true),
            retention: RwLock::new(()),
            key,
        })
    }
    fn require_key(&self) -> StoreResult<()> {
        if self.available.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StoreError::fault("test codec", "key unavailable"))
        }
    }
    fn erase_key(&self) {
        let _guard = self.retention.write().unwrap();
        self.available.store(false, Ordering::SeqCst);
    }
}
impl PayloadCodec for Codec {
    fn seal(&self, aad: &[u8], plaintext: &[u8]) -> StoreResult<Vec<u8>> {
        self.require_key()?;
        let masked: Vec<u8> = plaintext.iter().map(|b| b ^ self.key).collect();
        Ok(serde_json::to_vec(&(aad, masked))?)
    }
    fn open(&self, aad: &[u8], ciphertext: &[u8]) -> StoreResult<Vec<u8>> {
        self.require_key()?;
        let (bound, masked): (Vec<u8>, Vec<u8>) = serde_json::from_slice(ciphertext)?;
        if bound != aad {
            return Err(StoreError::fault("test codec", "different associated data"));
        }
        Ok(masked.iter().map(|b| b ^ self.key).collect())
    }
    fn retain(&self, publish: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
        let _guard = self.retention.read().unwrap();
        self.require_key()?;
        publish()
    }
}
fn protection(domain: &str, codec: Arc<Codec>) -> PayloadProtection {
    PayloadProtection::new(domain, codec).unwrap()
}
fn store() -> ContentStore {
    ContentStore::open_in_memory_protected(protection("project-A", Codec::new(73))).unwrap()
}
struct Fixture(std::path::PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "whip-protection-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn path(&self) -> std::path::PathBuf {
        self.0.join("content.sqlite")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn protected_blobs_preserve_the_content_preparation_and_publication_contracts() {
    crate::content::conformance::run_suite(store).unwrap();
    crate::content::preparation::conformance::check(store);
    crate::content::publication::conformance::check(store);
}

#[test]
fn protected_reopen_requires_original_domain_and_never_converts_existing_stores() {
    let fixture = Fixture::new();
    let codec = Codec::new(73);
    let binding = protection("project-A", codec.clone());
    let store = ContentStore::create_protected(fixture.path(), binding.clone()).unwrap();
    let secret = b"private workflow customer payload";
    let id = store.put(secret).unwrap();
    assert_eq!(id, crate::stable_hash_bytes_hex(secret));
    assert_eq!(store.put(secret).unwrap(), id);
    store
        .connection
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let disk = std::fs::read(fixture.path()).unwrap();
    assert!(!disk.windows(secret.len()).any(|part| part == secret));
    drop(store);
    assert!(ContentStore::open(fixture.path()).is_err());
    assert!(ContentStore::open_existing(fixture.path()).is_err());
    assert!(ContentStore::open_read_only(fixture.path()).is_err());
    assert!(ContentStore::open_for_retained_publication(fixture.path()).is_err());
    assert!(ContentStore::create_protected(fixture.path(), binding.clone()).is_err());
    assert!(
        ContentStore::open_existing_protected(fixture.path(), protection("project-B", codec))
            .is_err()
    );
    let read = ContentStore::open_read_only_protected(fixture.path(), binding.clone()).unwrap();
    assert_eq!(read.get(&id).unwrap().as_deref(), Some(secret.as_slice()));
    assert!(read.put(b"read only").is_err());
    assert!(read
        .publish_retained(std::slice::from_ref(&id), || Ok(()))
        .is_err());
    drop(read);
    let reopened = ContentStore::open_existing_protected(fixture.path(), binding).unwrap();
    assert_eq!(
        reopened.get(&id).unwrap().as_deref(),
        Some(secret.as_slice())
    );
    assert_eq!(
        reopened.status(&id).unwrap(),
        BlobStatus::Live {
            byte_len: secret.len() as u64
        }
    );
    let plain = fixture.0.join("plain.sqlite");
    ContentStore::open(&plain)
        .unwrap()
        .put(b"old plaintext")
        .unwrap();
    assert!(
        ContentStore::open_existing_protected(&plain, protection("project-A", Codec::new(73)))
            .is_err()
    );
    assert!(ContentStore::open_existing_protected(
        fixture.0.join("missing"),
        protection("project-A", Codec::new(73))
    )
    .is_err());
    assert!(!fixture.0.join("missing").exists());
    assert!(PayloadProtection::new(" ", Codec::new(1)).is_err());
}

#[test]
fn unavailable_keys_and_transplanted_ciphertext_never_become_plaintext_or_absence() {
    let codec = Codec::new(73);
    let store =
        ContentStore::open_in_memory_protected(protection("project-A", codec.clone())).unwrap();
    let a = store.put(b"first secret").unwrap();
    let b = store.put(b"second secret").unwrap();
    store.connection.execute("UPDATE content_blobs SET body = (SELECT body FROM content_blobs WHERE id=?1) WHERE id=?2", params![a, b]).unwrap();
    assert!(
        store.get(&b).is_err(),
        "ciphertext is bound to its content coordinate"
    );
    codec.erase_key();
    assert!(store.get(&a).is_err());
    assert!(store.cached_read_available(&a).is_err());
    assert!(store.put(b"must not persist").is_err());
    let called = std::cell::Cell::new(false);
    assert!(store
        .publish_retained(std::slice::from_ref(&a), || {
            called.set(true);
            Ok(())
        })
        .is_err());
    assert!(!called.get());
    assert_eq!(store.status(&a).unwrap(), BlobStatus::Live { byte_len: 12 });
    assert_eq!(store.get("unknown").unwrap(), None);
    let fixture = Fixture::new();
    let original =
        ContentStore::create_protected(fixture.path(), protection("project-A", Codec::new(1)))
            .unwrap();
    let id = original.put(b"wrong key cannot read this").unwrap();
    drop(original);
    let wrong = ContentStore::open_existing_protected(
        fixture.path(),
        protection("project-A", Codec::new(2)),
    )
    .unwrap();
    assert!(wrong.get(&id).is_err());
}

#[test]
fn packs_and_erasure_never_reinline_plaintext() {
    let store = store();
    let first = "first private chunk";
    let second = "second private chunk";
    let third = "third private chunk";
    let ids = [first, second, third].map(|s| store.put(s.as_bytes()).unwrap());
    let body = format!("{first}{second}{third}");
    let root = crate::stable_hash_bytes_hex(body.as_bytes());
    store
        .put_chunk_root(&root, &ids, body.len() as u64)
        .unwrap();
    assert_eq!(store.pack_root(&root).unwrap(), 3);
    assert_eq!(store.get(&root).unwrap().as_deref(), Some(body.as_bytes()));
    assert_eq!(
        store.erase(&ids[0], "erase").unwrap(),
        EraseOutcome::Erased {
            byte_len: first.len() as u64
        }
    );
    assert_eq!(
        store.get(&ids[1]).unwrap().as_deref(),
        Some(second.as_bytes())
    );
    assert!(store.get(&ids[0]).unwrap().is_none());
    let rows: Vec<Vec<u8>> = store
        .connection
        .prepare("SELECT body FROM content_blobs")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for row in rows {
        for secret in [first, second, third] {
            assert!(!row
                .windows(secret.len())
                .any(|part| part == secret.as_bytes()));
        }
    }
    // Root erasure takes a different unpacking path; exercise it separately.
    let store = self::store();
    let root = store
        .put_chunked(
            &body,
            &crate::chunking::ChunkingConfig {
                whole_blob_threshold: 8,
                min_size: 4,
                avg_size: 8,
                max_size: 32,
            },
        )
        .unwrap();
    assert!(store.pack_root(&root).unwrap() > 0);
    assert!(matches!(
        store.erase(&root, "erase-root").unwrap(),
        EraseOutcome::Erased { .. }
    ));
    assert!(store.get(&root).unwrap().is_none());
    assert!(matches!(
        store.status(&root).unwrap(),
        BlobStatus::Erased { .. }
    ));
}

#[test]
fn missing_mode_metadata_cannot_be_reinitialized_as_plaintext() {
    for damage in [
        "DROP TABLE content_payload_protection",
        "DELETE FROM content_payload_protection",
    ] {
        let fixture = Fixture::new();
        let binding = protection("project-A", Codec::new(73));
        let store = ContentStore::create_protected(fixture.path(), binding.clone()).unwrap();
        store.connection.execute_batch(damage).unwrap();
        drop(store);
        assert!(ContentStore::open(fixture.path()).is_err());
        assert!(ContentStore::open_read_only(fixture.path()).is_err());
        assert!(ContentStore::open_existing_protected(fixture.path(), binding).is_err());
    }
    let existing = Connection::open_in_memory().unwrap();
    existing
        .execute_batch("CREATE TABLE existing(value TEXT)")
        .unwrap();
    assert!(
        ContentStore::initialize_protected(existing, protection("project-A", Codec::new(73)))
            .is_err()
    );
}

#[test]
fn malformed_native_bytes_are_storage_corruption_before_codec_resolution() {
    for protected in [false, true] {
        let store = if protected {
            store()
        } else {
            ContentStore::open(":memory:").unwrap()
        };
        let id = store.put(b"content").unwrap();
        store.connection.execute_batch("ALTER TABLE content_blobs RENAME TO damaged_blobs; CREATE VIEW content_blobs AS SELECT id, NULL AS body FROM damaged_blobs;").unwrap();
        // Operators must see storage corruption, not a missing blob, unavailable
        // key or a later JSON-codec error. Exercise both storage modes.
        let error = store.get(&id).unwrap_err();
        assert!(matches!(error, StoreError::Fault { subject, detail }
            if subject == "content protection" && detail == "invalid retained blob representation"));
        assert!(store.get("unknown").unwrap().is_none());
    }
}

#[test]
fn retained_publication_excludes_key_erasure_until_references_commit() {
    let codec = Codec::new(73);
    let store =
        ContentStore::open_in_memory_protected(protection("project-A", codec.clone())).unwrap();
    let id = store.put(b"prepared bytes").unwrap();
    let (start, receive) = std::sync::mpsc::channel();
    let (observed, observed_rx) = std::sync::mpsc::channel();
    let eraser_codec = codec.clone();
    let eraser = std::thread::spawn(move || {
        receive.recv().unwrap();
        assert!(
            eraser_codec.retention.try_write().is_err(),
            "publication must hold key retention"
        );
        observed.send(()).unwrap();
        eraser_codec.erase_key();
    });
    store
        .publish_retained(std::slice::from_ref(&id), || {
            start.send(()).unwrap();
            observed_rx.recv().unwrap();
            assert_eq!(
                store.get(&id).unwrap().as_deref(),
                Some(b"prepared bytes".as_slice())
            );
            Ok(())
        })
        .unwrap();
    eraser.join().unwrap();
    assert!(store.get(&id).is_err());
}

#[test]
fn payload_coordinates_and_retention_callbacks_cannot_be_substituted() {
    let first = protection("project-A", Codec::new(73));
    let second = protection("project-B", Codec::new(73));
    let sealed = first.seal("content.blob", "id", b"payload").unwrap();
    assert!(second.open("content.blob", "id", &sealed).is_err());
    assert!(first.open("runtime.fact", "id", &sealed).is_err());
    assert!(first.open("content.blob", "other-id", &sealed).is_err());
    struct BrokenRetainer {
        calls: usize,
        propagate: bool,
    }
    impl PayloadCodec for BrokenRetainer {
        fn seal(&self, _: &[u8], _: &[u8]) -> StoreResult<Vec<u8>> {
            unreachable!()
        }
        fn open(&self, _: &[u8], _: &[u8]) -> StoreResult<Vec<u8>> {
            unreachable!()
        }
        fn retain(&self, callback: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
            for _ in 0..self.calls {
                let result = callback();
                if self.propagate {
                    result?;
                }
            }
            Ok(())
        }
    }
    for count in [0, 2] {
        let bad = PayloadProtection::new(
            "domain",
            Arc::new(BrokenRetainer {
                calls: count,
                propagate: false,
            }),
        )
        .unwrap();
        let invoked = std::cell::Cell::new(0);
        assert!(bad
            .retain(|| {
                invoked.set(invoked.get() + 1);
                Ok(())
            })
            .is_err());
        assert_eq!(invoked.get(), usize::from(count > 0));
    }
    let repeating = PayloadProtection::new(
        "domain",
        Arc::new(BrokenRetainer {
            calls: 2,
            propagate: true,
        }),
    )
    .unwrap();
    let error = repeating.retain(|| Ok(())).unwrap_err();
    assert!(matches!(error, StoreError::Fault { subject, detail }
        if subject == "payload protection" && detail == "codec repeated retained publication"));
    let swallowing = PayloadProtection::new(
        "domain",
        Arc::new(BrokenRetainer {
            calls: 1,
            propagate: false,
        }),
    )
    .unwrap();
    let content = store();
    let error = swallowing
        .retain(|| crate::content::publication::verify_prepared(&content, &["missing".into()]))
        .unwrap_err();
    assert!(matches!(error, StoreError::Fault { subject, detail }
        if subject == "payload protection" && detail == "codec omitted retained publication"));
}

#[test]
fn protected_read_only_open_refuses_unknown_schema_generation() {
    let fixture = Fixture::new();
    let binding = protection("project-A", Codec::new(73));
    let store = ContentStore::create_protected(fixture.path(), binding.clone()).unwrap();
    store
        .connection
        .execute("UPDATE schema_migrations SET version=999", [])
        .unwrap();
    drop(store);
    assert!(ContentStore::open_read_only_protected(fixture.path(), binding).is_err());
}
