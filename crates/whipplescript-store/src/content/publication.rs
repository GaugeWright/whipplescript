//! Prepared bytes must remain readable until their reference is published.
//! The callback publishes references only; payload writes commit beforehand.
use super::ContentBlobs;
use crate::{StoreError, StoreResult};

pub fn verify_prepared(store: &(impl ContentBlobs + ?Sized), ids: &[String]) -> StoreResult<()> {
    for id in ids {
        if store.get(id)?.is_none() {
            return Err(StoreError::Conflict(format!(
                "prepared publication content is unavailable: {id}"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "native")]
pub(super) fn native_publish<T>(
    store: &super::ContentStore,
    ids: &[String],
    publish: impl FnOnce() -> StoreResult<T>,
) -> StoreResult<T> {
    // No content is written in this transaction. A branch commit can survive
    // its rollback because the prepared bytes committed before we entered it.
    let transaction = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )?;
    verify_prepared(store, ids)?;
    let result = publish()?;
    transaction.commit()?;
    Ok(result)
}

/// Captures only the blobs prepared by this change, preserving incremental
/// manifest updates. Reads retain their original store semantics.
pub(crate) struct PreparedBlobs<'a, C> {
    inner: &'a C,
    ids: std::cell::RefCell<std::collections::BTreeSet<String>>,
}
impl<'a, C: ContentBlobs> PreparedBlobs<'a, C> {
    pub(crate) fn new(inner: &'a C) -> Self {
        Self {
            inner,
            ids: Default::default(),
        }
    }
    pub(crate) fn ids(&self) -> Vec<String> {
        self.ids.borrow().iter().cloned().collect()
    }
}
impl<C: ContentBlobs> ContentBlobs for PreparedBlobs<'_, C> {
    fn put(&self, body: &[u8]) -> StoreResult<String> {
        let id = self.inner.put(body)?;
        self.ids.borrow_mut().insert(id.clone());
        Ok(id)
    }
    fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
        self.inner.get(id)
    }
}

/// Both real authorities run these obligations; declining publication is not
/// a passing implementation of this suite.
pub mod conformance {
    use super::*;
    use std::cell::Cell;

    pub fn check<C: ContentBlobs>(make: impl Fn() -> C) {
        let store = make();
        let id = store.put_text("durable preparation").expect("prepare");
        let calls = Cell::new(0);
        assert_eq!(
            store
                .publish_retained(std::slice::from_ref(&id), || {
                    calls.set(calls.get() + 1);
                    Ok(42)
                })
                .expect("publish"),
            42
        );
        assert_eq!(calls.get(), 1);
        for missing in ["missing".to_owned(), {
            let erased = store.put_text("erased preparation").expect("prepare");
            assert!(matches!(
                store.erase(&erased, "t1").expect("erase"),
                crate::content::EraseOutcome::Erased { .. }
            ));
            erased
        }] {
            let error = store
                .publish_retained(&[id.clone(), missing], || {
                    calls.set(calls.get() + 1);
                    Ok(())
                })
                .expect_err("unavailable preparation");
            assert!(format!("{error:?}").contains("prepared publication content is unavailable"));
            assert_eq!(calls.get(), 1, "refusal must precede publication");
        }
        let error = store
            .publish_retained(std::slice::from_ref(&id), || {
                Err::<(), _>(StoreError::Conflict("publication refused".into()))
            })
            .expect_err("propagate publication failure");
        assert!(format!("{error:?}").contains("publication refused"));
        assert_eq!(
            store.get(&id).expect("durable payload").as_deref(),
            Some(&b"durable preparation"[..])
        );
        store
            .publish_retained(&[id], || Ok(()))
            .expect("exclusion released after failure");
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::content::ContentStore;
    use std::cell::Cell;

    fn content() -> ContentStore {
        ContentStore::open(":memory:").expect("content")
    }

    #[test]
    fn native_and_cached_authorities_obey_retained_publication() {
        conformance::check(content);
        conformance::check(|| crate::read_through::ReadThrough::new(content(), content()));
    }

    #[test]
    fn prepared_blob_tracking_preserves_content_and_records_every_write() {
        // The factory lends a distinct authority to each driver case. The
        // bounded pool lives until every borrowed wrapper has been dropped.
        let stores: [_; 8] = std::array::from_fn(|_| content());
        let next = Cell::new(0);
        crate::content::conformance::run_suite(|| {
            let index = next.get();
            next.set(index + 1);
            PreparedBlobs::new(&stores[index])
        })
        .expect("content conformance");
        let store = content();
        let prepared = PreparedBlobs::new(&store);
        let first = prepared.put_text("first").expect("put");
        let second = prepared.put_text("second").expect("put");
        prepared.put_text("first").expect("deduplicated put");
        let read_only = store.put_text("only read").expect("external put");
        prepared.get(&read_only).expect("read");
        let mut expected = vec![first, second];
        expected.sort();
        assert_eq!(prepared.ids(), expected);
        let called = Cell::new(false);
        let error = prepared
            .publish_retained(&expected, || {
                called.set(true);
                Ok(())
            })
            .expect_err("preparation is not publication authority");
        assert!(format!("{error:?}")
            .contains("content authority does not support retained publication"));
        assert!(!called.get());
    }

    #[test]
    fn a_cached_copy_cannot_publish_erased_authority_content() {
        let cache = content();
        let authority = content();
        let id = authority.put_text("protected").expect("prepare");
        cache.put_text("protected").expect("cache");
        authority.erase(&id, "t1").expect("erase authority");
        assert!(cache
            .get(&id)
            .expect("physical cache retains the copy")
            .is_some());
        let cached = crate::read_through::ReadThrough::new(cache, authority);
        assert_eq!(cached.get(&id).expect("erasure-aware read"), None);
        let called = Cell::new(false);
        let error = cached
            .publish_retained(&[id], || {
                called.set(true);
                Ok(())
            })
            .expect_err("cache is not retention authority");
        assert!(format!("{error:?}").contains("prepared publication content is unavailable"));
        assert!(!called.get());
    }

    #[test]
    fn an_older_collector_cannot_reopen_content_generation_two() {
        let store = content();
        assert!(matches!(
            crate::stamp_satellite_schema(&store.connection, "content", 1),
            Err(StoreError::UnsupportedVersion {
                found: 2,
                supported: 1,
                ..
            })
        ));
    }

    #[test]
    fn publication_excludes_collection_before_its_root_read_and_survives_callback_loss() {
        use crate::branches::{
            AdvanceOutcome, BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID,
        };
        use crate::vcs::NativeWorkspaceVcs;
        use std::collections::BTreeMap;
        struct Directory(std::path::PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        for lose_callback in [false, true] {
            let directory = Directory(std::env::temp_dir().join(format!(
                    "whip-publication-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("clock")
                        .as_nanos()
                )));
            std::fs::create_dir_all(&directory.0).expect("fixture directory");
            let content_path = directory.0.join("content.sqlite");
            let branch_path = directory.0.join("branches.sqlite");
            let content = ContentStore::open(&content_path).expect("publisher content");
            let mut branches = BranchStore::open(&branch_path).expect("publisher branches");
            branches.ensure_mainline("t0").expect("init");
            let mut collector =
                NativeWorkspaceVcs::open(&branch_path, &content_path).expect("collector");
            collector
                .content_store()
                .connection
                .busy_timeout(std::time::Duration::ZERO)
                .expect("nonblocking competitor");
            let id = content
                .put_text("durably prepared before publication")
                .expect("prepare body");
            let manifest = crate::manifest_tree::build(
                &content,
                &BTreeMap::from([("file.txt".into(), id.clone())]),
            )
            .expect("prepare manifest");
            let roots_read = Cell::new(false);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                content.publish_retained(&[id.clone(), manifest.clone()], || {
                    // A competing collector cannot take a stale snapshot and
                    // then wait for this publication to finish before deleting.
                    assert!(collector
                        .content_store()
                        .purge_unreachable(|| {
                            roots_read.set(true);
                            Ok(Default::default())
                        })
                        .is_err());
                    assert!(
                        !roots_read.get(),
                        "collection must lock before reading roots"
                    );
                    assert!(collector.content_store().erase(&id, "t1").is_err());
                    assert!(matches!(
                        branches.commit_write(CutRecord {
                            cut_id: "saved",
                            change_id: "saved",
                            branch_id: MAINLINE_BRANCH_ID,
                            manifest_hash: &manifest,
                            parent_cut_id: None,
                            origin: Some("write:file.txt"),
                            actor: Some("person:one"),
                            intent: None,
                            recorded_at: "t1",
                        })?,
                        AdvanceOutcome::Advanced(_)
                    ));
                    assert!(!lose_callback, "lost callback after branch commit");
                    Ok(())
                })
            }));
            if lose_callback {
                assert!(result.is_err());
            } else {
                result.expect("no panic").expect("publication");
            }
            collector
                .purge_unreachable("t2")
                .expect("collection after publication");
            assert_eq!(
                collector
                    .read_at_cut("saved", "file.txt")
                    .expect("published content")
                    .as_deref(),
                Some("durably prepared before publication")
            );
            collector
                .content_store()
                .erase(&id, "t3")
                .expect("explicit later erasure");
            assert!(collector
                .content_store()
                .get(&id)
                .expect("erasure retained")
                .is_none());
        }
    }
}
