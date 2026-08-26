//! DR-0070 §3 / DR-0066 §2: content is served by an authority plus
//! **read-through caches, never peer replicas**.
//!
//! The distinction is the whole of DR-0066's content-plane argument, and it is
//! easy to lose in implementation. A *replica* has an independent write path,
//! so it can diverge and a reader cannot tell which copy is right. A *cache*
//! holds `hash → bytes` entries that can never change, so it has nothing to
//! diverge about — it can be colder or slower than the authority, never wrong.
//!
//! One rule makes the difference, and it is the rule this type exists to
//! enforce: **a cache may never answer "I don't have it" on its own.** A miss
//! is not an answer; it is a reason to ask the authority. A cache that reports
//! `Unknown` from its own emptiness has silently become a replica with a very
//! bad replication protocol, and every conclusion the design draws from
//! content-addressing stops holding.
//!
//! **A mismatch is refused, not repaired.** Pulling through on a bad cache
//! entry would hand the caller correct bytes and overwrite the bad ones, which
//! is what a cache ordinarily should do. It is refused here because a cache
//! returning bytes that are not the bytes asked for is a fault about which
//! nothing else is known — the same store may be wrong in ways no hash catches
//! — and a self-healing read makes that fault invisible for exactly as long as
//! it stays survivable. DR-0068's gaps section reached the same conclusion for
//! a lapsed pin: "the honest resolution is refusal on resume, not silent
//! re-fetch."
//!
//! What is deliberately absent: eviction, size bounds, and cache warming. They
//! are policy over a correct core, and none of them changes what an answer
//! means. Any object store plugs in as the `authority` — choosing and
//! provisioning one is a deployment decision, and nothing in this file needs to
//! know which was made. (Named a vendor until 2026-08-25; DR-0071 refusal 1.)

use crate::content::{BlobStatus, ContentBlobs, EraseOutcome};
use crate::StoreResult;

/// An authority with a cache in front of it.
///
/// Reads consult the cache, fall through to the authority on a miss, and
/// populate on the way back. Writes go to the authority — a cache is never a
/// place where content originates, because content that exists only in a cache
/// is content the authority cannot serve to anyone else.
pub struct ReadThrough<C, A> {
    cache: C,
    authority: A,
}

impl<C: ContentBlobs, A: ContentBlobs> ReadThrough<C, A> {
    pub fn new(cache: C, authority: A) -> Self {
        Self { cache, authority }
    }

    /// The authority, for callers that must bypass the cache deliberately —
    /// erasure, for instance, which has to reach the bytes that matter.
    pub fn authority(&self) -> &A {
        &self.authority
    }
}

impl<C: ContentBlobs, A: ContentBlobs> ContentBlobs for ReadThrough<C, A> {
    /// Writes reach the authority. The cache is populated as a side effect,
    /// which is an optimization rather than part of the write: a cache that
    /// failed to accept the copy would not make the write less durable.
    fn put(&self, body: &str) -> StoreResult<String> {
        let id = self.authority.put(body)?;
        let _ = self.cache.put(body);
        Ok(id)
    }

    fn get(&self, id: &str) -> StoreResult<Option<String>> {
        if let Some(body) = self.cache.get(id)? {
            // THE VERIFICATION (DR-0066 §3). This is the boundary the whole
            // cache-is-not-a-replica argument rests on: a cache "can never be
            // wrong, only colder", and that is a property of content addressing
            // only if somebody actually checks. Unverified, this line hands the
            // caller whatever the cache said — which is the silent-wrong-bytes
            // failure the substrate exists to exclude, reached through the one
            // component added for speed.
            crate::content::verify_body(id, &body, "read-through cache")?;
            return Ok(Some(body));
        }
        // THE PULL-THROUGH. Without this the cache's emptiness would be
        // indistinguishable from the content not existing.
        let Some(body) = self.authority.get(id)? else {
            return Ok(None);
        };
        // The authority is verified too. It is more trusted than the cache, not
        // trusted — §3 is an obligation on readers, and "I got it from the
        // authority" is exactly the reasoning it refuses.
        crate::content::verify_body(id, &body, "content authority")?;
        let _ = self.cache.put(&body);
        Ok(Some(body))
    }

    /// Status is answered by the AUTHORITY whenever the cache does not hold the
    /// bytes, and this is the clause that keeps a cache from becoming a replica.
    ///
    /// A cache holding the bytes proves `Live`; that much it may answer alone.
    /// It can never prove `Erased` or `Unknown` — those are statements about
    /// what the authority knows, and a cache asserting them from its own
    /// emptiness would report content as gone that is merely elsewhere.
    fn status(&self, id: &str) -> StoreResult<BlobStatus> {
        if let BlobStatus::Live { byte_len } = self.cache.status(id)? {
            return Ok(BlobStatus::Live { byte_len });
        }
        self.authority.status(id)
    }

    /// Erasure must remove the bytes, so it reaches the authority — and then
    /// the cached copy, which would otherwise keep serving what policy dropped.
    fn erase(&self, id: &str, at: &str) -> StoreResult<EraseOutcome> {
        let outcome = self.authority.erase(id, at)?;
        // Best-effort, and the ordering matters: authority first, so a cache
        // that refuses erasure cannot leave the authority holding the bytes.
        let _ = self.cache.erase(id, at);
        Ok(outcome)
    }

    fn chunk_ids(&self, id: &str) -> StoreResult<Option<Vec<String>>> {
        match self.cache.chunk_ids(id)? {
            Some(ids) => Ok(Some(ids)),
            None => self.authority.chunk_ids(id),
        }
    }

    fn put_chunk_root(
        &self,
        root_id: &str,
        chunk_ids: &[String],
        byte_len: u64,
    ) -> StoreResult<()> {
        self.authority
            .put_chunk_root(root_id, chunk_ids, byte_len)?;
        let _ = self.cache.put_chunk_root(root_id, chunk_ids, byte_len);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// A blob store that counts reads, so a test can tell a cache hit from a
    /// pull-through rather than inferring it.
    #[derive(Default)]
    struct CountingBlobs {
        stored: RefCell<BTreeMap<String, String>>,
        erased: RefCell<BTreeMap<String, u64>>,
        gets: RefCell<usize>,
    }

    impl CountingBlobs {
        fn gets(&self) -> usize {
            *self.gets.borrow()
        }
        fn erase_locally(&self, id: &str) {
            let len = self.stored.borrow_mut().remove(id).map_or(0, |b| b.len());
            self.erased.borrow_mut().insert(id.to_owned(), len as u64);
        }
    }

    impl ContentBlobs for CountingBlobs {
        /// `stable_hash_hex`, because that is what `ContentStore::put` mints.
        ///
        /// This said `items::sha256_hex` until 2026-08-25 — a full 256-bit id
        /// where the real store mints a 128-bit one. Every read-through test
        /// was therefore running against a store whose ids no real backend
        /// produces, and nothing noticed because no reader verified. Adding
        /// DR-0066 §3's check broke five tests immediately, which is the check
        /// doing precisely its job on its first outing.
        fn put(&self, body: &str) -> StoreResult<String> {
            let id = crate::stable_hash_hex(body);
            self.stored.borrow_mut().insert(id.clone(), body.to_owned());
            Ok(id)
        }
        fn get(&self, id: &str) -> StoreResult<Option<String>> {
            *self.gets.borrow_mut() += 1;
            Ok(self.stored.borrow().get(id).cloned())
        }
        fn status(&self, id: &str) -> StoreResult<BlobStatus> {
            if let Some(body) = self.stored.borrow().get(id) {
                return Ok(BlobStatus::Live {
                    byte_len: body.len() as u64,
                });
            }
            if let Some(len) = self.erased.borrow().get(id) {
                return Ok(BlobStatus::Erased { byte_len: *len });
            }
            Ok(BlobStatus::Unknown)
        }
        /// The idempotent-retry arm is here because the conformance suite
        /// caught its absence: this double returned `Unknown` on a re-erase
        /// where the real `ContentStore` returns `AlreadyErased`.
        ///
        /// A test double that does not satisfy the contract it stands in for
        /// makes every test using it a check against a backend that could not
        /// exist. Running the suite against the doubles, not only the real
        /// stores, is what surfaces that.
        fn erase(&self, id: &str, _at: &str) -> StoreResult<EraseOutcome> {
            let existing = self.stored.borrow_mut().remove(id);
            match existing {
                Some(body) => {
                    self.erased
                        .borrow_mut()
                        .insert(id.to_owned(), body.len() as u64);
                    Ok(EraseOutcome::Erased {
                        byte_len: body.len() as u64,
                    })
                }
                None if self.erased.borrow().contains_key(id) => Ok(EraseOutcome::AlreadyErased),
                None => Ok(EraseOutcome::Unknown),
            }
        }
    }

    fn layered() -> ReadThrough<CountingBlobs, CountingBlobs> {
        ReadThrough::new(CountingBlobs::default(), CountingBlobs::default())
    }

    /// A store that answers every id with bytes that are not that id's bytes.
    ///
    /// The whole point of the double: content addressing means a cache "cannot
    /// be wrong, only colder" — but only if a reader checks. This is the store
    /// that lies, and without one nothing distinguishes a reader that verifies
    /// from a reader that trusts.
    #[derive(Default)]
    struct LyingBlobs;

    impl ContentBlobs for LyingBlobs {
        fn put(&self, body: &str) -> StoreResult<String> {
            Ok(crate::stable_hash_hex(body))
        }
        fn get(&self, _id: &str) -> StoreResult<Option<String>> {
            Ok(Some("not the bytes you asked for".to_owned()))
        }
        fn status(&self, _id: &str) -> StoreResult<BlobStatus> {
            Ok(BlobStatus::Live { byte_len: 29 })
        }
    }

    /// DR-0066 §3 on the cache side: the substrate's most emphatic obligation,
    /// and until 2026-08-25 it was implemented on no read path at all and was
    /// not listed among the obligations with no check. Two independent reviews
    /// found it separately.
    #[test]
    fn a_lying_cache_is_refused_rather_than_returned() {
        let layered = ReadThrough::new(LyingBlobs, CountingBlobs::default());
        let id = layered
            .put("the real body")
            .expect("put reaches the authority");

        let read = layered.get(&id);
        let Err(crate::StoreError::ContentMismatch {
            id: asked, source, ..
        }) = read
        else {
            panic!("a cache answering with the wrong bytes must be refused, got {read:?}");
        };
        assert_eq!(asked, id, "the refusal must name the id that was asked for");
        assert_eq!(
            source, "read-through cache",
            "and must say which reader caught it, since the authority is \
             verified on the same path"
        );
    }

    /// The authority gets no more trust than the cache. §3 is an obligation on
    /// readers, and "it came from the authority" is the reasoning it refuses —
    /// an object store with a corrupted object is exactly as wrong as a bad
    /// cache, and is the harder of the two to notice.
    #[test]
    fn a_lying_authority_is_refused_too() {
        let layered = ReadThrough::new(CountingBlobs::default(), LyingBlobs);

        let read = layered.get("blob_that_the_authority_will_lie_about");
        let Err(crate::StoreError::ContentMismatch { source, .. }) = read else {
            panic!("an authority answering with the wrong bytes must be refused, got {read:?}");
        };
        assert_eq!(source, "content authority");
    }

    /// The refusal must not be reachable by an honest miss — otherwise "content
    /// does not exist" and "content came back wrong" collapse into one answer,
    /// which is the *absent*-for-*erased* confusion in a different register.
    #[test]
    fn an_honest_miss_is_still_none_not_a_mismatch() {
        let layered = layered();
        assert_eq!(
            layered.get("nothing_was_ever_stored_here").expect("miss"),
            None
        );
    }

    /// The cache layer must satisfy the content contract itself, not merely
    /// forward to something that does. This is where a violation would be
    /// easiest to introduce — a wrapper that answers from its own state is
    /// exactly the replica this type exists to prevent — so it runs the same
    /// suite the bare stores run.
    #[test]
    fn the_cache_layer_passes_the_content_conformance_suite() {
        crate::content::conformance::run_suite(layered).expect("suite runs");
    }

    #[test]
    fn a_miss_pulls_through_and_populates() {
        let authority = CountingBlobs::default();
        let id = authority.put("body").expect("authority holds it");
        let layered = ReadThrough::new(CountingBlobs::default(), authority);

        assert_eq!(layered.get(&id).expect("get").as_deref(), Some("body"));
        let after_first = layered.authority().gets();
        // Second read is served by the cache: the authority is not touched.
        assert_eq!(layered.get(&id).expect("get").as_deref(), Some("body"));
        assert_eq!(
            layered.authority().gets(),
            after_first,
            "a populated cache must not re-ask the authority"
        );
    }

    /// **The defining property.** A cache that answers `Unknown` from its own
    /// emptiness has become a replica with a bad replication protocol, and
    /// every conclusion the design draws from content addressing stops holding.
    #[test]
    fn a_cold_cache_never_reports_content_as_missing() {
        let authority = CountingBlobs::default();
        let id = authority.put("only at the authority").expect("put");
        let layered = ReadThrough::new(CountingBlobs::default(), authority);

        assert!(
            matches!(
                layered.status(&id).expect("status"),
                BlobStatus::Live { .. }
            ),
            "an empty cache must consult the authority rather than answer Unknown"
        );
        assert!(layered.get(&id).expect("get").is_some());
    }

    /// A cache may prove `Live` on its own — it is holding the bytes — but the
    /// asymmetry is deliberate: presence is self-evident, absence never is.
    #[test]
    fn a_warm_cache_answers_live_without_the_authority() {
        let layered = layered();
        let id = layered.put("cached").expect("put");
        let before = layered.authority().gets();
        assert!(matches!(
            layered.status(&id).expect("status"),
            BlobStatus::Live { .. }
        ));
        assert_eq!(
            layered.authority().gets(),
            before,
            "a cache holding the bytes need not ask"
        );
    }

    /// DR-0066 §5 has to survive the cache: erased must not read as absent just
    /// because the cache never held it.
    #[test]
    fn an_erased_blob_reads_as_erased_through_a_cold_cache() {
        let authority = CountingBlobs::default();
        let id = authority.put("doomed").expect("put");
        authority.erase_locally(&id);
        let layered = ReadThrough::new(CountingBlobs::default(), authority);

        assert!(
            matches!(
                layered.status(&id).expect("status"),
                BlobStatus::Erased { .. }
            ),
            "a cold cache must not turn an erasure into an absence"
        );
    }

    /// Erasure has to reach the cached copy too, or the cache keeps serving
    /// what policy dropped — the honesty downgrade downgrading nothing.
    #[test]
    fn erasure_reaches_the_cached_copy() {
        let layered = layered();
        let id = layered.put("doomed").expect("put");
        assert!(layered.get(&id).expect("get").is_some());

        assert!(matches!(
            layered.erase(&id, "2026-08-24T00:00:00Z").expect("erase"),
            EraseOutcome::Erased { .. }
        ));
        assert_eq!(
            layered.get(&id).expect("get"),
            None,
            "the cache must stop serving erased bytes"
        );
        assert!(matches!(
            layered.status(&id).expect("status"),
            BlobStatus::Erased { .. }
        ));
    }

    /// Content written straight to the authority — by another cache's peer, or
    /// by a warm-up — is visible here without any invalidation step. That is
    /// the property that makes this a cache and not a replica: there is no
    /// coherence protocol because immutability leaves nothing to cohere.
    #[test]
    fn content_written_behind_the_cache_is_still_visible() {
        let authority = CountingBlobs::default();
        let layered = ReadThrough::new(CountingBlobs::default(), authority);

        let id = layered.authority().put("written behind").expect("put");
        assert_eq!(
            layered.get(&id).expect("get").as_deref(),
            Some("written behind"),
            "no invalidation is needed, because a hash never means new bytes"
        );
    }

    /// A write reaches the authority, not merely the cache. Content that exists
    /// only in a cache is content the authority cannot serve to anyone else.
    #[test]
    fn a_write_reaches_the_authority() {
        let layered = layered();
        let id = layered.put("durable").expect("put");
        assert_eq!(
            layered.authority().get(&id).expect("get").as_deref(),
            Some("durable")
        );
    }
}
