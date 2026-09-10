// Explicit test-only items also keep standalone source scans from counting
// injected storage faults and assertion patterns as production refusals.
use super::*;
use crate::branches::BranchStore;
use crate::content::ContentStore;

fn vcs() -> WorkspaceVcs<BranchStore, ContentStore> {
    WorkspaceVcs::from_parts(
        BranchStore::open_in_memory().expect("branches"),
        ContentStore::open(":memory:").expect("content"),
    )
}

#[cfg(test)]
#[test]
fn native_resolution_recording_conformance() {
    conformance::check(&mut vcs());
}

#[cfg(test)]
#[test]
fn resolution_recording_keeps_losing_payloads_through_collection() {
    let mut vcs = vcs();
    vcs.set_actor(Some("person-1".into()));
    vcs.set_intent(Some("intent-1".into()));
    vcs.record_region_resolutions_recorded("first", &[conformance::resolution("first body")], "t1")
        .expect("first");
    let receipt = vcs
        .record_region_resolutions_recorded(
            "second",
            &[conformance::resolution("losing body")],
            "t2",
        )
        .expect("second");
    let orphan = vcs
        .content_store()
        .put_text("uncommitted residue")
        .expect("orphan");
    vcs.purge_unreachable("t3").expect("collection");
    assert_eq!(
        vcs.content_store().get(&orphan).expect("orphan reclaimed"),
        None
    );
    for identity in receipt
        .request
        .entries
        .iter()
        .map(|entry| &entry.resolution)
        .chain(receipt.outcomes.iter().map(|outcome| &outcome.resolution))
    {
        assert!(vcs
            .content_store()
            .get(identity)
            .expect("retained reference")
            .is_some());
    }
}

#[cfg(test)]
#[test]
fn resolution_recording_requires_verified_preparation_and_retained_publication() {
    struct ResolutionPreparationFault {
        inner: ContentStore,
        wrong_identity: bool,
    }
    impl ContentBlobs for ResolutionPreparationFault {
        fn put(&self, body: &[u8]) -> StoreResult<String> {
            let id = self.inner.put(body)?;
            Ok(if self.wrong_identity {
                "wrong-identity".into()
            } else {
                id
            })
        }
        fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
            self.inner.get(id)
        }
        fn publish_retained<T>(
            &self,
            _: &[String],
            _: impl FnOnce() -> StoreResult<T>,
        ) -> StoreResult<T> {
            Err(crate::StoreError::Conflict(
                "publication unavailable".into(),
            ))
        }
    }
    for wrong_identity in [true, false] {
        let mut vcs = WorkspaceVcs::from_parts(
            BranchStore::open_in_memory().expect("branches"),
            ResolutionPreparationFault {
                inner: ContentStore::open(":memory:").expect("content"),
                wrong_identity,
            },
        );
        vcs.set_actor(Some("person-1".into()));
        vcs.set_intent(Some("intent-1".into()));
        let error = vcs
            .record_region_resolutions_recorded(
                "knowledge",
                &[conformance::resolution("prepared")],
                "t1",
            )
            .expect_err("must not publish");
        if wrong_identity {
            assert!(matches!(error, crate::StoreError::ContentMismatch { .. }));
        } else {
            assert!(format!("{error:?}").contains("publication unavailable"));
        }
        assert_eq!(
            vcs.resolution_receipt("knowledge").expect("no effect"),
            None
        );
        let key = WorkspaceVcs::<BranchStore, ResolutionPreparationFault>::region_key(
            "dog", "tiger", "lion",
        );
        assert_eq!(
            vcs.branches
                .resolution_memory(&key)
                .expect("no partial knowledge"),
            None
        );
        let id = crate::chunking::content_hash_hex(b"prepared");
        assert_eq!(
            vcs.content_store()
                .get(&id)
                .expect("unreferenced preparation permitted"),
            Some(b"prepared".to_vec())
        );
    }
}

#[cfg(test)]
#[test]
fn native_resolution_scope_conformance() {
    crate::vcs::resolution_scope::conformance::check(&mut vcs());
}

#[cfg(test)]
#[test]
fn native_resolution_observation_conformance() {
    crate::vcs::resolution_scope::conformance::check_observations(&mut vcs());
}

#[cfg(test)]
#[test]
fn native_resolution_binary_observation_conformance() {
    crate::vcs::resolution_scope::conformance::check_binary_observation(&mut vcs());
}
