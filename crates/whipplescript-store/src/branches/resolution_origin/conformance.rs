use super::*;
use crate::branches::{resolution_batch::conformance::request, Branches};

pub fn check(store: &mut impl Branches) {
    assert_eq!(
        store.resolution_observation("missing").expect("missing"),
        ResolutionObservation::Missing
    );
    store
        .record_resolution_memory("triple-a", "legacy", "t0")
        .expect("legacy");
    let first = store.record_resolution_batch(&request()).expect("batch");
    let observed = ResolutionObservation::Recorded {
        content_hash: "requested-b".into(),
        origin: ResolutionOrigin {
            operation_id: first.request.operation_id.clone(),
            receipt_hash: first.encode().expect("receipt digest").1,
            outcome_index: 1,
        },
    };
    assert_eq!(
        store.resolution_observation("triple-a").expect("unindexed"),
        ResolutionObservation::OriginUnavailable {
            content_hash: "legacy".into()
        }
    );
    assert_eq!(
        store.resolution_observation("triple-b").expect("origin"),
        observed
    );
    let mut later = request();
    later.operation_id = "agent-observation".into();
    later.actor = "agent-2".into();
    later.entries[1].resolution = "later-proposal".into();
    let receipt = store
        .record_resolution_batch(&later)
        .expect("later observer");
    assert!(receipt.outcomes.iter().all(|outcome| !outcome.inserted));
    assert_eq!(
        store
            .resolution_observation("triple-b")
            .expect("original author"),
        observed
    );
    assert_eq!(
        store
            .record_resolution_batch(&first.request)
            .expect("retry"),
        first
    );
    assert_eq!(
        store
            .resolution_observation("triple-b")
            .expect("stable origin"),
        observed
    );
}

/// Each fixture is executed against the real native and DO SQL-backed store.
pub fn corruptions() -> &'static [(&'static str, &'static str)] {
    &[
        ("DELETE FROM resolution_memory WHERE triple_key = 'triple-b'", "incomplete resolution origin snapshot"),
        ("DELETE FROM resolution_batches WHERE operation_id = 'resolve-1'", "incomplete resolution origin snapshot"),
        ("UPDATE resolution_origins SET operation_id = 'absent' WHERE triple_key = 'triple-b'", "incomplete resolution origin snapshot"),
        ("UPDATE resolution_origins SET outcome_index = -1 WHERE triple_key = 'triple-b'", "resolution origin does not identify its inserted outcome"),
        ("UPDATE resolution_origins SET outcome_index = 99 WHERE triple_key = 'triple-b'", "resolution origin does not identify its inserted outcome"),
        ("UPDATE resolution_origins SET outcome_index = 2 WHERE triple_key = 'triple-b'", "resolution origin does not identify its inserted outcome"),
        ("UPDATE resolution_origins SET outcome_index = 0 WHERE triple_key = 'triple-b'", "resolution origin does not identify its inserted outcome"),
        ("UPDATE resolution_memory SET resolution = 'wrong' WHERE triple_key = 'triple-b'", "resolution origin does not identify its inserted outcome"),
        ("UPDATE resolution_memory SET resolution = '' WHERE triple_key = 'triple-b'", "resolution origin does not identify its inserted outcome"),
        ("UPDATE resolution_batches SET receipt_json = '{}' WHERE operation_id = 'resolve-1'", "invalid receipt:"),
        ("UPDATE resolution_batches SET receipt_hash = 'wrong' WHERE operation_id = 'resolve-1'", "contradictory receipt"),
        ("UPDATE resolution_origins SET outcome_index = 'not an integer' WHERE triple_key = 'triple-b'", "invalid resolution origin SQL row"),
    ]
}
