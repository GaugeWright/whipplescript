use super::*;
use crate::branches::Branches;

pub fn entry(key: &str, resolution: &str) -> ResolutionMemoryEntry {
    ResolutionMemoryEntry {
        triple_key: key.into(),
        resolution: resolution.into(),
    }
}

pub fn outcome(key: &str, resolution: &str, inserted: bool) -> ResolutionMemoryOutcome {
    ResolutionMemoryOutcome {
        triple_key: key.into(),
        resolution: resolution.into(),
        inserted,
    }
}

pub fn request() -> ResolutionMemoryBatch {
    ResolutionMemoryBatch {
        operation_id: "resolve-1".into(),
        actor: "person-1".into(),
        intent: "intent-1".into(),
        recorded_at: "t1".into(),
        entries: vec![
            entry("triple-a", "requested-a"),
            entry("triple-b", "requested-b"),
            entry("triple-b", "later-b"),
        ],
    }
}

pub fn check(store: &mut impl Branches) {
    let request = request();
    store
        .record_resolution_memory("triple-a", "legacy-a", "t0")
        .expect("existing first winner");
    assert_eq!(
        store
            .resolution_batch(&request.operation_id)
            .expect("fixture"),
        None
    );
    for field in [
        "operation",
        "actor",
        "intent",
        "time",
        "entries",
        "key",
        "content",
    ] {
        let mut invalid = request.clone();
        match field {
            "operation" => invalid.operation_id = " ".into(),
            "actor" => invalid.actor.clear(),
            "intent" => invalid.intent.clear(),
            "time" => invalid.recorded_at.clear(),
            "entries" => invalid.entries.clear(),
            "key" => invalid.entries[1].triple_key.clear(),
            _ => invalid.entries[1].resolution.clear(),
        }
        let error = store
            .record_resolution_batch(&invalid)
            .expect_err("invalid batch must refuse");
        assert!(matches!(error, StoreError::Conflict(_)), "{field}");
        assert_eq!(store.resolution_memory("triple-b").expect("fixture"), None);
        assert_eq!(
            store
                .resolution_batch(&request.operation_id)
                .expect("fixture"),
            None
        );
    }
    let receipt = store.record_resolution_batch(&request).expect("fixture");
    assert_eq!(receipt.request, request);
    assert_eq!(
        receipt.outcomes,
        vec![
            outcome("triple-a", "legacy-a", false),
            outcome("triple-b", "requested-b", true),
            outcome("triple-b", "requested-b", false)
        ]
    );
    assert_eq!(
        store
            .resolution_batch(&request.operation_id)
            .expect("fixture"),
        Some(receipt.clone())
    );
    assert_eq!(
        store.record_resolution_batch(&request).expect("fixture"),
        receipt
    );
    for field in [
        "actor", "intent", "time", "key", "content", "order", "count",
    ] {
        let mut changed = request.clone();
        match field {
            "actor" => changed.actor = "agent-2".into(),
            "intent" => changed.intent = "intent-2".into(),
            "time" => changed.recorded_at = "t2".into(),
            "key" => changed.entries[0].triple_key = "triple-c".into(),
            "content" => changed.entries[0].resolution = "new-content".into(),
            "order" => changed.entries.reverse(),
            _ => {
                changed.entries.pop();
            }
        }
        let error = store
            .record_resolution_batch(&changed)
            .expect_err("invalid batch must refuse");
        assert!(matches!(error, StoreError::Conflict(_)), "{field}");
        assert_eq!(
            store
                .resolution_batch(&request.operation_id)
                .expect("fixture"),
            Some(receipt.clone())
        );
        assert_eq!(store.resolution_memory("triple-c").expect("fixture"), None);
    }
    let later = ResolutionMemoryBatch {
        operation_id: "resolve-2".into(),
        actor: "agent-2".into(),
        ..request
    };
    assert_eq!(
        store
            .record_resolution_batch(&later)
            .expect("fixture")
            .outcomes,
        receipt
            .outcomes
            .iter()
            .map(|entry| outcome(&entry.triple_key, &entry.resolution, false))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        store
            .resolution_memory("triple-a")
            .expect("fixture")
            .as_deref(),
        Some("legacy-a")
    );
}

/// Broken persisted receipt cases used by both storage backends. Rehash the
/// structural cases so a digest check alone cannot hide a missing invariant.
pub fn contradictions() -> Vec<(String, String, String)> {
    let valid = ResolutionMemoryReceipt {
        request: request(),
        outcomes: vec![
            outcome("triple-a", "requested-a", true),
            outcome("triple-b", "requested-b", true),
            outcome("triple-b", "requested-b", false),
        ],
    };
    let (json, digest) = valid.encode().expect("fixture");
    let mut cases = vec![
        ("other-operation".into(), json.clone(), digest.clone()),
        (
            valid.request.operation_id.clone(),
            json.clone(),
            "wrong-digest".into(),
        ),
        (valid.request.operation_id.clone(), "{".into(), digest),
    ];
    for field in [
        "actor",
        "outcomes",
        "key",
        "content",
        "inserted-content",
        "duplicate-winner",
        "duplicate-insert",
    ] {
        let mut changed = valid.clone();
        match field {
            "actor" => changed.request.actor.clear(),
            "outcomes" => {
                changed.outcomes.pop();
            }
            "key" => changed.outcomes[0].triple_key = "other-key".into(),
            "inserted-content" => changed.outcomes[0].resolution = "other-content".into(),
            "duplicate-winner" => changed.outcomes[2].resolution = "other-content".into(),
            "duplicate-insert" => {
                changed.request.entries[2].resolution = "requested-b".into();
                changed.outcomes[2].inserted = true;
            }
            _ => changed.outcomes[0].resolution.clear(),
        }
        let (json, digest) = changed.encode().expect("fixture");
        cases.push((valid.request.operation_id.clone(), json, digest));
    }
    let json = json.replacen("{", "{\"unrecognized\":true,", 1);
    cases.push((
        valid.request.operation_id.clone(),
        json.clone(),
        receipt_hash(&json),
    ));
    cases
}
