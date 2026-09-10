use super::*;
use crate::branches::BranchStore;
use crate::content::ContentStore;
fn workspace() -> WorkspaceVcs<BranchStore, ContentStore> {
    WorkspaceVcs::from_parts(
        BranchStore::open_in_memory().expect("fixture"),
        ContentStore::open(":memory:").expect("fixture"),
    )
}
#[test]
fn native_bound_resolution_recording_conformance() {
    conformance::check(workspace());
}

#[test]
fn resolution_recording_input_refuses_ambiguous_shapes() {
    let valid: serde_json::Value =
        serde_json::from_str(&conformance::input("liger")).expect("fixture");
    for field in [
        "protocol",
        "empty",
        "unknown",
        "nested-unknown",
        "missing",
        "wrong-type",
    ] {
        let mut value = valid.clone();
        match field {
            "protocol" => value["protocol"] = "legacy".into(),
            "empty" => value["resolutions"] = serde_json::json!([]),
            "unknown" => value["authority"] = "invented".into(),
            "nested-unknown" => value["resolutions"][0]["authority"] = "invented".into(),
            "missing" => {
                value["resolutions"][0]
                    .as_object_mut()
                    .expect("fixture")
                    .remove("ours_text");
            }
            _ => value["resolutions"][0]["ours_text"] = serde_json::Value::Null,
        }
        assert!(
            serde_json::from_value::<ResolutionRecordingInput>(value).is_err(),
            "{field}"
        );
    }
    assert!(ResolutionRecordingInput::new(vec![]).is_err());
    let mut deletion = valid;
    for field in ["base_text", "ours_text", "theirs_text", "resolution_text"] {
        deletion["resolutions"][0][field] = "".into();
    }
    assert!(serde_json::from_value::<ResolutionRecordingInput>(deletion).is_ok());
}
#[test]
fn resolution_recording_binding_requires_exact_coordinates_and_actual_input() {
    let body = conformance::input("liger");
    let binding = conformance::binding(&body);
    let valid = serde_json::to_value(&binding).expect("fixture");
    let serialized = serde_json::to_string(&binding).expect("fixture");
    for text in ["dog", "tiger", "lion", "liger"] {
        assert!(!serialized.contains(text));
    }
    assert_eq!(
        serde_json::from_str::<ResolutionRecordingBinding>(&serialized).expect("fixture"),
        binding
    );
    for field in [
        "protocol",
        "hash",
        "label",
        "scope",
        "actor",
        "intent",
        "time",
        "operation",
        "empty",
        "key",
        "resolution",
        "unknown",
        "nested-unknown",
    ] {
        let mut value = valid.clone();
        match field {
            "protocol" => value["protocol"] = "legacy".into(),
            "hash" => value["input_hash"] = "ABC".into(),
            "label" => value["input_label"] = " ".into(),
            "scope" => value["scope"]["authority"] = "".into(),
            "actor" => value["batch"]["actor"] = "".into(),
            "intent" => value["batch"]["intent"] = "".into(),
            "time" => value["batch"]["recorded_at"] = "".into(),
            "operation" => value["batch"]["operation_id"] = "".into(),
            "empty" => value["batch"]["entries"] = serde_json::json!([]),
            "key" => value["batch"]["entries"][0]["triple_key"] = "rk|legacy".into(),
            "resolution" => value["batch"]["entries"][0]["resolution"] = "plaintext".into(),
            "unknown" => value["grants"] = true.into(),
            _ => value["batch"]["entries"][0]["authority"] = "invented".into(),
        }
        assert!(
            serde_json::from_value::<ResolutionRecordingBinding>(value).is_err(),
            "{field}"
        );
    }
    for field in ["input_hash", "scope", "key", "resolution", "order"] {
        let mut value = valid.clone();
        match field {
            "input_hash" => value["input_hash"] = "0".repeat(32).into(),
            "scope" => value["scope"]["compartment"] = "foreign".into(),
            "key" => {
                value["batch"]["entries"][0]["triple_key"] =
                    format!("rks1|{}", "0".repeat(64)).into()
            }
            "resolution" => value["batch"]["entries"][0]["resolution"] = "0".repeat(32).into(),
            _ => value["batch"]["entries"]
                .as_array_mut()
                .expect("fixture")
                .reverse(),
        }
        let changed = serde_json::from_value(value).expect("fixture");
        assert!(
            BoundResolutionRecording::new(workspace(), changed, &body).is_err(),
            "{field}"
        );
    }
    assert!(BoundResolutionRecording::new(
        workspace(),
        binding.clone(),
        &conformance::input("other")
    )
    .is_err());
    // Exact bytes matter even when two serializations decode to the same rows.
    assert!(BoundResolutionRecording::new(workspace(), binding, &format!("{body}\n")).is_err());
}
