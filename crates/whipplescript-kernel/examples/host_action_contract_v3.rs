//! Recording codecs extend the immutable scoped bundle. Reports cross the
//! version boundary as JSON so its private harness types need no modification.
#[path = "host_action_contract_v2.rs"]
mod scoped;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use whipplescript_store::vcs_resolution_recording::{
    ResolutionRecordingBinding, ResolutionRecordingInput,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Vectors {
    schema: String,
    contract_revision: String,
    description: String,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    message_type: String,
    value: Option<Value>,
    base: Option<String>,
    #[serde(default)]
    set: Vec<Edit>,
    #[serde(default)]
    remove: Vec<String>,
    wire_valid: bool,
    schema_valid: bool,
    syntax_valid: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    pointer: String,
    value: Value,
}

fn observe<T: DeserializeOwned + Serialize>(value: &Value) -> Value {
    let decoded = serde_json::from_value::<T>(value.clone()).ok();
    json!({
        "wire_valid": decoded.is_some(),
        "syntax_valid": decoded.as_ref().map(|_| true),
        "normalized": decoded,
        "signing_sha256": null,
        "fingerprint": null,
        "identity": null,
    })
}

fn edit(value: &mut Value, pointer: &str, replacement: Option<Value>) {
    let (parent, key) = pointer.rsplit_once('/').expect("fixture field pointer");
    let key = key.replace("~1", "/").replace("~0", "~");
    let object = value
        .pointer_mut(parent)
        .expect("fixture parent")
        .as_object_mut()
        .expect("fixture field owner");
    if let Some(replacement) = replacement {
        object.insert(key, replacement);
    } else {
        assert!(
            object.remove(&key).is_some(),
            "missing fixture field {pointer}"
        );
    }
}

pub fn contract_reports() -> Vec<Value> {
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../../spec/host-action-contract-fixtures-v3.json"
    ))
    .expect("pinned recording vectors");
    assert_eq!(
        vectors.schema,
        "whipplescript.host_action_contract_fixtures.v3"
    );
    assert_eq!(
        vectors.contract_revision,
        "whipplescript-host-action/v3.0.0"
    );
    assert!(!vectors.description.is_empty());
    let bases: BTreeMap<_, _> = vectors
        .cases
        .iter()
        .filter_map(|case| case.value.as_ref().map(|value| (case.id.as_str(), value)))
        .collect();
    let mut reports: Vec<Value> = scoped::contract_reports()
        .into_iter()
        .map(|report| serde_json::to_value(report).expect("unchanged scoped report"))
        .collect();
    let mut ids: BTreeSet<_> = reports
        .iter()
        .map(|report| report["id"].as_str().expect("scoped vector id").to_owned())
        .collect();
    for case in &vectors.cases {
        assert!(ids.insert(case.id.clone()), "duplicate vector {}", case.id);
        assert_ne!(
            case.value.is_some(),
            case.base.is_some(),
            "one vector source"
        );
        let mut value = case.value.clone().unwrap_or_else(|| {
            (*bases
                .get(case.base.as_deref().expect("base"))
                .expect("recording base"))
            .clone()
        });
        for change in &case.set {
            edit(&mut value, &change.pointer, Some(change.value.clone()));
        }
        for pointer in &case.remove {
            edit(&mut value, pointer, None);
        }
        let observation = match case.message_type.as_str() {
            "ResolutionRecordingInput" => observe::<ResolutionRecordingInput>(&value),
            "ResolutionRecordingBinding" => observe::<ResolutionRecordingBinding>(&value),
            other => panic!("unregistered recording contract type {other}"),
        };
        assert_eq!(
            observation["wire_valid"],
            json!(case.wire_valid),
            "{} wire",
            case.id
        );
        assert_eq!(
            observation["syntax_valid"],
            json!(case.syntax_valid),
            "{} syntax",
            case.id
        );
        reports.push(json!({"id": case.id, "message_type": case.message_type,
            "value": value, "schema_valid": case.schema_valid, "observation": observation}));
    }
    reports
}

#[allow(dead_code)] // The integration test executes this same emitter as a module.
fn main() {
    println!(
        "{}",
        serde_json::to_string(&contract_reports()).expect("recording reports")
    );
}
