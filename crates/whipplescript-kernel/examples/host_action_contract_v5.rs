//! Current-authority read codecs extend the immutable tracker bundle. Reports cross the
//! version boundary as JSON so its private harness types need no modification.
#[path = "host_action_contract_v4.rs"]
mod tracker;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use whipplescript_kernel::host_protocol::action_result::ReadActionResult;

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
        "../../../spec/host-action-contract-fixtures-v5.json"
    ))
    .expect("pinned current-authority read vectors");
    assert_eq!(
        vectors.schema,
        "whipplescript.host_action_contract_fixtures.v5"
    );
    assert_eq!(
        vectors.contract_revision,
        "whipplescript-host-action/v5.0.0"
    );
    assert!(!vectors.description.is_empty());
    let bases: BTreeMap<_, _> = vectors
        .cases
        .iter()
        .filter_map(|case| case.value.as_ref().map(|value| (case.id.as_str(), value)))
        .collect();
    let mut reports: Vec<Value> = tracker::contract_reports()
        .into_iter()
        .map(|report| serde_json::to_value(report).expect("unchanged recording report"))
        .collect();
    let mut ids: BTreeSet<_> = reports
        .iter()
        .map(|report| {
            report["id"]
                .as_str()
                .expect("recording vector id")
                .to_owned()
        })
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
                .expect("current-authority read base"))
            .clone()
        });
        for change in &case.set {
            edit(&mut value, &change.pointer, Some(change.value.clone()));
        }
        for pointer in &case.remove {
            edit(&mut value, pointer, None);
        }
        assert_eq!(case.message_type, "ReadActionResult");
        let mut observation = observe::<ReadActionResult>(&value);
        if let Ok(request) = serde_json::from_value::<ReadActionResult>(value.clone()) {
            let bytes = request.signing_bytes().ok();
            observation["syntax_valid"] = json!(bytes.is_some());
            observation["signing_sha256"] = json!(bytes.map(|bytes| {
                Sha256::digest(bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            }));
        }
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
        serde_json::to_string(&contract_reports()).expect("current-authority read reports")
    );
}
