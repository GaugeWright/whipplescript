//! Scoped evidence codecs plus the unchanged, explicitly pinned v1 vectors.
//! Decoding and internal consistency confer neither authority nor application.
#[path = "host_action_contract.rs"]
mod legacy;

use legacy::{Observation, Report};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use whipplescript_store::{
    branches::resolution_batch::ResolutionMemoryReceipt,
    vcs::resolution_scope::ResolutionMemoryScope, vcs_file_save::ScopedSaveReceipt,
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
    identity: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    pointer: String,
    value: Value,
}

fn observe<T: DeserializeOwned + Serialize>(
    value: &Value,
    annotate: impl FnOnce(&T, &mut Observation),
) -> Observation {
    let Ok(decoded) = serde_json::from_value::<T>(value.clone()) else {
        return Observation::default();
    };
    let mut observation = Observation {
        wire_valid: true,
        normalized: Some(serde_json::to_value(&decoded).expect("typed scoped serialization")),
        ..Observation::default()
    };
    annotate(&decoded, &mut observation);
    observation
}

fn inspect(kind: &str, value: &Value) -> Observation {
    match kind {
        "ResolutionMemoryScope" => observe::<ResolutionMemoryScope>(value, |scope, observed| {
            observed.syntax_valid = Some(true);
            observed.identity = Some(scope.version_ref());
        }),
        "ScopedSaveReceipt" => observe::<ScopedSaveReceipt>(value, |receipt, observed| {
            observed.syntax_valid = Some(receipt.validate().is_ok());
        }),
        "ResolutionMemoryReceipt" => {
            observe::<ResolutionMemoryReceipt>(value, |receipt, observed| {
                let (json, digest) = receipt.encode().expect("encode memory receipt");
                observed.syntax_valid = Some(
                    ResolutionMemoryReceipt::decode(&receipt.request.operation_id, &json, &digest)
                        .is_ok(),
                );
                observed.identity = Some(digest);
            })
        }
        other => panic!("unregistered scoped contract type {other}"),
    }
}

fn edit(value: &mut Value, pointer: &str, replacement: Option<Value>) {
    let (parent, key) = pointer.rsplit_once('/').expect("fixture field pointer");
    let key = key.replace("~1", "/").replace("~0", "~");
    let object = value
        .pointer_mut(parent)
        .expect("fixture pointer parent")
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

pub fn contract_reports() -> Vec<Report> {
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../../spec/host-action-contract-fixtures-v2.json"
    ))
    .expect("pinned scoped vectors");
    assert_eq!(
        vectors.schema,
        "whipplescript.host_action_contract_fixtures.v2"
    );
    assert_eq!(
        vectors.contract_revision,
        "whipplescript-host-action/v2.0.0"
    );
    assert!(!vectors.description.is_empty());
    let bases: BTreeMap<_, _> = vectors
        .cases
        .iter()
        .filter_map(|case| case.value.as_ref().map(|value| (case.id.as_str(), value)))
        .collect();
    let mut reports = legacy::contract_reports();
    let mut ids: BTreeSet<_> = reports.iter().map(|report| report.id.clone()).collect();
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
                .expect("positive scoped base"))
            .clone()
        });
        for change in &case.set {
            edit(&mut value, &change.pointer, Some(change.value.clone()));
        }
        for pointer in &case.remove {
            edit(&mut value, pointer, None);
        }
        let observation = inspect(&case.message_type, &value);
        assert_eq!(observation.wire_valid, case.wire_valid, "{} wire", case.id);
        assert_eq!(
            observation.syntax_valid, case.syntax_valid,
            "{} syntax",
            case.id
        );
        if let Some(expected) = &case.identity {
            assert_eq!(
                observation.identity.as_ref(),
                Some(expected),
                "{} identity",
                case.id
            );
        }
        reports.push(Report {
            id: case.id.clone(),
            message_type: case.message_type.clone(),
            value,
            schema_valid: case.schema_valid,
            observation,
        });
    }
    reports
}

#[allow(dead_code)] // The integration test invokes this same emitter as a module.
fn main() {
    println!(
        "{}",
        serde_json::to_string(&contract_reports()).expect("scoped reports")
    );
}
