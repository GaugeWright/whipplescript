//! Executable wire and canonical-identity vectors for embedding hosts.
//! These synthetic messages grant no authority and touch no runtime store.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use whipplescript_kernel::host_protocol::{
    action::{ActionAdmissionReceipt, HostActionCommand},
    action_result::{ActionResultSnapshot, ReadActionResult},
    execution::ExecuteActionEffect,
    recovery::{ReconcileEffectCommand, ReconciliationReceipt},
    ProtocolError,
};
use whipplescript_store::{branches::write_evidence::WriteEvidenceRef, vcs_file_save::SaveReceipt};

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
    fingerprint: Option<String>,
    identity: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Edit {
    pointer: String,
    value: Value,
}
#[derive(Default, Serialize)]
pub struct Observation {
    pub wire_valid: bool,
    pub syntax_valid: Option<bool>,
    pub normalized: Option<Value>,
    pub signing_sha256: Option<String>,
    pub fingerprint: Option<String>,
    pub identity: Option<String>,
}
#[derive(Serialize)]
pub struct Report {
    pub id: String,
    pub message_type: String,
    pub value: Value,
    pub schema_valid: bool,
    pub observation: Observation,
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
        normalized: Some(serde_json::to_value(&decoded).expect("typed serialization")),
        ..Observation::default()
    };
    annotate(&decoded, &mut observation);
    observation
}
fn signed(observation: &mut Observation, bytes: Result<Vec<u8>, ProtocolError>) {
    observation.syntax_valid = Some(bytes.is_ok());
    observation.signing_sha256 = bytes.ok().map(|bytes| {
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    });
}
fn inspect(kind: &str, value: &Value) -> Observation {
    match kind {
        "HostActionCommand" => observe::<HostActionCommand>(value, |command, observation| {
            signed(observation, command.signing_bytes());
            observation.fingerprint = command.fingerprint().ok();
            observation.identity = command.instance_ref().ok();
        }),
        "ExecuteActionEffect" => observe::<ExecuteActionEffect>(value, |command, observation| {
            signed(observation, command.signing_bytes());
        }),
        "ReadActionResult" => observe::<ReadActionResult>(value, |command, observation| {
            signed(observation, command.signing_bytes());
        }),
        "ReconcileEffectCommand" => {
            observe::<ReconcileEffectCommand>(value, |command, observation| {
                signed(observation, command.signing_bytes());
                observation.fingerprint = command.fingerprint().ok();
                observation.identity = command.request_key().ok();
            })
        }
        "WriteEvidenceRef" => observe::<WriteEvidenceRef>(value, |reference, observation| {
            observation.syntax_valid = Some(reference.validate().is_ok());
        }),
        "ActionAdmissionReceipt" => observe::<ActionAdmissionReceipt>(value, |_, _| {}),
        "ActionResultSnapshot" => observe::<ActionResultSnapshot>(value, |_, _| {}),
        "ReconciliationReceipt" => observe::<ReconciliationReceipt>(value, |_, _| {}),
        "SaveReceipt" => observe::<SaveReceipt>(value, |_, _| {}),
        other => panic!("unregistered contract type {other}"),
    }
}
fn edit(value: &mut Value, pointer: &str, replacement: Option<Value>) {
    let (parent, key) = pointer
        .rsplit_once('/')
        .expect("JSON pointer to an object field");
    let key = key.replace("~1", "/").replace("~0", "~");
    let object = value
        .pointer_mut(parent)
        .expect("fixture pointer parent")
        .as_object_mut()
        .expect("fixture field owner");
    match replacement {
        Some(value) => {
            object.insert(key, value);
        }
        None => {
            assert!(
                object.remove(&key).is_some(),
                "missing fixture field {pointer}"
            );
        }
    }
}

pub fn contract_reports() -> Vec<Report> {
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../../spec/host-action-contract-fixtures-v1.json"
    ))
    .expect("pinned vectors");
    assert_eq!(
        vectors.schema,
        "whipplescript.host_action_contract_fixtures.v1"
    );
    assert_eq!(
        vectors.contract_revision,
        "whipplescript-host-action/v1.0.0"
    );
    assert!(!vectors.description.is_empty());
    let bases: BTreeMap<_, _> = vectors
        .cases
        .iter()
        .filter_map(|case| case.value.as_ref().map(|value| (case.id.as_str(), value)))
        .collect();
    let mut ids = BTreeSet::new();
    vectors
        .cases
        .iter()
        .map(|case| {
            assert!(ids.insert(&case.id), "duplicate vector {}", case.id);
            assert_ne!(
                case.value.is_some(),
                case.base.is_some(),
                "one vector source"
            );
            let mut value = case.value.clone().unwrap_or_else(|| {
                (*bases
                    .get(case.base.as_deref().expect("base"))
                    .expect("positive vector base"))
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
            if let Some(expected) = &case.fingerprint {
                assert_eq!(
                    observation.fingerprint.as_ref(),
                    Some(expected),
                    "{} fingerprint",
                    case.id
                );
            }
            if let Some(expected) = &case.identity {
                assert_eq!(
                    observation.identity.as_ref(),
                    Some(expected),
                    "{} identity",
                    case.id
                );
            }
            Report {
                id: case.id.clone(),
                message_type: case.message_type.clone(),
                value,
                schema_valid: case.schema_valid,
                observation,
            }
        })
        .collect()
}

#[allow(dead_code)] // The integration test runs this same emitter as a module.
fn main() {
    println!(
        "{}",
        serde_json::to_string(&contract_reports()).expect("contract reports")
    );
}
