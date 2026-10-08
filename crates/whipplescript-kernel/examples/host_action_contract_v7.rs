//! Immutable anchor/footprint codecs; semantic authority remains with the host.
#[path = "host_action_contract_v6.rs"]
pub mod previous;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use whipplescript_kernel::host_protocol::action::{
    ActionAdmissionReceipt, ActionAnchor, HostActionCommand,
};
use whipplescript_kernel::host_protocol::action_result::{
    ActFootprint, ActionFootprint, ActionResultSnapshot, ReadActionResult,
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
    value: Value,
    wire_valid: bool,
    schema_valid: bool,
    syntax_valid: Option<bool>,
}
fn observe<T: DeserializeOwned + Serialize>(value: &Value) -> Value {
    let decoded = serde_json::from_value::<T>(value.clone()).ok();
    json!({"wire_valid":decoded.is_some(),"syntax_valid":decoded.as_ref().map(|_|true),"normalized":decoded,"signing_sha256":null,"fingerprint":null,"identity":null})
}
fn signing(observation: &mut Value, bytes: Option<Vec<u8>>) {
    observation["syntax_valid"] = json!(bytes.is_some());
    observation["signing_sha256"] = json!(bytes.map(|bytes| hex::encode(Sha256::digest(bytes))));
}
pub fn contract_reports() -> Vec<Value> {
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../../spec/host-action-contract-fixtures-v7.json"
    ))
    .expect("V7 vectors");
    assert_eq!(
        vectors.schema,
        "whipplescript.host_action_contract_fixtures.v7"
    );
    assert_eq!(
        vectors.contract_revision,
        "whipplescript-host-action/v7.0.0"
    );
    assert!(!vectors.description.is_empty());
    let mut reports = previous::contract_reports();
    for case in vectors.cases {
        assert!(!reports.iter().any(|r| r["id"] == case.id));
        let mut observation = match case.message_type.as_str() {
            "ActionAnchor" => observe::<ActionAnchor>(&case.value),
            "HostActionCommand" => observe::<HostActionCommand>(&case.value),
            "ActionAdmissionReceipt" => observe::<ActionAdmissionReceipt>(&case.value),
            "ReadActionResult" => observe::<ReadActionResult>(&case.value),
            "ActFootprint" => observe::<ActFootprint>(&case.value),
            "ActionFootprint" => observe::<ActionFootprint>(&case.value),
            "ActionResultSnapshot" => observe::<ActionResultSnapshot>(&case.value),
            _ => panic!("unknown V7 type"),
        };
        if case.message_type == "ActionAnchor" {
            if let Ok(anchor) = serde_json::from_value::<ActionAnchor>(case.value.clone()) {
                observation["syntax_valid"] = json!(anchor.validate().is_ok());
            }
        }
        if case.message_type == "HostActionCommand" {
            if let Ok(command) = serde_json::from_value::<HostActionCommand>(case.value.clone()) {
                signing(&mut observation, command.signing_bytes().ok());
                observation["fingerprint"] = json!(command.fingerprint().ok());
                observation["identity"] = json!(command.instance_ref().ok());
            }
        }
        if case.message_type == "ReadActionResult" {
            if let Ok(request) = serde_json::from_value::<ReadActionResult>(case.value.clone()) {
                signing(&mut observation, request.signing_bytes().ok());
            }
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
        reports.push(json!({"id":case.id,"message_type":case.message_type,"value":case.value,"schema_valid":case.schema_valid,"observation":observation}));
    }
    reports
}
#[allow(dead_code)]
fn main() {
    println!(
        "{}",
        serde_json::to_string(&contract_reports()).expect("V7 reports")
    );
}
