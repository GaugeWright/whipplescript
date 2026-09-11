#[path = "../examples/host_action_contract_v4.rs"]
mod emitter;

#[test]
fn tracker_host_action_vectors_extend_all_immutable_base_bundles() {
    let reports = emitter::contract_reports();
    assert_eq!(reports.len(), 205);
    let types: std::collections::BTreeSet<_> = reports
        .iter()
        .filter(|report| report["observation"]["wire_valid"] == true)
        .map(|report| report["message_type"].as_str().expect("message type"))
        .collect();
    assert_eq!(types.len(), 23);
    let value = &reports
        .iter()
        .find(|report| report["id"] == "RecoverTrackerResult")
        .expect("recovery vector")["value"];
    use whipplescript_kernel::host_protocol::tracker_recovery::{
        RecoverTrackerClosure, RecoverTrackerFiling, RecoverTrackerResult,
    };
    let canonical: RecoverTrackerResult = serde_json::from_value(value.clone()).unwrap();
    let filing: RecoverTrackerFiling = serde_json::from_value(value.clone()).unwrap();
    let closing: RecoverTrackerClosure = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        canonical.signing_bytes().unwrap(),
        filing.signing_bytes().unwrap()
    );
    assert_eq!(
        canonical.signing_bytes().unwrap(),
        closing.signing_bytes().unwrap()
    );
}
