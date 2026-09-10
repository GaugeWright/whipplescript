#[path = "../examples/host_action_contract_v3.rs"]
mod emitter;

#[test]
fn recording_host_action_vectors_extend_both_immutable_base_bundles() {
    let reports = emitter::contract_reports();
    assert_eq!(reports.len(), 118);
    let types: std::collections::BTreeSet<_> = reports
        .iter()
        .filter(|report| report["observation"]["wire_valid"] == true)
        .map(|report| report["message_type"].as_str().expect("message type"))
        .collect();
    assert_eq!(types.len(), 14);
    for name in ["ResolutionRecordingInput", "ResolutionRecordingBinding"] {
        assert!(types.contains(name));
    }
}
