#[path = "../examples/host_action_contract_v2.rs"]
mod emitter;

#[test]
fn scoped_host_action_vectors_extend_the_pinned_legacy_codecs() {
    let reports = emitter::contract_reports();
    assert_eq!(reports.len(), 80);
    let types: std::collections::BTreeSet<_> = reports
        .iter()
        .filter(|report| report.observation.wire_valid)
        .map(|report| report.message_type.as_str())
        .collect();
    assert_eq!(types.len(), 12);
    for name in [
        "ResolutionMemoryScope",
        "ScopedSaveReceipt",
        "ResolutionMemoryReceipt",
    ] {
        assert!(types.contains(name));
    }
}
