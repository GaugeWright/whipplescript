#[path = "../examples/host_action_contract.rs"]
mod emitter;

#[test]
fn published_host_action_vectors_match_the_runtime_codecs_and_identities() {
    let reports = emitter::contract_reports();
    let covered: std::collections::BTreeSet<_> = reports
        .iter()
        .filter(|report| report.observation.wire_valid)
        .map(|report| report.message_type.as_str())
        .collect();
    assert_eq!(
        covered,
        std::collections::BTreeSet::from([
            "HostActionCommand",
            "ActionAdmissionReceipt",
            "ExecuteActionEffect",
            "ReadActionResult",
            "ActionResultSnapshot",
            "ReconcileEffectCommand",
            "ReconciliationReceipt",
            "SaveReceipt",
            "WriteEvidenceRef",
        ])
    );
    assert!(reports
        .iter()
        .any(|report| report.observation.syntax_valid == Some(false)));
    assert!(reports.iter().any(|report| !report.observation.wire_valid));
}
