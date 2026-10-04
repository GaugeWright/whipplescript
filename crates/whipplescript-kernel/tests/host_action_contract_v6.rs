#[path = "../examples/host_action_contract_v6.rs"]
mod emitter;

#[test]
fn reconciliation_authority_extends_immutable_vectors_and_binds_both_issuers() {
    let reports = emitter::contract_reports();
    assert_eq!(reports.len(), 231);
    let find = |id: &str| reports.iter().find(|r| r["id"] == id).expect("vector");
    let hash = |id| find(id)["observation"]["signing_sha256"].clone();
    assert_eq!(hash("reconcile-applied"), hash("legacy-reconciliation"));
    // Golden bytes and retry identity from the actual published V5 runtime.
    assert_eq!(
        hash("legacy-reconciliation"),
        "7755c382e7cf68a03c63c7dc9e6ecad03d6094ff575d50e6618720cdce539665"
    );
    assert_eq!(
        find("legacy-reconciliation")["observation"]["identity"],
        "reconciliation:f96e6e6354006d7aedc2f017aa2da5b48d4a38189147316122f38fe320666ce9"
    );
    for id in [
        "legacy-reconciliation",
        "current-authority-reconciliation-other-current",
        "current-authority-reconciliation-other-original",
    ] {
        assert_ne!(hash("current-authority-reconciliation"), hash(id));
        assert_ne!(
            find("current-authority-reconciliation")["observation"]["identity"],
            find(id)["observation"]["identity"]
        );
    }
    use whipplescript_kernel::host_protocol::recovery::ReconcileEffectCommand;
    for (id, domain) in [
        (
            "legacy-reconciliation",
            &b"whipplescript:effect-reconciliation:command:v1\0"[..],
        ),
        (
            "current-authority-reconciliation",
            &b"whipplescript:effect-reconciliation:command:v2\0"[..],
        ),
    ] {
        let command: ReconcileEffectCommand =
            serde_json::from_value(find(id)["value"].clone()).unwrap();
        assert!(command.signing_bytes().unwrap().starts_with(domain));
    }
}
