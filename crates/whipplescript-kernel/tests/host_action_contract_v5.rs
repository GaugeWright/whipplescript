#[path = "../examples/host_action_contract_v5.rs"]
mod emitter;

#[test]
fn current_read_authority_extends_immutable_vectors_and_binds_each_coordinate() {
    let reports = emitter::contract_reports();
    assert_eq!(reports.len(), 218);
    let find = |id: &str| reports.iter().find(|r| r["id"] == id).expect("vector");
    let hash = |id| find(id)["observation"]["signing_sha256"].clone();
    assert_eq!(hash("pinned-read"), hash("legacy-authority-read"));
    // SHA-256 of the published V1 fixture, canonical JSON and original domain.
    assert_eq!(
        hash("pinned-read"),
        "6e0a232eaf7220a2af07c12baa8d82f8946b9bed163fc14f147e06d7f086da26"
    );
    assert_ne!(
        hash("legacy-authority-read"),
        hash("current-authority-read")
    );
    assert_ne!(
        hash("current-authority-read"),
        hash("current-authority-read-other-authority")
    );
    assert_ne!(
        hash("current-authority-read"),
        hash("current-authority-read-old-issuer")
    );
    use whipplescript_kernel::host_protocol::action_result::ReadActionResult;
    for (id, domain) in [
        (
            "legacy-authority-read",
            &b"whipplescript:action-result:read:v1\0"[..],
        ),
        (
            "current-authority-read",
            &b"whipplescript:action-result:read:v2\0"[..],
        ),
    ] {
        let request: ReadActionResult = serde_json::from_value(find(id)["value"].clone()).unwrap();
        assert!(request.signing_bytes().unwrap().starts_with(domain));
    }
}
