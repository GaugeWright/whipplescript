#[path = "../examples/host_action_contract_v7.rs"]
mod emitter;
use emitter::previous;
use whipplescript_kernel::host_protocol::action::HostActionCommand;
use whipplescript_kernel::host_protocol::action_result::{ActionFootprint, ReadActionResult};
#[test]
fn negotiated_footprint_preserves_old_bytes_and_binds_anchor() {
    let reports = emitter::contract_reports();
    assert_eq!(reports.len(), 274);
    assert_eq!(&reports[..231], previous::contract_reports().as_slice());
    let find = |id: &str| reports.iter().find(|r| r["id"] == id).expect("vector");
    let hash = |id| find(id)["observation"]["signing_sha256"].clone();
    assert_eq!(hash("command-anchor-null"), hash("command-anchor-absent"));
    assert_eq!(hash("command-anchor-absent"), hash("human-save"));
    assert_ne!(hash("command-anchor"), hash("command-anchor-other"));
    let request: ReadActionResult =
        serde_json::from_value(find("footprint-read")["value"].clone()).expect("read");
    assert!(request
        .signing_bytes()
        .expect("signing")
        .starts_with(b"whipplescript:action-result:read:v4\0"));
    let command: HostActionCommand =
        serde_json::from_value(find("command-anchor")["value"].clone()).expect("command");
    let mut receipt = request.admission.clone();
    receipt.instance_ref = command.instance_ref().expect("identity");
    receipt.fingerprint = command.fingerprint().expect("fingerprint");
    receipt.admitted_at.instance_ref = receipt.instance_ref.clone();
    assert!(receipt.validate_for(&command).is_ok());
    // Runtime fixture anchor attribution is tested by
    // the owning runtime cohort; live holding remains the installed host verifier.
    assert_eq!(receipt.anchor, command.anchor);
    receipt.anchor = None;
    assert!(receipt.validate_for(&command).is_err());
}
#[test]
fn structural_counts_do_not_claim_runtime_semantics() {
    let reports = emitter::contract_reports();
    let value = reports
        .iter()
        .find(|r| r["id"] == "footprint-inconsistent-structural")
        .expect("vector")["value"]
        .clone();
    let decoded: ActionFootprint =
        serde_json::from_value(value).expect("structural codec accepts counts");
    assert_ne!(decoded.total, decoded.acts.len() as u64);
    let empty = ActionFootprint::from_acts(Vec::new());
    assert_eq!(empty.unobserved_share(), None);
}

#[test]
fn actual_classification_derives_exact_share_and_unknown_is_opaque() {
    use whipplescript_kernel::host_protocol::action_result::{
        act_observation, ActFootprint, FootprintObservation,
    };
    let acts = ["file.read", "exec.command", "future.unknown"]
        .into_iter()
        .enumerate()
        .map(|(i, kind)| ActFootprint {
            effect_id: format!("effect:{i}"),
            kind: kind.into(),
            observation: act_observation(kind),
        })
        .collect();
    let footprint = ActionFootprint::from_acts(acts);
    assert_eq!((footprint.unobserved, footprint.total), (2, 3));
    assert_eq!(footprint.unobserved_share(), Some(2.0 / 3.0));
    assert_eq!(
        footprint.acts[2].observation,
        FootprintObservation::Unobserved
    );
}
