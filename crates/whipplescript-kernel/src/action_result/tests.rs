use super::*;
use crate::host_action::CompiledHostAction;
use crate::host_facade::GovernedHostFacade;
use crate::host_protocol::action::tests::{command, envelope, mutations, ExactAdmission};
use crate::host_protocol::action_result::{ActionResultVerifier, ACTION_RESULT_PROTOCOL};
use whipplescript_store::native_stores::NativeStores;

struct ReadAuthority(Vec<u8>);
impl ActionResultVerifier for ReadAuthority {
    fn verify(
        &self,
        _: &ReadActionResult,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if bytes == self.0 && proof == b"read authorization" {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture result read proof"))
        }
    }
}

fn fixture() -> (
    CompiledHostAction,
    ReadActionResult,
    GovernedHostFacade<NativeStores>,
) {
    let action = CompiledHostAction::compile(
        "reference.echo",
        r#"
workflow ResultFixture
input content InputReference
output result Result
class InputReference { handle string version_ref string label_ref string }
class Result { handle string }
rule echo when InputReference as reference => { complete result { handle reference.handle } }
"#,
        None,
    )
    .unwrap();
    let mut command = command();
    command.operation = "reference.echo".into();
    command.program_version_ref = action.version_ref().into();
    command.input_schema_ref = action.input_schema_ref().into();
    command.inputs.get_mut("content").unwrap().handle = "ledger".into();
    command.resources.clear();
    let mut facade = GovernedHostFacade::from_verified_store(
        NativeStores::open_in_memory().unwrap(),
        7,
        envelope(7, "product"),
    )
    .unwrap();
    let admission = facade
        .admit_action(
            command.clone(),
            &action,
            &ExactAdmission(command.signing_bytes().unwrap()),
            b"authenticated fixture",
        )
        .unwrap();
    let request = ReadActionResult {
        protocol: ACTION_RESULT_PROTOCOL.into(),
        issuer: command.issuer,
        scope: command.scope,
        policy: command.policy,
        provenance: command.provenance,
        admission,
        evidence_handle: "ledger".into(),
        evidence_label_ref: "label:private".into(),
        through: None,
    };
    (action, request, facade)
}

fn read(
    facade: &GovernedHostFacade<NativeStores>,
    request: &ReadActionResult,
) -> Result<ActionResultSnapshot, HostFacadeError> {
    facade.read_action_result(
        request.clone(),
        &ReadAuthority(request.signing_bytes()?),
        b"read authorization",
    )
}

#[test]
fn result_lookup_survives_restart_and_policy_renewal_without_executing() {
    let (action, mut request, mut facade) = fixture();
    let initial_events = facade
        .kernel()
        .store()
        .list_events(&request.admission.instance_ref)
        .unwrap();
    let pending = read(&facade, &request).unwrap();
    assert!(pending.terminal.is_none());
    assert!(pending.effects.is_empty());
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(&request.admission.instance_ref)
            .unwrap(),
        initial_events
    );
    crate::rule_pass::step_instance_generic(
        facade.kernel_mut(),
        &request.admission.instance_ref,
        action.program(),
        None,
        None,
    )
    .unwrap();
    let completed = read(&facade, &request).unwrap();
    assert_eq!(
        completed.terminal.as_ref().unwrap().status,
        ActionWorkflowStatus::Completed
    );
    assert_eq!(completed.admission, pending.admission);
    facade
        .kernel_mut()
        .store_mut()
        .append_event(whipplescript_store::NewEvent {
            instance_id: &request.admission.instance_ref,
            event_type: "workflow.failed",
            payload_json: r#"{"secret_body":"must not cross the result boundary"}"#,
            source: "external",
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
        })
        .unwrap();
    let later = read(&facade, &request).unwrap();
    assert_eq!(later.terminal, completed.terminal);
    assert_ne!(later.observed_at, completed.observed_at);
    assert!(!serde_json::to_string(&later)
        .unwrap()
        .contains("secret_body"));
    request.through = Some(pending.observed_at.clone());
    assert_eq!(read(&facade, &request).unwrap(), pending);
    request.through = Some(completed.observed_at.clone());
    assert_eq!(read(&facade, &request).unwrap(), completed);
    facade
        .kernel_mut()
        .store_mut()
        .rebuild_projections(&request.admission.instance_ref)
        .unwrap();
    let store = facade.into_kernel().into_store();
    let facade = GovernedHostFacade::from_verified_store(store, 8, envelope(8, "product")).unwrap();
    assert!(
        read(&facade, &request).is_err(),
        "old read policy is not current authority"
    );
    request.policy = facade.policy_ref().clone();
    let renewed = read(&facade, &request).unwrap();
    assert_eq!(renewed.admission, completed.admission);
    assert_eq!(renewed.terminal, completed.terminal);
    assert_eq!(renewed.command.policy.epoch, 7);
    assert_eq!(renewed.read_policy.epoch, 8);
}

#[test]
fn result_lookup_requires_current_exact_read_authority() {
    let (_, request, facade) = fixture();
    let authority = ReadAuthority(request.signing_bytes().unwrap());
    assert!(facade
        .read_action_result(request.clone(), &authority, b"admission proof")
        .is_err());
    for changed in mutations(&serde_json::to_value(&request).unwrap()) {
        let Ok(changed) = serde_json::from_value::<ReadActionResult>(changed) else {
            continue;
        };
        assert!(facade
            .read_action_result(changed, &authority, b"read authorization")
            .is_err());
    }
    let mut ungoverned = request.clone();
    ungoverned.evidence_handle = "not-granted".into();
    assert!(read(&facade, &ungoverned).is_err());
    let mut wrong_issuer = request.clone();
    wrong_issuer.issuer = "another-authority".into();
    assert!(read(&facade, &wrong_issuer).is_err());
    assert!(VerifiedResultRead::verify(
        wrong_issuer.clone(),
        &envelope(7, "product"),
        &ReadAuthority(wrong_issuer.signing_bytes().unwrap()),
        b"read authorization"
    )
    .is_err());
    let mut wrong_pin = request.clone();
    wrong_pin.through = Some(PinnedPosition {
        instance_ref: request.admission.instance_ref.clone(),
        sequence: 999,
        head_digest: "wrong".into(),
    });
    assert!(read(&facade, &wrong_pin).is_err());
    wrong_pin.through.as_mut().unwrap().sequence = 1;
    assert!(wrong_pin.signing_bytes().is_err());
    let mut wrong_protocol = request.clone();
    wrong_protocol.protocol = "future".into();
    assert!(wrong_protocol.signing_bytes().is_err());
    let mut wrong_coordinate = request.clone();
    wrong_coordinate.admission.admitted_at.instance_ref = "another".into();
    assert!(wrong_coordinate.signing_bytes().is_err());
    wrong_coordinate = request.clone();
    wrong_coordinate.admission.admitted_at.sequence = 0;
    assert!(wrong_coordinate.signing_bytes().is_err());
}

#[test]
fn result_lookup_records_control_plane_cancellation_without_inventing_output() {
    let (_, request, mut facade) = fixture();
    for (status, expected) in [
        ("paused", ActionInstanceStatus::Paused),
        ("running", ActionInstanceStatus::Running),
        ("cancelled", ActionInstanceStatus::Cancelled),
    ] {
        facade
            .kernel_mut()
            .store_mut()
            .transition_instance(whipplescript_store::InstanceTransition {
                instance_id: &request.admission.instance_ref,
                status,
                reason: Some("result fixture"),
                idempotency_key: Some(status),
            })
            .unwrap();
        let result = read(&facade, &request).unwrap();
        assert_eq!(result.instance_status, expected);
        assert_eq!(result.status_evidence.kind, "instance.transitioned");
        assert!(
            result.terminal.is_none(),
            "control cancellation supplies no workflow output"
        );
    }
}

#[test]
fn result_lookup_refuses_corrupt_or_substituted_recorded_evidence() {
    let (action, request, mut facade) = fixture();
    crate::rule_pass::step_instance_generic(
        facade.kernel_mut(),
        &request.admission.instance_ref,
        action.program(),
        None,
        None,
    )
    .unwrap();
    let prefix = facade
        .kernel()
        .store()
        .chain_prefix(&request.admission.instance_ref)
        .unwrap();
    assert!(snapshot(&request, prefix.clone()).is_ok());
    assert!(snapshot(&request, vec![]).is_err());
    // A valid but incomplete retained prefix must identify missing admission
    // evidence, so callers can distinguish availability from contradictory
    // evidence. Neither case permits reconstructing or resubmitting the act.
    assert!(matches!(
        snapshot(&request, prefix[..1].to_vec()),
        Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
            "result admission is unavailable"
        )))
    ));
    let mut pinned_request = request.clone();
    pinned_request.through = Some(pin(&request.admission.instance_ref, &prefix).unwrap());
    let mut negative = prefix.clone();
    let mut invalid = prefix[0].clone();
    invalid.sequence = -1;
    negative.insert(0, invalid);
    assert!(snapshot(&pinned_request, negative).is_err());
    for index in 0..prefix.len() {
        let mut missing = prefix.clone();
        missing.remove(index);
        if index + 1 < prefix.len() {
            assert!(snapshot(&request, missing).is_err());
        }
    }
    for (source, kind, key) in [
        ("external", "host.action.admitted", "host-action-admission"),
        ("host-runtime", "external.started", "host-action-admission"),
        ("host-runtime", "host.action.admitted", "another-key"),
    ] {
        let mut changed = prefix.clone();
        changed[1].source = Some(source.into());
        changed[1].event_type = kind.into();
        changed[1].idempotency_key = Some(key.into());
        let mut repinned = request.clone();
        repinned.admission.admitted_at =
            pin(&request.admission.instance_ref, &changed[..2]).unwrap();
        assert!(snapshot(&repinned, changed).is_err());
    }
    let mut changed = prefix.clone();
    let mut payload: serde_json::Value = serde_json::from_str(&changed[1].payload_json).unwrap();
    payload["fingerprint"] = "different".into();
    changed[1].payload_json = payload.to_string();
    let mut repinned = request.clone();
    repinned.admission.admitted_at = pin(&request.admission.instance_ref, &changed[..2]).unwrap();
    assert!(snapshot(&repinned, changed).is_err());
    let mut wrong = request.clone();
    wrong.admission.admitted_at.head_digest = "different".into();
    assert!(snapshot(&wrong, prefix.clone()).is_err());
    wrong = request.clone();
    wrong.scope = "another-scope".into();
    assert!(snapshot(&wrong, prefix.clone()).is_err());
    let mut duplicate = prefix.clone();
    let mut terminal = prefix
        .iter()
        .find(|event| event.event_type == "workflow.completed")
        .unwrap()
        .clone();
    terminal.sequence = i64::try_from(prefix.len() + 1).unwrap();
    terminal.event_id = "another-terminal".into();
    duplicate.push(terminal);
    assert!(snapshot(&request, duplicate).is_err());
}

#[test]
fn result_workflow_terminal_does_not_settle_an_external_attempt() {
    use serde_json::json;
    use whipplescript_store::effect_recovery::{
        DispatchFrame, DispatchMarker, DispositionEvidence, EvidenceDisposition,
        ExternalDisposition, RecoveryCeiling, EFFECT_RECOVERY_PROTOCOL,
    };
    let (_, request, facade) = fixture();
    let mut prefix = facade
        .kernel()
        .store()
        .chain_prefix(&request.admission.instance_ref)
        .unwrap();
    fn append(prefix: &mut Vec<OwnedChainEntry>, kind: &str, payload: serde_json::Value) {
        let sequence = i64::try_from(prefix.len() + 1).unwrap();
        prefix.push(OwnedChainEntry {
            event_id: format!("fixture:{sequence}"),
            sequence,
            event_type: kind.into(),
            payload_json: payload.to_string(),
            occurred_at: "2026-09-05T00:00:00Z".into(),
            source: Some("kernel".into()),
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
            format_version: Some(1),
        });
    }
    let frame = DispatchFrame {
        protocol: EFFECT_RECOVERY_PROTOCOL.into(),
        instance_id: request.admission.instance_ref.clone(),
        effect_id: "attempted".into(),
        run_id: "run:1".into(),
        idempotency_key: "stable-effect-key".into(),
        kind: "file.write".into(),
        target: Some("workspace".into()),
        provider: "file".into(),
        input_fingerprint: "input-digest".into(),
        execution_fingerprint: "execution-digest".into(),
        action_admission: Some(whipplescript_store::host_actions::ActionAdmissionBinding {
            fingerprint: request.admission.fingerprint.clone(),
            sequence: i64::try_from(request.admission.admitted_at.sequence).unwrap(),
            head_digest: request.admission.admitted_at.head_digest.clone(),
        }),
    };
    append(
        &mut prefix,
        "rule.committed",
        json!({"effects": [{"effect_id":"attempted"}, {"effect_id":"not-started"}]}),
    );
    append(
        &mut prefix,
        "effect.run_started",
        json!({"effect_id":"attempted", "run_id":"run:1", "external_dispatch":DispatchMarker {frame: frame.clone(), ceiling: RecoveryCeiling::Unverifiable}}),
    );
    append(
        &mut prefix,
        "effect.terminal",
        json!({"effect_id":"attempted", "run_id":"run:1", "status":"completed"}),
    );
    append(
        &mut prefix,
        "workflow.completed",
        json!({"payload":{"secret":"not returned"}}),
    );
    let before = snapshot(&request, prefix.clone()).unwrap();
    assert_eq!(
        before.terminal.as_ref().unwrap().status,
        ActionWorkflowStatus::Completed
    );
    assert_eq!(
        before.effects[0].attempts[0].disposition,
        ExternalDisposition::Unknown
    );
    assert_eq!(
        before.effects[0].attempts[0].terminal_status.as_deref(),
        Some("completed")
    );
    assert!(before.effects[1].attempts.is_empty());
    let evidence = DispositionEvidence {
        frame,
        disposition: EvidenceDisposition::Applied,
        evidence_ref: "receipt:1".into(),
        evidence_digest: "receipt-digest".into(),
        authority_ref: "target-authority".into(),
    };
    append(
        &mut prefix,
        "effect.disposition.recorded",
        serde_json::to_value(&evidence).unwrap(),
    );
    let settled = snapshot(&request, prefix.clone()).unwrap();
    assert_eq!(
        settled.effects[0].attempts[0].disposition,
        ExternalDisposition::Applied
    );
    assert_eq!(settled.terminal, before.terminal);
    let opposite = DispositionEvidence {
        disposition: EvidenceDisposition::NotApplied,
        evidence_ref: "receipt:2".into(),
        ..evidence
    };
    append(
        &mut prefix,
        "effect.disposition.recorded",
        serde_json::to_value(opposite).unwrap(),
    );
    let disputed = snapshot(&request, prefix).unwrap();
    assert!(disputed.effects[0].attempts[0].disputed);
    assert_eq!(disputed.effects[0].attempts[0].evidence.len(), 2);
    assert_eq!(disputed.terminal, before.terminal);
}
