use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};

use super::super::{action::*, action_result::*, execution::*, recovery::*};

fn rejects_extra<T: DeserializeOwned + Serialize>(value: Value, paths: &[&str]) {
    let decoded: T = serde_json::from_value(value.clone()).expect("valid wire fixture");
    assert_eq!(serde_json::to_value(decoded).expect("encode"), value);
    for path in paths {
        let mut changed = value.clone();
        changed
            .pointer_mut(path)
            .expect("fixture coordinate")
            .as_object_mut()
            .expect("object")
            .insert("unsupported_constraint".into(), json!("must not disappear"));
        match serde_json::from_value::<T>(changed) {
            Ok(_) => panic!("unknown field at {path} was silently discarded"),
            Err(error) => assert!(
                error
                    .to_string()
                    .contains("unknown field `unsupported_constraint`"),
                "{path}: {error}"
            ),
        }
    }
}

#[test]
fn action_wire_nested_constraints_are_never_silently_discarded() {
    let command = super::super::action::tests::command();
    let raw = serde_json::to_value(&command).expect("command");
    let decoded: HostActionCommand = serde_json::from_value(raw.clone()).expect("decode");
    assert_eq!(
        decoded.signing_bytes().expect("valid fixture"),
        command.signing_bytes().expect("valid fixture")
    );
    assert_eq!(
        decoded.fingerprint().expect("valid fixture"),
        command.fingerprint().expect("valid fixture")
    );
    rejects_extra::<HostActionCommand>(
        raw.clone(),
        &["", "/policy", "/resources/file/resource", "/provenance"],
    );
    let position = json!({
        "instance_ref": command.instance_ref().expect("valid fixture"), "sequence": 1,
        "head_digest": "retained-prefix"
    });
    let admission = json!({
        "protocol": HOST_ACTION_PROTOCOL, "fingerprint": command.fingerprint().expect("valid fixture"),
        "instance_ref": command.instance_ref().expect("valid fixture"), "admitted_at": position
    });
    rejects_extra::<ActionAdmissionReceipt>(admission.clone(), &["", "/admitted_at"]);
    let read = json!({
        "protocol": ACTION_RESULT_PROTOCOL, "issuer": command.issuer,
        "scope": command.scope, "policy": raw["policy"], "provenance": raw["provenance"],
        "admission": admission, "evidence_handle": "history", "evidence_label_ref": "private",
        "through": position
    });
    rejects_extra::<ReadActionResult>(
        read.clone(),
        &["/policy", "/admission/admitted_at", "/through"],
    );
    let execution = json!({
        "protocol": ACTION_EXECUTION_PROTOCOL, "issuer": command.issuer,
        "scope": command.scope, "policy": raw["policy"], "provenance": raw["provenance"],
        "admission": admission, "effect_id": "save", "effect_fingerprint": "exact-effect"
    });
    rejects_extra::<ExecuteActionEffect>(execution, &["/policy", "/admission/admitted_at"]);
    let recovery = json!({
        "protocol": EFFECT_RECONCILIATION_PROTOCOL, "issuer": command.issuer,
        "scope": command.scope, "request_id": "recover", "policy": raw["policy"],
        "provenance": raw["provenance"], "evidence_label_ref": "private",
        "evidence": {
            "frame": {
                "protocol": "whipplescript.effect-recovery.v1",
                "instance_id": command.instance_ref().expect("valid fixture"), "effect_id": "save",
                "run_id": "attempt-1", "idempotency_key": "stable-key", "kind": "file.write",
                "target": null, "provider": "files", "input_fingerprint": "input",
                "execution_fingerprint": "execution"
            },
            "disposition": "applied", "evidence_ref": "target-result",
            "evidence_digest": "digest", "authority_ref": "target-authority"
        }
    });
    rejects_extra::<ReconcileEffectCommand>(recovery, &["/policy", "/evidence/frame"]);
    rejects_extra::<ReconciliationReceipt>(
        json!({
            "protocol": EFFECT_RECONCILIATION_PROTOCOL, "request_key": "recovery-key",
            "fingerprint": "recovery-fingerprint", "recorded_at": position
        }),
        &["/recorded_at"],
    );
    let terminal = json!({
        "status": "completed", "recorded_at": position,
        "evidence": {"event_id": "completed", "sequence": 1, "kind": "workflow.completed"}
    });
    rejects_extra::<ActionTerminalEvidence>(terminal.clone(), &["/recorded_at"]);
    rejects_extra::<ActionResultSnapshot>(
        json!({
            "protocol": ACTION_RESULT_PROTOCOL, "admission": admission, "command": raw,
            "read_policy": command.policy, "evidence_handle": "history",
            "evidence_label_ref": "private", "observed_at": position,
            "instance_status": "completed", "status_evidence": terminal["evidence"],
            "terminal": terminal, "effects": [], "evidence": []
        }),
        &[
            "/read_policy",
            "/observed_at",
            "/terminal/recorded_at",
            "/admission/admitted_at",
        ],
    );

    // Optional fields keep both wire spellings already accepted by v1.
    let mut without_pin = read;
    without_pin
        .as_object_mut()
        .expect("valid fixture")
        .remove("through");
    assert!(
        serde_json::from_value::<ReadActionResult>(without_pin.clone())
            .expect("valid fixture")
            .through
            .is_none()
    );
    without_pin["through"] = Value::Null;
    assert!(serde_json::from_value::<ReadActionResult>(without_pin)
        .expect("valid fixture")
        .through
        .is_none());
}

#[test]
fn action_wire_strictness_preserves_the_legacy_shared_readers() {
    use super::super::{PinnedPosition, PolicyEpochRef, ResourceRef};
    let legacy_policy =
        json!({"epoch": 1, "envelope_hash": "hash", "signer": "signer", "extension": true});
    let legacy_resource = json!({"handle": "handle", "kind": "files", "extension": true});
    let legacy_position = json!({"instance_ref": "instance", "sequence": 1, "head_digest": "digest", "extension": true});
    assert!(serde_json::from_value::<PolicyEpochRef>(legacy_policy).is_ok());
    assert!(serde_json::from_value::<ResourceRef>(legacy_resource).is_ok());
    assert!(serde_json::from_value::<PinnedPosition>(legacy_position).is_ok());
}
