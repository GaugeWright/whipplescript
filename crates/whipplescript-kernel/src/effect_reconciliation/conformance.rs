//! The authenticated late-evidence door runs over both actual SQL backends.
//! Target receipts here are pinned fixtures; this does not qualify a live sink.
use crate::gov::{ExternalAttestation, GovernanceAttestationVerifier, SignedEnvelope};
use crate::host_facade::GovernedHostFacade;
use crate::host_protocol::action::ActionProvenance;
use crate::host_protocol::recovery::{
    EffectEvidenceVerifier, ReconcileEffectCommand, RecordedReconciliation,
    EFFECT_RECONCILIATION_PROTOCOL,
};
use crate::host_protocol::ProtocolError;
use crate::ifc::VerifiedEnvelope;
use serde_json::{json, Value};
use std::cell::Cell;
use whipplescript_store::effect_recovery::{
    fold_attempts, DispositionEvidence, EvidenceDisposition, ExternalDisposition,
};
use whipplescript_store::log_append::LogAppend;
use whipplescript_store::{
    EffectCompletion, NewEffect, NewInstance, RetryEffect, RuleCommit, RunStart, RuntimeStore,
};

struct PolicyRoot;
impl GovernanceAttestationVerifier for PolicyRoot {
    fn verify(&self, _: &[u8], attestation: &ExternalAttestation) -> Result<(), String> {
        if attestation.signature == "pinned-policy-proof" {
            Ok(())
        } else {
            Err("untrusted policy proof".into())
        }
    }
}

const TARGET_PROOF: &[u8] = b"authenticated target receipt for this exact attempt";
struct TargetRoot {
    expected: ReconcileEffectCommand,
    revoked: Cell<bool>,
}
impl TargetRoot {
    fn new(command: &ReconcileEffectCommand) -> Self {
        Self {
            expected: command.clone(),
            revoked: Cell::new(false),
        }
    }
}
impl EffectEvidenceVerifier for TargetRoot {
    fn verify(
        &self,
        command: &ReconcileEffectCommand,
        signing: &[u8],
        authorization_proof: &[u8],
        target_proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if self.revoked.get()
            || command != &self.expected
            || signing != self.expected.signing_bytes()?
            || authorization_proof != b"current-authority"
            || target_proof != TARGET_PROOF
        {
            return Err(ProtocolError::Mismatch(
                "pinned reconciliation authority/target proof",
            ));
        }
        Ok(())
    }
}

pub fn journey<S: RuntimeStore + LogAppend>(mut store: S, actor: &str) -> Value {
    let version = whipplescript_store::host_actions::conformance::register(&mut store);
    let instance = store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("reconciliation conformance step");
    let id = &instance.instance_id;
    store
        .commit_rule(RuleCommit {
            instance_id: id,
            rule: "fixture",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &[NewEffect {
                effect_id: "effect",
                kind: "timer.wait",
                target: None,
                input_json: "{}",
                status: "queued",
                idempotency_key: "original-effect-key",
                required_capabilities_json: "[]",
                profile: None,
                correlation_id: None,
                source_span_json: None,
                timeout_seconds: None,
            }],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("fixture-rule"),
            marks: &[],
            context_json: None,
        })
        .expect("reconciliation conformance step");
    store
        .start_run(RunStart {
            instance_id: id,
            effect_id: "effect",
            run_id: "first-run",
            provider: "builtin",
            worker_id: "worker",
            lease_id: "first-lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        })
        .expect("reconciliation conformance step");
    store
        .complete_effect(EffectCompletion {
            instance_id: id,
            effect_id: "effect",
            run_id: "first-run",
            provider: "builtin",
            worker_id: "worker",
            status: "failed",
            exit_code: None,
            summary: None,
            metadata_json: "{}",
            idempotency_key: Some("first-terminal"),
        })
        .expect("reconciliation conformance step");
    let attempts = fold_attempts(
        id,
        "effect",
        &store
            .list_events(id)
            .expect("reconciliation conformance step"),
    )
    .expect("reconciliation conformance step");
    assert_eq!(attempts[0].disposition, ExternalDisposition::Unknown);
    let signed = SignedEnvelope::from_external_signature_v2(
        "grant file_store ledger -> file:/srv/ledger.db readable by Operator\n",
        "fixture-signer",
        "fixture",
        "fixture-key",
        "pinned-policy-proof",
        7,
        "product",
    )
    .expect("reconciliation conformance step");
    let envelope = VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &PolicyRoot)
        .expect("reconciliation conformance step");
    let mut host = GovernedHostFacade::from_verified_store(store, 7, envelope)
        .expect("reconciliation conformance step");
    let command = ReconcileEffectCommand {
        protocol: EFFECT_RECONCILIATION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace:1".into(),
        request_id: "reconcile-first".into(),
        policy: host.policy_ref().clone(),
        provenance: ActionProvenance {
            initiator: actor.into(),
            executor: actor.into(),
            origin: "recovery.inspect".into(),
            delegation: vec![],
            causes: vec![],
        },
        evidence: DispositionEvidence {
            frame: attempts[0]
                .dispatch
                .as_ref()
                .expect("reconciliation conformance step")
                .frame
                .clone(),
            disposition: EvidenceDisposition::NotApplied,
            evidence_ref: "ledger".into(),
            evidence_digest: whipplescript_store::items::sha256_hex(
                std::str::from_utf8(TARGET_PROOF).expect("reconciliation conformance step"),
            ),
            authority_ref: "pinned-target".into(),
        },
        evidence_label_ref: "label:private".into(),
    };
    let root = TargetRoot::new(&command);
    let epoch = host
        .kernel()
        .store()
        .instance_owner_epoch(id)
        .expect("reconciliation conformance step");
    let before = host
        .kernel()
        .store()
        .list_events(id)
        .expect("reconciliation conformance step");
    for (authorization, receipt) in [
        (&b"forged"[..], TARGET_PROOF),
        (&b"current-authority"[..], &b"forged"[..]),
        (&b"current-authority"[..], &b""[..]),
    ] {
        assert!(host
            .reconcile_effect(command.clone(), epoch, &root, authorization, receipt)
            .is_err());
    }
    let mut changed = command.clone();
    changed.evidence.disposition = EvidenceDisposition::Applied;
    assert!(host
        .reconcile_effect(changed, epoch, &root, b"current-authority", TARGET_PROOF)
        .is_err());
    assert!(host
        .reconcile_effect(
            command.clone(),
            epoch + 1,
            &root,
            b"current-authority",
            TARGET_PROOF
        )
        .is_err());
    assert_eq!(
        before,
        host.kernel()
            .store()
            .list_events(id)
            .expect("reconciliation conformance step")
    );

    // Even a correctly authenticated statement cannot substitute another
    // attempt, input, target or key for the recorded dispatch.
    for field in [
        "effect_id",
        "run_id",
        "idempotency_key",
        "kind",
        "target",
        "provider",
        "input_fingerprint",
        "execution_fingerprint",
    ] {
        let mut value = serde_json::to_value(&command).expect("reconciliation conformance step");
        value["evidence"]["frame"][field] = json!("another-coordinate");
        let drifted: ReconcileEffectCommand =
            serde_json::from_value(value).expect("reconciliation conformance step");
        let verifier = TargetRoot::new(&drifted);
        assert!(
            host.reconcile_effect(
                drifted,
                epoch,
                &verifier,
                b"current-authority",
                TARGET_PROOF
            )
            .is_err(),
            "{field}"
        );
    }
    assert_eq!(
        before,
        host.kernel()
            .store()
            .list_events(id)
            .expect("reconciliation conformance step")
    );

    let receipt = host
        .reconcile_effect(
            command.clone(),
            epoch,
            &root,
            b"current-authority",
            TARGET_PROOF,
        )
        .expect("reconciliation conformance step");
    let recorded = host
        .kernel()
        .store()
        .list_events(id)
        .expect("reconciliation conformance step");
    assert_eq!(recorded.len(), before.len() + 1);
    assert!(!recorded
        .last()
        .expect("reconciliation conformance step")
        .payload_json
        .contains(std::str::from_utf8(TARGET_PROOF).expect("reconciliation conformance step")));
    let stored: RecordedReconciliation = serde_json::from_str(
        &recorded
            .last()
            .expect("reconciliation conformance step")
            .payload_json,
    )
    .expect("reconciliation conformance step");
    assert_eq!(stored.command, command);
    assert!(stored.diagnostic.is_none());
    assert_eq!(stored.command.provenance.initiator, actor);
    host.kernel_mut()
        .store_mut()
        .rebuild_projections(id)
        .expect("reconciliation conformance step");
    assert_eq!(
        recorded,
        host.kernel()
            .store()
            .list_events(id)
            .expect("reconciliation conformance step")
    );
    assert_eq!(
        receipt,
        host.reconcile_effect(
            command.clone(),
            epoch,
            &root,
            b"current-authority",
            TARGET_PROOF
        )
        .expect("reconciliation conformance step")
    );
    assert_eq!(
        recorded,
        host.kernel()
            .store()
            .list_events(id)
            .expect("reconciliation conformance step")
    );
    root.revoked.set(true);
    assert!(host
        .reconcile_effect(
            command.clone(),
            epoch,
            &root,
            b"current-authority",
            TARGET_PROOF
        )
        .is_err());
    root.revoked.set(false);

    let mut changed = command.clone();
    changed.provenance.origin = "changed-meaning".into();
    let changed_root = TargetRoot::new(&changed);
    assert_eq!(
        changed
            .request_key()
            .expect("reconciliation conformance step"),
        command
            .request_key()
            .expect("reconciliation conformance step")
    );
    assert!(host
        .reconcile_effect(
            changed,
            epoch,
            &changed_root,
            b"current-authority",
            TARGET_PROOF
        )
        .is_err());
    let attempts = fold_attempts(
        id,
        "effect",
        &host
            .kernel()
            .store()
            .list_events(id)
            .expect("reconciliation conformance step"),
    )
    .expect("reconciliation conformance step");
    assert_eq!(attempts[0].disposition, ExternalDisposition::NotApplied);
    host.kernel_mut()
        .store_mut()
        .retry_effect(RetryEffect {
            instance_id: id,
            effect_id: "effect",
            retry_after: None,
            idempotency_key: Some("retry"),
        })
        .expect("reconciliation conformance step");
    host.kernel_mut()
        .store_mut()
        .start_run(RunStart {
            instance_id: id,
            effect_id: "effect",
            run_id: "second-run",
            provider: "builtin",
            worker_id: "worker",
            lease_id: "second-lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        })
        .expect("reconciliation conformance step");
    host.kernel_mut()
        .store_mut()
        .expire_leases(id, "2031-01-01T00:00:00Z")
        .expect("reconciliation conformance step");
    assert!(host
        .kernel_mut()
        .store_mut()
        .retry_effect(RetryEffect {
            instance_id: id,
            effect_id: "effect",
            retry_after: None,
            idempotency_key: Some("unsafe-retry"),
        })
        .is_err());
    let mut contradictory = command.clone();
    contradictory.request_id = "late-contradiction".into();
    contradictory.evidence.disposition = EvidenceDisposition::Applied;
    let contradiction_root = TargetRoot::new(&contradictory);
    host.reconcile_effect(
        contradictory,
        epoch,
        &contradiction_root,
        b"current-authority",
        TARGET_PROOF,
    )
    .expect("reconciliation conformance step");
    let attempts = fold_attempts(
        id,
        "effect",
        &host
            .kernel()
            .store()
            .list_events(id)
            .expect("reconciliation conformance step"),
    )
    .expect("reconciliation conformance step");
    let late = host
        .kernel()
        .store()
        .list_events(id)
        .expect("reconciliation conformance step");
    let record: RecordedReconciliation = serde_json::from_str(
        &late
            .last()
            .expect("reconciliation conformance step")
            .payload_json,
    )
    .expect("reconciliation conformance step");
    let diagnostic = record
        .diagnostic
        .expect("contradictory evidence needs a durable diagnostic");
    assert_eq!(diagnostic.code, "runtime.recovery_uncertain");
    assert_eq!(diagnostic.run_id, "first-run");
    assert_eq!(diagnostic.effect_id, "effect");
    assert_eq!(attempts.len(), 2);
    assert!(attempts[0].disputed);
    assert_eq!(attempts[0].disposition, ExternalDisposition::NotApplied);
    assert_eq!(attempts[0].evidence.len(), 2);
    assert_eq!(attempts[1].disposition, ExternalDisposition::Unknown);
    assert_eq!(
        attempts[1]
            .dispatch
            .as_ref()
            .expect("reconciliation conformance step")
            .frame
            .idempotency_key,
        "original-effect-key"
    );
    assert_eq!(
        receipt,
        host.reconcile_effect(command, epoch, &root, b"current-authority", TARGET_PROOF)
            .expect("reconciliation conformance step")
    );
    json!({"attempts": attempts.len(), "disputed": attempts[0].disputed,
        "first_disposition": attempts[0].disposition, "second_disposition": attempts[1].disposition,
        "evidence": attempts[0].evidence.len()})
}
