//! Real recording, retained target receipt and fenced reconciliation. The
//! authority is a synthetic exact-claims fixture, never a product trust root.
use super::*;
use crate::host_protocol::recovery::{
    EffectEvidenceVerifier, ReconcileEffectCommand, EFFECT_RECONCILIATION_PROTOCOL,
};
use whipplescript_store::{
    branches::resolution_batch::ResolutionMemoryReceipt,
    effect_recovery::{
        fold_attempts, DispositionEvidence, EvidenceDisposition, ExternalDisposition,
    },
    items::sha256_hex,
};

struct RecoveryAuthority {
    original: HostActionCommand,
    binding: ResolutionRecordingBinding,
    signed: Vec<u8>,
    denied: &'static str,
    reads: Cell<usize>,
}
#[cfg(test)]
impl ResolutionRecordingReconciliationAuthority for RecoveryAuthority {
    fn authenticate(
        &self,
        _: &ReconcileEffectCommand,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if self.denied == "authentication" || bytes != self.signed || proof != b"recover" {
            return Err(ProtocolError::Mismatch(
                "fixture current recording recovery authentication",
            ));
        }
        Ok(())
    }
    fn authorize(
        &self,
        _: &ReconcileEffectCommand,
        original: &HostActionCommand,
        _: &ExecuteActionEffect,
        binding: &ResolutionRecordingBinding,
    ) -> Result<(), ProtocolError> {
        self.reads.set(self.reads.get() + 1);
        if self.denied == "authority" || original != &self.original || binding != &self.binding {
            return Err(ProtocolError::Mismatch(
                "fixture original and current recording evidence authority",
            ));
        }
        Ok(())
    }
}

fn current_envelope(case: &str) -> VerifiedEnvelope {
    let mut policy = json!({"resources": {"memory:/corrections": {}, "memory:/resolutions": {}, "result": {}, "error": {}},
        "bindings": {"admitted_corrections": "memory:/corrections", "admitted_resolutions": "memory:/resolutions"}});
    if case == "confidentiality" {
        policy["resources"]["memory:/corrections"]["reader"] = json!(["Private"]);
    }
    if case == "integrity" || case == "memory-integrity" {
        policy["resources"]["memory:/resolutions"]["writer_sink"] = json!(["Trusted"]);
    }
    if case == "memory-integrity" {
        policy["resources"]["memory:/corrections"]["writer"] = json!(["Trusted"]);
    }
    let signed = SignedEnvelope::from_external_signature_v2(
        &policy.to_string(),
        "fixture",
        "fixture",
        "fixture",
        "fixture",
        8,
        "product",
    )
    .expect("renewed policy");
    VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &PolicyFixture)
        .expect("current envelope")
}

fn executed(case: &str, actor: &str) -> Fixture {
    let mut f = setup(case, actor);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.execute()));
    if case.starts_with("interrupt-") {
        assert!(result.is_err());
    } else {
        result.expect("no interruption").expect("settled");
    }
    f.facade = GovernedHostFacade::from_verified_store(
        f.facade.into_kernel().into_store(),
        8,
        current_envelope("allowed"),
    )
    .expect("reopened at current epoch");
    f
}

fn workspace(f: &Fixture) -> WorkspaceVcs<BranchStore, ContentStore> {
    WorkspaceVcs::from_parts(
        BranchStore::open_read_only(f._root.0.join("branches.sqlite")).expect("read-only branches"),
        ContentStore::open_read_only(f._root.0.join("content.sqlite")).expect("read-only content"),
    )
}

fn command(f: &Fixture, receipt: Option<&ResolutionMemoryReceipt>) -> ReconcileEffectCommand {
    let instance = &f.request.admission.instance_ref;
    let events = f
        .facade
        .kernel()
        .store()
        .list_events(instance)
        .expect("events");
    let frame = fold_attempts(instance, &f.request.effect_id, &events).expect("attempts")[0]
        .dispatch
        .as_ref()
        .expect("dispatch")
        .frame
        .clone();
    ReconcileEffectCommand {
        protocol: EFFECT_RECONCILIATION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace".into(),
        request_id: "recovery".into(),
        policy: f.facade.policy_ref().clone(),
        provenance: f.request.provenance.clone(),
        evidence: DispositionEvidence {
            frame,
            disposition: EvidenceDisposition::Applied,
            evidence_ref: "admitted_resolutions".into(),
            authority_ref: "target-authority".into(),
            evidence_digest: receipt
                .map(|r| sha256_hex(&r.encode().expect("proof JSON").0))
                .unwrap_or_else(|| "a".repeat(64)),
        },
        evidence_label_ref: "memory-label".into(),
    }
}

fn authority(
    f: &Fixture,
    command: &ReconcileEffectCommand,
    denied: &'static str,
) -> RecoveryAuthority {
    RecoveryAuthority {
        original: f.authority.original.clone(),
        binding: f.authority.binding.clone(),
        signed: command.signing_bytes().expect("current signing"),
        denied,
        reads: Cell::new(0),
    }
}

#[cfg(test)]
#[test]
fn recording_recovery_preserves_terminal_and_erasure_for_humans_and_agents() {
    for actor in ["human:one", "agent:one"] {
        for case in [
            "success",
            "target-failure",
            "failure-after-publication",
            "interrupt-before-publication",
            "interrupt-after-publication",
        ] {
            let mut f = executed(case, actor);
            let instance = f.request.admission.instance_ref.clone();
            let target = workspace(&f);
            let batch = target
                .resolution_receipt(&f.authority.binding.batch().operation_id)
                .expect("target query");
            let command = command(&f, batch.as_ref());
            let allowed = authority(&f, &command, "allowed");
            let source = ResolutionRecordingEvidenceSource {
                action: &f.action,
                admission: &f.request.admission,
                workspace: &target,
                authority_ref: "target-authority",
            };
            let epoch = f
                .facade
                .kernel_mut()
                .store_mut()
                .claim_instance_ownership(&instance)
                .expect("ownership");
            let before = f
                .facade
                .kernel()
                .store()
                .list_events(&instance)
                .expect("before");
            let runs = f
                .facade
                .kernel()
                .store()
                .list_runs(&instance)
                .expect("runs");
            let facts = f
                .facade
                .kernel()
                .store()
                .list_facts(&instance)
                .expect("facts");
            let workflow = f
                .facade
                .kernel()
                .store()
                .get_instance(&instance)
                .expect("workflow");
            let calls = f.calls.get();
            let result = f.facade.reconcile_resolution_recording(
                command.clone(),
                epoch,
                &source,
                &allowed,
                b"recover",
            );
            if batch.is_none() {
                assert!(matches!(
                    result,
                    Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
                        "recording target has no committed result"
                    )))
                ));
                assert_eq!(
                    f.facade
                        .kernel()
                        .store()
                        .list_events(&instance)
                        .expect("after"),
                    before
                );
                assert_eq!(
                    fold_attempts(&instance, &f.request.effect_id, &before).expect("fold")[0]
                        .disposition,
                    ExternalDisposition::Unknown
                );
                continue;
            }
            let receipt = result.expect("positive recovery");
            let after = f
                .facade
                .kernel()
                .store()
                .list_events(&instance)
                .expect("after");
            assert_eq!(after.len(), before.len() + 1);
            assert_eq!(
                fold_attempts(&instance, &f.request.effect_id, &after).expect("fold")[0]
                    .disposition,
                ExternalDisposition::Applied
            );
            assert_eq!(
                f.facade
                    .kernel()
                    .store()
                    .list_runs(&instance)
                    .expect("same runs"),
                runs
            );
            assert_eq!(
                f.facade
                    .kernel()
                    .store()
                    .list_facts(&instance)
                    .expect("same facts"),
                facts
            );
            assert_eq!(
                f.facade
                    .kernel()
                    .store()
                    .get_instance(&instance)
                    .expect("same workflow"),
                workflow
            );
            f.facade
                .kernel_mut()
                .store_mut()
                .rebuild_projections(&instance)
                .expect("rebuild");
            assert_eq!(
                f.facade
                    .reconcile_resolution_recording(
                        command.clone(),
                        epoch,
                        &source,
                        &allowed,
                        b"recover"
                    )
                    .expect("redelivery"),
                receipt
            );
            assert_eq!(
                allowed.reads.get(),
                2,
                "redelivery reauthorizes the actual target read"
            );
            let contents =
                ContentStore::open(f._root.0.join("content.sqlite")).expect("custody fixture");
            let winner = &batch.as_ref().expect("batch").outcomes[0].resolution;
            contents
                .erase(winner, "2026-09-10T13:00:00Z")
                .expect("erase correction");
            assert_eq!(contents.get(winner).expect("erased body"), None);
            assert_eq!(
                f.facade
                    .reconcile_resolution_recording(
                        command.clone(),
                        epoch,
                        &source,
                        &allowed,
                        b"recover"
                    )
                    .expect("historical receipt survives body erasure"),
                receipt
            );
            assert_eq!(contents.get(winner).expect("still erased"), None);
            assert_eq!(
                f.facade
                    .kernel()
                    .store()
                    .list_events(&instance)
                    .expect("no replay append"),
                after
            );
            assert_eq!(f.calls.get(), calls, "recovery never invokes recording");
            assert_eq!(
                target
                    .resolution_receipt(&f.authority.binding.batch().operation_id)
                    .expect("unchanged batch"),
                batch
            );
        }
    }
}

#[cfg(test)]
#[test]
fn recording_recovery_refuses_current_authority_flow_digest_and_stale_owner() {
    for actor in ["human:one", "agent:one"] {
        for case in [
            "authentication",
            "authority",
            "proof",
            "confidentiality",
            "integrity",
            "memory-integrity",
            "digest",
            "domain-hash",
            "owner",
        ] {
            let mut f = executed("success", actor);
            f.facade = GovernedHostFacade::from_verified_store(
                f.facade.into_kernel().into_store(),
                8,
                current_envelope(case),
            )
            .expect("current policy");
            let target = workspace(&f);
            let batch = target
                .resolution_receipt(&f.authority.binding.batch().operation_id)
                .expect("receipt")
                .expect("committed");
            let mut command = command(&f, Some(&batch));
            if case == "digest" {
                command.evidence.evidence_digest = "a".repeat(64);
            }
            if case == "domain-hash" {
                command.evidence.evidence_digest = batch.encode().expect("batch identity").1;
            }
            let authority = authority(&f, &command, case);
            let source = ResolutionRecordingEvidenceSource {
                action: &f.action,
                admission: &f.request.admission,
                workspace: &target,
                authority_ref: "target-authority",
            };
            let instance = &f.request.admission.instance_ref;
            let epoch = f
                .facade
                .kernel_mut()
                .store_mut()
                .claim_instance_ownership(instance)
                .expect("ownership");
            if case == "owner" {
                f.facade
                    .kernel_mut()
                    .store_mut()
                    .claim_instance_ownership(instance)
                    .expect("supersede owner");
            }
            let before = f
                .facade
                .kernel()
                .store()
                .list_events(instance)
                .expect("before");
            let error = f
                .facade
                .reconcile_resolution_recording(
                    command,
                    epoch,
                    &source,
                    &authority,
                    if case == "proof" {
                        b"wrong"
                    } else {
                        b"recover"
                    },
                )
                .expect_err(case);
            match case {
                "confidentiality" | "integrity" | "memory-integrity" => assert!(
                    matches!(error, HostFacadeError::PolicyRejected(_)),
                    "{error:?}"
                ),
                "owner" => assert!(matches!(error, HostFacadeError::Store(_)), "{error:?}"),
                _ => {
                    let expected = match case {
                        "authentication" | "proof" => {
                            "fixture current recording recovery authentication"
                        }
                        "authority" => "fixture original and current recording evidence authority",
                        _ => "reconciliation target proof digest",
                    };
                    assert!(
                        matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message)) if message == expected),
                        "{case}: {error:?}"
                    );
                }
            }
            assert_eq!(
                f.facade
                    .kernel()
                    .store()
                    .list_events(instance)
                    .expect("unchanged"),
                before
            );
        }
    }
}

#[cfg(test)]
#[test]
fn recording_recovery_checks_original_dispatch_and_cannot_mint_context_from_a_receipt() {
    let f = executed("success", "human:one");
    let target = workspace(&f);
    let batch = target
        .resolution_receipt(&f.authority.binding.batch().operation_id)
        .expect("receipt")
        .expect("batch");
    let command = command(&f, Some(&batch));
    let authority = authority(&f, &command, "allowed");
    let source = ResolutionRecordingEvidenceSource {
        action: &f.action,
        admission: &f.request.admission,
        workspace: &target,
        authority_ref: "target-authority",
    };
    let prefix = f
        .facade
        .kernel()
        .store()
        .chain_prefix(&command.evidence.frame.instance_id)
        .expect("prefix");
    let prepare = |command: &ReconcileEffectCommand, prefix: &[_]| {
        super::super::recovery::prepare(
            command,
            &source,
            prefix,
            &authority,
            b"recover",
            &current_envelope("allowed"),
        )
    };
    let verified = prepare(&command, &prefix).expect("actual evidence");
    let signing = command.signing_bytes().expect("signing");
    let proof = batch.encode().expect("proof").0;
    verified
        .verify(&command, &signing, b"recover", proof.as_bytes())
        .expect("exact context");
    for case in ["command", "signing", "authorization", "target"] {
        let mut changed = command.clone();
        if case == "command" {
            changed.request_id.push_str("-changed");
        }
        assert!(
            verified
                .verify(
                    &changed,
                    if case == "signing" {
                        b"wrong"
                    } else {
                        &signing
                    },
                    if case == "authorization" {
                        b"wrong"
                    } else {
                        b"recover"
                    },
                    if case == "target" {
                        b"wrong"
                    } else {
                        proof.as_bytes()
                    }
                )
                .is_err(),
            "{case}"
        );
    }
    for case in [
        "kind",
        "target",
        "provider",
        "admission",
        "disposition",
        "authority",
        "frame",
        "missing",
        "duplicate",
        "execution",
        "fingerprint",
        "binding",
        "input-hash",
        "label",
        "reference",
    ] {
        let mut changed = command.clone();
        let mut history = prefix.clone();
        let index = history
            .iter()
            .position(|e| e.event_type == "effect.run_started")
            .expect("dispatch index");
        let mut payload: Value =
            serde_json::from_str(&history[index].payload_json).expect("payload");
        let expected = match case {
            "kind" | "target" | "provider" | "admission" | "disposition" | "authority" => {
                match case {
                    "kind" => changed.evidence.frame.kind = "file.write".into(),
                    "target" => changed.evidence.frame.target = Some("other".into()),
                    "provider" => changed.evidence.frame.provider = "other".into(),
                    "admission" => changed.evidence.frame.action_admission = None,
                    "disposition" => changed.evidence.disposition = EvidenceDisposition::NotApplied,
                    _ => changed.evidence.authority_ref = "other".into(),
                }
                "recording reconciliation scope and disposition"
            }
            "frame" => {
                payload["external_dispatch"]["frame"]["input_fingerprint"] = json!("changed");
                "recording exact recorded dispatch"
            }
            "missing" => {
                history[index].event_type = "unrelated".into();
                "recording dispatch is unavailable"
            }
            "duplicate" => {
                history.push(history[index].clone());
                "recording exact recorded dispatch"
            }
            "execution" => {
                payload["metadata"]["action_execution"]["request"]["effect_id"] = json!("other");
                "recording original executing authority"
            }
            "fingerprint" => {
                payload["metadata"]["action_execution"]["fingerprint"] = json!("other");
                "recording original executing authority"
            }
            "binding" => {
                payload["metadata"]["resolution_recording"]["batch"]["actor"] = json!("other");
                "recording command does not bind the target adapter"
            }
            "input-hash" => {
                payload["metadata"]["resolution_recording"]["input_hash"] = json!("a".repeat(32));
                "fixture original and current recording evidence authority"
            }
            "label" => {
                changed.evidence_label_ref = "other".into();
                "recording original evidence reference and label"
            }
            "reference" => {
                changed.evidence.evidence_ref = "admitted_corrections".into();
                "recording original evidence reference and label"
            }
            _ => unreachable!(),
        };
        history[index].payload_json = payload.to_string();
        let error = prepare(&changed, &history).expect_err(case);
        assert!(
            matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message)) if message == expected),
            "{case}: {error:?}"
        );
    }
}

#[cfg(test)]
#[test]
fn recording_recovery_authorizes_before_reading_corrupt_or_different_target_evidence() {
    for case in ["corrupt", "different-batch"] {
        let mut f = executed("success", "human:one");
        let target = workspace(&f);
        let mut batch = target
            .resolution_receipt(&f.authority.binding.batch().operation_id)
            .expect("actual target")
            .expect("committed");
        let command = command(&f, Some(&batch));
        let denied = authority(&f, &command, "authority");
        let allowed = authority(&f, &command, "allowed");
        batch.request.recorded_at = "different-recording-time".into();
        let (json, digest) = batch.encode().expect("different valid receipt");
        let connection = rusqlite::Connection::open(f._root.0.join("branches.sqlite"))
            .expect("fixture target corruption");
        connection.execute("UPDATE resolution_batches SET receipt_json = ?1, receipt_hash = ?2 WHERE operation_id = ?3",
            rusqlite::params![json, if case == "corrupt" { "corrupt" } else { &digest }, batch.request.operation_id])
            .expect("change fixture evidence");
        let source = ResolutionRecordingEvidenceSource {
            action: &f.action,
            admission: &f.request.admission,
            workspace: &target,
            authority_ref: "target-authority",
        };
        let instance = &f.request.admission.instance_ref;
        let epoch = f
            .facade
            .kernel_mut()
            .store_mut()
            .claim_instance_ownership(instance)
            .expect("ownership");
        let before = f
            .facade
            .kernel()
            .store()
            .list_events(instance)
            .expect("before");
        for (authority, expected) in [
            (
                &denied,
                "fixture original and current recording evidence authority",
            ),
            (
                &allowed,
                "recording retained target evidence is unavailable",
            ),
        ] {
            let error = f
                .facade
                .reconcile_resolution_recording(
                    command.clone(),
                    epoch,
                    &source,
                    authority,
                    b"recover",
                )
                .expect_err("authority precedes actual receipt comparison");
            assert!(
                matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message)) if message == expected),
                "{case}: {error:?}"
            );
        }
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .list_events(instance)
                .expect("unchanged"),
            before
        );
    }
}
