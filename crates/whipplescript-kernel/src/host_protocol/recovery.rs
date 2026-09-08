//! Authenticated late evidence is a new attributable operation. A run's
//! failure, a submitted label, or the original action's authority cannot mint it.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use whipplescript_store::effect_recovery::{DispositionEvidence, EFFECT_RECOVERY_PROTOCOL};

use super::action::{canonical_json, hex, ActionProvenance};
use super::{nonempty, PinnedPosition, PolicyEpochRef, ProtocolError};
use crate::ifc::VerifiedEnvelope;

pub const EFFECT_RECONCILIATION_PROTOCOL: &str = "whipplescript.effect-reconciliation.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileEffectCommand {
    pub protocol: String,
    pub issuer: String,
    pub scope: String,
    pub request_id: String,
    #[serde(deserialize_with = "super::action_wire::Policy::deserialize")]
    pub policy: PolicyEpochRef,
    pub provenance: ActionProvenance,
    pub evidence: DispositionEvidence,
    pub evidence_label_ref: String,
}

impl ReconcileEffectCommand {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol != EFFECT_RECONCILIATION_PROTOCOL
            || self.evidence.frame.protocol != EFFECT_RECOVERY_PROTOCOL
        {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        let frame = &self.evidence.frame;
        for (name, value) in [
            ("reconciliation issuer", &self.issuer),
            ("reconciliation scope", &self.scope),
            ("reconciliation request", &self.request_id),
            ("dispatch instance", &frame.instance_id),
            ("dispatch effect", &frame.effect_id),
            ("dispatch run", &frame.run_id),
            ("dispatch key", &frame.idempotency_key),
            ("dispatch kind", &frame.kind),
            ("dispatch provider", &frame.provider),
            ("dispatch input", &frame.input_fingerprint),
            ("dispatch execution", &frame.execution_fingerprint),
            ("evidence reference", &self.evidence.evidence_ref),
            ("evidence digest", &self.evidence.evidence_digest),
            ("evidence authority", &self.evidence.authority_ref),
            ("evidence label", &self.evidence_label_ref),
        ] {
            nonempty(name, value)?;
        }
        if let Some(target) = &frame.target {
            nonempty("dispatch target", target)?;
        }
        self.policy.validate()?;
        self.provenance.validate()
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|_| ProtocolError::Invalid("reconciliation serialization"))?;
        let mut bytes = b"whipplescript:effect-reconciliation:command:v1\0".to_vec();
        canonical_json(&value, &mut bytes)?;
        Ok(bytes)
    }

    pub fn fingerprint(&self) -> Result<String, ProtocolError> {
        Ok(hex(&Sha256::digest(self.signing_bytes()?)))
    }

    /// Within an instance, issuer/scope/request is spent once. Changing the
    /// run, evidence, principal or policy under it must collide and be refused.
    pub fn request_key(&self) -> Result<String, ProtocolError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&[
            EFFECT_RECONCILIATION_PROTOCOL,
            &self.evidence.frame.instance_id,
            &self.issuer,
            &self.scope,
            &self.request_id,
        ])
        .map_err(|_| ProtocolError::Invalid("reconciliation identity"))?;
        Ok(format!("reconciliation:{}", hex(&Sha256::digest(bytes))))
    }
}

/// Trusted host adapter, backed by pinned authorization and target trust roots.
/// Verify current authority/revocation for this reconciliation and scope, every
/// provenance/delegation claim, and the authenticated target proof of the exact
/// frame and disposition. Authorize access to the receipt under its exact label.
/// An unsigned success/absence label is never a target proof. Neither transient
/// proof is copied to the event log. There is deliberately no default verifier.
pub trait EffectEvidenceVerifier {
    fn verify(
        &self,
        command: &ReconcileEffectCommand,
        signing_bytes: &[u8],
        authorization_proof: &[u8],
        target_proof: &[u8],
    ) -> Result<(), ProtocolError>;
}

pub(crate) struct VerifiedReconciliation {
    command: ReconcileEffectCommand,
}

impl VerifiedReconciliation {
    pub(crate) fn verify(
        command: ReconcileEffectCommand,
        envelope: &VerifiedEnvelope,
        verifier: &dyn EffectEvidenceVerifier,
        authorization_proof: &[u8],
        target_proof: &[u8],
    ) -> Result<Self, ProtocolError> {
        let policy = PolicyEpochRef::from_verified(command.policy.epoch, envelope)?;
        if command.policy != policy
            || !envelope.attestation().is_some_and(|attestation| {
                attestation.epoch == Some(command.policy.epoch)
                    && attestation.authority.as_deref() == Some(command.issuer.as_str())
            })
        {
            return Err(ProtocolError::Mismatch(
                "reconciliation signed authority and epoch",
            ));
        }
        let signing = command.signing_bytes()?;
        if target_proof.is_empty()
            || command.evidence.evidence_digest != hex(&Sha256::digest(target_proof))
        {
            return Err(ProtocolError::Mismatch(
                "reconciliation target proof digest",
            ));
        }
        verifier.verify(&command, &signing, authorization_proof, target_proof)?;
        Ok(Self { command })
    }

    pub(crate) fn command(&self) -> &ReconcileEffectCommand {
        &self.command
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationReceipt {
    pub protocol: String,
    pub request_key: String,
    pub fingerprint: String,
    #[serde(deserialize_with = "super::action_wire::Position::deserialize")]
    pub recorded_at: PinnedPosition,
}

/// The kernel derives diagnostics from prior admitted evidence. They are not
/// caller-selectable parts of the reconciliation command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedReconciliation {
    pub command: ReconcileEffectCommand,
    pub diagnostic: Option<ReconciliationDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationDiagnostic {
    pub code: String,
    pub effect_id: String,
    pub run_id: String,
    pub message: String,
    pub evidence_refs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_protocol::action::tests::{command as action, envelope, mutations};
    use whipplescript_store::effect_recovery::{DispatchFrame, EvidenceDisposition};

    struct Exact(Vec<u8>);
    impl EffectEvidenceVerifier for Exact {
        fn verify(
            &self,
            _: &ReconcileEffectCommand,
            signing: &[u8],
            auth: &[u8],
            target: &[u8],
        ) -> Result<(), ProtocolError> {
            if signing == self.0 && auth == b"current-authority" && target == b"target-receipt" {
                Ok(())
            } else {
                Err(ProtocolError::Mismatch("pinned evidence authority"))
            }
        }
    }

    fn command() -> ReconcileEffectCommand {
        let action = action();
        ReconcileEffectCommand {
            protocol: EFFECT_RECONCILIATION_PROTOCOL.into(),
            issuer: action.issuer,
            scope: action.scope,
            request_id: "reconcile:1".into(),
            policy: action.policy,
            provenance: action.provenance,
            evidence: DispositionEvidence {
                frame: DispatchFrame {
                    protocol: EFFECT_RECOVERY_PROTOCOL.into(),
                    instance_id: "instance:1".into(),
                    effect_id: "effect:1".into(),
                    run_id: "run:1".into(),
                    idempotency_key: "key:1".into(),
                    kind: "file.write".into(),
                    target: Some("ledger".into()),
                    provider: "workspace".into(),
                    input_fingerprint: "input-digest".into(),
                    execution_fingerprint: "execution-digest".into(),
                    action_admission: Some(
                        whipplescript_store::host_actions::ActionAdmissionBinding {
                            fingerprint: "action-fingerprint".into(),
                            sequence: 2,
                            head_digest: "admission-digest".into(),
                        },
                    ),
                },
                disposition: EvidenceDisposition::NotApplied,
                evidence_ref: "ledger".into(),
                evidence_digest: hex(&Sha256::digest(b"target-receipt")),
                authority_ref: "target:1".into(),
            },
            evidence_label_ref: "label:private".into(),
        }
    }

    #[test]
    fn reconciliation_binds_every_semantic_leaf_to_current_authority_and_target_proof() {
        let command = command();
        let verifier = Exact(command.signing_bytes().unwrap());
        let policy = envelope(7, "product");
        VerifiedReconciliation::verify(
            command.clone(),
            &policy,
            &verifier,
            b"current-authority",
            b"target-receipt",
        )
        .unwrap();
        for value in mutations(&serde_json::to_value(&command).unwrap()) {
            let Ok(changed) = serde_json::from_value::<ReconcileEffectCommand>(value) else {
                continue;
            };
            assert!(VerifiedReconciliation::verify(
                changed,
                &policy,
                &verifier,
                b"current-authority",
                b"target-receipt"
            )
            .is_err());
        }
        for (auth, target) in [
            (&b"forged"[..], &b"target-receipt"[..]),
            (&b"current-authority"[..], &b"forged"[..]),
            (&b"current-authority"[..], &b""[..]),
        ] {
            assert!(VerifiedReconciliation::verify(
                command.clone(),
                &policy,
                &verifier,
                auth,
                target
            )
            .is_err());
        }
        for wrong_policy in [envelope(7, "other-issuer"), envelope(8, "product")] {
            assert!(VerifiedReconciliation::verify(
                command.clone(),
                &wrong_policy,
                &verifier,
                b"current-authority",
                b"target-receipt"
            )
            .is_err());
        }
        let mut changed = command.clone();
        changed.evidence.disposition = EvidenceDisposition::Applied;
        assert_eq!(
            changed.request_key().unwrap(),
            command.request_key().unwrap()
        );
        assert_ne!(
            changed.fingerprint().unwrap(),
            command.fingerprint().unwrap()
        );
        changed.scope = "another-scope".into();
        assert_ne!(
            changed.request_key().unwrap(),
            command.request_key().unwrap()
        );
        let mut wire = serde_json::to_value(&command).unwrap();
        wire["skip_target_verification"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ReconcileEffectCommand>(wire).is_err());
    }

    #[test]
    fn reconciliation_refuses_unknown_versions_before_host_verification() {
        let mut wrong = command();
        wrong.protocol = "whipplescript.effect-reconciliation.future".into();
        assert!(wrong.validate().is_err());
        wrong = command();
        wrong.evidence.frame.protocol = "whipplescript.effect-recovery.future".into();
        assert!(wrong.validate().is_err());
    }

    #[test]
    fn reconciliation_authentication_cannot_substitute_a_different_receipt_digest() {
        let mut wrong = command();
        wrong.evidence.evidence_digest = hex(&Sha256::digest(b"another-target-receipt"));
        // The host authenticates these exact command bytes and the genuine
        // target proof. The runtime must independently reject their mismatch.
        let verifier = Exact(wrong.signing_bytes().unwrap());
        assert!(VerifiedReconciliation::verify(
            wrong,
            &envelope(7, "product"),
            &verifier,
            b"current-authority",
            b"target-receipt",
        )
        .is_err());
    }
}
