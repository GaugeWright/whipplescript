//! Current authority for one effect of an immutable admitted action.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use whipplescript_store::ClaimableEffect;

use super::action::{
    canonical_json, hex, ActionAdmissionReceipt, ActionProvenance, HostActionCommand,
    HOST_ACTION_PROTOCOL,
};
use super::{nonempty, PolicyEpochRef, ProtocolError};
use crate::ifc::VerifiedEnvelope;

pub const ACTION_EXECUTION_PROTOCOL: &str = "whipplescript.action-execution.v1";

/// The observation subsequently compared inside dispatch admission. It binds
/// every field used by a handler, without placing input bodies in the command.
pub fn effect_observation_fingerprint(effect: &ClaimableEffect) -> Result<String, ProtocolError> {
    let value = serde_json::json!([
        effect.effect_id,
        effect.kind,
        effect.target,
        effect.profile,
        effect.input_json,
        effect.required_capabilities_json,
        effect.declared_profiles_json,
    ]);
    let mut bytes = b"whipplescript:action-execution:effect:v1\0".to_vec();
    canonical_json(&value, &mut bytes)?;
    Ok(hex(&Sha256::digest(bytes)))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteActionEffect {
    pub protocol: String,
    pub issuer: String,
    pub scope: String,
    pub admission: ActionAdmissionReceipt,
    #[serde(deserialize_with = "super::action_wire::Policy::deserialize")]
    pub policy: PolicyEpochRef,
    pub provenance: ActionProvenance,
    pub effect_id: String,
    pub effect_fingerprint: String,
}

impl ExecuteActionEffect {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.protocol != ACTION_EXECUTION_PROTOCOL
            || self.admission.protocol != HOST_ACTION_PROTOCOL
        {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        for (field, value) in [
            ("execution issuer", &self.issuer),
            ("execution scope", &self.scope),
            ("execution effect", &self.effect_id),
            ("execution effect fingerprint", &self.effect_fingerprint),
            (
                "execution admission fingerprint",
                &self.admission.fingerprint,
            ),
            ("execution instance", &self.admission.instance_ref),
            (
                "execution admission digest",
                &self.admission.admitted_at.head_digest,
            ),
        ] {
            nonempty(field, value)?;
        }
        if self.admission.admitted_at.sequence == 0
            || self.admission.admitted_at.instance_ref != self.admission.instance_ref
        {
            return Err(ProtocolError::Mismatch("execution admission coordinates"));
        }
        self.policy.validate()?;
        self.provenance.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|_| ProtocolError::Invalid("execution request serialization"))?;
        let mut bytes = b"whipplescript:action-execution:request:v1\0".to_vec();
        canonical_json(&value, &mut bytes)?;
        Ok(bytes)
    }
}

/// The host's pinned, current execution boundary. Authenticate the complete
/// request, actual executor/delegation and current revocation on EVERY call.
/// Authorize this exact observed effect within the original command's scope,
/// operation, input/resource labels and bases; a newer policy cannot widen
/// that original ceiling. Verify the actual resource mapping supplied to the
/// handler. An admission proof, actor string or receipt alone grants nothing.
/// Proof bytes are transient and must not be copied into evidence or errors.
pub trait ActionExecutionVerifier {
    /// Authenticate before inspecting the action's stored command or effect.
    /// This includes current access to the exact admission's metadata scope.
    fn authenticate(
        &self,
        request: &ExecuteActionEffect,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError>;

    /// Recheck current execution rights against the recorded original ceiling
    /// and exact observed effect, immediately before entering its handler.
    fn authorize(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
    ) -> Result<(), ProtocolError>;
}

pub(crate) struct AuthenticatedActionExecution {
    request: ExecuteActionEffect,
    fingerprint: String,
}
impl AuthenticatedActionExecution {
    pub(crate) fn verify(
        request: ExecuteActionEffect,
        envelope: &VerifiedEnvelope,
        verifier: &dyn ActionExecutionVerifier,
        proof: &[u8],
    ) -> Result<Self, ProtocolError> {
        let bytes = request.signing_bytes()?;
        let policy = PolicyEpochRef::from_verified(request.policy.epoch, envelope)?;
        if request.policy != policy
            || !envelope.attestation().is_some_and(|attestation| {
                attestation.epoch == Some(request.policy.epoch)
                    && attestation.authority.as_deref() == Some(request.issuer.as_str())
            })
        {
            return Err(ProtocolError::Mismatch(
                "execution signed authority and epoch",
            ));
        }
        verifier.authenticate(&request, &bytes, proof)?;
        Ok(Self {
            request,
            fingerprint: hex(&Sha256::digest(bytes)),
        })
    }
    pub(crate) fn request(&self) -> &ExecuteActionEffect {
        &self.request
    }
    pub(crate) fn authorize(
        self,
        original: &HostActionCommand,
        effect: ClaimableEffect,
        verifier: &dyn ActionExecutionVerifier,
    ) -> Result<VerifiedActionExecution, ProtocolError> {
        let request = self.request;
        request.admission.validate_for(original)?;
        if request.issuer != original.issuer
            || request.scope != original.scope
            || request.effect_id != effect.effect_id
            || request.effect_fingerprint != effect_observation_fingerprint(&effect)?
        {
            return Err(ProtocolError::Mismatch("execution exact action and effect"));
        }
        verifier.authorize(&request, original, &effect)?;
        Ok(VerifiedActionExecution {
            request,
            observed: effect,
            fingerprint: self.fingerprint,
        })
    }
}

/// Only the facade can construct this transient, non-clonable grant. It is
/// consumed by a single dispatch and cannot be restored from recorded metadata.
pub(crate) struct VerifiedActionExecution {
    request: ExecuteActionEffect,
    observed: ClaimableEffect,
    fingerprint: String,
}
impl VerifiedActionExecution {
    pub(crate) fn request(&self) -> &ExecuteActionEffect {
        &self.request
    }
    pub(crate) fn observed(&self) -> &ClaimableEffect {
        &self.observed
    }
    pub(crate) fn evidence(&self) -> serde_json::Value {
        serde_json::json!({"request": self.request, "fingerprint": self.fingerprint})
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::host_protocol::action::tests::{command, envelope};

    struct ExactExecution(Vec<u8>);
    impl ActionExecutionVerifier for ExactExecution {
        fn authenticate(
            &self,
            _: &ExecuteActionEffect,
            bytes: &[u8],
            proof: &[u8],
        ) -> Result<(), ProtocolError> {
            if bytes == self.0 && proof == b"execution" {
                Ok(())
            } else {
                Err(ProtocolError::Mismatch("fixture execution proof"))
            }
        }
        fn authorize(
            &self,
            _: &ExecuteActionEffect,
            _: &HostActionCommand,
            _: &ClaimableEffect,
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
    }
    pub(crate) fn fixture(kind: &str) -> (ExecuteActionEffect, HostActionCommand, ClaimableEffect) {
        let original = command();
        let instance = original.instance_ref().expect("instance identity");
        let effect = ClaimableEffect {
            effect_id: "file-effect".into(),
            kind: kind.into(),
            target: None,
            profile: None,
            input_json: "{}".into(),
            required_capabilities_json: "[]".into(),
            declared_profiles_json: "[]".into(),
        };
        let request = ExecuteActionEffect {
            protocol: ACTION_EXECUTION_PROTOCOL.into(),
            issuer: original.issuer.clone(),
            scope: original.scope.clone(),
            admission: ActionAdmissionReceipt {
                protocol: HOST_ACTION_PROTOCOL.into(),
                fingerprint: original.fingerprint().expect("command fingerprint"),
                instance_ref: instance.clone(),
                admitted_at: super::super::PinnedPosition {
                    instance_ref: instance,
                    sequence: 2,
                    head_digest: "fixture-prefix".into(),
                },
            },
            policy: PolicyEpochRef::from_verified(8, &envelope(8, "product"))
                .expect("renewed policy"),
            provenance: original.provenance.clone(),
            effect_id: effect.effect_id.clone(),
            effect_fingerprint: effect_observation_fingerprint(&effect)
                .expect("effect fingerprint"),
        };
        (request, original, effect)
    }
    fn verify_fixture(
        request: ExecuteActionEffect,
        original: &HostActionCommand,
        effect: ClaimableEffect,
        envelope: &VerifiedEnvelope,
        verifier: &dyn ActionExecutionVerifier,
        proof: &[u8],
    ) -> Result<VerifiedActionExecution, ProtocolError> {
        AuthenticatedActionExecution::verify(request, envelope, verifier, proof)?
            .authorize(original, effect, verifier)
    }
    pub(crate) fn verified(kind: &str) -> VerifiedActionExecution {
        let (request, original, effect) = fixture(kind);
        let verifier = ExactExecution(request.signing_bytes().expect("request bytes"));
        verify_fixture(
            request,
            &original,
            effect,
            &envelope(8, "product"),
            &verifier,
            b"execution",
        )
        .expect("verified fixture")
    }

    #[test]
    fn execution_wire_and_current_policy_are_independent_of_original_admission() {
        let (request, original, effect) = fixture("file.write");
        assert_eq!(original.policy.epoch, 7);
        assert_eq!(verified("file.write").request().policy.epoch, 8);
        for field in [
            "protocol",
            "admission-protocol",
            "zero-position",
            "position-instance",
            "empty-effect",
            "empty-fingerprint",
        ] {
            let mut bad = request.clone();
            match field {
                "protocol" => bad.protocol = "unknown".into(),
                "admission-protocol" => bad.admission.protocol = "unknown".into(),
                "zero-position" => bad.admission.admitted_at.sequence = 0,
                "position-instance" => bad.admission.admitted_at.instance_ref = "other".into(),
                "empty-effect" => bad.effect_id.clear(),
                "empty-fingerprint" => bad.effect_fingerprint.clear(),
                _ => unreachable!(),
            }
            assert!(bad.signing_bytes().is_err(), "{field}");
        }
        let mut raw = serde_json::to_value(&request).expect("wire value");
        raw["unsupported"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ExecuteActionEffect>(raw).is_err());
        for field in [
            "policy-epoch",
            "policy-authority",
            "scope",
            "effect",
            "observation",
            "proof",
        ] {
            let mut bad = request.clone();
            let mut policy = envelope(8, "product");
            match field {
                // These contexts deliberately agree on the public PolicyEpochRef
                // and disagree only on its signed authority/epoch coordinates.
                "policy-epoch" => {
                    bad.policy =
                        PolicyEpochRef::from_verified(9, &policy).expect("mismatched epoch fixture")
                }
                "policy-authority" => {
                    policy = envelope(8, "other");
                    bad.policy =
                        PolicyEpochRef::from_verified(8, &policy).expect("other authority fixture");
                }
                "scope" => bad.scope = "other-workspace".into(),
                "effect" => bad.effect_id = "other-effect".into(),
                "observation" => bad.effect_fingerprint = "other-input".into(),
                _ => (),
            }
            let verifier = ExactExecution(bad.signing_bytes().expect("changed request bytes"));
            let proof = if field == "proof" {
                b"admission".as_slice()
            } else {
                b"execution".as_slice()
            };
            assert!(
                verify_fixture(bad, &original, effect.clone(), &policy, &verifier, proof).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn execution_observation_hash_binds_every_handler_coordinate() {
        let (_, _, effect) = fixture("file.write");
        let fingerprint = effect_observation_fingerprint(&effect).expect("fingerprint");
        for field in [
            "id",
            "kind",
            "target",
            "profile",
            "input",
            "capabilities",
            "profiles",
        ] {
            let mut changed = effect.clone();
            match field {
                "id" => changed.effect_id = "other".into(),
                "kind" => changed.kind = "file.read".into(),
                "target" => changed.target = Some("other".into()),
                "profile" => changed.profile = Some("other".into()),
                "input" => changed.input_json = "{\"other\":true}".into(),
                "capabilities" => changed.required_capabilities_json = "[\"other\"]".into(),
                "profiles" => changed.declared_profiles_json = "[\"other\"]".into(),
                _ => unreachable!(),
            }
            assert_ne!(
                effect_observation_fingerprint(&changed).expect("changed fingerprint"),
                fingerprint,
                "{field}"
            );
        }
    }
}
