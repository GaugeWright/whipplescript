//! Deterministic host action admission (spec/host-actions.md).
//!
//! Wire commands are untrusted data. Only verification against a signed policy
//! and the host's authenticated admission boundary produces a usable context.
//! This module performs no I/O, so native and hosted placements use one contract.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{nonempty, PinnedPosition, PolicyEpochRef, ProtocolError, ResourceRef};
use crate::ifc::VerifiedEnvelope;

pub const HOST_ACTION_PROTOCOL: &str = "whipplescript.host-action.v1";

/// Exact observation or expected absence. A mutable handle alone is no basis.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionBasis {
    Version { version_ref: String },
    Absent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionResource {
    #[serde(deserialize_with = "super::action_wire::Resource::deserialize")]
    pub resource: ResourceRef,
    pub basis: ActionBasis,
    pub label_ref: String,
}

/// Inputs carry immutable labeled references, never materialized secret bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionInput {
    pub handle: String,
    pub version_ref: String,
    pub label_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionDelegation {
    pub grant_ref: String,
    pub delegator: String,
    pub delegate: String,
}

/// An owner's immutable causal record; the owner retains its authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCause {
    pub authority: String,
    pub record_ref: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionProvenance {
    pub initiator: String,
    pub executor: String,
    pub delegation: Vec<ActionDelegation>,
    pub origin: String,
    pub causes: Vec<ActionCause>,
}

impl ActionProvenance {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        nonempty("action initiator", &self.initiator)?;
        nonempty("action executor", &self.executor)?;
        nonempty("action origin", &self.origin)?;
        let mut principal = &self.initiator;
        for link in &self.delegation {
            nonempty("delegation grant", &link.grant_ref)?;
            nonempty("delegation delegate", &link.delegate)?;
            if &link.delegator != principal {
                return Err(ProtocolError::Mismatch("action delegation chain"));
            }
            principal = &link.delegate;
        }
        if principal != &self.executor {
            return Err(ProtocolError::Mismatch("action executing principal"));
        }
        for cause in &self.causes {
            nonempty("causal authority", &cause.authority)?;
            nonempty("causal record", &cause.record_ref)?;
            nonempty("causal digest", &cause.digest)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostActionCommand {
    pub protocol: String,
    pub issuer: String,
    pub scope: String,
    pub request_id: String,
    pub operation: String,
    pub program_version_ref: String,
    pub input_schema_ref: String,
    #[serde(deserialize_with = "super::action_wire::Policy::deserialize")]
    pub policy: PolicyEpochRef,
    pub provenance: ActionProvenance,
    pub inputs: BTreeMap<String, ActionInput>,
    pub resources: BTreeMap<String, ActionResource>,
}

impl HostActionCommand {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol != HOST_ACTION_PROTOCOL {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        for (field, value) in [
            ("action issuer", &self.issuer),
            ("action scope", &self.scope),
            ("action request id", &self.request_id),
            ("action operation", &self.operation),
            ("action program version", &self.program_version_ref),
            ("action input schema", &self.input_schema_ref),
            ("action initiator", &self.provenance.initiator),
            ("action executor", &self.provenance.executor),
            ("action origin", &self.provenance.origin),
        ] {
            nonempty(field, value)?;
        }
        self.policy.validate()?;
        self.provenance.validate()?;
        for (name, input) in &self.inputs {
            nonempty("action input name", name)?;
            nonempty("action input handle", &input.handle)?;
            nonempty("action input version", &input.version_ref)?;
            nonempty("action input label", &input.label_ref)?;
        }
        for (name, resource) in &self.resources {
            nonempty("action resource name", name)?;
            nonempty("action resource handle", &resource.resource.handle)?;
            nonempty("action resource kind", &resource.resource.kind)?;
            nonempty("action resource label", &resource.label_ref)?;
            if let Some(selector) = &resource.resource.selector {
                nonempty("action resource selector", selector)?;
            }
            if let ActionBasis::Version { version_ref } = &resource.basis {
                nonempty("action resource version", version_ref)?;
            }
        }
        Ok(())
    }

    /// Sorted object keys, JSON framing, and a protocol-specific domain avoid
    /// delimiter collisions and dependence on a producer's property ordering.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        let value = serde_json::to_value(self)
            .map_err(|_| ProtocolError::Invalid("action serialization"))?;
        let mut bytes = b"whipplescript:host-action:command:v1\0".to_vec();
        canonical_json(&value, &mut bytes)?;
        Ok(bytes)
    }

    pub fn fingerprint(&self) -> Result<String, ProtocolError> {
        Ok(hex(&Sha256::digest(self.signing_bytes()?)))
    }

    /// The identity deliberately excludes payload and policy: changing them
    /// must collide at admission and be refused, never mint another action.
    pub fn instance_ref(&self) -> Result<String, ProtocolError> {
        self.validate()?;
        let key = serde_json::to_vec(&[&self.issuer, &self.scope, &self.request_id])
            .map_err(|_| ProtocolError::Invalid("action key serialization"))?;
        let mut hash = Sha256::new();
        hash.update(b"whipplescript:host-action:instance:v1\0");
        hash.update(key);
        Ok(format!(
            "{}{}",
            whipplescript_store::host_actions::HOST_ACTION_INSTANCE_PREFIX,
            hex(&hash.finalize())
        ))
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn canonical_json(
    value: &serde_json::Value,
    out: &mut Vec<u8>,
) -> Result<(), ProtocolError> {
    match value {
        serde_json::Value::Object(map) => {
            out.push(b'{');
            for (index, (key, value)) in map.iter().collect::<BTreeMap<_, _>>().iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                serde_json::to_writer(&mut *out, key)
                    .map_err(|_| ProtocolError::Invalid("action key serialization"))?;
                out.push(b':');
                canonical_json(value, out)?;
            }
            out.push(b'}');
        }
        serde_json::Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                canonical_json(value, out)?;
            }
            out.push(b']');
        }
        value => serde_json::to_writer(out, value)
            .map_err(|_| ProtocolError::Invalid("action value serialization"))?,
    }
    Ok(())
}

/// Implemented by the trusted receiving host, using its pinned admission trust
/// root/session boundary. It must verify the proof over these exact bytes,
/// authenticate every claimed principal/delegation, authorize this scope and
/// operation, and check current revocation. Proofs are transient, never logged.
pub trait ActionAdmissionVerifier {
    fn verify(
        &self,
        command: &HostActionCommand,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError>;
}

/// No Deserialize or public field constructor: command JSON cannot grant work.
pub struct VerifiedActionAdmission {
    command: HostActionCommand,
    fingerprint: String,
    instance_ref: String,
}

impl VerifiedActionAdmission {
    pub fn verify(
        command: HostActionCommand,
        envelope: &VerifiedEnvelope,
        verifier: &dyn ActionAdmissionVerifier,
        proof: &[u8],
    ) -> Result<Self, ProtocolError> {
        // The existing policy constructor owns the signed-envelope refusal.
        // An action additionally requires the signature to bind this exact
        // issuer and epoch; a legacy signature cannot supply that authority.
        let policy = PolicyEpochRef::from_verified(command.policy.epoch, envelope)?;
        if command.policy != policy
            || !envelope.attestation().is_some_and(|attestation| {
                attestation.epoch == Some(command.policy.epoch)
                    && attestation.authority.as_deref() == Some(command.issuer.as_str())
            })
        {
            return Err(ProtocolError::Mismatch(
                "action signed policy authority and epoch",
            ));
        }
        let bytes = command.signing_bytes()?;
        verifier.verify(&command, &bytes, proof)?;
        let fingerprint = hex(&Sha256::digest(bytes));
        let instance_ref = command.instance_ref()?;
        Ok(Self {
            command,
            fingerprint,
            instance_ref,
        })
    }

    pub fn command(&self) -> &HostActionCommand {
        &self.command
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn instance_ref(&self) -> &str {
        &self.instance_ref
    }
}

pub use whipplescript_store::effect_recovery::{ExternalDisposition, RecoveryCeiling};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionAdmissionReceipt {
    pub protocol: String,
    pub fingerprint: String,
    pub instance_ref: String,
    #[serde(deserialize_with = "super::action_wire::Position::deserialize")]
    pub admitted_at: PinnedPosition,
}

impl ActionAdmissionReceipt {
    pub fn validate_for(&self, command: &HostActionCommand) -> Result<(), ProtocolError> {
        if self.protocol != HOST_ACTION_PROTOCOL
            || self.fingerprint != command.fingerprint()?
            || self.instance_ref != command.instance_ref()?
            || self.admitted_at.instance_ref != self.instance_ref
            || self.admitted_at.sequence == 0
        {
            return Err(ProtocolError::Mismatch("action admission receipt"));
        }
        nonempty("action admission digest", &self.admitted_at.head_digest)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::gov::{ExternalAttestation, GovernanceAttestationVerifier, SignedEnvelope};

    struct PolicyVerifier;
    impl GovernanceAttestationVerifier for PolicyVerifier {
        fn verify(&self, _: &[u8], attestation: &ExternalAttestation) -> Result<(), String> {
            if attestation.signature == "fixture-signature" {
                Ok(())
            } else {
                Err("fixture signature mismatch".into())
            }
        }
    }

    pub(crate) struct ExactAdmission(pub(crate) Vec<u8>);
    impl ActionAdmissionVerifier for ExactAdmission {
        fn verify(
            &self,
            _: &HostActionCommand,
            signing_bytes: &[u8],
            proof: &[u8],
        ) -> Result<(), ProtocolError> {
            if self.0 == signing_bytes && proof == b"authenticated fixture" {
                Ok(())
            } else {
                Err(ProtocolError::Mismatch("authenticated action"))
            }
        }
    }

    pub(crate) fn envelope(epoch: u64, issuer: &str) -> VerifiedEnvelope {
        let signed = SignedEnvelope::from_external_signature_v2(
            "grant file_store ledger -> file:/srv/ledger.db readable by Operator\n",
            "policy-signer",
            "fixture",
            "fixture-key",
            "fixture-signature",
            epoch,
            issuer,
        )
        .expect("fixture envelope");
        VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &PolicyVerifier)
            .expect("verified fixture policy")
    }

    pub(crate) fn command() -> HostActionCommand {
        HostActionCommand {
            protocol: HOST_ACTION_PROTOCOL.into(),
            issuer: "product".into(),
            scope: "workspace:1".into(),
            request_id: "save:1".into(),
            operation: "file.save".into(),
            program_version_ref: "version:save-1".into(),
            input_schema_ref: "schema:save-1".into(),
            policy: PolicyEpochRef::from_verified(7, &envelope(7, "product")).unwrap(),
            provenance: ActionProvenance {
                initiator: "person:1".into(),
                executor: "system:workspace".into(),
                delegation: vec![ActionDelegation {
                    grant_ref: "grant:1".into(),
                    delegator: "person:1".into(),
                    delegate: "system:workspace".into(),
                }],
                origin: "editor.save".into(),
                causes: vec![ActionCause {
                    authority: "product".into(),
                    record_ref: "decision:1".into(),
                    digest: "cause-digest".into(),
                }],
            },
            inputs: BTreeMap::from([(
                "content".into(),
                ActionInput {
                    handle: "content:1".into(),
                    version_ref: "hash:content1".into(),
                    label_ref: "label:private".into(),
                },
            )]),
            resources: BTreeMap::from([(
                "file".into(),
                ActionResource {
                    resource: ResourceRef {
                        handle: "workspace:1".into(),
                        kind: "file_store".into(),
                        selector: Some("document.md".into()),
                        writable: Some(true),
                    },
                    basis: ActionBasis::Version {
                        version_ref: "cut:1".into(),
                    },
                    label_ref: "label:private".into(),
                },
            )]),
        }
    }

    #[test]
    fn host_action_verified_admission_binds_exact_command_and_policy() {
        let cmd = command();
        let verifier = ExactAdmission(cmd.signing_bytes().unwrap());
        let admission = VerifiedActionAdmission::verify(
            cmd.clone(),
            &envelope(7, "product"),
            &verifier,
            b"authenticated fixture",
        )
        .unwrap();
        assert_eq!(admission.command(), &cmd);
        assert_eq!(admission.fingerprint(), cmd.fingerprint().unwrap());
        assert_eq!(admission.instance_ref(), cmd.instance_ref().unwrap());
        assert!(VerifiedActionAdmission::verify(
            cmd.clone(),
            &envelope(7, "product"),
            &verifier,
            b"forged"
        )
        .is_err());
        assert!(VerifiedActionAdmission::verify(
            cmd.clone(),
            &envelope(8, "product"),
            &verifier,
            b"authenticated fixture"
        )
        .is_err());
        assert!(VerifiedActionAdmission::verify(
            cmd.clone(),
            &envelope(7, "another-issuer"),
            &verifier,
            b"authenticated fixture"
        )
        .is_err());
        let mut changed = cmd.clone();
        changed.policy.envelope_hash = "unverified-policy".into();
        assert!(VerifiedActionAdmission::verify(
            changed,
            &envelope(7, "product"),
            &verifier,
            b"authenticated fixture"
        )
        .is_err());
        let unsigned = VerifiedEnvelope::verify_text(
            "grant file_store ledger -> file:/srv/ledger.db readable by Operator\n",
        )
        .unwrap();
        assert!(VerifiedActionAdmission::verify(
            cmd.clone(),
            &unsigned,
            &verifier,
            b"authenticated fixture"
        )
        .is_err());
        let legacy = SignedEnvelope::sign_for_test(
            "grant file_store ledger -> file:/srv/ledger.db readable by Operator\n",
            "policy-signer",
        );
        let legacy = VerifiedEnvelope::verify_signed_text(&legacy.to_json()).unwrap();
        let mut legacy_cmd = cmd;
        legacy_cmd.policy = PolicyEpochRef::from_verified(7, &legacy).unwrap();
        assert!(VerifiedActionAdmission::verify(
            legacy_cmd,
            &legacy,
            &verifier,
            b"authenticated fixture"
        )
        .is_err());
    }

    // Mutate every serialized scalar, including nested authority and version
    // fields. Adding a semantic field automatically extends this binding test.
    pub(crate) fn mutations(value: &serde_json::Value) -> Vec<serde_json::Value> {
        use serde_json::Value;
        match value {
            Value::Object(map) => map
                .iter()
                .flat_map(|(key, value)| {
                    mutations(value).into_iter().map(move |changed| {
                        let mut result = map.clone();
                        result.insert(key.clone(), changed);
                        Value::Object(result)
                    })
                })
                .collect(),
            Value::Array(values) => values
                .iter()
                .enumerate()
                .flat_map(|(index, value)| {
                    mutations(value).into_iter().map(move |changed| {
                        let mut result = values.clone();
                        result[index] = changed;
                        Value::Array(result)
                    })
                })
                .collect(),
            Value::String(text) => vec![Value::String(format!("{text}-changed"))],
            Value::Number(number) => vec![Value::from(number.as_u64().unwrap() + 1)],
            Value::Bool(value) => vec![Value::Bool(!value)],
            Value::Null => vec![],
        }
    }

    #[test]
    fn host_action_every_semantic_field_is_bound_to_the_proof() {
        let cmd = command();
        let verifier = ExactAdmission(cmd.signing_bytes().unwrap());
        let changes = mutations(&serde_json::to_value(&cmd).unwrap());
        assert!(
            changes.len() > 25,
            "fixture must cover nested semantic fields"
        );
        for changed in changes {
            let Ok(changed) = serde_json::from_value::<HostActionCommand>(changed) else {
                continue;
            };
            assert!(VerifiedActionAdmission::verify(
                changed,
                &envelope(7, "product"),
                &verifier,
                b"authenticated fixture"
            )
            .is_err());
        }
    }

    #[test]
    fn host_action_key_is_stable_across_changed_meaning_and_scoped_without_collisions() {
        let cmd = command();
        let mut changed = cmd.clone();
        changed.resources.get_mut("file").unwrap().basis = ActionBasis::Absent;
        assert_eq!(cmd.instance_ref().unwrap(), changed.instance_ref().unwrap());
        assert_ne!(cmd.fingerprint().unwrap(), changed.fingerprint().unwrap());
        changed.scope = "workspace:2".into();
        assert_ne!(cmd.instance_ref().unwrap(), changed.instance_ref().unwrap());
        let mut left = cmd.clone();
        left.issuer = "a:b".into();
        left.scope = "c".into();
        let mut right = cmd;
        right.issuer = "a".into();
        right.scope = "b:c".into();
        assert_ne!(left.instance_ref().unwrap(), right.instance_ref().unwrap());
    }

    #[test]
    fn host_action_canonical_bytes_ignore_object_order_but_preserve_delegation_order() {
        let cmd = command();
        let mut raw = Vec::new();
        canonical_json(
            &serde_json::json!({"z": {"b": 1, "a": 2}, "a": ["z", "a"]}),
            &mut raw,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(raw).unwrap(),
            r#"{"a":["z","a"],"z":{"a":2,"b":1}}"#
        );
        let roundtrip: HostActionCommand =
            serde_json::from_str(&serde_json::to_string_pretty(&cmd).unwrap()).unwrap();
        assert_eq!(
            roundtrip.signing_bytes().unwrap(),
            cmd.signing_bytes().unwrap()
        );
        let mut broken = cmd;
        broken.provenance.delegation.clear();
        assert!(broken.validate().is_err());
        broken.provenance.executor = broken.provenance.initiator.clone();
        assert!(broken.validate().is_ok());
    }

    #[test]
    fn host_action_receipt_never_substitutes_another_action_or_empty_position() {
        let cmd = command();
        let instance_ref = cmd.instance_ref().unwrap();
        let receipt = ActionAdmissionReceipt {
            protocol: HOST_ACTION_PROTOCOL.into(),
            fingerprint: cmd.fingerprint().unwrap(),
            instance_ref: instance_ref.clone(),
            admitted_at: PinnedPosition {
                instance_ref,
                sequence: 2,
                head_digest: "chain-digest".into(),
            },
        };
        receipt.validate_for(&cmd).unwrap();
        for changed in mutations(&serde_json::to_value(&receipt).unwrap()) {
            let changed: ActionAdmissionReceipt = serde_json::from_value(changed).unwrap();
            // A digest/positive sequence needs store-backed verification, which
            // this structural validator deliberately cannot claim to perform.
            if changed.admitted_at.head_digest != receipt.admitted_at.head_digest
                || changed.admitted_at.sequence != receipt.admitted_at.sequence
            {
                continue;
            }
            assert!(changed.validate_for(&cmd).is_err());
        }
        let mut zero = receipt.clone();
        zero.admitted_at.sequence = 0;
        assert!(zero.validate_for(&cmd).is_err());
        let mut empty = receipt;
        empty.admitted_at.head_digest.clear();
        assert!(empty.validate_for(&cmd).is_err());
        assert_eq!(RecoveryCeiling::default(), RecoveryCeiling::Unverifiable);
        assert_eq!(ExternalDisposition::default(), ExternalDisposition::Unknown);
    }

    #[test]
    fn host_action_invalid_fields_and_unsupported_payloads_are_refused() {
        let cmd = command();
        let value = serde_json::to_value(&cmd).unwrap();
        for changed in mutations(&value) {
            // Replace each changed string with whitespace to test all required
            // string leaves, rather than hand-listing only the top-level names.
            fn blank(value: &mut serde_json::Value) {
                match value {
                    serde_json::Value::String(s) if s.ends_with("-changed") => *s = " ".into(),
                    serde_json::Value::Object(map) => map.values_mut().for_each(blank),
                    serde_json::Value::Array(values) => values.iter_mut().for_each(blank),
                    _ => (),
                }
            }
            let mut changed = changed;
            blank(&mut changed);
            let Ok(changed) = serde_json::from_value::<HostActionCommand>(changed) else {
                continue;
            };
            // Numeric/bool mutations stay valid; every blank field must fail.
            if serde_json::to_string(&changed).unwrap().contains("\" \"") {
                assert!(changed.validate().is_err());
            }
        }
        let mut extra = value;
        extra["unchecked_graph"] = serde_json::json!({});
        assert!(serde_json::from_value::<HostActionCommand>(extra).is_err());
    }
}
