//! Placement-neutral host protocol for governed agent turns.
//!
//! GaugeDesk and other hosts send commands containing references and a verified
//! policy identity; WhippleScript returns labeled evidence references and a
//! terminal receipt. Payload, secret, transcript, and tool-effect bodies remain
//! in their owning stores (GaugeWright ADR 0012; WhippleScript DR-0027/0028).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ifc::VerifiedEnvelope;

pub const HOST_PROTOCOL: &str = "whipplescript.host.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyEpochRef {
    pub epoch: u64,
    pub envelope_hash: String,
    pub signer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

impl PolicyEpochRef {
    /// Bind a nonzero host epoch to the exact attestation WhippleScript verified.
    pub fn from_verified(epoch: u64, envelope: &VerifiedEnvelope) -> Result<Self, ProtocolError> {
        if epoch == 0 {
            return Err(ProtocolError::Invalid("policy epoch must be nonzero"));
        }
        let Some(attestation) = envelope.attestation() else {
            return Err(ProtocolError::Invalid(
                "a host policy epoch requires a signed governance envelope",
            ));
        };
        Ok(Self {
            epoch,
            envelope_hash: attestation.envelope_hash.clone(),
            signer: attestation.signer.clone(),
            key_id: attestation.key_id.clone(),
        })
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.epoch == 0 {
            return Err(ProtocolError::Invalid("policy epoch must be nonzero"));
        }
        nonempty("policy envelope hash", &self.envelope_hash)?;
        nonempty("policy signer", &self.signer)?;
        if let Some(key_id) = &self.key_id {
            nonempty("policy attestation key id", key_id)?;
        }
        Ok(())
    }
}

/// An opaque durable resource name. Content crosses only through the resolver
/// associated with this handle; it is never copied into the command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceRef {
    pub handle: String,
    pub kind: String,
    /// Opaque resolver-local object name beneath the governed capability. IFC
    /// admission applies to `handle`; this chooses an object without minting a
    /// new policy principal or carrying its body in the command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// Optional host capability attenuation for a selected file-store object.
    /// `false` makes the selected object readable but not writable on every
    /// placement. `None` preserves the resolver's legacy access posture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writable: Option<bool>,
}

/// A credential-free provider binding. Secret material is resolved ephemerally
/// by reference after policy admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CredentialRef {
    pub credential_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderBindingRef {
    pub binding_id: String,
    pub credential: CredentialRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TurnInput {
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<ResourceRef>,
}

/// Open a durable WhippleScript instance for one host-owned chat. WhippleScript
/// issues the instance reference; the host persists that opaque reference with
/// its chat record and presents it on later turn commands.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenInstanceCommand {
    pub protocol: String,
    pub request_id: String,
    pub package_version_ref: String,
    pub policy: PolicyEpochRef,
}

impl OpenInstanceCommand {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol != HOST_PROTOCOL {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        nonempty("open-instance request id", &self.request_id)?;
        nonempty("package version ref", &self.package_version_ref)?;
        self.policy.validate()
    }
}

/// WhippleScript's durable answer to [`OpenInstanceCommand`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenedInstance {
    pub protocol: String,
    pub request_id: String,
    pub instance_ref: String,
    pub package_version_ref: String,
    pub policy: PolicyEpochRef,
    pub opened_at: EventPosition,
}

impl OpenedInstance {
    pub fn validate_for(&self, command: &OpenInstanceCommand) -> Result<(), ProtocolError> {
        command.validate()?;
        if self.protocol != HOST_PROTOCOL {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        if self.request_id != command.request_id
            || self.package_version_ref != command.package_version_ref
            || self.policy != command.policy
            || self.opened_at.instance_ref != self.instance_ref
        {
            return Err(ProtocolError::Mismatch("opened instance"));
        }
        nonempty("instance ref", &self.instance_ref)?;
        if self.opened_at.sequence == 0 {
            return Err(ProtocolError::Invalid(
                "instance-open event position must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Fork the live agent thread at an explicit source event coordinate into a
/// new durable instance. Resource bodies and workspace state are not carried by
/// this command; the embedding host forks those through their owning stores.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ForkInstanceCommand {
    pub protocol: String,
    pub request_id: String,
    pub source: EventPosition,
    pub target_request_id: String,
    pub package_version_ref: String,
    pub policy: PolicyEpochRef,
}

impl ForkInstanceCommand {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol != HOST_PROTOCOL {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        nonempty("fork-instance request id", &self.request_id)?;
        nonempty("source instance ref", &self.source.instance_ref)?;
        if self.source.sequence == 0 {
            return Err(ProtocolError::Invalid(
                "source instance event position must be nonzero",
            ));
        }
        nonempty("target open-instance request id", &self.target_request_id)?;
        nonempty("package version ref", &self.package_version_ref)?;
        self.policy.validate()
    }

    pub fn target_open_command(&self) -> OpenInstanceCommand {
        OpenInstanceCommand {
            protocol: self.protocol.clone(),
            request_id: self.target_request_id.clone(),
            package_version_ref: self.package_version_ref.clone(),
            policy: self.policy.clone(),
        }
    }
}

/// WhippleScript's durable answer to [`ForkInstanceCommand`]. The target has a
/// distinct instance identity and records the exact source coordinate from
/// which its initial thread was seeded.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ForkedInstance {
    pub protocol: String,
    pub request_id: String,
    pub source: EventPosition,
    pub target: OpenedInstance,
    pub forked_at: EventPosition,
}

impl ForkedInstance {
    pub fn validate_for(&self, command: &ForkInstanceCommand) -> Result<(), ProtocolError> {
        command.validate()?;
        self.target.validate_for(&command.target_open_command())?;
        if self.protocol != HOST_PROTOCOL {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        if self.request_id != command.request_id
            || self.source != command.source
            || self.forked_at.instance_ref != self.target.instance_ref
            || self.source.instance_ref == self.target.instance_ref
        {
            return Err(ProtocolError::Mismatch("forked instance"));
        }
        if self.forked_at.sequence == 0 {
            return Err(ProtocolError::Invalid(
                "instance-fork event position must be nonzero",
            ));
        }
        Ok(())
    }
}

/// Tombstone a fork target that its embedding host could not admit. This is a
/// lifecycle terminal, not history deletion: the exact fork evidence remains
/// auditable, while the abandoned instance can never execute a turn.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscardInstanceCommand {
    pub protocol: String,
    pub request_id: String,
    pub instance_ref: String,
    pub policy: PolicyEpochRef,
}

impl DiscardInstanceCommand {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol != HOST_PROTOCOL {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        nonempty("discard-instance request id", &self.request_id)?;
        nonempty("discarded instance ref", &self.instance_ref)?;
        self.policy.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiscardedInstance {
    pub protocol: String,
    pub request_id: String,
    pub instance_ref: String,
    pub discarded_at: EventPosition,
}

impl DiscardedInstance {
    pub fn validate_for(&self, command: &DiscardInstanceCommand) -> Result<(), ProtocolError> {
        command.validate()?;
        if self.protocol != HOST_PROTOCOL {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        if self.request_id != command.request_id
            || self.instance_ref != command.instance_ref
            || self.discarded_at.instance_ref != command.instance_ref
            || self.discarded_at.sequence == 0
        {
            return Err(ProtocolError::Mismatch("discarded instance"));
        }
        Ok(())
    }
}

/// The command GaugeDesk admits before WhippleScript begins a turn.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StartTurnCommand {
    pub protocol: String,
    pub command_id: String,
    pub run_ref: String,
    pub instance_ref: String,
    pub package_version_ref: String,
    pub policy: PolicyEpochRef,
    /// Product-authenticated principal served by this turn. WhippleScript does
    /// not authenticate it; it resolves the identity through the signed policy's
    /// party map and enforces that principal's IFC ceiling.
    pub actor_ref: String,
    pub input: TurnInput,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<ResourceRef>,
    pub provider_binding: ProviderBindingRef,
    pub placement_ceiling_ref: String,
}

impl StartTurnCommand {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol != HOST_PROTOCOL {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        nonempty("command id", &self.command_id)?;
        nonempty("run ref", &self.run_ref)?;
        nonempty("instance ref", &self.instance_ref)?;
        nonempty("package version ref", &self.package_version_ref)?;
        nonempty("authenticated actor ref", &self.actor_ref)?;
        nonempty("provider binding ref", &self.provider_binding.binding_id)?;
        nonempty(
            "provider credential ref",
            &self.provider_binding.credential.credential_id,
        )?;
        nonempty("placement ceiling ref", &self.placement_ceiling_ref)?;
        self.policy.validate()?;
        for resource in self.resources.iter().chain(self.input.images.iter()) {
            nonempty("resource handle", &resource.handle)?;
            nonempty("resource kind", &resource.kind)?;
            if let Some(selector) = &resource.selector {
                nonempty("resource selector", selector)?;
            }
            if resource.writable.is_some() && resource.kind != "file_store" {
                return Err(ProtocolError::Invalid(
                    "resource write attenuation requires kind file_store",
                ));
            }
        }
        Ok(())
    }
}

/// A stable WhippleScript event-log coordinate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EventPosition {
    pub instance_ref: String,
    pub sequence: u64,
}

/// One ordered runtime happening. Label and payload bodies remain
/// WhippleScript-owned and are named by stable evidence references.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LabeledRuntimeEvent {
    pub protocol: String,
    pub command_id: String,
    pub position: EventPosition,
    pub policy: PolicyEpochRef,
    pub kind: String,
    pub label_ref: String,
    pub evidence_ref: String,
    pub payload_ref: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnStatus {
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

/// The terminal proof returned for a command. Bodies are referenced, never
/// duplicated into GaugeDesk's decision log.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TurnReceipt {
    pub protocol: String,
    pub command_id: String,
    pub run_ref: String,
    pub instance_ref: String,
    pub policy: PolicyEpochRef,
    pub terminal_position: EventPosition,
    pub status: TurnStatus,
    pub output_handle: Option<String>,
    pub usage_ref: String,
    pub guarantee_report_ref: String,
    pub workspace_cut_ref: Option<String>,
}

/// A body-free pointer to authoritative runtime evidence owned by
/// WhippleScript. Embedding products may admit this value into their decision
/// log without copying the evidence body or inventing a parallel event schema.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "pointer_kind", content = "pointer", rename_all = "snake_case")]
pub enum RuntimeEvidencePointer {
    Event(LabeledRuntimeEvent),
    TurnReceipt(TurnReceipt),
}

impl TurnReceipt {
    /// Validate the receipt against the command it claims to settle. This is the
    /// host-side anti-mixup check; it does not reinterpret runtime evidence.
    pub fn validate_for(&self, command: &StartTurnCommand) -> Result<(), ProtocolError> {
        command.validate()?;
        if self.protocol != HOST_PROTOCOL {
            return Err(ProtocolError::WrongVersion(self.protocol.clone()));
        }
        if self.command_id != command.command_id
            || self.run_ref != command.run_ref
            || self.instance_ref != command.instance_ref
            || self.terminal_position.instance_ref != command.instance_ref
        {
            return Err(ProtocolError::Mismatch("receipt command/run/instance"));
        }
        if self.policy != command.policy {
            return Err(ProtocolError::Mismatch("receipt policy epoch"));
        }
        if self.terminal_position.sequence == 0 {
            return Err(ProtocolError::Invalid(
                "terminal event position must be nonzero",
            ));
        }
        nonempty("usage ref", &self.usage_ref)?;
        nonempty("guarantee report ref", &self.guarantee_report_ref)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    Invalid(&'static str),
    WrongVersion(String),
    Mismatch(&'static str),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid host protocol: {message}"),
            Self::WrongVersion(version) => {
                write!(formatter, "unsupported host protocol version `{version}`")
            }
            Self::Mismatch(field) => write!(formatter, "host protocol mismatch: {field}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

fn nonempty(field: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.trim().is_empty() {
        Err(ProtocolError::Invalid(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gov::SignedEnvelope;

    fn policy() -> PolicyEpochRef {
        let signed = SignedEnvelope::sign_for_test(
            "grant file_store project -> file:/workspace readable by Operator\n",
            "gaugedesk-admin",
        );
        let verified = VerifiedEnvelope::verify_signed_text(&signed.to_json()).expect("verified");
        PolicyEpochRef::from_verified(7, &verified).expect("epoch")
    }

    fn command() -> StartTurnCommand {
        StartTurnCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: "turn-command-1".to_owned(),
            run_ref: "gaugedesk:run:1".to_owned(),
            instance_ref: "whip:instance:1".to_owned(),
            package_version_ref: "whip:package-version:1".to_owned(),
            policy: policy(),
            actor_ref: "operator".to_owned(),
            input: TurnInput {
                text: "inspect the project".to_owned(),
                images: Vec::new(),
            },
            resources: vec![ResourceRef {
                handle: "gaugedesk:resource:project".to_owned(),
                kind: "file_store".to_owned(),
                selector: None,
                writable: None,
            }],
            provider_binding: ProviderBindingRef {
                binding_id: "gaugedesk:provider:primary".to_owned(),
                credential: CredentialRef {
                    credential_id: "gaugedesk:credential:primary".to_owned(),
                },
            },
            placement_ceiling_ref: "gaugedesk:placement:local".to_owned(),
        }
    }

    #[test]
    fn command_round_trips_without_resource_or_secret_bodies() {
        let command = command();
        command.validate().expect("valid");
        let json = serde_json::to_string(&command).expect("serialize");
        assert!(!json.contains("api_key"));
        assert!(!json.contains("resource body"));
        let decoded: StartTurnCommand = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded, command);
    }

    #[test]
    fn resource_write_attenuation_is_backward_compatible_and_file_store_only() {
        let legacy: ResourceRef = serde_json::from_str(
            r#"{"handle":"project","kind":"file_store","selector":"targets/t-a"}"#,
        )
        .expect("legacy resource ref");
        assert_eq!(legacy.writable, None);

        let mut invalid = command();
        invalid.resources.push(ResourceRef {
            handle: "command".to_owned(),
            kind: "command".to_owned(),
            selector: None,
            writable: Some(false),
        });
        assert!(matches!(
            invalid.validate(),
            Err(ProtocolError::Invalid(
                "resource write attenuation requires kind file_store"
            ))
        ));
    }

    #[test]
    fn opened_instance_is_bound_to_package_and_policy() {
        let command = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-chat-1".to_owned(),
            package_version_ref: "whip:package-version:1".to_owned(),
            policy: policy(),
        };
        let opened = OpenedInstance {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: command.request_id.clone(),
            instance_ref: "whip:instance:1".to_owned(),
            package_version_ref: command.package_version_ref.clone(),
            policy: command.policy.clone(),
            opened_at: EventPosition {
                instance_ref: "whip:instance:1".to_owned(),
                sequence: 1,
            },
        };
        opened.validate_for(&command).expect("bound");

        let mut mixed = opened;
        mixed.policy.epoch += 1;
        assert!(mixed.validate_for(&command).is_err());
    }

    #[test]
    fn forked_instance_binds_distinct_target_to_exact_source_position() {
        let command = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "fork-chat-1".to_owned(),
            source: EventPosition {
                instance_ref: "whip:instance:source".to_owned(),
                sequence: 17,
            },
            target_request_id: "open-chat-2".to_owned(),
            package_version_ref: "whip:package-version:1".to_owned(),
            policy: policy(),
        };
        let target = OpenedInstance {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: command.target_request_id.clone(),
            instance_ref: "whip:instance:target".to_owned(),
            package_version_ref: command.package_version_ref.clone(),
            policy: command.policy.clone(),
            opened_at: EventPosition {
                instance_ref: "whip:instance:target".to_owned(),
                sequence: 1,
            },
        };
        let forked = ForkedInstance {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: command.request_id.clone(),
            source: command.source.clone(),
            target,
            forked_at: EventPosition {
                instance_ref: "whip:instance:target".to_owned(),
                sequence: 3,
            },
        };
        forked.validate_for(&command).expect("bound fork");

        let mut mixed = forked;
        mixed.source.sequence += 1;
        assert_eq!(
            mixed.validate_for(&command),
            Err(ProtocolError::Mismatch("forked instance"))
        );
    }

    #[test]
    fn discarded_instance_receipt_binds_the_terminal_to_the_exact_command() {
        let command = DiscardInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "discard-chat-2".to_owned(),
            instance_ref: "whip:instance:target".to_owned(),
            policy: policy(),
        };
        let discarded = DiscardedInstance {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: command.request_id.clone(),
            instance_ref: command.instance_ref.clone(),
            discarded_at: EventPosition {
                instance_ref: command.instance_ref.clone(),
                sequence: 4,
            },
        };
        discarded.validate_for(&command).expect("bound discard");
        let mut mixed = discarded;
        mixed.discarded_at.instance_ref = "whip:instance:other".to_owned();
        assert_eq!(
            mixed.validate_for(&command),
            Err(ProtocolError::Mismatch("discarded instance"))
        );
    }

    #[test]
    fn receipt_must_echo_the_exact_command_instance_and_policy() {
        let command = command();
        let mut receipt = TurnReceipt {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: command.command_id.clone(),
            run_ref: command.run_ref.clone(),
            instance_ref: command.instance_ref.clone(),
            policy: command.policy.clone(),
            terminal_position: EventPosition {
                instance_ref: command.instance_ref.clone(),
                sequence: 42,
            },
            status: TurnStatus::Completed,
            output_handle: Some("whip:output:1".to_owned()),
            usage_ref: "whip:evidence:usage:1".to_owned(),
            guarantee_report_ref: "whip:evidence:guarantee:1".to_owned(),
            workspace_cut_ref: None,
        };
        receipt.validate_for(&command).expect("matching receipt");
        receipt.policy.epoch += 1;
        assert_eq!(
            receipt.validate_for(&command),
            Err(ProtocolError::Mismatch("receipt policy epoch"))
        );
    }
}
