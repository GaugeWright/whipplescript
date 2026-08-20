//! Store-generic governed host facade shared by native and cloud placements.
//!
//! This is the admission spine of `whipplescript.host.v1`: verify one signed
//! immutable policy epoch, bind an authored package to an instance, validate an
//! attributable turn, and durably enqueue that turn without ever accepting
//! secret or resource bodies in the command. Placement-specific drivers then
//! execute the admitted effect over the same [`RuntimeStore`] backend.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use whipplescript_store::{NewEffect, NewEvent, RuleCommit, RuntimeStore, StoreError};

use crate::gov::GovernanceAttestationVerifier;
use crate::host_package::{PackageResolver, ResolvedPackage};
use crate::host_protocol::{
    EventPosition, OpenInstanceCommand, OpenedInstance, PolicyEpochRef, ProtocolError,
    StartTurnCommand, HOST_PROTOCOL,
};
use crate::ifc::VerifiedEnvelope;
use crate::{idempotency_key, ProgramVersionInput, RuntimeKernel};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct InstanceMetadata {
    protocol: String,
    package_version_ref: String,
    policy: PolicyEpochRef,
}

/// Credential-free provider identity returned after a placement resolves the
/// command's opaque credential capability. Secret bytes deliberately cannot be
/// represented here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderRealization<'a> {
    pub provider: &'a str,
    pub model: &'a str,
    pub base_url: &'a str,
}

/// The exact opaque capabilities a placement may resolve after WhippleScript
/// has admitted the command. Returning this value is the phase boundary that
/// prevents a Worker from reading provider material before policy admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostTurnAdmission {
    pub provider_binding_id: String,
    pub credential_id: String,
    pub placement_ceiling_ref: String,
    pub provider: String,
    pub model: String,
    pub base_url: String,
    /// The request dialect the verified policy declared for this binding, if it
    /// declared one. Carried out with the rest of the tuple because a placement
    /// that has to re-derive it from the base URL is guessing at exactly the
    /// point the signature could have told it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire: Option<String>,
}

/// The common governed facade over any WhippleScript runtime store.
pub struct GovernedHostFacade<S: RuntimeStore> {
    kernel: RuntimeKernel<S>,
    policy: PolicyEpochRef,
    envelope: VerifiedEnvelope,
}

impl<S: RuntimeStore> GovernedHostFacade<S> {
    pub fn from_verified_store(
        store: S,
        epoch: u64,
        envelope: VerifiedEnvelope,
    ) -> Result<Self, HostFacadeError> {
        let policy = PolicyEpochRef::from_verified(epoch, &envelope)?;
        Ok(Self {
            kernel: RuntimeKernel::new(store),
            policy,
            envelope,
        })
    }

    pub fn from_signed_store_with_verifier<V: GovernanceAttestationVerifier + ?Sized>(
        store: S,
        epoch: u64,
        signed_envelope: &str,
        verifier: &V,
    ) -> Result<Self, HostFacadeError> {
        let envelope = VerifiedEnvelope::verify_signed_text_with(signed_envelope, verifier)
            .map_err(HostFacadeError::PolicyRejected)?;
        Self::from_verified_store(store, epoch, envelope)
    }

    pub fn policy_ref(&self) -> &PolicyEpochRef {
        &self.policy
    }

    pub fn kernel(&self) -> &RuntimeKernel<S> {
        &self.kernel
    }

    pub fn kernel_mut(&mut self) -> &mut RuntimeKernel<S> {
        &mut self.kernel
    }

    pub fn into_kernel(self) -> RuntimeKernel<S> {
        self.kernel
    }

    /// Create or replay the placement's durable runtime instance for a product
    /// engagement. The registered program is the exact pinned package IR, so a
    /// DO driver can reattach after eviction without recompiling a different
    /// package.
    pub fn open_instance<P: PackageResolver + ?Sized>(
        &mut self,
        command: &OpenInstanceCommand,
        packages: &P,
    ) -> Result<OpenedInstance, HostFacadeError> {
        command.validate()?;
        self.require_policy(&command.policy)?;
        let package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostFacadeError::Resolver)?;
        self.validate_package(&package, &command.package_version_ref)?;
        self.check_package_ifc(&package)?;
        if let Some(opened) = self.replayed_open_instance(command, &package)? {
            return Ok(opened);
        }

        let version = self
            .kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &package.agent,
                    source_hash: &package.source_hash,
                    ir_hash: &package.ir_hash,
                    compiler_version: HOST_PROTOCOL,
                },
                &package.program,
            )
            .map_err(HostFacadeError::Store)?;
        let metadata = InstanceMetadata {
            protocol: HOST_PROTOCOL.to_owned(),
            package_version_ref: command.package_version_ref.clone(),
            policy: command.policy.clone(),
        };
        let input_json = serde_json::to_string(&metadata).map_err(HostFacadeError::Json)?;
        let instance_ref = self
            .kernel
            .create_instance(&version, &input_json)
            .map_err(HostFacadeError::Store)?;
        let payload = json!({
            "request_id": command.request_id,
            "package_version_ref": command.package_version_ref,
            "policy": command.policy,
        })
        .to_string();
        let event = self
            .kernel
            .store()
            .append_event(NewEvent {
                instance_id: &instance_ref,
                event_type: "host.instance.opened",
                payload_json: &payload,
                source: "host-runtime",
                causation_id: None,
                correlation_id: Some(&command.request_id),
                idempotency_key: Some(&idempotency_key(&[
                    &instance_ref,
                    &command.request_id,
                    "host-instance-opened",
                ])),
            })
            .map_err(HostFacadeError::Store)?;
        let opened = OpenedInstance {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: command.request_id.clone(),
            instance_ref: instance_ref.clone(),
            package_version_ref: command.package_version_ref.clone(),
            policy: command.policy.clone(),
            opened_at: EventPosition {
                instance_ref,
                sequence: positive_sequence(event.sequence)?,
            },
        };
        opened.validate_for(command)?;
        Ok(opened)
    }

    /// Validate and durably enqueue one host turn. Replaying the exact command
    /// is idempotent; reusing its id for different bytes fails closed. Provider
    /// secret resolution happens before this call's `ProviderRealization` is
    /// constructed, but only the admitted non-secret identity crosses here.
    pub fn begin_turn<P: PackageResolver + ?Sized>(
        &mut self,
        command: &StartTurnCommand,
        packages: &P,
        provider: ProviderRealization<'_>,
    ) -> Result<bool, HostFacadeError> {
        self.validate_turn(command, packages)?;
        let package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostFacadeError::Resolver)?;
        if !self.envelope.permits_provider_binding(
            &command.provider_binding.binding_id,
            &command.provider_binding.credential.credential_id,
            provider.provider,
            provider.model,
            provider.base_url,
            &command.placement_ceiling_ref,
        ) {
            return Err(HostFacadeError::PolicyRejected(
                "resolved provider, credential reference, or placement was not admitted by the policy epoch"
                    .to_owned(),
            ));
        }
        let command_json = serde_json::to_string(command).map_err(HostFacadeError::Json)?;
        if let Some(existing) = self
            .kernel
            .store()
            .list_effects(&command.instance_ref)
            .map_err(HostFacadeError::Store)?
            .into_iter()
            .find(|effect| effect.effect_id == command.command_id)
        {
            if existing.input_json != command_json {
                return Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
                    "command id reused with different turn",
                )));
            }
            return Ok(false);
        }
        let profile = package
            .program
            .agents
            .iter()
            .find(|agent| agent.name == package.agent)
            .and_then(|agent| agent.profile.as_deref());
        self.kernel
            .commit_rule(RuleCommit {
                instance_id: &command.instance_ref,
                rule: "host.turn",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    effect_id: &command.command_id,
                    kind: "agent.tell",
                    target: Some(&package.agent),
                    input_json: &command_json,
                    status: "queued",
                    idempotency_key: &idempotency_key(&[
                        &command.instance_ref,
                        &command.command_id,
                        "host-turn-effect",
                    ]),
                    required_capabilities_json: "[]",
                    profile,
                    correlation_id: Some(&command.run_ref),
                    source_span_json: None,
                    timeout_seconds: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some(&idempotency_key(&[
                    &command.instance_ref,
                    &command.command_id,
                    "host-turn-commit",
                ])),
                marks: &[],
                context_json: None,
            })
            .map_err(HostFacadeError::Store)?;
        Ok(true)
    }

    /// Validate a host command through policy, instance/package binding, IFC,
    /// and the authenticated actor ceiling, then return only the opaque
    /// capabilities the placement may resolve. No secret lookup belongs before
    /// this method succeeds.
    pub fn validate_turn<P: PackageResolver + ?Sized>(
        &self,
        command: &StartTurnCommand,
        packages: &P,
    ) -> Result<HostTurnAdmission, HostFacadeError> {
        self.admit_turn(command, packages)?;
        let binding = self
            .envelope
            .resolve_provider_binding(
                &command.provider_binding.binding_id,
                &command.provider_binding.credential.credential_id,
                &command.placement_ceiling_ref,
            )
            .ok_or_else(|| {
                HostFacadeError::PolicyRejected(
                    "provider binding has no exact realization in the verified policy epoch"
                        .to_owned(),
                )
            })?;
        Ok(HostTurnAdmission {
            provider_binding_id: command.provider_binding.binding_id.clone(),
            credential_id: command.provider_binding.credential.credential_id.clone(),
            placement_ceiling_ref: command.placement_ceiling_ref.clone(),
            provider: binding.provider.clone(),
            model: binding.model.clone(),
            base_url: binding.base_url.clone(),
            wire: binding.wire.clone(),
        })
    }

    fn admit_turn<P: PackageResolver + ?Sized>(
        &self,
        command: &StartTurnCommand,
        packages: &P,
    ) -> Result<ResolvedPackage, HostFacadeError> {
        command.validate()?;
        self.require_policy(&command.policy)?;
        self.require_governed(&command.provider_binding.binding_id)?;
        self.require_governed(&command.placement_ceiling_ref)?;
        for resource in command.resources.iter().chain(command.input.images.iter()) {
            self.require_governed(&resource.handle)?;
        }
        let instance = self
            .kernel
            .store()
            .get_instance(&command.instance_ref)
            .map_err(HostFacadeError::Store)?
            .ok_or_else(|| HostFacadeError::UnknownInstance(command.instance_ref.clone()))?;
        let metadata: InstanceMetadata =
            serde_json::from_str(&instance.input_json).map_err(HostFacadeError::Json)?;
        if metadata.protocol != HOST_PROTOCOL
            || metadata.package_version_ref != command.package_version_ref
            || metadata.policy != command.policy
        {
            return Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
                "instance package/policy binding",
            )));
        }
        let package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostFacadeError::Resolver)?;
        self.validate_package(&package, &command.package_version_ref)?;
        self.check_package_ifc(&package)?;
        let principal = crate::ifc::check_principal_ceiling_for_identity(
            &package.program,
            &self.envelope,
            &command.actor_ref,
        );
        if !principal.is_empty() {
            return Err(HostFacadeError::Ifc(
                principal.into_iter().map(|item| item.message).collect(),
            ));
        }
        Ok(package)
    }

    fn validate_package(
        &self,
        package: &ResolvedPackage,
        expected_ref: &str,
    ) -> Result<(), HostFacadeError> {
        if package.version_ref != expected_ref {
            return Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
                "resolved package version",
            )));
        }
        if package.agent.trim().is_empty()
            || package.system_prompt.trim().is_empty()
            || package.max_steps == 0
        {
            return Err(HostFacadeError::Resolver(
                "resolved package is incomplete".to_owned(),
            ));
        }
        if !self.envelope.permits_capabilities(&package.capabilities) {
            return Err(HostFacadeError::PolicyRejected(format!(
                "package requests capabilities outside the policy epoch: {}",
                package.capabilities.join(", ")
            )));
        }
        Ok(())
    }

    fn check_package_ifc(&self, package: &ResolvedPackage) -> Result<(), HostFacadeError> {
        let diagnostics = crate::ifc::check_with_envelope(&package.program, &self.envelope);
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(HostFacadeError::Ifc(
                diagnostics.into_iter().map(|item| item.message).collect(),
            ))
        }
    }

    fn require_policy(&self, policy: &PolicyEpochRef) -> Result<(), HostFacadeError> {
        if policy == &self.policy {
            Ok(())
        } else {
            Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
                "runtime policy epoch",
            )))
        }
    }

    fn require_governed(&self, handle: &str) -> Result<(), HostFacadeError> {
        if self.envelope.governs(handle) {
            Ok(())
        } else {
            Err(HostFacadeError::UngovernedHandle(handle.to_owned()))
        }
    }

    fn replayed_open_instance(
        &mut self,
        command: &OpenInstanceCommand,
        package: &ResolvedPackage,
    ) -> Result<Option<OpenedInstance>, HostFacadeError> {
        for instance in self
            .kernel
            .store()
            .list_instances()
            .map_err(HostFacadeError::Store)?
        {
            for event in self
                .kernel
                .store()
                .list_events(&instance.instance_id)
                .map_err(HostFacadeError::Store)?
            {
                if event.event_type != "host.instance.opened" {
                    continue;
                }
                let payload: Value =
                    serde_json::from_str(&event.payload_json).map_err(HostFacadeError::Json)?;
                if payload.get("request_id").and_then(Value::as_str)
                    != Some(command.request_id.as_str())
                {
                    continue;
                }
                let opened = OpenedInstance {
                    protocol: HOST_PROTOCOL.to_owned(),
                    request_id: command.request_id.clone(),
                    instance_ref: instance.instance_id.clone(),
                    package_version_ref: payload
                        .get("package_version_ref")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            HostFacadeError::Incomplete("opened package ref".to_owned())
                        })?
                        .to_owned(),
                    policy: serde_json::from_value(payload["policy"].clone())
                        .map_err(HostFacadeError::Json)?,
                    opened_at: EventPosition {
                        instance_ref: instance.instance_id.clone(),
                        sequence: positive_sequence(event.sequence)?,
                    },
                };
                opened.validate_for(command)?;
                let version = self
                    .kernel
                    .store()
                    .get_program_version(&instance.version_id)
                    .map_err(HostFacadeError::Store)?
                    .ok_or_else(|| {
                        HostFacadeError::UnknownInstance(instance.instance_id.clone())
                    })?;
                // Different authored content under a replayed request is the
                // integrity breach this guard exists for.
                if version.source_hash != package.source_hash {
                    return Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
                        "replayed package content",
                    )));
                }
                // Same authored program, different IR: re-attest under the
                // current compiler rather than strand the instance
                // (spec/agent-harness.md "Program identity across toolchains").
                if version.ir_hash != package.ir_hash {
                    self.kernel
                        .reattest_instance_program(
                            &instance.instance_id,
                            ProgramVersionInput {
                                program_name: &package.agent,
                                source_hash: &package.source_hash,
                                ir_hash: &package.ir_hash,
                                compiler_version: HOST_PROTOCOL,
                            },
                        )
                        .map_err(HostFacadeError::Store)?;
                }
                return Ok(Some(opened));
            }
        }
        Ok(None)
    }
}

#[derive(Debug)]
pub enum HostFacadeError {
    Protocol(ProtocolError),
    Store(StoreError),
    Json(serde_json::Error),
    Resolver(String),
    PolicyRejected(String),
    UngovernedHandle(String),
    UnknownInstance(String),
    Incomplete(String),
    Ifc(Vec<String>),
}

impl fmt::Display for HostFacadeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "{error}"),
            Self::Store(error) => write!(formatter, "store error: {error:?}"),
            Self::Json(error) => write!(formatter, "invalid host JSON: {error}"),
            Self::Resolver(error) => write!(formatter, "host resolver rejected input: {error}"),
            Self::PolicyRejected(error) => write!(formatter, "host policy rejected input: {error}"),
            Self::UngovernedHandle(handle) => write!(formatter, "ungoverned handle `{handle}`"),
            Self::UnknownInstance(instance) => write!(formatter, "unknown instance `{instance}`"),
            Self::Incomplete(item) => write!(formatter, "incomplete host state: {item}"),
            Self::Ifc(items) => write!(formatter, "IFC rejected package: {}", items.join("; ")),
        }
    }
}

impl std::error::Error for HostFacadeError {}

impl From<ProtocolError> for HostFacadeError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

fn positive_sequence(sequence: i64) -> Result<u64, HostFacadeError> {
    u64::try_from(sequence)
        .ok()
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| HostFacadeError::Incomplete("non-positive event sequence".to_owned()))
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    use crate::gov::SignedEnvelope;
    use crate::host_package::{AuthoredAgentPackage, AGENT_PACKAGE_SCHEMA};
    use crate::host_policy::{
        HostGovernancePolicy, PlacementPolicy, ProviderBindingPolicy, ResourcePolicy,
    };
    use crate::host_protocol::{CredentialRef, ProviderBindingRef, TurnInput};
    use whipplescript_store::SqliteStore;

    fn package() -> AuthoredAgentPackage {
        AuthoredAgentPackage::from_documents(
            json!({
                "schema": AGENT_PACKAGE_SCHEMA,
                "source": "method.whip",
                "workflow": "Method",
                "agent": "assistant",
                "system_prompt": "persona.md",
                "capabilities": [],
                "agent_abilities": [],
                "max_steps": 4,
            })
            .to_string(),
            r#"
workflow Method {
  agent assistant {
    provider owned
    profile "plain"
    capacity 1
    capabilities []
  }
  rule converse when started => { tell assistant "Answer without tools." }
}
"#,
            "Be helpful.",
        )
        .expect("package")
    }

    fn envelope() -> VerifiedEnvelope {
        let principal = ResourcePolicy {
            principal: true,
            ..ResourcePolicy::default()
        };
        let policy = HostGovernancePolicy {
            resources: BTreeMap::from([
                ("provider:openai".to_owned(), principal.clone()),
                ("placement:do".to_owned(), principal),
            ]),
            bindings: BTreeMap::from([
                ("model".to_owned(), "provider:openai".to_owned()),
                ("do".to_owned(), "placement:do".to_owned()),
            ]),
            parties: BTreeMap::from([("operator".to_owned(), "public".to_owned())]),
            provider_bindings: BTreeMap::from([(
                "model".to_owned(),
                ProviderBindingPolicy {
                    provider: "openai".to_owned(),
                    model: "gpt-test".to_owned(),
                    base_url: "https://provider.invalid".to_owned(),
                    credential_ref: "credential:model".to_owned(),
                    wire: None,
                },
            )]),
            placements: BTreeMap::from([(
                "do".to_owned(),
                PlacementPolicy {
                    kind: "durable_object".to_owned(),
                    provider_bindings: BTreeSet::from(["model".to_owned()]),
                    command_network: false,
                },
            )]),
            ..HostGovernancePolicy::default()
        };
        let signed =
            SignedEnvelope::sign_for_test(&policy.to_json().expect("policy"), "gaugedesk-admin");
        VerifiedEnvelope::verify_signed_text(&signed.to_json()).expect("verified")
    }

    #[test]
    fn store_generic_facade_opens_and_admits_an_idempotent_turn() {
        let package = package();
        let mut host = GovernedHostFacade::from_verified_store(
            SqliteStore::open_in_memory().expect("store"),
            7,
            envelope(),
        )
        .expect("host");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-1".to_owned(),
            package_version_ref: package.version_ref().to_owned(),
            policy: host.policy_ref().clone(),
        };
        let opened = host.open_instance(&open, &package).expect("opened");
        assert_eq!(
            host.open_instance(&open, &package).expect("replayed"),
            opened
        );

        let turn = StartTurnCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: "turn-1".to_owned(),
            run_ref: "gaugedesk:run:1".to_owned(),
            instance_ref: opened.instance_ref,
            package_version_ref: package.version_ref().to_owned(),
            policy: host.policy_ref().clone(),
            actor_ref: "operator".to_owned(),
            input: TurnInput {
                text: "hello".to_owned(),
                images: Vec::new(),
            },
            resources: Vec::new(),
            provider_binding: ProviderBindingRef {
                binding_id: "model".to_owned(),
                credential: CredentialRef {
                    credential_id: "credential:model".to_owned(),
                },
            },
            placement_ceiling_ref: "do".to_owned(),
        };
        let provider = ProviderRealization {
            provider: "openai",
            model: "gpt-test",
            base_url: "https://provider.invalid",
        };
        let admission = host
            .validate_turn(&turn, &package)
            .expect("verified policy realization");
        assert_eq!(admission.provider_binding_id, "model");
        assert_eq!(admission.credential_id, "credential:model");
        assert_eq!(admission.placement_ceiling_ref, "do");
        assert_eq!(admission.provider, provider.provider);
        assert_eq!(admission.model, provider.model);
        assert_eq!(admission.base_url, provider.base_url);
        assert!(host
            .begin_turn(&turn, &package, provider)
            .expect("new turn"));
        assert!(!host.begin_turn(&turn, &package, provider).expect("replay"));
        let effects = host
            .kernel()
            .store()
            .list_effects(&turn.instance_ref)
            .expect("effects");
        assert_eq!(effects.len(), 1);
        assert_eq!(
            effects[0].input_json,
            serde_json::to_string(&turn).expect("serialize admitted turn")
        );
    }
}
