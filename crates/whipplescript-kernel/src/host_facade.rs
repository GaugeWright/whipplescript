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

use crate::construct_coverage::{embedded_std_registry_for_program, CheckedConstructBasis};
use crate::gov::GovernanceAttestationVerifier;
use crate::host_package::{PackageResolver, ResolvedPackage};
use crate::host_protocol::{
    EventPosition, OpenInstanceCommand, OpenedInstance, PolicyEpochRef, ProtocolError,
    StartTurnCommand, HOST_PROTOCOL,
};
use crate::ifc::VerifiedEnvelope;
use crate::import_coverage::{CheckedImportBasis, NO_LOCK_DIGEST};
use crate::{idempotency_key, ProgramVersionInput, RuntimeKernel};

mod resolution_recording;
pub use resolution_recording::{
    ResolutionRecordingAuthority, ResolutionRecordingEvidenceSource,
    ResolutionRecordingReconciliationAuthority,
};

mod scoped_save;
pub use scoped_save::ScopedSaveExecutionAuthority;

mod materialized_inputs;
pub use materialized_inputs::ActionInputResolver;

mod tracker;
pub use tracker::TrackerExecutionAuthority;
mod tracker_closure;
mod tracker_control;
mod tracker_control_recovery;
pub use tracker_control::TrackerControlAuthority;
pub use tracker_control_recovery::TrackerControlRecoveryAuthority;
mod tracker_closure_recovery;
pub use tracker_closure::TrackerClosureAuthority;
pub use tracker_closure_recovery::TrackerClosureRecoveryAuthority;
mod tracker_recovery;
pub use tracker_recovery::TrackerRecoveryAuthority;

mod tracker_wait;
pub use tracker_wait::TrackerWaitAuthority;
mod signal_delivery;
pub use signal_delivery::SignalDeliveryAuthority;

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

/// Exact hosted/chat program basis offered to the Home before a target write.
/// The Home persists the runtime's target-store incarnation and operation ID.
pub struct OpenInstanceOperationBasis<'a> {
    pub target_store_incarnation: &'a str,
    pub kind: &'a str,
    /// Present for re-attestation, binding the Home pointer to one instance.
    pub instance_ref: Option<&'a str>,
    pub from_version_id: Option<&'a str>,
    pub request_id: &'a str,
    pub package_version_ref: &'a str,
    pub program_name: &'a str,
    pub source_digest: &'a str,
    pub version_source_digest: &'a str,
    pub lock_digest: &'a str,
    pub ir_hash: &'a str,
    pub compiler_artifact_digest: &'a str,
    pub policy: &'a PolicyEpochRef,
    pub construct_basis: Option<&'a CheckedConstructBasis<'a>>,
}

/// Immutable checked target operation used to complete the Home pointer.
pub struct OpenInstanceOperationEvidence<'a> {
    pub target_store_incarnation: &'a str,
    pub request_id: &'a str,
    pub operation_id: &'a str,
    /// Present when the checked operation moved an existing instance.
    pub instance_ref: Option<&'a str>,
    pub version_id: &'a str,
    pub witness_digest: &'a str,
}

/// Product-owned pending/completed Home journal and exact retained-use door.
/// `allow_retained_use` may recover an interrupted target write by the exact
/// registered request and operation; a missing legacy pin must refuse rather
/// than infer an origin from a version. Registration, completion, and retained
/// use must bind the same target-store incarnation; a reused path or DO name
/// cannot inherit an older pointer. The use callback runs for a fresh open
/// after its instance event is written and again for every exact replay.
pub trait OpenInstanceHomeJournal {
    fn register(
        &mut self,
        basis: &OpenInstanceOperationBasis<'_>,
    ) -> Result<String, HostFacadeError>;
    fn complete_for_use(
        &mut self,
        evidence: &OpenInstanceOperationEvidence<'_>,
    ) -> Result<(), HostFacadeError>;
    fn allow_retained_use(
        &mut self,
        target_store_incarnation: &str,
        request_id: &str,
        instance_ref: &str,
        version_id: &str,
    ) -> Result<(), HostFacadeError>;
}

/// Exact source proof offered before a cross-store fork or adoption can write
/// to its target. The Home resolves this to one completed source admission;
/// a legacy or ambiguous source must not acquire a fabricated pin.
pub struct ForkSourceHomeBasis<'a> {
    pub source_store_incarnation: &'a str,
    pub source_instance_ref: &'a str,
    pub source_observed_version_id: &'a str,
    pub source_sequence: u64,
    pub source_chain_digest: &'a str,
    pub source_thread_digest: &'a str,
    pub policy: &'a PolicyEpochRef,
}

/// Durable pending handoff identity registered before target-open, seed, or
/// fork-event writes. The target import is a separate Home operation; its
/// request ID here links the two obligations without pretending they commit
/// atomically across stores.
pub struct ForkInstanceOperationBasis<'a> {
    pub kind: &'a str,
    pub request_id: &'a str,
    pub source: &'a ForkSourceHomeBasis<'a>,
    pub source_home_operation_id: &'a str,
    pub target_store_incarnation: &'a str,
    pub target_request_id: &'a str,
    pub target_package_version_ref: &'a str,
}

/// Exact immutable target evidence offered for Home completion and replay.
/// The Home checks the named events and both store identities before it permits
/// the target to be used as the imported conversation.
pub struct ForkInstanceOperationEvidence<'a> {
    pub request_id: &'a str,
    pub operation_id: &'a str,
    pub source: &'a ForkSourceHomeBasis<'a>,
    pub source_home_operation_id: &'a str,
    pub target_store_incarnation: &'a str,
    pub target_request_id: &'a str,
    pub target_instance_ref: &'a str,
    pub target_version_id: &'a str,
    pub seed_event_id: &'a str,
    pub seed_sequence: u64,
    pub fork_event_id: &'a str,
    pub fork_sequence: u64,
}

/// Product-owned Home door for native cross-store fork and adoption. The
/// source pin and pending fork precede every target write. Completion may
/// recover exact persisted target evidence after a crash, but must leave a
/// post-seal operation pending until current-basis revalidation. Retained use
/// checks both the target import and fork pointer; an open target alone is not
/// an admitted chat. The embedding product must use the same door before turns.
pub trait ForkInstanceHomeJournal: OpenInstanceHomeJournal {
    fn pin_source_for_fork(
        &mut self,
        source: &ForkSourceHomeBasis<'_>,
    ) -> Result<String, HostFacadeError>;
    fn register_fork(
        &mut self,
        basis: &ForkInstanceOperationBasis<'_>,
    ) -> Result<String, HostFacadeError>;
    fn complete_fork_for_use(
        &mut self,
        evidence: &ForkInstanceOperationEvidence<'_>,
    ) -> Result<(), HostFacadeError>;
    fn allow_retained_fork_use(
        &mut self,
        evidence: &ForkInstanceOperationEvidence<'_>,
    ) -> Result<(), HostFacadeError>;
}

/// Read and validate the identity that a Home operation must bind before any
/// target write. A legacy or damaged store cannot join a Home admission.
pub fn require_home_store_incarnation<S: RuntimeStore>(
    store: &S,
) -> Result<String, HostFacadeError> {
    let id = store
        .store_incarnation()
        .map_err(HostFacadeError::Store)?
        .ok_or_else(|| {
            HostFacadeError::Incomplete("Home target store has no incarnation".into())
        })?;
    whipplescript_store::store_incarnation::validate(&id).map_err(HostFacadeError::Store)?;
    Ok(id)
}

/// Refuse completion if the runtime no longer names the registered target.
pub fn require_same_home_store_incarnation<S: RuntimeStore>(
    store: &S,
    expected: &str,
) -> Result<(), HostFacadeError> {
    if require_home_store_incarnation(store)? == expected {
        Ok(())
    } else {
        Err(HostFacadeError::Incomplete(
            "Home target store incarnation changed during admission".into(),
        ))
    }
}

/// The common governed facade over any WhippleScript runtime store.
pub struct GovernedHostFacade<S: RuntimeStore> {
    kernel: RuntimeKernel<S>,
    policy: PolicyEpochRef,
    envelope: VerifiedEnvelope,
    compiler_artifact_digest: Option<String>,
    embedded_std_manifests: Option<&'static [(&'static str, &'static str)]>,
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
            compiler_artifact_digest: None,
            embedded_std_manifests: None,
        })
    }

    /// The host supplies the identity of the running compiler artifact once
    /// for this facade. Version admission refuses when it was not supplied.
    pub fn with_compiler_artifact_digest(mut self, digest: impl Into<String>) -> Self {
        self.compiler_artifact_digest = Some(digest.into());
        self
    }

    /// Bind the product host's shipped vocabulary to checked package admission.
    pub fn with_embedded_std_manifests(
        mut self,
        manifests: &'static [(&'static str, &'static str)],
    ) -> Self {
        self.embedded_std_manifests = Some(manifests);
        self
    }

    /// The checked construct registry this facade admits `program` under.
    /// An unconfigured facade has no shipped vocabulary to resolve against,
    /// so it refuses rather than record an admission whose construct and
    /// declaration classes are unknown. A host that ships no standard
    /// manifests says so with an explicit empty set.
    fn shipped_construct_registry(
        &self,
        program: &whipplescript_parser::IrProgram,
        admission: &str,
    ) -> Result<whipplescript_core::ContractRegistry, HostFacadeError> {
        let manifests = self.embedded_std_manifests.ok_or_else(|| {
            HostFacadeError::Resolver(format!(
                "{admission} requires the host's shipped standard registry"
            ))
        })?;
        embedded_std_registry_for_program(program, manifests).map_err(HostFacadeError::Resolver)
    }

    /// Judge a retained admission's construct and declaration edges against
    /// the basis this host would admit the same checked `program` under now:
    /// its shipped registry and compiler artifact. Registry or source drift
    /// makes an edge unknown; nothing here re-resolves or rewrites evidence.
    /// The caller supplies the program checked for the witness's version.
    pub fn revalidate_retained_constructs(
        &self,
        program: &whipplescript_parser::IrProgram,
        witness: &whipplescript_store::program_imports::ProgramImportWitness,
    ) -> Result<crate::construct_revalidation::RetainedConstructStanding, HostFacadeError> {
        let compiler_artifact_digest =
            self.compiler_artifact_digest.as_deref().ok_or_else(|| {
                HostFacadeError::Resolver(
                    "construct revalidation requires the exact compiler artifact digest".to_owned(),
                )
            })?;
        let registry = self.shipped_construct_registry(program, "construct revalidation")?;
        crate::construct_revalidation::revalidate(
            witness,
            &crate::construct_revalidation::CurrentConstructBasis {
                registry: &registry,
                compiler_artifact_digest,
                sources: &[],
            },
        )
        .map_err(HostFacadeError::Resolver)
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

    /// Admit deterministic human, agent or system work without a conversation.
    /// Authentication, immutable program identity and IFC all precede storage.
    pub fn admit_action(
        &mut self,
        command: crate::host_protocol::action::HostActionCommand,
        action: &crate::host_action::CompiledHostAction,
        verifier: &dyn crate::host_protocol::action::ActionAdmissionVerifier,
        proof: &[u8],
    ) -> Result<crate::host_protocol::action::ActionAdmissionReceipt, HostFacadeError>
    where
        S: whipplescript_store::log_append::LogAppend,
    {
        self.admit_action_inner(command, action, verifier, proof, None)
    }

    /// Admit through the authenticated Home's pending/completed operation
    /// journal. The product must use this door for a Home-wide coverage claim.
    pub fn admit_action_with_home_journal(
        &mut self,
        command: crate::host_protocol::action::HostActionCommand,
        action: &crate::host_action::CompiledHostAction,
        verifier: &dyn crate::host_protocol::action::ActionAdmissionVerifier,
        proof: &[u8],
        journal: &mut dyn crate::host_action::HostActionHomeJournal,
    ) -> Result<crate::host_protocol::action::ActionAdmissionReceipt, HostFacadeError>
    where
        S: whipplescript_store::log_append::LogAppend,
    {
        self.admit_action_inner(command, action, verifier, proof, Some(journal))
    }

    fn admit_action_inner(
        &mut self,
        command: crate::host_protocol::action::HostActionCommand,
        action: &crate::host_action::CompiledHostAction,
        verifier: &dyn crate::host_protocol::action::ActionAdmissionVerifier,
        proof: &[u8],
        journal: Option<&mut dyn crate::host_action::HostActionHomeJournal>,
    ) -> Result<crate::host_protocol::action::ActionAdmissionReceipt, HostFacadeError>
    where
        S: whipplescript_store::log_append::LogAppend,
    {
        self.require_policy(&command.policy)?;
        let admission = crate::host_protocol::action::VerifiedActionAdmission::verify(
            command,
            &self.envelope,
            verifier,
            proof,
        )?;
        for input in admission.command().inputs.values() {
            self.require_governed(&input.handle)?;
        }
        for resource in admission.command().resources.values() {
            self.require_governed(&resource.resource.handle)?;
        }
        self.check_program_ifc(action.program())?;
        let compiler_artifact_digest =
            self.compiler_artifact_digest.as_deref().ok_or_else(|| {
                HostFacadeError::Resolver(
                    "host action admission requires the exact compiler artifact digest".to_owned(),
                )
            })?;
        let registry =
            self.shipped_construct_registry(action.program(), "host action admission")?;
        let construct_basis = CheckedConstructBasis {
            registry: &registry,
            sources: &[],
        };
        self.kernel.admit_compiled_host_action(
            action,
            &admission,
            compiler_artifact_digest,
            Some(&construct_basis),
            journal,
        )
    }

    /// Execute one ordinary file effect under freshly verified current authority.
    /// The trusted host supplies the exact, confined file binding authorized by
    /// its verifier. Product bindings must resolve the original immutable inputs
    /// and resource bases; a raw ambient filesystem is not such a binding.
    pub fn execute_action_file_effect(
        &mut self,
        request: crate::host_protocol::execution::ExecuteActionEffect,
        action: &crate::host_action::CompiledHostAction,
        verifier: &dyn crate::host_protocol::execution::ActionExecutionVerifier,
        proof: &[u8],
        files: &dyn whipplescript_store::files::FileStore,
    ) -> Result<whipplescript_store::StoredEvent, HostFacadeError>
    where
        S: whipplescript_store::log_append::LogAppend,
    {
        let (verified, _) = self.prepare_action_execution(request, action, verifier, proof)?;
        if files.scoped_save_binding().is_some() {
            return Err(ProtocolError::Mismatch(
                "scoped save requires verified memory execution authority",
            )
            .into());
        }
        self.kernel
            .execute_verified_file_effect(verified, files)
            .map_err(HostFacadeError::Store)
    }

    fn prepare_action_execution(
        &self,
        request: crate::host_protocol::execution::ExecuteActionEffect,
        action: &crate::host_action::CompiledHostAction,
        verifier: &dyn crate::host_protocol::execution::ActionExecutionVerifier,
        proof: &[u8],
    ) -> Result<
        (
            crate::host_protocol::execution::VerifiedActionExecution,
            crate::host_protocol::action::HostActionCommand,
        ),
        HostFacadeError,
    >
    where
        S: whipplescript_store::log_append::LogAppend,
    {
        self.require_policy(&request.policy)?;
        let authenticated = crate::host_protocol::execution::AuthenticatedActionExecution::verify(
            request,
            &self.envelope,
            verifier,
            proof,
        )?;
        self.prepare_authenticated_action_execution(authenticated, action, verifier)
    }

    fn prepare_authenticated_action_execution(
        &self,
        authenticated: crate::host_protocol::execution::AuthenticatedActionExecution,
        action: &crate::host_action::CompiledHostAction,
        verifier: &dyn crate::host_protocol::execution::ActionExecutionVerifier,
    ) -> Result<
        (
            crate::host_protocol::execution::VerifiedActionExecution,
            crate::host_protocol::action::HostActionCommand,
        ),
        HostFacadeError,
    >
    where
        S: whipplescript_store::log_append::LogAppend,
    {
        let request = authenticated.request();
        let prefix = self
            .kernel
            .store()
            .chain_prefix(&request.admission.instance_ref)
            .map_err(HostFacadeError::Store)?;
        let (original, _) = crate::host_action::recorded_action_command(
            &request.admission,
            &request.issuer,
            &request.scope,
            &prefix,
        )?;
        action.validate_command(&original)?;
        for input in original.inputs.values() {
            self.require_governed(&input.handle)?;
        }
        for resource in original.resources.values() {
            self.require_governed(&resource.resource.handle)?;
        }
        self.check_materialized_action_inputs(action, &original, &request.provenance.executor)?;
        self.check_program_ifc(action.program())?;
        let effect = self
            .kernel
            .claimable_effects(&request.admission.instance_ref)
            .map_err(HostFacadeError::Store)?
            .into_iter()
            .find(|effect| effect.effect_id == request.effect_id)
            .ok_or(ProtocolError::Mismatch("execution effect is not claimable"))?;
        let verified = authenticated.authorize(&original, effect, verifier)?;
        Ok((verified, original))
    }

    /// Retrieve recorded action evidence under current read authority. This
    /// projection never re-admits the action or resumes its execution.
    pub fn read_action_result(
        &self,
        request: crate::host_protocol::action_result::ReadActionResult,
        verifier: &dyn crate::host_protocol::action_result::ActionResultVerifier,
        proof: &[u8],
    ) -> Result<crate::host_protocol::action_result::ActionResultSnapshot, HostFacadeError>
    where
        S: whipplescript_store::log_append::LogAppend,
    {
        self.require_policy(&request.policy)?;
        let verified = crate::host_protocol::action_result::VerifiedResultRead::verify(
            request,
            &self.envelope,
            verifier,
            proof,
        )?;
        self.require_governed(&verified.request().evidence_handle)?;
        self.kernel.read_recorded_action_result(&verified)
    }

    /// Verify the actual retained versioned save under current authority, then
    /// record its applied disposition through the ordinary reconciliation door.
    pub fn reconcile_versioned_save<B, C>(
        &mut self,
        command: crate::host_protocol::recovery::ReconcileEffectCommand,
        owner_epoch: i64,
        source: &crate::save_reconciliation::VersionedSaveEvidenceSource<'_, B, C>,
        authority: &dyn crate::save_reconciliation::SaveReconciliationAuthority,
        proof: &[u8],
    ) -> Result<crate::host_protocol::recovery::ReconciliationReceipt, HostFacadeError>
    where
        S: whipplescript_store::log_append::LogAppend,
        B: whipplescript_store::branches::Branches,
        C: whipplescript_store::content::ContentBlobs,
    {
        self.require_policy(&command.policy)?;
        authority.authenticate(&command, &command.signing_bytes()?, proof)?;
        self.require_governed(&command.evidence.evidence_ref)?;
        let prefix = self
            .kernel
            .store()
            .chain_prefix(&command.evidence.frame.instance_id)
            .map_err(HostFacadeError::Store)?;
        let verified =
            crate::save_reconciliation::prepare(&command, source, &prefix, authority, proof)?;
        self.reconcile_effect(
            command,
            owner_epoch,
            &verified,
            proof,
            verified.target_proof(),
        )
    }

    /// Reconcile a v2 result only after the host verifies the original and
    /// current knowledge scope. A legacy save verifier cannot grant this read.
    pub fn reconcile_scoped_versioned_save<B, C>(
        &mut self,
        command: crate::host_protocol::recovery::ReconcileEffectCommand,
        owner_epoch: i64,
        source: &crate::save_reconciliation::ScopedVersionedSaveEvidenceSource<'_, B, C>,
        authority: &dyn crate::save_reconciliation::ScopedSaveReconciliationAuthority,
        proof: &[u8],
    ) -> Result<crate::host_protocol::recovery::ReconciliationReceipt, HostFacadeError>
    where
        S: whipplescript_store::log_append::LogAppend,
        B: whipplescript_store::branches::Branches,
        C: whipplescript_store::content::ContentBlobs,
    {
        self.require_policy(&command.policy)?;
        authority.authenticate(&command, &command.signing_bytes()?, proof)?;
        self.require_governed(&command.evidence.evidence_ref)?;
        let prefix = self
            .kernel
            .store()
            .chain_prefix(&command.evidence.frame.instance_id)
            .map_err(HostFacadeError::Store)?;
        let verified = crate::save_reconciliation::prepare_scoped(
            &command, source, &prefix, authority, proof,
        )?;
        self.reconcile_effect(
            command,
            owner_epoch,
            &verified,
            proof,
            verified.target_proof(),
        )
    }

    /// Record authenticated target evidence without executing or retrying a sink.
    /// The embedding host supplies its already-held log ownership fence.
    pub fn reconcile_effect(
        &mut self,
        command: crate::host_protocol::recovery::ReconcileEffectCommand,
        owner_epoch: i64,
        verifier: &dyn crate::host_protocol::recovery::EffectEvidenceVerifier,
        authorization_proof: &[u8],
        target_proof: &[u8],
    ) -> Result<crate::host_protocol::recovery::ReconciliationReceipt, HostFacadeError>
    where
        S: whipplescript_store::log_append::LogAppend,
    {
        self.require_policy(&command.policy)?;
        let verified = crate::host_protocol::recovery::VerifiedReconciliation::verify(
            command,
            &self.envelope,
            verifier,
            authorization_proof,
            target_proof,
        )?;
        self.require_governed(&verified.command().evidence.evidence_ref)?;
        self.kernel.record_reconciliation(&verified, owner_epoch)
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
        self.open_instance_inner(command, packages, None)
    }

    /// Open a Home-owned instance through a durable pending/completed operation.
    /// This door also checks retained use on exact replay and re-attests changed
    /// compiler IR under a distinct Home-chosen operation before use.
    pub fn open_instance_with_home_journal<P: PackageResolver + ?Sized>(
        &mut self,
        command: &OpenInstanceCommand,
        packages: &P,
        journal: &mut dyn OpenInstanceHomeJournal,
    ) -> Result<OpenedInstance, HostFacadeError> {
        self.open_instance_inner(command, packages, Some(journal))
    }

    fn open_instance_inner<P: PackageResolver + ?Sized>(
        &mut self,
        command: &OpenInstanceCommand,
        packages: &P,
        mut journal: Option<&mut dyn OpenInstanceHomeJournal>,
    ) -> Result<OpenedInstance, HostFacadeError> {
        let target_store_incarnation = journal
            .as_ref()
            .map(|_| require_home_store_incarnation(self.kernel.store()))
            .transpose()?;
        command.validate()?;
        self.require_policy(&command.policy)?;
        let package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostFacadeError::Resolver)?;
        self.validate_package(&package, &command.package_version_ref)?;
        let source_digest = package
            .checked_import_source_digest()
            .map_err(HostFacadeError::Resolver)?;
        self.check_package_ifc(&package)?;
        if let Some((opened, version_id)) = self.replayed_open_instance(
            command,
            &package,
            target_store_incarnation.as_deref(),
            &mut journal,
        )? {
            if let Some(journal) = journal.as_mut() {
                journal.allow_retained_use(
                    target_store_incarnation
                        .as_deref()
                        .expect("Home identity checked"),
                    &command.request_id,
                    &opened.instance_ref,
                    &version_id,
                )?;
            }
            return Ok(opened);
        }
        let compiler_artifact_digest =
            self.compiler_artifact_digest.as_deref().ok_or_else(|| {
                HostFacadeError::Resolver(
                    "hosted program admission requires the exact compiler artifact digest"
                        .to_owned(),
                )
            })?;

        let input = ProgramVersionInput {
            program_name: &package.agent,
            source_hash: &package.source_hash,
            ir_hash: &package.ir_hash,
            compiler_version: HOST_PROTOCOL,
            ir_snapshot: None,
        };
        let import_basis = CheckedImportBasis {
            program_source_digest: &source_digest,
            version_source_digest: Some(&package.source_hash),
            lock_digest: NO_LOCK_DIGEST,
            compiler_artifact_digest,
            packages: &[],
        };
        let registry =
            self.shipped_construct_registry(&package.program, "hosted program admission")?;
        let construct_basis = CheckedConstructBasis {
            registry: &registry,
            sources: &[],
        };
        let operation_id = journal
            .as_mut()
            .map(|journal| {
                journal.register(&OpenInstanceOperationBasis {
                    target_store_incarnation: target_store_incarnation
                        .as_deref()
                        .expect("Home identity checked"),
                    kind: "open",
                    instance_ref: None,
                    from_version_id: None,
                    request_id: &command.request_id,
                    package_version_ref: &command.package_version_ref,
                    program_name: &package.agent,
                    source_digest: &source_digest,
                    version_source_digest: &package.source_hash,
                    lock_digest: NO_LOCK_DIGEST,
                    ir_hash: &package.ir_hash,
                    compiler_artifact_digest,
                    policy: &command.policy,
                    construct_basis: Some(&construct_basis),
                })
            })
            .transpose()?;
        let admission = match operation_id.as_deref() {
            Some(operation_id) => self
                .kernel
                .create_program_version_for_program_with_imports_and_constructs_at_id(
                    input,
                    &package.program,
                    &import_basis,
                    &construct_basis,
                    operation_id,
                ),
            None => self
                .kernel
                .create_program_version_for_program_with_imports_and_constructs(
                    input,
                    &package.program,
                    &import_basis,
                    &construct_basis,
                ),
        }
        .map_err(HostFacadeError::Store)?;
        if let Some(journal) = journal.as_mut() {
            require_same_home_store_incarnation(
                self.kernel.store(),
                target_store_incarnation
                    .as_deref()
                    .expect("Home identity checked"),
            )?;
            journal.complete_for_use(&OpenInstanceOperationEvidence {
                target_store_incarnation: target_store_incarnation
                    .as_deref()
                    .expect("Home identity checked"),
                request_id: &command.request_id,
                operation_id: &admission.operation_id,
                instance_ref: None,
                version_id: &admission.version_id,
                witness_digest: &admission.witness_digest,
            })?;
        }
        let version = whipplescript_store::ProgramVersionRecord {
            program_id: admission.program_id,
            version_id: admission.version_id,
        };
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
        if let Some(journal) = journal.as_mut() {
            journal.allow_retained_use(
                target_store_incarnation
                    .as_deref()
                    .expect("Home identity checked"),
                &command.request_id,
                &opened.instance_ref,
                &version.version_id,
            )?;
        }
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
        let (_admission, package) = self.admit_turn_with_binding(command, packages)?;
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
        Ok(self.admit_turn_with_binding(command, packages)?.0)
    }

    /// The admission an admitted turn produces, together with the package it
    /// already resolved. `begin_turn` needs both, and resolving a package
    /// compiles it, so handing the resolved value forward keeps one host turn to
    /// one compile. Every check below runs in the order it always did.
    fn admit_turn_with_binding<P: PackageResolver + ?Sized>(
        &self,
        command: &StartTurnCommand,
        packages: &P,
    ) -> Result<(HostTurnAdmission, ResolvedPackage), HostFacadeError> {
        let package = self.admit_turn(command, packages)?;
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
        Ok((
            HostTurnAdmission {
                provider_binding_id: command.provider_binding.binding_id.clone(),
                credential_id: command.provider_binding.credential.credential_id.clone(),
                placement_ceiling_ref: command.placement_ceiling_ref.clone(),
                provider: binding.provider.clone(),
                model: binding.model.clone(),
                base_url: binding.base_url.clone(),
                wire: binding.wire.clone(),
            },
            package,
        ))
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
        self.check_program_ifc(&package.program)
    }

    fn check_program_ifc(
        &self,
        program: &whipplescript_parser::IrProgram,
    ) -> Result<(), HostFacadeError> {
        let diagnostics = crate::ifc::check_with_envelope(program, &self.envelope);
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
        target_store_incarnation: Option<&str>,
        journal: &mut Option<&mut dyn OpenInstanceHomeJournal>,
    ) -> Result<Option<(OpenedInstance, String)>, HostFacadeError> {
        for instance in self
            .kernel
            .store()
            .list_instances()
            .map_err(HostFacadeError::Store)?
        {
            // The opened event is appended under a key derived from exactly this
            // (instance, request) pair, so one indexed point lookup per instance
            // decides the replay question that a full event-log scan used to.
            let replay_key = idempotency_key(&[
                &instance.instance_id,
                &command.request_id,
                "host-instance-opened",
            ]);
            let Some(stored) = self
                .kernel
                .store()
                .event_by_idempotency_key(&instance.instance_id, &replay_key)
                .map_err(HostFacadeError::Store)?
            else {
                continue;
            };
            let Some(event) = self
                .kernel
                .store()
                .list_events(&instance.instance_id)
                .map_err(HostFacadeError::Store)?
                .into_iter()
                .find(|event| event.event_id == stored.event_id)
            else {
                continue;
            };
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
                    .ok_or_else(|| HostFacadeError::Incomplete("opened package ref".to_owned()))?
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
                .ok_or_else(|| HostFacadeError::UnknownInstance(instance.instance_id.clone()))?;
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
            let current_version_id = if version.ir_hash != package.ir_hash {
                if let Some(journal) = journal.as_mut() {
                    journal.allow_retained_use(
                        target_store_incarnation.expect("Home identity checked"),
                        &command.request_id,
                        &instance.instance_id,
                        &version.version_id,
                    )?;
                }
                let source_digest = package
                    .checked_import_source_digest()
                    .map_err(HostFacadeError::Resolver)?;
                let compiler_artifact_digest =
                    self.compiler_artifact_digest.as_deref().ok_or_else(|| {
                        HostFacadeError::Resolver(
                            "hosted program re-attestation requires the exact compiler artifact digest"
                                .to_owned(),
                        )
                    })?;
                let input = ProgramVersionInput {
                    program_name: &package.agent,
                    source_hash: &package.source_hash,
                    ir_hash: &package.ir_hash,
                    compiler_version: HOST_PROTOCOL,
                    ir_snapshot: None,
                };
                let import_basis = CheckedImportBasis {
                    program_source_digest: &source_digest,
                    version_source_digest: Some(&package.source_hash),
                    lock_digest: NO_LOCK_DIGEST,
                    compiler_artifact_digest,
                    packages: &[],
                };
                let registry = self.shipped_construct_registry(
                    &package.program,
                    "hosted program re-attestation",
                )?;
                let construct_basis = CheckedConstructBasis {
                    registry: &registry,
                    sources: &[],
                };
                let operation_id = journal
                    .as_mut()
                    .map(|journal| {
                        journal.register(&OpenInstanceOperationBasis {
                            target_store_incarnation: target_store_incarnation
                                .expect("Home identity checked"),
                            kind: "reattest",
                            instance_ref: Some(&instance.instance_id),
                            from_version_id: Some(&version.version_id),
                            request_id: &command.request_id,
                            package_version_ref: &command.package_version_ref,
                            program_name: &package.agent,
                            source_digest: &source_digest,
                            version_source_digest: &package.source_hash,
                            lock_digest: NO_LOCK_DIGEST,
                            ir_hash: &package.ir_hash,
                            compiler_artifact_digest,
                            policy: &command.policy,
                            construct_basis: Some(&construct_basis),
                        })
                    })
                    .transpose()?;
                let admission = if let Some(operation_id) = operation_id.as_deref() {
                    self.kernel
                        .reattest_instance_program_with_imports_and_constructs_at_id(
                            &instance.instance_id,
                            input,
                            &package.program,
                            &import_basis,
                            Some(&construct_basis),
                            operation_id,
                        )
                } else {
                    self.kernel
                        .reattest_instance_program_with_imports_and_constructs(
                            &instance.instance_id,
                            input,
                            &package.program,
                            &import_basis,
                            &construct_basis,
                        )
                }
                .map_err(HostFacadeError::Store)?;
                if let Some(journal) = journal.as_mut() {
                    require_same_home_store_incarnation(
                        self.kernel.store(),
                        target_store_incarnation.expect("Home identity checked"),
                    )?;
                    journal.complete_for_use(&OpenInstanceOperationEvidence {
                        target_store_incarnation: target_store_incarnation
                            .expect("Home identity checked"),
                        request_id: &command.request_id,
                        operation_id: &admission.operation_id,
                        instance_ref: Some(&instance.instance_id),
                        version_id: &admission.version_id,
                        witness_digest: &admission.witness_digest,
                    })?;
                }
                admission.version_id
            } else {
                version.version_id
            };
            return Ok(Some((opened, current_version_id)));
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

pub(crate) fn positive_sequence(sequence: i64) -> Result<u64, HostFacadeError> {
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

    const HOME_OPERATION: &str = "imp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HOME_REATTEST_OPERATION: &str = "imp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[derive(Default)]
    struct TestOpenHomeJournal {
        fail_at: Option<&'static str>,
        target_store_incarnation: Option<String>,
        registered: usize,
        completed: usize,
        retained: usize,
    }

    impl OpenInstanceHomeJournal for TestOpenHomeJournal {
        fn register(
            &mut self,
            basis: &OpenInstanceOperationBasis<'_>,
        ) -> Result<String, HostFacadeError> {
            self.registered += 1;
            assert_eq!(basis.target_store_incarnation.len(), 32);
            if let Some(expected) = &self.target_store_incarnation {
                if expected != basis.target_store_incarnation {
                    return Err(HostFacadeError::Incomplete(
                        "Home target store incarnation changed".into(),
                    ));
                }
            } else {
                self.target_store_incarnation = Some(basis.target_store_incarnation.to_owned());
            }
            assert_eq!(basis.request_id, "home-open");
            assert!(!basis.source_digest.is_empty());
            assert_eq!(basis.lock_digest, NO_LOCK_DIGEST);
            assert!(!basis.compiler_artifact_digest.is_empty());
            let operation_id = match basis.kind {
                "open" => {
                    assert!(basis.instance_ref.is_none());
                    assert!(basis.from_version_id.is_none());
                    HOME_OPERATION
                }
                "reattest" => {
                    assert!(basis.instance_ref.is_some());
                    assert!(basis.from_version_id.is_some());
                    HOME_REATTEST_OPERATION
                }
                other => panic!("unexpected Home operation kind: {other}"),
            };
            if self.fail_at == Some("register") {
                return Err(HostFacadeError::Incomplete(
                    "Home registration refused".into(),
                ));
            }
            Ok(operation_id.into())
        }

        fn complete_for_use(
            &mut self,
            evidence: &OpenInstanceOperationEvidence<'_>,
        ) -> Result<(), HostFacadeError> {
            self.completed += 1;
            assert_eq!(evidence.target_store_incarnation.len(), 32);
            assert_eq!(
                self.target_store_incarnation.as_deref(),
                Some(evidence.target_store_incarnation)
            );
            assert!(matches!(
                evidence.operation_id,
                HOME_OPERATION | HOME_REATTEST_OPERATION
            ));
            assert_eq!(
                evidence.instance_ref.is_some(),
                evidence.operation_id == HOME_REATTEST_OPERATION
            );
            assert!(!evidence.version_id.is_empty());
            assert!(!evidence.witness_digest.is_empty());
            if self.fail_at == Some("complete") {
                return Err(HostFacadeError::Incomplete(
                    "Home completion refused".into(),
                ));
            }
            Ok(())
        }

        fn allow_retained_use(
            &mut self,
            target_store_incarnation: &str,
            request_id: &str,
            instance_ref: &str,
            version_id: &str,
        ) -> Result<(), HostFacadeError> {
            assert_eq!(target_store_incarnation.len(), 32);
            assert_eq!(
                self.target_store_incarnation.as_deref(),
                Some(target_store_incarnation)
            );
            self.retained += 1;
            assert_eq!(request_id, "home-open");
            assert!(!instance_ref.is_empty());
            assert!(!version_id.is_empty());
            if self.fail_at == Some("retained") {
                return Err(HostFacadeError::Incomplete(
                    "Home retained use refused".into(),
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn home_chat_open_registers_before_target_and_completes_before_instance() {
        let package = package();
        let mut host = GovernedHostFacade::from_verified_store(
            SqliteStore::open_in_memory().expect("store"),
            7,
            envelope(),
        )
        .expect("host")
        .with_embedded_std_manifests(crate::construct_coverage::TEST_SHIPPED_STD_MANIFESTS)
        .with_compiler_artifact_digest("a".repeat(64));
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-open".into(),
            package_version_ref: package.version_ref().into(),
            policy: host.policy_ref().clone(),
        };
        let mut register_refusal = TestOpenHomeJournal {
            fail_at: Some("register"),
            ..Default::default()
        };
        assert!(host
            .open_instance_with_home_journal(&open, &package, &mut register_refusal)
            .is_err());
        assert!(host
            .kernel()
            .store()
            .program_import_operation_roster()
            .unwrap()
            .operations
            .is_empty());

        let mut completion_refusal = TestOpenHomeJournal {
            fail_at: Some("complete"),
            ..Default::default()
        };
        assert!(host
            .open_instance_with_home_journal(&open, &package, &mut completion_refusal)
            .is_err());
        assert_eq!(completion_refusal.registered, 1);
        assert_eq!(completion_refusal.completed, 1);
        assert!(host.kernel().store().list_instances().unwrap().is_empty());
        let before = host
            .kernel()
            .store()
            .program_import_operation_roster()
            .unwrap();
        assert_eq!(before.operations.len(), 1);
        assert_eq!(before.operations[0].operation_id, HOME_OPERATION);

        let mut journal = TestOpenHomeJournal {
            fail_at: Some("retained"),
            ..Default::default()
        };
        let refused = host
            .open_instance_with_home_journal(&open, &package, &mut journal)
            .expect_err("fresh instance cannot return before its Home use check");
        assert!(format!("{refused:?}").contains("Home retained use refused"));
        assert_eq!(journal.registered, 1);
        assert_eq!(journal.completed, 1);
        assert_eq!(journal.retained, 1);
        assert_eq!(host.kernel().store().list_instances().unwrap().len(), 1);
        journal.fail_at = None;
        let opened = host
            .open_instance_with_home_journal(&open, &package, &mut journal)
            .expect("exact retry recovers the withheld instance");
        assert_eq!(journal.registered, 1);
        assert_eq!(journal.completed, 1);
        assert_eq!(journal.retained, 2);
        assert_eq!(host.kernel().store().list_instances().unwrap().len(), 1);
        assert_eq!(
            host.kernel()
                .store()
                .program_import_operation_roster()
                .unwrap(),
            before
        );

        journal.fail_at = Some("retained");
        assert!(host
            .open_instance_with_home_journal(&open, &package, &mut journal)
            .is_err());
        assert_eq!(journal.retained, 3);
        journal.fail_at = None;
        assert_eq!(
            host.open_instance_with_home_journal(&open, &package, &mut journal)
                .expect("exact retained use"),
            opened
        );
        assert_eq!(journal.retained, 4);
    }

    #[test]
    fn home_chat_refuses_reused_pointer_after_target_store_replacement() {
        let package = package();
        let mut first = GovernedHostFacade::from_verified_store(
            SqliteStore::open_in_memory().expect("first store"),
            7,
            envelope(),
        )
        .expect("first host")
        .with_embedded_std_manifests(crate::construct_coverage::TEST_SHIPPED_STD_MANIFESTS)
        .with_compiler_artifact_digest("a".repeat(64));
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-open".into(),
            package_version_ref: package.version_ref().into(),
            policy: first.policy_ref().clone(),
        };
        let mut journal = TestOpenHomeJournal::default();
        first
            .open_instance_with_home_journal(&open, &package, &mut journal)
            .expect("first target admitted");
        let first_id = journal.target_store_incarnation.clone().unwrap();

        let mut replacement = GovernedHostFacade::from_verified_store(
            SqliteStore::open_in_memory().expect("replacement store"),
            7,
            envelope(),
        )
        .expect("replacement host")
        .with_embedded_std_manifests(crate::construct_coverage::TEST_SHIPPED_STD_MANIFESTS)
        .with_compiler_artifact_digest("a".repeat(64));
        assert_ne!(
            replacement.kernel().store().store_incarnation().unwrap(),
            Some(first_id)
        );
        let refused = replacement.open_instance_with_home_journal(&open, &package, &mut journal);
        assert!(format!("{refused:?}").contains("incarnation changed"));
        assert!(replacement
            .kernel()
            .store()
            .program_import_operation_roster()
            .unwrap()
            .operations
            .is_empty());
    }

    #[test]
    fn home_completion_refuses_a_changed_target_store_incarnation() {
        let store = SqliteStore::open_in_memory().expect("store");
        let actual = require_home_store_incarnation(&store).expect("incarnation");
        require_same_home_store_incarnation(&store, &actual).expect("same target");
        let foreign = SqliteStore::open_in_memory().expect("foreign store");
        let foreign_id = require_home_store_incarnation(&foreign).expect("foreign incarnation");
        assert_ne!(actual, foreign_id);
        assert!(format!(
            "{:?}",
            require_same_home_store_incarnation(&store, &foreign_id)
        )
        .contains("incarnation changed"));
    }

    #[test]
    fn home_open_refuses_a_target_without_store_incarnation_before_registration() {
        let path = std::env::temp_dir().join(format!(
            "whip-home-missing-incarnation-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut host = GovernedHostFacade::from_verified_store(
            SqliteStore::open(&path).expect("store"),
            7,
            envelope(),
        )
        .expect("host")
        .with_embedded_std_manifests(crate::construct_coverage::TEST_SHIPPED_STD_MANIFESTS)
        .with_compiler_artifact_digest("a".repeat(64));
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "DROP TRIGGER runtime_store_incarnation_no_delete; \
                 DELETE FROM runtime_store_incarnation WHERE id = 1;",
            )
            .unwrap();
        let package = package();
        let command = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-open".into(),
            package_version_ref: package.version_ref().into(),
            policy: host.policy_ref().clone(),
        };
        let mut journal = TestOpenHomeJournal::default();
        let refusal = host.open_instance_with_home_journal(&command, &package, &mut journal);
        assert!(format!("{refusal:?}").contains("Home target store has no incarnation"));
        assert_eq!(journal.registered, 0);
        assert!(host
            .kernel()
            .store()
            .program_import_operation_roster()
            .unwrap()
            .operations
            .is_empty());
        drop(host);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn home_chat_replay_reattests_under_exact_home_operation() {
        let package = package();
        let mut host = GovernedHostFacade::from_verified_store(
            SqliteStore::open_in_memory().expect("store"),
            7,
            envelope(),
        )
        .expect("host")
        .with_embedded_std_manifests(crate::construct_coverage::TEST_SHIPPED_STD_MANIFESTS)
        .with_compiler_artifact_digest("a".repeat(64));
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-open".into(),
            package_version_ref: package.version_ref().into(),
            policy: host.policy_ref().clone(),
        };
        let mut journal = TestOpenHomeJournal::default();
        let opened = host
            .open_instance_with_home_journal(&open, &package, &mut journal)
            .expect("first admission");
        let resolved = package.resolve_package(package.version_ref()).unwrap();
        host.kernel_mut()
            .reattest_instance_program(
                &opened.instance_ref,
                ProgramVersionInput {
                    program_name: &resolved.agent,
                    source_hash: &resolved.source_hash,
                    ir_hash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    compiler_version: HOST_PROTOCOL,
                    ir_snapshot: None,
                },
            )
            .expect("model pre-Home compiler drift");
        let before = host
            .kernel()
            .store()
            .program_import_operation_roster()
            .unwrap();
        journal.fail_at = Some("retained");
        assert!(host
            .open_instance_with_home_journal(&open, &package, &mut journal)
            .is_err());
        assert_eq!(
            host.kernel()
                .store()
                .program_import_operation_roster()
                .unwrap(),
            before,
            "an unresolved old use cannot be re-attested into a new target operation"
        );
        journal.fail_at = Some("register");
        assert!(host
            .open_instance_with_home_journal(&open, &package, &mut journal)
            .is_err());
        assert_eq!(
            host.kernel()
                .store()
                .program_import_operation_roster()
                .unwrap(),
            before
        );
        assert_eq!(journal.retained, 3);
        journal.fail_at = Some("complete");
        assert!(host
            .open_instance_with_home_journal(&open, &package, &mut journal)
            .is_err());
        let after = host
            .kernel()
            .store()
            .program_import_operation_roster()
            .unwrap();
        assert_eq!(after.operations.len(), before.operations.len() + 1);
        assert_eq!(
            after.operations.last().unwrap().operation_id,
            HOME_REATTEST_OPERATION
        );
        journal.fail_at = Some("retained");
        assert!(host
            .open_instance_with_home_journal(&open, &package, &mut journal)
            .is_err());
        journal.fail_at = None;
        assert_eq!(
            host.open_instance_with_home_journal(&open, &package, &mut journal)
                .expect("retained use can recover exact pending target"),
            opened
        );
        assert_eq!(journal.retained, 6);
        assert_eq!(
            host.kernel()
                .store()
                .program_import_operation_roster()
                .unwrap(),
            after
        );
    }

    #[test]
    fn construct_revalidation_refuses_a_facade_without_its_compiler_identity() {
        let compiled = whipplescript_parser::compile_program(
            r#"
workflow Method
file store project {
  root "."
  allow read ["**"]
}
"#,
        );
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let program = compiled.ir.expect("program");
        let compiler_digest = "c".repeat(64);
        let registry = crate::construct_coverage::embedded_std_registry_for_program(
            &program,
            crate::construct_coverage::TEST_SHIPPED_STD_MANIFESTS,
        )
        .expect("shipped registry");
        let mut witness = crate::import_coverage::capture(
            &program,
            &"a".repeat(64),
            &"b".repeat(64),
            &compiler_digest,
            &[],
        )
        .expect("imports");
        witness.constructs = Some(
            crate::construct_coverage::capture(&program, &registry, &witness, &[])
                .expect("constructs"),
        );
        witness.declarations = Some(
            crate::construct_coverage::capture_declarations(&program, &registry, &witness)
                .expect("declarations"),
        );
        let host = GovernedHostFacade::from_verified_store(
            SqliteStore::open_in_memory().expect("store"),
            7,
            envelope(),
        )
        .expect("host")
        .with_embedded_std_manifests(crate::construct_coverage::TEST_SHIPPED_STD_MANIFESTS);
        let Err(refusal) = host.revalidate_retained_constructs(&program, &witness) else {
            panic!("a facade without its compiler identity judged retained edges");
        };
        assert!(refusal
            .to_string()
            .contains("construct revalidation requires the exact compiler artifact digest"));
        // The same witness is judged, and holds, once the facade names the
        // compiler it would admit under now.
        let host = host.with_compiler_artifact_digest(&compiler_digest);
        let standing = host
            .revalidate_retained_constructs(&program, &witness)
            .expect("judged");
        assert_eq!(standing.declarations.as_ref().map(Vec::len), Some(1));
        assert!(standing.all_current(), "{standing:?}");
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
        assert!(host
            .open_instance(&open, &package)
            .unwrap_err()
            .to_string()
            .contains("hosted program admission requires the exact compiler artifact digest"));
        let compiler_digest = "a".repeat(64);
        let mut host = host.with_compiler_artifact_digest(&compiler_digest);
        assert!(host
            .open_instance(&open, &package)
            .unwrap_err()
            .to_string()
            .contains("hosted program admission requires the host's shipped standard registry"));
        assert!(host
            .kernel()
            .store()
            .program_import_operation_roster()
            .expect("operations after registry refusal")
            .operations
            .is_empty());
        assert!(host
            .kernel()
            .store()
            .list_instances()
            .expect("instances after registry refusal")
            .is_empty());
        let mut host =
            host.with_embedded_std_manifests(crate::construct_coverage::TEST_SHIPPED_STD_MANIFESTS);
        let opened = host.open_instance(&open, &package).expect("opened");
        assert_eq!(
            host.open_instance(&open, &package).expect("replayed"),
            opened
        );
        let roster = host
            .kernel()
            .store()
            .program_import_operation_roster()
            .expect("import operations");
        assert_eq!(roster.operations.len(), 1);
        assert_eq!(
            roster.operations[0].kind,
            whipplescript_store::program_imports::ProgramImportOperationKind::Checked
        );
        let witness = host
            .kernel()
            .store()
            .program_import_witness(
                &roster.operations[0].version_id,
                roster.operations[0]
                    .witness_digest
                    .as_deref()
                    .expect("checked witness"),
            )
            .expect("witness lookup")
            .expect("stored witness");
        assert_eq!(witness.compiler_artifact_digest, compiler_digest);
        assert!(witness.examined.is_empty());

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

    #[test]
    fn changed_ir_replay_requires_compiler_identity_and_retains_a_checked_witness() {
        let package = package();
        let resolved = package
            .resolve_package(package.version_ref())
            .expect("resolved fixture package");
        let mut host = GovernedHostFacade::from_verified_store(
            SqliteStore::open_in_memory().expect("store"),
            7,
            envelope(),
        )
        .expect("host")
        .with_embedded_std_manifests(crate::construct_coverage::TEST_SHIPPED_STD_MANIFESTS)
        .with_compiler_artifact_digest("a".repeat(64));
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "replay-1".to_owned(),
            package_version_ref: package.version_ref().to_owned(),
            policy: host.policy_ref().clone(),
        };
        let opened = host
            .open_instance(&open, &package)
            .expect("first admission");
        let drifted = host
            .kernel_mut()
            .reattest_instance_program(
                &opened.instance_ref,
                ProgramVersionInput {
                    program_name: &resolved.agent,
                    source_hash: &resolved.source_hash,
                    ir_hash: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    compiler_version: HOST_PROTOCOL,
                    ir_snapshot: None,
                },
            )
            .expect("model an earlier unwitnessed compiler move");
        let before = host
            .kernel()
            .store()
            .program_import_operation_roster()
            .expect("operations before replay");
        assert_eq!(
            before.operations.last().expect("drift operation").kind,
            whipplescript_store::program_imports::ProgramImportOperationKind::Unwitnessed
        );
        let mut host =
            GovernedHostFacade::from_verified_store(host.into_kernel().into_store(), 7, envelope())
                .expect("reopened host without compiler artifact");
        assert!(host
            .open_instance(&open, &package)
            .unwrap_err()
            .to_string()
            .contains("re-attestation requires the exact compiler artifact digest"));
        assert_eq!(
            host.kernel()
                .store()
                .program_import_operation_roster()
                .expect("operations after refusal"),
            before
        );
        assert_eq!(
            host.kernel()
                .store()
                .get_instance(&opened.instance_ref)
                .expect("instance")
                .expect("recorded")
                .version_id,
            drifted.version_id
        );
        // A compiler identity alone is not a construct basis: without the
        // shipped registry the re-attestation would retain unknown classes.
        let mut host = host.with_compiler_artifact_digest("a".repeat(64));
        assert!(host
            .open_instance(&open, &package)
            .unwrap_err()
            .to_string()
            .contains("re-attestation requires the host's shipped standard registry"));
        assert_eq!(
            host.kernel()
                .store()
                .program_import_operation_roster()
                .expect("operations after registry refusal"),
            before
        );
        let mut host =
            host.with_embedded_std_manifests(crate::construct_coverage::TEST_SHIPPED_STD_MANIFESTS);
        assert_eq!(
            host.open_instance(&open, &package).expect("checked replay"),
            opened
        );
        let roster = host
            .kernel()
            .store()
            .program_import_operation_roster()
            .expect("operations after checked replay");
        assert_eq!(roster.operations.len(), before.operations.len() + 1);
        let operation = roster.operations.last().expect("checked move");
        assert_eq!(
            operation.kind,
            whipplescript_store::program_imports::ProgramImportOperationKind::Checked
        );
        let witness = host
            .kernel()
            .store()
            .program_import_witness(
                &operation.version_id,
                operation.witness_digest.as_deref().expect("witness digest"),
            )
            .expect("witness lookup")
            .expect("retained witness");
        assert_eq!(witness.compiler_artifact_digest, "a".repeat(64));
        assert_eq!(witness.version_source_digest, Some(resolved.source_hash));
        assert_eq!(witness.lock_digest, NO_LOCK_DIGEST);
    }
}
