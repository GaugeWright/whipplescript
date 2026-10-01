//! Compiler-checked ordinary workflows admitted through the host-action protocol.
use serde_json::json;
use whipplescript_parser::{compile_program_with_root, IrProgram, IrWorkflowContractKind};
use whipplescript_store::host_actions::HostActionStart;
use whipplescript_store::log_append::LogAppend;
use whipplescript_store::{NewFact, NewInstance, NewInstanceAuthority, RuntimeStore};

use crate::construct_coverage::CheckedConstructBasis;
use crate::host_facade::HostFacadeError;
use crate::host_protocol::action::{
    ActionAdmissionReceipt, HostActionCommand, VerifiedActionAdmission, HOST_ACTION_PROTOCOL,
};
use crate::host_protocol::{PinnedPosition, ProtocolError};
use crate::import_coverage::{CheckedImportBasis, NO_LOCK_DIGEST};
use crate::workflow_input::{validate_workflow_start_input, WorkflowInputFact};
use crate::{idempotency_key, ProgramVersionInput, RuntimeKernel};

/// Exact checked-action basis offered to the Home before this runtime writes
/// content or a program version. The runtime supplies its durable incarnation;
/// the Home binds that identity to its own target-store pointer.
pub struct HostActionOperationBasis<'a> {
    pub target_store_incarnation: &'a str,
    pub instance_ref: &'a str,
    pub command_fingerprint: &'a str,
    pub version_ref: &'a str,
    pub program_name: &'a str,
    pub source_digest: &'a str,
    pub ir_hash: &'a str,
    pub compiler_artifact_digest: &'a str,
    pub facts_digest: &'a str,
    pub policy: &'a crate::host_protocol::PolicyEpochRef,
    pub construct_basis: Option<&'a CheckedConstructBasis<'a>>,
}

/// The immutable target evidence to which a pending Home pointer is completed.
pub struct HostActionOperationEvidence<'a> {
    pub target_store_incarnation: &'a str,
    pub instance_ref: &'a str,
    pub command_fingerprint: &'a str,
    pub operation_id: &'a str,
    pub program_id: &'a str,
    pub version_id: &'a str,
    pub witness_digest: &'a str,
}

/// Product-owned durable Home journal and use door. `register` must persist a
/// pending pointer before returning its operation ID and return that same ID
/// on an exact retry. `complete_for_use` binds the checked program operation's
/// evidence and enforces the current epoch before an instance can start.
/// Retained instances need their original Home admission and target-store
/// incarnation checked again, even when the logical target name is unchanged.
pub trait HostActionHomeJournal {
    fn register(&mut self, basis: &HostActionOperationBasis<'_>)
        -> Result<String, HostFacadeError>;
    fn complete_for_use(
        &mut self,
        evidence: &HostActionOperationEvidence<'_>,
    ) -> Result<(), HostFacadeError>;
    fn allow_retained_use(
        &mut self,
        target_store_incarnation: &str,
        instance_ref: &str,
        command_fingerprint: &str,
        version_id: &str,
    ) -> Result<(), HostFacadeError>;
}

/// Only the compiler can construct this value. Hosts cannot inject a graph or
/// mutate the program after its source, schema and IR identity were checked.
pub struct CompiledHostAction {
    operation: String,
    source: String,
    program: IrProgram,
    identity: String,
    version_ref: String,
    input_schema_ref: String,
    materialized_inputs: bool,
}

impl CompiledHostAction {
    pub fn compile(operation: &str, source: &str, root: Option<&str>) -> Result<Self, String> {
        Self::compile_inputs(operation, source, root, false)
    }

    /// Compile unchanged workflow source whose declared inputs receive values
    /// from governed immutable custody during admission.
    pub fn compile_materialized_inputs(
        operation: &str,
        source: &str,
        root: Option<&str>,
    ) -> Result<Self, String> {
        Self::compile_inputs(operation, source, root, true)
    }

    fn compile_inputs(
        operation: &str,
        source: &str,
        root: Option<&str>,
        materialized_inputs: bool,
    ) -> Result<Self, String> {
        if operation.trim().is_empty() {
            return Err("host action operation is empty".into());
        }
        let compiled = compile_program_with_root(source, root);
        // The ordinary compiler emits IR only when every error channel is
        // empty. Consume that result once and preserve its diagnostics.
        let program = compiled.ir.ok_or_else(|| {
            format!(
                "host action compilation failed: {}",
                compiled
                    .diagnostics
                    .iter()
                    .map(|item| item.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })?;
        if !program
            .workflow_contracts
            .iter()
            .any(|contract| contract.kind == IrWorkflowContractKind::Output)
        {
            return Err("host action requires a declared terminal output schema".into());
        }
        let identity = whipplescript_parser::snapshot::identity_projection(&program.to_snapshot());
        let mut registration = vec![
            json!(HOST_ACTION_PROTOCOL),
            json!(operation),
            json!(source),
            json!(identity),
            json!(whipplescript_core::version()),
        ];
        if materialized_inputs {
            registration.push(json!("materialized-inputs.v1"));
        }
        let version_ref = format!(
            "action:{}",
            crate::gov::hash_hex(&json!(registration).to_string())
        );
        // The compiled identity includes every referenced class, not just the
        // top-level input name. Editing a nested type changes this schema ref.
        let schema_identity = if materialized_inputs {
            json!(["materialized-inputs.v1", identity]).to_string()
        } else {
            identity.clone()
        };
        let input_schema_ref = format!("action-input:{}", crate::gov::hash_hex(&schema_identity));
        Ok(Self {
            operation: operation.into(),
            source: source.into(),
            program,
            identity,
            version_ref,
            input_schema_ref,
            materialized_inputs,
        })
    }

    pub fn program(&self) -> &IrProgram {
        &self.program
    }
    pub fn version_ref(&self) -> &str {
        &self.version_ref
    }
    pub fn input_schema_ref(&self) -> &str {
        &self.input_schema_ref
    }

    pub fn has_materialized_inputs(&self) -> bool {
        self.materialized_inputs
    }

    pub(crate) fn validate_command(
        &self,
        command: &HostActionCommand,
    ) -> Result<(), HostFacadeError> {
        if command.operation != self.operation
            || command.program_version_ref != self.version_ref
            || command.input_schema_ref != self.input_schema_ref
        {
            return Err(ProtocolError::Mismatch(
                "registered host action operation, program or input schema",
            )
            .into());
        }
        Ok(())
    }

    fn validate_inputs(
        &self,
        admission: &VerifiedActionAdmission,
    ) -> Result<Vec<WorkflowInputFact>, HostFacadeError> {
        let command = admission.command();
        self.validate_command(command)?;
        if self.materialized_inputs {
            return Err(ProtocolError::Invalid(
                "materialized workflow requires governed input custody",
            )
            .into());
        }
        // Untyped legacy workflows may accept an arbitrary external.started
        // payload; this versioned protocol locks even the empty input schema.
        if !command.inputs.is_empty()
            && !self
                .program
                .workflow_contracts
                .iter()
                .any(|contract| contract.kind == IrWorkflowContractKind::Input)
        {
            return Err(
                ProtocolError::Invalid("host action supplies undeclared workflow inputs").into(),
            );
        }
        validate_workflow_start_input(
            &self.program,
            &serde_json::to_value(&command.inputs).map_err(HostFacadeError::Json)?,
        )
        .map_err(HostFacadeError::Resolver)
    }
}

impl<S: RuntimeStore + LogAppend> RuntimeKernel<S> {
    /// The verified command starts an ordinary workflow. The admitted input is
    /// the command's immutable handles; materialization remains behind governed
    /// read capabilities during execution. No source callback runs here.
    pub(crate) fn admit_compiled_host_action(
        &mut self,
        action: &CompiledHostAction,
        admission: &VerifiedActionAdmission,
        compiler_artifact_digest: &str,
        construct_basis: Option<&CheckedConstructBasis<'_>>,
        journal: Option<&mut dyn HostActionHomeJournal>,
    ) -> Result<ActionAdmissionReceipt, HostFacadeError> {
        let facts = action.validate_inputs(admission)?;
        self.admit_host_action_inputs(
            action,
            admission,
            facts,
            compiler_artifact_digest,
            construct_basis,
            journal,
        )
    }

    pub(crate) fn admit_host_action_inputs(
        &mut self,
        action: &CompiledHostAction,
        admission: &VerifiedActionAdmission,
        facts: Vec<WorkflowInputFact>,
        compiler_artifact_digest: &str,
        construct_basis: Option<&CheckedConstructBasis<'_>>,
        mut journal: Option<&mut dyn HostActionHomeJournal>,
    ) -> Result<ActionAdmissionReceipt, HostFacadeError> {
        let target_store_incarnation = journal
            .as_ref()
            .map(|_| crate::host_facade::require_home_store_incarnation(self.store()))
            .transpose()?;
        if let Some(journal) = journal.as_deref_mut() {
            if let Some(receipt) = self.existing_action_admission(admission)? {
                let instance = self
                    .store()
                    .get_instance(admission.instance_ref())
                    .map_err(HostFacadeError::Store)?
                    .ok_or_else(|| {
                        HostFacadeError::Incomplete(
                            "retained host action instance is missing".into(),
                        )
                    })?;
                journal.allow_retained_use(
                    target_store_incarnation
                        .as_deref()
                        .expect("Home identity checked"),
                    admission.instance_ref(),
                    admission.fingerprint(),
                    &instance.version_id,
                )?;
                return Ok(receipt);
            }
        }
        let ir_hash = whipplescript_store::stable_hash_hex(&action.identity);
        let source_digest = crate::exec_http::sha256_hex(action.source.as_bytes());
        let facts_digest = crate::exec_http::sha256_hex(
            &serde_json::to_vec(
                &facts
                    .iter()
                    .map(|fact| (&fact.name, &fact.key, &fact.value_json))
                    .collect::<Vec<_>>(),
            )
            .map_err(HostFacadeError::Json)?,
        );
        let operation_id = if let Some(journal) = journal.as_deref_mut() {
            let basis = HostActionOperationBasis {
                target_store_incarnation: target_store_incarnation
                    .as_deref()
                    .expect("Home identity checked"),
                instance_ref: admission.instance_ref(),
                command_fingerprint: admission.fingerprint(),
                version_ref: action.version_ref(),
                program_name: &action.program.workflow,
                source_digest: &source_digest,
                ir_hash: &ir_hash,
                compiler_artifact_digest,
                facts_digest: &facts_digest,
                policy: &admission.command().policy,
                construct_basis,
            };
            let id = journal.register(&basis)?;
            whipplescript_store::program_imports::validate_operation_id(&id)
                .map_err(HostFacadeError::Store)?;
            Some(id)
        } else {
            None
        };
        let source_hash = self
            .store()
            .put_content(&action.source)
            .map_err(HostFacadeError::Store)?;
        let input = ProgramVersionInput {
            program_name: &action.program.workflow,
            source_hash: &source_hash,
            ir_hash: &ir_hash,
            ir_snapshot: Some(&action.identity),
            compiler_version: whipplescript_core::version(),
        };
        let import_basis = CheckedImportBasis {
            program_source_digest: &source_digest,
            version_source_digest: None,
            lock_digest: NO_LOCK_DIGEST,
            compiler_artifact_digest,
            packages: &[],
        };
        let version_admission = match (construct_basis, operation_id.as_deref()) {
            (Some(construct_basis), Some(id)) => self
                .create_program_version_for_program_with_imports_and_constructs_at_id(
                    input,
                    &action.program,
                    &import_basis,
                    construct_basis,
                    id,
                ),
            (Some(construct_basis), None) => self
                .create_program_version_for_program_with_imports_and_constructs(
                    input,
                    &action.program,
                    &import_basis,
                    construct_basis,
                ),
            (None, Some(id)) => self.create_program_version_for_program_with_imports_at_id(
                input,
                &action.program,
                &import_basis,
                id,
            ),
            (None, None) => self.create_program_version_for_program_with_imports(
                input,
                &action.program,
                &import_basis,
            ),
        }
        .map_err(HostFacadeError::Store)?;
        if let Some(journal) = journal {
            crate::host_facade::require_same_home_store_incarnation(
                self.store(),
                target_store_incarnation
                    .as_deref()
                    .expect("Home identity checked"),
            )?;
            journal.complete_for_use(&HostActionOperationEvidence {
                target_store_incarnation: target_store_incarnation
                    .as_deref()
                    .expect("Home identity checked"),
                instance_ref: admission.instance_ref(),
                command_fingerprint: admission.fingerprint(),
                operation_id: &version_admission.operation_id,
                program_id: &version_admission.program_id,
                version_id: &version_admission.version_id,
                witness_digest: &version_admission.witness_digest,
            })?;
        }
        let command = admission.command();
        let command_json = serde_json::to_string(command).map_err(HostFacadeError::Json)?;
        let input_json = serde_json::to_string(&command.inputs).map_err(HostFacadeError::Json)?;
        let keys: Vec<_> = facts
            .iter()
            .map(|fact| {
                idempotency_key(&[
                    admission.instance_ref(),
                    "host-action-input",
                    &fact.name,
                    &fact.key,
                ])
            })
            .collect();
        let inputs: Vec<_> = facts
            .iter()
            .zip(&keys)
            .map(|(fact, key)| NewFact {
                fact_id: key,
                name: &fact.name,
                key: &fact.key,
                value_json: &fact.value_json,
                schema_id: None,
                provenance_class: "external",
                correlation_id: Some(admission.fingerprint()),
                source_span_json: None,
                validity_json: None,
            })
            .collect();
        let principal = format!("workflow:{}/{}", command.issuer, action.program.workflow);
        // Product grants remain in the signed envelope and at dispatch. This
        // snapshot only records the immutable workflow identity; it cannot mint
        // a file, repair or provider authority absent from that envelope.
        let authority = json!([principal]).to_string();
        let admitted = self
            .store_mut()
            .admit_host_action(HostActionStart {
                instance_id: admission.instance_ref(),
                fingerprint: admission.fingerprint(),
                command_json: &command_json,
                instance: NewInstance {
                    program_id: &version_admission.program_id,
                    version_id: &version_admission.version_id,
                    input_json: &input_json,
                },
                authority: NewInstanceAuthority {
                    workflow_principal: &principal,
                    effective_authority_json: &authority,
                },
                input_facts: &inputs,
            })
            .map_err(HostFacadeError::Store)?;
        // Reconstruct the original admission pin after a retry, even if newer
        // events now exist. Cached middle-row digests are not authority.
        let mut prefix = self
            .store()
            .chain_prefix(&admitted.instance_id)
            .map_err(HostFacadeError::Store)?;
        prefix.retain(|entry| entry.sequence <= admitted.admitted.sequence);
        let pin = admission_pin(&admitted.instance_id, &admitted.admitted, &prefix)?;
        let receipt = ActionAdmissionReceipt {
            protocol: HOST_ACTION_PROTOCOL.into(),
            fingerprint: admission.fingerprint().into(),
            instance_ref: admitted.instance_id.clone(),
            admitted_at: pin,
        };
        receipt.validate_for(command)?;
        Ok(receipt)
    }

    /// Recover before body reads; consumed or erased inputs cannot be reseeded.
    pub(crate) fn existing_action_admission(
        &self,
        admission: &VerifiedActionAdmission,
    ) -> Result<Option<ActionAdmissionReceipt>, HostFacadeError> {
        let Some(stored) = self
            .store()
            .event_by_idempotency_key(admission.instance_ref(), "host-action-admission")
            .map_err(HostFacadeError::Store)?
        else {
            return Ok(None);
        };
        let mut prefix = self
            .store()
            .chain_prefix(admission.instance_ref())
            .map_err(HostFacadeError::Store)?;
        prefix.retain(|event| event.sequence <= stored.sequence);
        let receipt = ActionAdmissionReceipt {
            protocol: HOST_ACTION_PROTOCOL.into(),
            fingerprint: admission.fingerprint().into(),
            instance_ref: admission.instance_ref().into(),
            admitted_at: admission_pin(admission.instance_ref(), &stored, &prefix)?,
        };
        let command = admission.command();
        // This validates the recorded command against the authenticated
        // fingerprint as well as its complete original admission prefix.
        recorded_action_command(&receipt, &command.issuer, &command.scope, &prefix)?;
        Ok(Some(receipt))
    }
}

/// Read the exact original command from its committed admission prefix.
/// Both result inspection and execution use this validation; neither accepts
/// a caller-supplied command as a replacement for the recorded admission.
#[derive(serde::Deserialize)]
struct RecordedAdmission {
    fingerprint: String,
    command: HostActionCommand,
}

pub(crate) fn recorded_action_command(
    receipt: &ActionAdmissionReceipt,
    issuer: &str,
    scope: &str,
    prefix: &[whipplescript_store::event_chain::OwnedChainEntry],
) -> Result<(HostActionCommand, usize), HostFacadeError> {
    let instance = &receipt.instance_ref;
    let admission_index = usize::try_from(receipt.admitted_at.sequence.saturating_sub(1))
        .map_err(|_| ProtocolError::Invalid("result admission sequence"))?;
    let admitted = prefix
        .get(admission_index)
        .ok_or(ProtocolError::Mismatch("result admission is unavailable"))?;
    if admitted.source.as_deref() != Some("host-runtime")
        || admitted.idempotency_key.as_deref() != Some("host-action-admission")
    {
        return Err(ProtocolError::Mismatch("result recorded admission source").into());
    }
    let record: RecordedAdmission =
        serde_json::from_str(&admitted.payload_json).map_err(HostFacadeError::Json)?;
    receipt.validate_for(&record.command)?;
    let original_pin = crate::host_action::admission_pin(
        instance,
        &whipplescript_store::StoredEvent {
            event_id: admitted.event_id.clone(),
            sequence: admitted.sequence,
        },
        &prefix[..=admission_index],
    )?;
    if record.fingerprint != receipt.fingerprint
        || original_pin != receipt.admitted_at
        || record.command.issuer != issuer
        || record.command.scope != scope
    {
        return Err(ProtocolError::Mismatch("result exact admitted command and scope").into());
    }

    Ok((record.command, admission_index))
}

/// A receipt pins a complete prefix ending at the admission it names. A store
/// returning a truncated or different prefix cannot turn that into evidence.
pub(crate) fn admission_pin(
    instance_id: &str,
    admitted: &whipplescript_store::StoredEvent,
    prefix: &[whipplescript_store::event_chain::OwnedChainEntry],
) -> Result<PinnedPosition, HostFacadeError> {
    let last_matches = prefix.last().is_some_and(|entry| {
        entry.sequence == admitted.sequence
            && entry.event_id == admitted.event_id
            && entry.event_type == "host.action.admitted"
    });
    let contiguous = prefix.iter().enumerate().all(|(index, entry)| {
        i64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
            == Some(entry.sequence)
    });
    if !last_matches || !contiguous {
        return Err(ProtocolError::Mismatch("durable action admission prefix").into());
    }
    let head = whipplescript_store::event_chain::fold_owned(instance_id, prefix);
    Ok(PinnedPosition {
        instance_ref: instance_id.into(),
        sequence: crate::host_facade::positive_sequence(admitted.sequence)?,
        head_digest: head.digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_facade::GovernedHostFacade;
    use crate::host_protocol::action::tests::{command, envelope, ExactAdmission};
    use whipplescript_store::native_stores::NativeStores;

    const COMPILER_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    const SOURCE: &str = r#"
workflow ReferenceAction
input content InputReference
output result Result
class InputReference { handle string version_ref string label_ref string }
class Result { handle string }
rule echo
  when InputReference as r
=> { complete result { handle r.handle } }
"#;

    fn fixture() -> (
        CompiledHostAction,
        crate::host_protocol::action::HostActionCommand,
        GovernedHostFacade<NativeStores>,
    ) {
        let action = CompiledHostAction::compile("reference.echo", SOURCE, None).unwrap();
        let mut command = command();
        command.operation = "reference.echo".into();
        command.program_version_ref = action.version_ref().into();
        command.input_schema_ref = action.input_schema_ref().into();
        command.inputs.get_mut("content").unwrap().handle = "ledger".into();
        command.resources.clear();
        let facade = GovernedHostFacade::from_verified_store(
            NativeStores::open_in_memory().unwrap(),
            7,
            envelope(7, "product"),
        )
        .unwrap()
        .with_compiler_artifact_digest(COMPILER_DIGEST);
        (action, command, facade)
    }

    #[test]
    fn host_action_executes_an_ordinary_workflow_once_without_a_model() {
        let (action, command, mut facade) = fixture();
        let verifier = ExactAdmission(command.signing_bytes().unwrap());
        let first = facade
            .admit_action(
                command.clone(),
                &action,
                &verifier,
                b"authenticated fixture",
            )
            .unwrap();
        let roster = facade
            .kernel()
            .store()
            .program_import_operation_roster()
            .expect("host action import operations");
        assert_eq!(roster.operations.len(), 1);
        assert_eq!(
            roster.operations[0].kind,
            whipplescript_store::program_imports::ProgramImportOperationKind::Checked
        );
        let witness = facade
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
        assert_eq!(
            witness.program_source_digest,
            crate::exec_http::sha256_hex(SOURCE.as_bytes())
        );
        assert_eq!(witness.compiler_artifact_digest, COMPILER_DIGEST);
        assert_eq!(witness.lock_digest, NO_LOCK_DIGEST);
        assert!(witness.examined.is_empty());
        assert_eq!(facade.kernel().store().list_instances().unwrap().len(), 1);
        let start_events = facade
            .kernel()
            .store()
            .list_events(&first.instance_ref)
            .unwrap();
        assert!(start_events
            .iter()
            .any(|event| event.event_type == "external.started"));
        assert!(facade
            .kernel()
            .store()
            .list_effects(&first.instance_ref)
            .unwrap()
            .is_empty());
        let retry = facade
            .admit_action(
                command.clone(),
                &action,
                &verifier,
                b"authenticated fixture",
            )
            .unwrap();
        assert_eq!(retry, first);
        assert_eq!(
            facade
                .kernel()
                .store()
                .list_events(&first.instance_ref)
                .unwrap(),
            start_events
        );

        crate::rule_pass::step_instance_generic(
            facade.kernel_mut(),
            &first.instance_ref,
            action.program(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            facade
                .kernel()
                .store()
                .get_instance(&first.instance_ref)
                .unwrap()
                .unwrap()
                .status,
            "completed"
        );
        let final_events = facade
            .kernel()
            .store()
            .list_events(&first.instance_ref)
            .unwrap();
        let final_facts = facade
            .kernel()
            .store()
            .list_facts(&first.instance_ref)
            .unwrap();
        assert_eq!(
            facade
                .admit_action(
                    command.clone(),
                    &action,
                    &verifier,
                    b"authenticated fixture"
                )
                .unwrap(),
            first
        );
        assert_eq!(
            facade
                .kernel()
                .store()
                .list_events(&first.instance_ref)
                .unwrap(),
            final_events
        );
        assert_eq!(
            facade
                .kernel()
                .store()
                .list_facts(&first.instance_ref)
                .unwrap(),
            final_facts
        );
        facade
            .kernel_mut()
            .store_mut()
            .rebuild_projections(&first.instance_ref)
            .unwrap();
        assert_eq!(
            facade
                .admit_action(command, &action, &verifier, b"authenticated fixture")
                .unwrap(),
            first
        );
        assert_eq!(facade.kernel().store().list_instances().unwrap().len(), 1);
    }

    #[test]
    fn host_action_retains_compiler_checked_file_store_declaration() {
        const EMBEDDED_FILES: &[(&str, &str)] = &[(
            "std.files",
            include_str!("../../../std/manifests/files.json"),
        )];
        let source = format!(
            "file store project {{\n  root \".\"\n  allow read [\"**\"]\n  allow write [\"**\"]\n}}\n{SOURCE}"
        );
        let action = CompiledHostAction::compile("reference.echo", &source, None)
            .expect("compiled action with declaration");
        let (_, mut command, facade) = fixture();
        command.program_version_ref = action.version_ref().into();
        command.input_schema_ref = action.input_schema_ref().into();
        let verifier = ExactAdmission(command.signing_bytes().unwrap());
        let mut facade = facade.with_embedded_std_manifests(EMBEDDED_FILES);
        facade
            .admit_action(command, &action, &verifier, b"authenticated fixture")
            .expect("checked action admission");
        let roster = facade
            .kernel()
            .store()
            .program_import_operation_roster()
            .expect("action operations");
        let operation = roster.operations.last().expect("checked operation");
        let witness = facade
            .kernel()
            .store()
            .program_import_witness(
                &operation.version_id,
                operation.witness_digest.as_deref().expect("witness digest"),
            )
            .expect("witness lookup")
            .expect("checked witness");
        assert!(witness
            .constructs
            .expect("rule constructs examined")
            .edges
            .is_empty());
        assert_eq!(
            witness
                .declarations
                .expect("declarations examined")
                .edges
                .iter()
                .map(|edge| edge.registration_id.as_str())
                .collect::<Vec<_>>(),
            ["files.file_store"]
        );
    }

    #[test]
    fn host_action_refuses_an_unresolved_local_import_before_version_admission() {
        let (_, mut command, mut facade) = fixture();
        let source = format!("use local.dep\n{SOURCE}");
        let action =
            CompiledHostAction::compile("reference.echo", &source, None).expect("compiled action");
        command.program_version_ref = action.version_ref().into();
        command.input_schema_ref = action.input_schema_ref().into();
        let verifier = ExactAdmission(command.signing_bytes().expect("command"));
        assert!(facade
            .admit_action(command, &action, &verifier, b"authenticated fixture")
            .unwrap_err()
            .to_string()
            .contains("unresolved local package import `local.dep`"));
        assert!(facade
            .kernel()
            .store()
            .program_import_operation_roster()
            .expect("import operations")
            .operations
            .is_empty());
    }

    #[test]
    fn host_action_refuses_missing_compiler_artifact_before_version_admission() {
        let (action, command, facade) = fixture();
        let mut facade = GovernedHostFacade::from_verified_store(
            facade.into_kernel().into_store(),
            7,
            envelope(7, "product"),
        )
        .expect("facade without compiler artifact");
        let verifier = ExactAdmission(command.signing_bytes().expect("command"));
        assert!(facade
            .admit_action(command, &action, &verifier, b"authenticated fixture")
            .unwrap_err()
            .to_string()
            .contains("requires the exact compiler artifact digest"));
        assert!(facade
            .kernel()
            .store()
            .program_import_operation_roster()
            .expect("import operations")
            .operations
            .is_empty());
    }

    #[test]
    fn host_action_receipt_requires_the_complete_original_admission_prefix() {
        let (action, command, mut facade) = fixture();
        let verifier = ExactAdmission(command.signing_bytes().unwrap());
        let receipt = facade
            .admit_action(command, &action, &verifier, b"authenticated fixture")
            .unwrap();
        let mut prefix = facade
            .kernel()
            .store()
            .chain_prefix(&receipt.instance_ref)
            .unwrap();
        prefix.truncate(2);
        let admitted = whipplescript_store::StoredEvent {
            event_id: prefix[1].event_id.clone(),
            sequence: prefix[1].sequence,
        };
        assert_eq!(
            admission_pin(&receipt.instance_ref, &admitted, &prefix).unwrap(),
            receipt.admitted_at
        );
        for fault in [
            "empty",
            "missing-first",
            "missing-admission",
            "wrong-event",
            "wrong-type",
            "gap",
        ] {
            let mut broken = prefix.clone();
            match fault {
                "empty" => broken.clear(),
                "missing-first" => {
                    broken.remove(0);
                }
                "missing-admission" => {
                    broken.pop();
                }
                "wrong-event" => broken[1].event_id = "other".into(),
                "wrong-type" => broken[1].event_type = "other".into(),
                "gap" => broken[0].sequence = 0,
                _ => unreachable!(),
            }
            assert!(
                admission_pin(&receipt.instance_ref, &admitted, &broken).is_err(),
                "{fault}"
            );
        }
    }

    #[test]
    fn host_action_authenticated_retry_cannot_rebind_a_request() {
        let (action, command, mut facade) = fixture();
        let verifier = ExactAdmission(command.signing_bytes().unwrap());
        let first = facade
            .admit_action(
                command.clone(),
                &action,
                &verifier,
                b"authenticated fixture",
            )
            .unwrap();
        let before = facade
            .kernel()
            .store()
            .list_events(&first.instance_ref)
            .unwrap();
        let mut changed = command;
        changed.provenance.origin = "another-surface".into();
        // This is a freshly authenticated delivery, not merely a bad signature.
        // The durable identity guard must still refuse changed meaning.
        let renewed = ExactAdmission(changed.signing_bytes().unwrap());
        assert!(facade
            .admit_action(changed, &action, &renewed, b"authenticated fixture")
            .is_err());
        assert_eq!(
            facade
                .kernel()
                .store()
                .list_events(&first.instance_ref)
                .unwrap(),
            before
        );
    }

    #[test]
    fn host_action_bad_authority_or_registered_contract_creates_no_instance() {
        for field in [
            "proof",
            "operation",
            "version",
            "schema",
            "input-name",
            "resource",
            "epoch",
        ] {
            let (action, mut command, mut facade) = fixture();
            match field {
                "operation" => command.operation = "unregistered".into(),
                "version" => command.program_version_ref = "action:other".into(),
                "schema" => command.input_schema_ref = "schema:other".into(),
                "input-name" => {
                    let input = command.inputs.remove("content").unwrap();
                    command.inputs.insert("extra".into(), input);
                }
                "resource" => {
                    command.inputs.get_mut("content").unwrap().handle = "not-granted".into()
                }
                "epoch" => command.policy.epoch = 8,
                _ => (),
            }
            let verifier = ExactAdmission(command.signing_bytes().unwrap());
            let proof = if field == "proof" {
                b"forged".as_slice()
            } else {
                b"authenticated fixture".as_slice()
            };
            assert!(
                facade
                    .admit_action(command, &action, &verifier, proof)
                    .is_err(),
                "{field}"
            );
            assert!(facade.kernel().store().list_instances().unwrap().is_empty());
        }
    }

    #[test]
    fn host_action_compilation_and_input_shape_are_closed() {
        assert!(CompiledHostAction::compile("", SOURCE, None).is_err());
        let invalid = "this is not a workflow";
        let compiled = compile_program_with_root(invalid, None);
        assert!(compiled.ir.is_none());
        assert!(!compiled.diagnostics.is_empty());
        let Err(message) = CompiledHostAction::compile("echo", invalid, None) else {
            panic!("an ordinary compiler error must prevent action registration");
        };
        assert!(message.starts_with("host action compilation failed: "));
        for diagnostic in compiled.diagnostics {
            assert!(
                message.contains(&diagnostic.message),
                "compiler diagnostic lost: {message}"
            );
        }
        assert!(CompiledHostAction::compile(
            "echo",
            "workflow NoResult\nrule idle\n when external.started\n=> { }",
            None
        )
        .is_err());
        let (action, _, _) = fixture();
        let altered = CompiledHostAction::compile(
            "reference.echo",
            &SOURCE.replace("version_ref string", "version_ref int"),
            None,
        )
        .unwrap();
        assert_ne!(action.version_ref(), altered.version_ref());
        assert_ne!(action.input_schema_ref(), altered.input_schema_ref());
        let (_, mut command, mut facade) = fixture();
        command.program_version_ref = altered.version_ref().into();
        command.input_schema_ref = altered.input_schema_ref().into();
        let verifier = ExactAdmission(command.signing_bytes().unwrap());
        assert!(facade
            .admit_action(command, &altered, &verifier, b"authenticated fixture")
            .is_err());
        assert!(facade.kernel().store().list_instances().unwrap().is_empty());
    }

    #[test]
    fn host_action_without_input_contract_refuses_supplied_handles() {
        let source = r#"
workflow NoInput
output result Result
class Result { handle string }
rule finish
  when external.started
=> { complete result { handle "done" } }
"#;
        let action = CompiledHostAction::compile("reference.echo", source, None).unwrap();
        let (_, mut command, mut facade) = fixture();
        command.program_version_ref = action.version_ref().into();
        command.input_schema_ref = action.input_schema_ref().into();
        let verifier = ExactAdmission(command.signing_bytes().unwrap());
        assert!(facade
            .admit_action(
                command.clone(),
                &action,
                &verifier,
                b"authenticated fixture"
            )
            .is_err());
        assert!(facade.kernel().store().list_instances().unwrap().is_empty());

        // The same authority and registered program accept exactly no inputs.
        command.inputs.clear();
        let verifier = ExactAdmission(command.signing_bytes().unwrap());
        facade
            .admit_action(command, &action, &verifier, b"authenticated fixture")
            .unwrap();
    }
}
