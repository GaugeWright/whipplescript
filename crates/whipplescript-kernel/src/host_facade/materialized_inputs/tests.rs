use super::*;
use crate::gov::{ExternalAttestation, GovernanceAttestationVerifier, SignedEnvelope};
use crate::host_protocol::action::{
    tests::{command, ExactAdmission},
    ActionInput,
};
use std::cell::Cell;
use whipplescript_store::native_stores::NativeStores;

const SOURCE: &str = r#"
workflow Typed(learner: Learner) -> string
class Learner { authority string }
rule begin
  when Learner as learner
=> {
  done learner
  complete result learner.authority
}
"#;

fn policy() -> Value {
    json!({"resources": {
        "input:learner": {"reader": "Member", "writer": "Member"},
        "fact:Learner": {"reader": "Member", "writer": "Member"},
        "result": {"reader": "Member", "writer": []},
        "error": {"reader": "Member", "writer": []},
        "tutorials": {"reader": "Member", "writer": []}
    }, "parties": {"system:workspace": "Member"}})
}
struct Signature;
impl GovernanceAttestationVerifier for Signature {
    fn verify(&self, _: &[u8], signature: &ExternalAttestation) -> Result<(), String> {
        if signature.signature == "fixture-signature" {
            Ok(())
        } else {
            Err("fixture signature".into())
        }
    }
}
fn envelope(policy: Value, epoch: u64) -> VerifiedEnvelope {
    let signed = SignedEnvelope::from_external_signature_v2(
        &policy.to_string(),
        "policy-signer",
        "fixture",
        "fixture-key",
        "fixture-signature",
        epoch,
        "product",
    )
    .expect("materialized-input fixture");
    VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &Signature)
        .expect("materialized-input fixture")
}
fn fixture(
    policy: Value,
    source: &str,
) -> (
    CompiledHostAction,
    HostActionCommand,
    GovernedHostFacade<NativeStores>,
) {
    let action = CompiledHostAction::compile_materialized_inputs("workflow.launch", source, None)
        .expect("materialized-input fixture");
    let mut cmd = command();
    let facade = GovernedHostFacade::from_verified_store(
        NativeStores::open_in_memory().expect("materialized-input fixture"),
        7,
        envelope(policy, 7),
    )
    .expect("materialized-input fixture");
    cmd.operation = "workflow.launch".into();
    cmd.program_version_ref = action.version_ref().into();
    cmd.input_schema_ref = action.input_schema_ref().into();
    cmd.policy = facade.policy_ref().clone();
    cmd.resources.clear();
    cmd.inputs = BTreeMap::from([(
        "learner".into(),
        ActionInput {
            handle: "input:learner".into(),
            version_ref: "immutable:one".into(),
            label_ref: "label:member".into(),
        },
    )]);
    (action, cmd, facade)
}
struct Custody {
    values: BTreeMap<String, Value>,
    reads: Cell<usize>,
    expected: HostActionCommand,
    unavailable: bool,
}
impl Custody {
    fn new(command: &HostActionCommand) -> Self {
        Self {
            values: BTreeMap::from([("learner".into(), json!({"authority": "person:learner"}))]),
            reads: Cell::new(0),
            expected: command.clone(),
            unavailable: false,
        }
    }
}
impl ActionInputResolver for Custody {
    fn with_inputs<T>(
        &self,
        admission: &VerifiedActionAdmission,
        consume: impl FnOnce(BTreeMap<String, Value>) -> T,
    ) -> Result<T, HostFacadeError> {
        assert_eq!(admission.command(), &self.expected);
        self.reads.set(self.reads.get() + 1);
        if self.unavailable {
            return Err(HostFacadeError::Resolver("PRIVATE_INPUT_DIAGNOSTIC".into()));
        }
        Ok(consume(self.values.clone()))
    }
}
fn admit(
    facade: &mut GovernedHostFacade<NativeStores>,
    action: &CompiledHostAction,
    cmd: &HostActionCommand,
    custody: &Custody,
) -> Result<ActionAdmissionReceipt, HostFacadeError> {
    facade.admit_action_with_inputs(
        cmd.clone(),
        action,
        &ExactAdmission(cmd.signing_bytes().expect("materialized-input fixture")),
        b"authenticated fixture",
        custody,
    )
}

#[test]
fn materialized_action_preserves_source_and_retries_after_consumption_without_reloading() {
    let root = std::env::temp_dir().join(format!(
        "whip-materialized-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("fixture clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let open = || {
        GovernedHostFacade::from_verified_store(
            NativeStores::open(
                root.join("runtime.db"),
                root.join("coord.db"),
                root.join("items.db"),
            )
            .unwrap(),
            7,
            envelope(policy(), 7),
        )
        .unwrap()
    };
    let (action, cmd, _) = fixture(policy(), SOURCE);
    let mut facade = open();
    let mut custody = Custody::new(&cmd);
    let first = admit(&mut facade, &action, &cmd, &custody).unwrap();
    assert_eq!(custody.reads.get(), 1);
    drop(facade);
    let mut facade = open();
    assert_eq!(admit(&mut facade, &action, &cmd, &custody).unwrap(), first);
    assert_eq!(custody.reads.get(), 1);
    let instance = facade
        .kernel()
        .store()
        .get_instance(&first.instance_ref)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&instance.input_json).unwrap(),
        json!(cmd.inputs)
    );
    let facts = facade
        .kernel()
        .store()
        .list_facts(&first.instance_ref)
        .unwrap();
    assert!(facts.iter().any(|fact| fact.name == "Learner"
        && serde_json::from_str::<Value>(&fact.value_json).unwrap()
            == json!({"authority": "person:learner"})));
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
    let events = facade
        .kernel()
        .store()
        .list_events(&first.instance_ref)
        .unwrap();
    let facts = facade
        .kernel()
        .store()
        .list_facts(&first.instance_ref)
        .unwrap();
    custody.unavailable = true;
    assert!(!facts.iter().any(|fact| fact.name == "Learner"));
    drop(facade);
    let mut facade = open();
    assert_eq!(admit(&mut facade, &action, &cmd, &custody).unwrap(), first);
    assert_eq!(custody.reads.get(), 1);
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(&first.instance_ref)
            .unwrap(),
        events
    );
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_facts(&first.instance_ref)
            .unwrap(),
        facts
    );
    facade
        .kernel_mut()
        .store_mut()
        .rebuild_projections(&first.instance_ref)
        .unwrap();
    assert_eq!(admit(&mut facade, &action, &cmd, &custody).unwrap(), first);
    let mut changed = cmd.clone();
    changed.inputs.get_mut("learner").unwrap().version_ref = "immutable:two".into();
    let changed_custody = Custody::new(&changed);
    assert!(admit(&mut facade, &action, &changed, &changed_custody).is_err());
    assert_eq!(changed_custody.reads.get(), 0);
    drop(facade);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn materialized_action_refuses_authority_and_label_errors_before_any_body_read() {
    let forged = SignedEnvelope::from_external_signature_v2(
        &policy().to_string(),
        "policy-signer",
        "fixture",
        "fixture-key",
        "forged-signature",
        7,
        "product",
    )
    .expect("forged policy fixture");
    assert!(
        matches!(GovernedHostFacade::from_signed_store_with_verifier(
        NativeStores::open_in_memory().expect("policy fixture store"),
        7, &forged.to_json(), &Signature,
    ), Err(HostFacadeError::PolicyRejected(message)) if message.contains("fixture signature"))
    );
    for fault in [
        "missing",
        "extra",
        "unknown-input",
        "unknown-fact",
        "unmapped",
        "no-parties",
        "fact-reader",
        "fact-writer",
        "fact-clearance",
        "output",
        "version",
        "proof",
    ] {
        let mut document = policy();
        match fault {
            "unknown-fact" => {
                document["resources"]
                    .as_object_mut()
                    .unwrap()
                    .remove("fact:Learner");
            }
            "unmapped" => document["parties"] = json!({"other": "Member"}),
            "no-parties" => {
                document.as_object_mut().unwrap().remove("parties");
            }
            "fact-reader" => {
                document["resources"]["fact:Learner"]["reader"] = json!([]);
                document["resources"]["fact:Learner"]["reader_sink"] = json!("Member");
            }
            "fact-writer" => {
                document["resources"]["fact:Learner"]["writer"] = json!("Trusted");
                document["resources"]["fact:Learner"]["writer_sink"] = json!("Member");
            }
            "fact-clearance" => {
                document["resources"]["fact:Learner"]["reader"] = json!(["Member", "Other"])
            }
            "output" => document["resources"]["result"]["reader"] = json!([]),
            _ => (),
        }
        let (action, mut cmd, mut facade) = fixture(document, SOURCE);
        match fault {
            "missing" => cmd.inputs.clear(),
            "extra" => {
                cmd.inputs
                    .insert("extra".into(), cmd.inputs["learner"].clone());
            }
            "unknown-input" => cmd.inputs.get_mut("learner").unwrap().handle = "ungranted".into(),
            "version" => cmd.program_version_ref = "unregistered".into(),
            _ => (),
        }
        let custody = Custody::new(&cmd);
        let proof = if fault == "proof" {
            b"forged".as_slice()
        } else {
            b"authenticated fixture".as_slice()
        };
        assert!(
            facade
                .admit_action_with_inputs(
                    cmd.clone(),
                    &action,
                    &ExactAdmission(cmd.signing_bytes().unwrap()),
                    proof,
                    &custody
                )
                .is_err(),
            "{fault}"
        );
        assert_eq!(custody.reads.get(), 0, "{fault}");
        assert!(
            facade.kernel().store().list_instances().unwrap().is_empty(),
            "{fault}"
        );
    }
}

#[test]
fn materialized_action_preserves_read_integrity_independently_of_the_write_sink() {
    // Consuming the fact would introduce a separate write to its directional
    // sink. This workflow only reads it, so whole-program IFC cannot mask a
    // materialization that incorrectly promotes ordinary input to Trusted.
    let source = SOURCE.replace("  done learner\n", "");
    for trusted_input in [false, true] {
        let mut document = policy();
        document["resources"]["fact:Learner"]["writer"] = json!("Trusted");
        document["resources"]["fact:Learner"]["writer_sink"] = json!("Member");
        if trusted_input {
            document["resources"]["input:learner"]["writer"] = json!(["Member", "Trusted"]);
        }
        let verified = envelope(document.clone(), 7);
        assert_eq!(
            verified.check_resource_flow("input:learner", "fact:Learner"),
            Ok(())
        );
        let expected = if trusted_input {
            Ok(())
        } else {
            Err("materialized fact elevates input integrity".into())
        };
        assert_eq!(
            verified.check_materialized_input("input:learner", "fact:Learner", "system:workspace"),
            expected
        );
        let (action, cmd, mut facade) = fixture(document, &source);
        facade.check_program_ifc(action.program()).unwrap();
        let custody = Custody::new(&cmd);
        let result = admit(&mut facade, &action, &cmd, &custody);
        if trusted_input {
            let receipt = result.unwrap();
            assert_eq!(custody.reads.get(), 1);
            assert!(facade
                .kernel()
                .store()
                .get_instance(&receipt.instance_ref)
                .unwrap()
                .is_some());
        } else {
            assert!(
                matches!(result, Err(HostFacadeError::PolicyRejected(message))
                if message == "materialized fact elevates input integrity")
            );
            assert_eq!(custody.reads.get(), 0);
            assert!(facade.kernel().store().list_instances().unwrap().is_empty());
        }
    }
}

#[test]
fn materialized_action_validates_resolved_names_and_values_before_publication() {
    for fault in [
        "missing",
        "extra",
        "wrong-field-type",
        "missing-field",
        "unavailable",
    ] {
        let (action, cmd, mut facade) = fixture(policy(), SOURCE);
        let mut custody = Custody::new(&cmd);
        match fault {
            "missing" => custody.values.clear(),
            "extra" => {
                custody.values.insert("extra".into(), json!(true));
            }
            "wrong-field-type" => {
                custody.values.get_mut("learner").unwrap()["authority"] = json!(9)
            }
            "missing-field" => {
                custody.values.insert("learner".into(), json!({}));
            }
            "unavailable" => custody.unavailable = true,
            _ => unreachable!(),
        }
        assert!(
            admit(&mut facade, &action, &cmd, &custody).is_err(),
            "{fault}"
        );
        assert_eq!(custody.reads.get(), 1);
        assert!(facade.kernel().store().list_instances().unwrap().is_empty());
    }
}

#[test]
fn materialized_and_reference_registration_are_distinct_and_each_door_is_closed() {
    let (materialized, cmd, mut facade) = fixture(policy(), SOURCE);
    let reference = CompiledHostAction::compile("workflow.launch", SOURCE, None).unwrap();
    assert_ne!(materialized.version_ref(), reference.version_ref());
    assert_ne!(
        materialized.input_schema_ref(),
        reference.input_schema_ref()
    );
    assert_eq!(
        materialized.program().to_snapshot(),
        reference.program().to_snapshot()
    );
    let mut registration = vec![
        json!(crate::host_protocol::action::HOST_ACTION_PROTOCOL),
        json!("workflow.launch"),
        json!(SOURCE),
        json!(whipplescript_parser::snapshot::identity_projection(
            &reference.program().to_snapshot()
        )),
        json!(whipplescript_core::version()),
    ];
    assert_eq!(
        reference.version_ref(),
        format!(
            "action:{}",
            crate::gov::hash_hex(&json!(registration).to_string())
        )
    );
    registration.push(json!("materialized-inputs.v1"));
    assert_eq!(
        materialized.version_ref(),
        format!(
            "action:{}",
            crate::gov::hash_hex(&json!(registration).to_string())
        )
    );
    assert!(facade
        .admit_action(
            cmd.clone(),
            &materialized,
            &ExactAdmission(cmd.signing_bytes().unwrap()),
            b"authenticated fixture"
        )
        .is_err());
    let mut reference_cmd = cmd;
    reference_cmd.program_version_ref = reference.version_ref().into();
    reference_cmd.input_schema_ref = reference.input_schema_ref().into();
    let custody = Custody::new(&reference_cmd);
    assert!(admit(&mut facade, &reference, &reference_cmd, &custody).is_err());
    assert_eq!(custody.reads.get(), 0);
    assert!(facade.kernel().store().list_instances().unwrap().is_empty());
}

#[test]
fn materialized_action_rechecks_fact_labels_and_executor_before_effect_authorization() {
    use crate::host_protocol::execution::{
        effect_observation_fingerprint, ActionExecutionVerifier, ExecuteActionEffect,
        ACTION_EXECUTION_PROTOCOL,
    };
    struct Execution {
        bytes: Vec<u8>,
        original: HostActionCommand,
        authorized: Cell<usize>,
    }
    impl ActionExecutionVerifier for Execution {
        fn authenticate(
            &self,
            _: &ExecuteActionEffect,
            bytes: &[u8],
            proof: &[u8],
        ) -> Result<(), ProtocolError> {
            if bytes == self.bytes && proof == b"execution" {
                Ok(())
            } else {
                Err(ProtocolError::Mismatch("fixture execution"))
            }
        }
        fn authorize(
            &self,
            _: &ExecuteActionEffect,
            original: &HostActionCommand,
            _: &whipplescript_store::ClaimableEffect,
        ) -> Result<(), ProtocolError> {
            assert_eq!(original, &self.original);
            self.authorized.set(self.authorized.get() + 1);
            Ok(())
        }
    }
    let source = r#"
workflow TypedEffect(learner: Learner) -> string
class Learner { authority string }
tracker tutorials
rule begin
  when Learner as learner
=> {
  then filed <- file issue into tutorials { title learner.authority }
  complete result learner.authority
}
"#;
    for fault in [
        "none",
        "missing-fact",
        "fact-reader",
        "fact-writer",
        "executor",
        "proof",
        "signing",
    ] {
        let (action, original, mut facade) = fixture(policy(), source);
        facade
            .kernel()
            .store()
            .register_package_manifest(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../std/manifests/tracker.json"
            )))
            .unwrap();
        let custody = Custody::new(&original);
        let admission = admit(&mut facade, &action, &original, &custody).unwrap();
        crate::rule_pass::step_instance_generic(
            facade.kernel_mut(),
            &admission.instance_ref,
            action.program(),
            None,
            None,
        )
        .unwrap();
        let effects = facade
            .kernel()
            .claimable_effects(&admission.instance_ref)
            .unwrap();
        assert_eq!(effects.len(), 1);
        let mut current = policy();
        match fault {
            "missing-fact" => {
                current["resources"]
                    .as_object_mut()
                    .unwrap()
                    .remove("fact:Learner");
            }
            "fact-reader" => {
                current["resources"]["fact:Learner"]["reader"] = json!([]);
                current["resources"]["fact:Learner"]["reader_sink"] = json!("Member");
            }
            "fact-writer" => {
                current["resources"]["fact:Learner"]["writer"] = json!("Trusted");
                current["resources"]["fact:Learner"]["writer_sink"] = json!("Member");
            }
            "executor" => current["parties"] = json!({"someone-else": "Member"}),
            _ => (),
        }
        let facade = GovernedHostFacade::from_verified_store(
            facade.into_kernel().into_store(),
            8,
            envelope(current, 8),
        )
        .unwrap();
        let request = ExecuteActionEffect {
            protocol: ACTION_EXECUTION_PROTOCOL.into(),
            issuer: original.issuer.clone(),
            scope: original.scope.clone(),
            admission,
            policy: facade.policy_ref().clone(),
            provenance: original.provenance.clone(),
            effect_id: effects[0].effect_id.clone(),
            effect_fingerprint: effect_observation_fingerprint(&effects[0]).unwrap(),
        };
        let mut verifier = Execution {
            bytes: request.signing_bytes().unwrap(),
            original,
            authorized: Cell::new(0),
        };
        if fault == "signing" {
            verifier.bytes.push(0);
        }
        let proof = if fault == "proof" {
            b"forged".as_slice()
        } else {
            b"execution".as_slice()
        };
        let prepared = facade.prepare_action_execution(request, &action, &verifier, proof);
        assert_eq!(prepared.is_ok(), fault == "none", "{fault}");
        assert_eq!(verifier.authorized.get(), usize::from(fault == "none"));
    }
}

#[test]
fn materialized_empty_and_scalar_input_contracts_use_ordinary_validation() {
    for (source, inputs) in [
        ("workflow Empty() -> bool\nrule done\n when external.started\n=> { complete result true }", BTreeMap::new()),
        ("workflow Scalar(count: int) -> bool\nrule done\n when external.started\n=> { complete result true }", BTreeMap::from([("count".into(), json!(3))])),
    ] {
        let mut document = policy();
        document["resources"]["fact:int"] = json!({"reader": "Member", "writer": "Member"});
        let (action, mut cmd, mut facade) = fixture(document, source);
        let reference = cmd.inputs["learner"].clone();
        cmd.inputs = inputs.keys().map(|name: &String| (name.clone(), reference.clone())).collect();
        let mut custody = Custody::new(&cmd);
        custody.values = inputs;
        let receipt = admit(&mut facade, &action, &cmd, &custody).unwrap();
        assert_eq!(custody.reads.get(), 1);
        assert!(facade.kernel().store().get_instance(&receipt.instance_ref).unwrap().is_some());
    }
}

#[test]
fn materialized_mode_cannot_enter_the_reference_door_even_with_a_reference_shaped_class() {
    let source = r#"
workflow ReferenceShaped(learner: Learner) -> string
class Learner { handle string version_ref string label_ref string }
rule echo
  when Learner as learner
=> { complete result learner.handle }
"#;
    let (materialized, cmd, mut facade) = fixture(policy(), source);
    let error = facade
        .admit_action(
            cmd.clone(),
            &materialized,
            &ExactAdmission(cmd.signing_bytes().unwrap()),
            b"authenticated fixture",
        )
        .unwrap_err();
    assert!(matches!(
        error,
        HostFacadeError::Protocol(ProtocolError::Invalid(
            "materialized workflow requires governed input custody"
        ))
    ));
    assert!(facade.kernel().store().list_instances().unwrap().is_empty());
    // The same schema is legitimate through the reference registration.
    let reference = CompiledHostAction::compile("workflow.launch", source, None).unwrap();
    let mut cmd = cmd;
    cmd.program_version_ref = reference.version_ref().into();
    cmd.input_schema_ref = reference.input_schema_ref().into();
    facade
        .admit_action(
            cmd.clone(),
            &reference,
            &ExactAdmission(cmd.signing_bytes().unwrap()),
            b"authenticated fixture",
        )
        .unwrap();
}

#[test]
fn materialized_empty_contract_refuses_a_resolver_that_invents_input() {
    let source =
        "workflow Empty() -> bool\nrule done\n when external.started\n=> { complete result true }";
    let (action, mut cmd, mut facade) = fixture(policy(), source);
    cmd.inputs.clear();
    let custody = Custody::new(&cmd); // deliberately still returns a Learner
    let error = admit(&mut facade, &action, &cmd, &custody).unwrap_err();
    assert!(matches!(
        error,
        HostFacadeError::Protocol(ProtocolError::Mismatch("resolved workflow input names"))
    ));
    assert_eq!(custody.reads.get(), 1);
    assert!(facade.kernel().store().list_instances().unwrap().is_empty());
}

#[test]
fn materialized_input_errors_do_not_disclose_payload_keys_or_custody_details() {
    for adapter_failure in [false, true] {
        let (action, cmd, mut facade) = fixture(policy(), SOURCE);
        let mut custody = Custody::new(&cmd);
        custody.unavailable = adapter_failure;
        custody.values.get_mut("learner").unwrap()["PRIVATE_INPUT_FIELD"] = json!("private value");
        let error = admit(&mut facade, &action, &cmd, &custody)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("PRIVATE_INPUT"), "{error}");
        assert!(!error.contains("private value"), "{error}");
        if adapter_failure {
            assert!(
                error.contains("workflow input custody is unavailable"),
                "{error}"
            );
        } else {
            assert!(
                error.contains("materialized input does not match workflow schema"),
                "{error}"
            );
        }
        assert!(facade.kernel().store().list_instances().unwrap().is_empty());
    }
}
