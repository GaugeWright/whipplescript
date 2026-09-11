use super::*;
use crate::host_facade::TrackerRecoveryAuthority;
use crate::host_protocol::tracker_recovery::{RecoverTrackerFiling, TRACKER_RECOVERY_PROTOCOL};
use crate::{
    gov::{ExternalAttestation, GovernanceAttestationVerifier, SignedEnvelope},
    host_action::CompiledHostAction,
    host_facade::{
        ActionInputResolver, GovernedHostFacade, HostFacadeError, TrackerExecutionAuthority,
    },
    host_protocol::{
        action::{
            tests::{command, ExactAdmission},
            ActionBasis, ActionDelegation, ActionInput, HostActionCommand, VerifiedActionAdmission,
        },
        execution::{
            effect_observation_fingerprint, ActionExecutionVerifier, ExecuteActionEffect,
            ACTION_EXECUTION_PROTOCOL,
        },
        ProtocolError, ResourceRef,
    },
    ifc::VerifiedEnvelope,
};
use std::{cell::Cell, collections::BTreeMap};
use whipplescript_store::{items::WorkItems, log_append::LogAppend, native_stores::NativeStores};

const SOURCE: &str = r#"
workflow FileTask(learner: Learner) -> string
class Learner { authority string }
tracker tutorials
rule begin
  when Learner as learner
=> {
  then issued <- file issue into tutorials {
    title "Create a chat"
    body "PRIVATE_TASK_BODY"
    assigned_to learner.authority
  }
  complete result issued.id
}
"#;

fn policy() -> Value {
    json!({"resources": {
        "input:learner": {"reader": "Member", "writer": "Member"},
        "fact:Learner": {"reader": "Member", "writer": "Member"},
        "tracker:1/tutorials": {"reader": "Member", "writer": "Member"},
        "result": {"reader": "Member", "writer": []},
        "error": {"reader": "Member", "writer": []}
    }, "bindings": {"tutorials": "tracker:1/tutorials"},
    "parties": {"person:learner": "Member", "agent:assistant": "Member", "system:workspace": "Member"}})
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

fn envelope(document: Value, epoch: u64) -> VerifiedEnvelope {
    let signed = SignedEnvelope::from_external_signature_v2(
        &document.to_string(),
        "policy-signer",
        "fixture",
        "fixture-key",
        "fixture-signature",
        epoch,
        "product",
    )
    .expect("sign fixture policy");
    VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &Signature)
        .expect("verify fixture policy")
}

struct Custody;
impl ActionInputResolver for Custody {
    fn with_inputs<T>(
        &self,
        _: &VerifiedActionAdmission,
        consume: impl FnOnce(BTreeMap<String, Value>) -> T,
    ) -> Result<T, HostFacadeError> {
        Ok(consume(BTreeMap::from([(
            "learner".into(),
            json!({"authority": "person:learner"}),
        )])))
    }
}

struct Fixture {
    facade: GovernedHostFacade<NativeStores>,
    action: CompiledHostAction,
    original: HostActionCommand,
    request: ExecuteActionEffect,
    binding: TrackerBinding,
}

fn fixture(actor: &str) -> Fixture {
    fixture_in(
        actor,
        NativeStores::open_in_memory().expect("open fixture stores"),
        |_| {},
    )
}

fn fixture_in(
    actor: &str,
    store: NativeStores,
    configure: impl FnOnce(&mut ActionResource),
) -> Fixture {
    fixture_for_source(actor, store, SOURCE, &Custody, configure)
}

fn fixture_for_source(
    actor: &str,
    store: NativeStores,
    source: &str,
    custody: &impl ActionInputResolver,
    configure: impl FnOnce(&mut ActionResource),
) -> Fixture {
    let action = CompiledHostAction::compile_materialized_inputs("workflow.launch", source, None)
        .expect("compile fixture workflow");
    let mut facade = GovernedHostFacade::from_verified_store(store, 7, envelope(policy(), 7))
        .expect("create governed fixture");
    facade
        .kernel()
        .store()
        .register_package_manifest(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../std/manifests/tracker.json"
        )))
        .expect("register tracker package");
    let mut original = command();
    original.operation = "workflow.launch".into();
    original.program_version_ref = action.version_ref().into();
    original.input_schema_ref = action.input_schema_ref().into();
    original.policy = facade.policy_ref().clone();
    original.provenance.initiator = "person:learner".into();
    original.provenance.delegation[0].delegator = "person:learner".into();
    original.inputs = BTreeMap::from([(
        "learner".into(),
        ActionInput {
            handle: "input:learner".into(),
            version_ref: "immutable:one".into(),
            label_ref: "label:member".into(),
        },
    )]);
    let mut binding = TrackerBinding {
        scope: original.scope.clone(),
        queue: "tutorials".into(),
        resource: ActionResource {
            resource: ResourceRef {
                handle: "tracker:1/tutorials".into(),
                kind: "tracker".into(),
                selector: Some("tutorials".into()),
                writable: Some(true),
            },
            basis: ActionBasis::Version {
                version_ref: "tracker-incarnation:one".into(),
            },
            label_ref: "label:member".into(),
        },
    };
    configure(&mut binding.resource);
    original.resources = BTreeMap::from([("tutorials".into(), binding.resource.clone())]);
    let admission = facade
        .admit_action_with_inputs(
            original.clone(),
            &action,
            &ExactAdmission(
                original
                    .signing_bytes()
                    .expect("serialize fixture admission"),
            ),
            b"authenticated fixture",
            custody,
        )
        .expect("admit fixture workflow");
    // This fixture prepares the queued effect directly. Product launch and
    // governed rule-pass observation remain separate integration requirements.
    crate::rule_pass::step_instance_generic(
        facade.kernel_mut(),
        &admission.instance_ref,
        action.program(),
        None,
        None,
    )
    .expect("queue fixture filing");
    let mut effects = facade
        .kernel()
        .claimable_effects(&admission.instance_ref)
        .expect("observe fixture effect");
    // A pending wait has a queued definition but no ready dispatch. Constructing
    // this fixture request cannot make it claimable at the governed API.
    if effects.is_empty() {
        effects = facade
            .kernel()
            .store()
            .list_effects(&admission.instance_ref)
            .expect("queued wait definition")
            .into_iter()
            .filter(|effect| effect.status == "queued")
            .map(|effect| ClaimableEffect {
                effect_id: effect.effect_id,
                kind: effect.kind,
                target: effect.target,
                profile: effect.profile,
                input_json: effect.input_json,
                required_capabilities_json: effect.required_capabilities_json,
                declared_profiles_json: effect.declared_profiles_json,
            })
            .collect();
    }
    assert_eq!(effects.len(), 1);
    let mut provenance = original.provenance.clone();
    provenance.executor = actor.into();
    provenance.delegation = if actor == provenance.initiator {
        vec![]
    } else {
        vec![ActionDelegation {
            grant_ref: "fixture:execution-grant".into(),
            delegator: provenance.initiator.clone(),
            delegate: actor.into(),
        }]
    };
    let request = ExecuteActionEffect {
        protocol: ACTION_EXECUTION_PROTOCOL.into(),
        issuer: original.issuer.clone(),
        scope: original.scope.clone(),
        admission,
        policy: facade.policy_ref().clone(),
        provenance,
        effect_id: effects[0].effect_id.clone(),
        effect_fingerprint: effect_observation_fingerprint(&effects[0])
            .expect("fingerprint fixture effect"),
    };
    Fixture {
        facade,
        action,
        original,
        request,
        binding,
    }
}

struct Authority {
    bytes: Vec<u8>,
    original: HostActionCommand,
    binding: TrackerBinding,
    observation: bool,
    filing: bool,
    observed: Cell<usize>,
    authorized: Cell<usize>,
}

struct RecoveryAuthority {
    request: RecoverTrackerFiling,
    original: HostActionCommand,
    binding: TrackerBinding,
    observation: bool,
    deny_publication: bool,
    checks: Cell<usize>,
}
impl TrackerRecoveryAuthority for RecoveryAuthority {
    fn authenticate(
        &self,
        request: &RecoverTrackerFiling,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request == &self.request && bytes == request.signing_bytes()? && proof == b"recovery" {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture recovery authentication"))
        }
    }
    fn authorize_observation(
        &self,
        request: &RecoverTrackerFiling,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError> {
        if self.observation && request.scope == self.original.scope && binding == &self.binding {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture recovery observation"))
        }
    }
    fn authorize_recovery(
        &self,
        request: &RecoverTrackerFiling,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        dispatch: &FilingDispatch,
    ) -> Result<(), ProtocolError> {
        assert_eq!(original, &self.original);
        assert_eq!(execution.provenance.executor, "person:learner");
        assert_eq!(request.provenance.executor, "agent:assistant");
        assert_eq!(dispatch.binding, self.binding);
        self.checks.set(self.checks.get() + 1);
        if self.deny_publication && self.checks.get() > 1 {
            Err(ProtocolError::Mismatch("fixture recovery revoked"))
        } else {
            Ok(())
        }
    }
}
impl crate::host_protocol::action_result::ActionResultVerifier for RecoveryAuthority {
    fn verify(
        &self,
        request: &crate::host_protocol::action_result::ReadActionResult,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request.admission == self.request.admission
            && request.policy == self.request.policy
            && request.issuer == self.request.issuer
            && request.scope == self.request.scope
            && request.provenance == self.request.provenance
            && request.evidence_handle == "result"
            && bytes == request.signing_bytes()?
            && proof == b"result read"
        {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture recovered result read"))
        }
    }
}
impl Authority {
    fn new(fixture: &Fixture) -> Self {
        Self {
            bytes: fixture
                .request
                .signing_bytes()
                .expect("serialize fixture execution"),
            original: fixture.original.clone(),
            binding: fixture.binding.clone(),
            observation: true,
            filing: true,
            observed: Cell::new(0),
            authorized: Cell::new(0),
        }
    }
}
impl ActionExecutionVerifier for Authority {
    fn authenticate(
        &self,
        _: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if bytes == self.bytes && proof == b"execution" {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture execution proof"))
        }
    }
    fn authorize(
        &self,
        _: &ExecuteActionEffect,
        original: &HostActionCommand,
        _: &ClaimableEffect,
    ) -> Result<(), ProtocolError> {
        assert_eq!(original, &self.original);
        Ok(())
    }
}
impl TrackerExecutionAuthority for Authority {
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError> {
        self.observed.set(self.observed.get() + 1);
        if self.observation && binding == &self.binding && request.scope == binding.scope {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture observation denied"))
        }
    }
    fn authorize_filing(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerBinding,
        filing: &TrackerFiling,
    ) -> Result<(), ProtocolError> {
        self.authorized.set(self.authorized.get() + 1);
        assert_eq!(original, &self.original);
        assert_eq!(binding, &self.binding);
        assert_eq!(filing.actor, request.provenance.executor);
        assert_eq!(filing.assigned_to.as_deref(), Some("person:learner"));
        if self.filing {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture filing denied"))
        }
    }
}

#[test]
fn governed_tracker_filing_attributes_the_actor_and_settles_the_ordinary_continuation() {
    for actor in ["person:learner", "agent:assistant"] {
        let mut f = fixture(actor);
        let authority = Authority::new(&f);
        let terminal = f
            .facade
            .execute_tracker_filing(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &f.binding,
            )
            .unwrap();
        let items = f
            .facade
            .kernel()
            .store()
            .list_items(Some("tutorials"), None)
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].filed_by.as_deref(), Some(actor));
        assert_eq!(items[0].assigned_to.as_deref(), Some("person:learner"));
        assert_eq!(items[0].body, "PRIVATE_TASK_BODY");
        let events = f
            .facade
            .kernel()
            .store()
            .list_events(&f.request.admission.instance_ref)
            .unwrap();
        let started = events
            .iter()
            .find(|event| event.event_type == "effect.run_started")
            .unwrap();
        let payload: Value = serde_json::from_str(&started.payload_json).unwrap();
        let dispatch: FilingDispatch =
            serde_json::from_value(payload["metadata"]["tracker_filing"].clone()).unwrap();
        assert!(!serde_json::to_string(&dispatch)
            .unwrap()
            .contains("PRIVATE_TASK_BODY"));
        let receipt = f
            .facade
            .kernel()
            .store()
            .filing_receipt(&dispatch.operation_id)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.fingerprint, dispatch.fingerprint);
        assert_eq!(receipt.item_id, items[0].id);
        assert_eq!(
            payload["metadata"]["action_execution"]["request"]["provenance"]["executor"],
            actor
        );
        let facts = f
            .facade
            .kernel()
            .store()
            .list_facts(&f.request.admission.instance_ref)
            .unwrap();
        let fact = facts
            .iter()
            .find(|fact| fact.name == "tracker.file.completed")
            .unwrap();
        let value: Value = serde_json::from_str(&fact.value_json).unwrap();
        assert_eq!(
            value["value"],
            json!({"queue": "tutorials", "id": items[0].id, "title": "Create a chat"})
        );
        let prefix = f
            .facade
            .kernel()
            .store()
            .chain_prefix(&f.request.admission.instance_ref)
            .unwrap();
        assert!(prefix.iter().any(|event| event.event_type == "fact.derived"
            && event.causation_id.as_deref() == Some(terminal.event_id.as_str())));
        assert!(f
            .facade
            .execute_tracker_filing(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &f.binding
            )
            .is_err());
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .list_items(None, None)
                .unwrap()
                .len(),
            1
        );
        crate::rule_pass::step_instance_generic(
            f.facade.kernel_mut(),
            &f.request.admission.instance_ref,
            f.action.program(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .get_instance(&f.request.admission.instance_ref)
                .unwrap()
                .unwrap()
                .status,
            "completed"
        );
    }
}

#[test]
fn ordinary_tracker_filing_refuses_credential_and_untyped_items() {
    let f = fixture("person:learner");
    let effect = f
        .facade
        .kernel()
        .claimable_effects(&f.request.admission.instance_ref)
        .expect("fixture effect")
        .remove(0);
    let input = json!({"item": {"title": "First task", "body": "Instructions",
        "labels": ["tutorial"], "metadata": {"lesson": "basics"}, "assigned_to": " person:learner "}});
    let filing = request(
        &f.request.admission.instance_ref,
        &effect,
        "person:learner",
        &input.to_string(),
    )
    .expect("ordinary typed filing");
    assert_eq!(filing.title, "First task");
    assert_eq!(filing.body, "Instructions");
    assert_eq!(filing.labels, vec!["tutorial"]);
    assert_eq!(filing.metadata, json!({"lesson": "basics"}));
    assert_eq!(filing.assigned_to.as_deref(), Some("person:learner"));
    for credential in [Value::Null, Value::Bool(false), json!({"scope": "secret"})] {
        let mut changed = input.clone();
        changed["credential"] = credential;
        let error = request(
            &f.request.admission.instance_ref,
            &effect,
            "person:learner",
            &changed.to_string(),
        )
        .expect_err("credential requests need their separate continuation");
        assert!(matches!(error, StoreError::Conflict(ref message)
            if message == "tracker filing requires an ordinary issue"));
    }
    for item in [
        json!({"title": 4}),
        json!({"body": []}),
        json!({"assigned_to": false}),
        json!({"labels": "tutorial"}),
        json!({"unknown": "PRIVATE_INPUT"}),
    ] {
        let error = request(
            &f.request.admission.instance_ref,
            &effect,
            "person:learner",
            &json!({"item": item}).to_string(),
        )
        .expect_err("malformed item must refuse");
        assert!(matches!(error, StoreError::Conflict(ref message)
            if message == "tracker filing item does not match its schema"));
    }
}

#[test]
fn governed_tracker_observation_refusal_precedes_unavailable_history() {
    let mut f = fixture("person:learner");
    let mut authority = Authority::new(&f);
    authority.observation = false;
    f.facade.kernel_mut().store_mut().runtime =
        whipplescript_store::SqliteStore::open_in_memory().unwrap();
    let error = f
        .facade
        .execute_tracker_filing(
            f.request.clone(),
            &f.action,
            &authority,
            b"execution",
            &f.binding,
        )
        .unwrap_err();
    assert!(matches!(
        error,
        HostFacadeError::Protocol(ProtocolError::Mismatch("fixture observation denied"))
    ));
    assert_eq!(authority.authorized.get(), 0);
    authority.observation = true;
    assert!(f
        .facade
        .execute_tracker_filing(f.request, &f.action, &authority, b"execution", &f.binding)
        .is_err());
    assert!(f
        .facade
        .kernel()
        .store()
        .list_items(None, None)
        .unwrap()
        .is_empty());
}

#[test]
fn governed_tracker_refuses_current_denial_and_broader_target_before_dispatch() {
    for change in [
        "proof",
        "filing-right",
        "label",
        "scope",
        "selector",
        "basis",
    ] {
        let mut f = fixture("person:learner");
        let mut authority = Authority::new(&f);
        match change {
            "filing-right" => authority.filing = false,
            "label" => f.binding.resource.label_ref = "label:other".into(),
            "scope" => f.binding.scope = "workspace:other".into(),
            "selector" => f.binding.resource.resource.selector = Some("another".into()),
            "basis" => f.binding.resource.basis = ActionBasis::Absent,
            _ => (),
        }
        authority.binding = f.binding.clone();
        let proof = if change == "proof" {
            b"forged".as_slice()
        } else {
            b"execution".as_slice()
        };
        assert!(
            f.facade
                .execute_tracker_filing(f.request.clone(), &f.action, &authority, proof, &f.binding)
                .is_err(),
            "{change}"
        );
        assert!(
            f.facade
                .kernel()
                .store()
                .list_runs(&f.request.admission.instance_ref)
                .unwrap()
                .is_empty(),
            "{change}"
        );
        assert!(
            f.facade
                .kernel()
                .store()
                .list_items(None, None)
                .unwrap()
                .is_empty(),
            "{change}"
        );
    }
}

#[test]
fn governed_tracker_refuses_an_alias_to_another_equally_labelled_object() {
    let mut f = fixture("person:learner");
    let mut current = policy();
    current["resources"]["tracker:other"] = current["resources"]["tracker:1/tutorials"].clone();
    current["bindings"]["tutorials"] = json!("tracker:other");
    f.facade = GovernedHostFacade::from_verified_store(
        f.facade.into_kernel().into_store(),
        8,
        envelope(current, 8),
    )
    .unwrap();
    f.request.policy = f.facade.policy_ref().clone();
    let authority = Authority::new(&f);
    let error = f
        .facade
        .execute_tracker_filing(
            f.request.clone(),
            &f.action,
            &authority,
            b"execution",
            &f.binding,
        )
        .unwrap_err();
    assert!(
        matches!(error, HostFacadeError::PolicyRejected(message) if message == "resource binding names a different object")
    );
    assert_eq!(authority.authorized.get(), 0);
    assert!(f
        .facade
        .kernel()
        .store()
        .list_runs(&f.request.admission.instance_ref)
        .unwrap()
        .is_empty());
    assert!(f
        .facade
        .kernel()
        .store()
        .list_items(None, None)
        .unwrap()
        .is_empty());
}

#[test]
fn governed_tracker_requires_a_writable_tracker_with_the_declared_selector() {
    for change in ["kind", "read-only", "missing-selector", "other-selector"] {
        let mut f = fixture_in(
            "person:learner",
            NativeStores::open_in_memory().unwrap(),
            |resource| match change {
                "kind" => resource.resource.kind = "file_store".into(),
                "read-only" => resource.resource.writable = Some(false),
                "missing-selector" => resource.resource.selector = None,
                "other-selector" => resource.resource.selector = Some("another-queue".into()),
                _ => unreachable!(),
            },
        );
        let authority = Authority::new(&f);
        let error = f
            .facade
            .execute_tracker_filing(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &f.binding,
            )
            .unwrap_err();
        assert!(
            matches!(
                error,
                HostFacadeError::Protocol(ProtocolError::Mismatch(
                    "tracker filing original resource binding"
                ))
            ),
            "{change}"
        );
        assert_eq!(authority.authorized.get(), 0);
        assert!(f
            .facade
            .kernel()
            .store()
            .list_runs(&f.request.admission.instance_ref)
            .unwrap()
            .is_empty());
        assert!(f
            .facade
            .kernel()
            .store()
            .list_items(None, None)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn governed_tracker_target_commit_recovers_after_restart_without_redispatch() {
    for scenario in ["running", "expired", "absent", "disputed"] {
        let expire = scenario != "running";
        let root = std::env::temp_dir().join(format!(
            "whip-tracker-interruption-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let open = || {
            NativeStores::open(
                root.join("runtime.sqlite"),
                root.join("coord.sqlite"),
                root.join("items.sqlite"),
            )
            .unwrap()
        };
        let mut f = fixture_in("person:learner", open(), |_| {});
        let authority = Authority::new(&f);
        let fault = rusqlite::Connection::open(root.join("runtime.sqlite")).unwrap();
        fault
            .execute_batch(
                "CREATE TRIGGER tracker_settlement_fault AFTER INSERT ON events
            WHEN NEW.event_type = 'effect.terminal'
            BEGIN SELECT RAISE(ABORT, 'injected terminal publication failure'); END;",
            )
            .unwrap();
        assert!(f
            .facade
            .execute_tracker_filing(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &f.binding
            )
            .is_err());
        let operation =
            filing_operation_id(&f.request.admission.instance_ref, &f.request.effect_id);
        let receipt = f
            .facade
            .kernel()
            .store()
            .filing_receipt(&operation)
            .unwrap()
            .unwrap();
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .list_items(None, None)
                .unwrap()
                .len(),
            1
        );
        assert!(!f
            .facade
            .kernel()
            .store()
            .list_facts(&f.request.admission.instance_ref)
            .unwrap()
            .iter()
            .any(|fact| fact.name == "tracker.file.completed"));
        fault
            .execute_batch("DROP TRIGGER tracker_settlement_fault;")
            .unwrap();
        drop(fault);
        let Fixture {
            facade,
            action,
            original,
            request,
            binding,
        } = f;
        drop(facade);
        let mut f = Fixture {
            facade: GovernedHostFacade::from_verified_store(open(), 7, envelope(policy(), 7))
                .unwrap(),
            action,
            original,
            request,
            binding,
        };
        if expire {
            assert_eq!(
                f.facade
                    .kernel_mut()
                    .expire_leases(&f.request.admission.instance_ref, "2099-01-01T00:00:00Z")
                    .unwrap()
                    .len(),
                1
            );
        }
        let authority = Authority::new(&f);
        assert!(f
            .facade
            .execute_tracker_filing(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &f.binding
            )
            .is_err());
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .filing_receipt(&operation)
                .unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .list_items(None, None)
                .unwrap()
                .len(),
            1
        );
        assert!(!f
            .facade
            .kernel()
            .store()
            .list_facts(&f.request.admission.instance_ref)
            .unwrap()
            .iter()
            .any(|fact| fact.name == "tracker.file.completed"));
        let instance = f.request.admission.instance_ref.clone();
        let owner = f
            .facade
            .kernel_mut()
            .store_mut()
            .claim_instance_ownership(&instance)
            .unwrap();
        let run_id = f.facade.kernel().store().list_runs(&instance).unwrap()[0]
            .run_id
            .clone();
        let mut provenance = f.request.provenance.clone();
        provenance.executor = "agent:assistant".into();
        provenance.delegation = vec![ActionDelegation {
            grant_ref: "grant:recover".into(),
            delegator: "person:learner".into(),
            delegate: "agent:assistant".into(),
        }];
        let recovery = RecoverTrackerFiling {
            protocol: TRACKER_RECOVERY_PROTOCOL.into(),
            issuer: f.request.issuer.clone(),
            scope: f.request.scope.clone(),
            admission: f.request.admission.clone(),
            policy: f.facade.policy_ref().clone(),
            provenance,
            effect_id: f.request.effect_id.clone(),
            run_id,
        };
        let mut recovery_authority = RecoveryAuthority {
            request: recovery.clone(),
            original: f.original.clone(),
            binding: f.binding.clone(),
            observation: true,
            deny_publication: true,
            checks: Cell::new(0),
        };
        let before = f.facade.kernel().store().chain_head(&instance).unwrap();
        assert!(f
            .facade
            .recover_tracker_filing(
                recovery.clone(),
                &f.action,
                owner,
                &recovery_authority,
                b"forged",
                &f.binding
            )
            .is_err());
        let denied = f
            .facade
            .recover_tracker_filing(
                recovery.clone(),
                &f.action,
                owner,
                &recovery_authority,
                b"recovery",
                &f.binding,
            )
            .unwrap_err();
        assert!(matches!(
            denied,
            HostFacadeError::Protocol(ProtocolError::Mismatch("fixture recovery revoked"))
        ));
        assert_eq!(
            f.facade.kernel().store().chain_head(&instance).unwrap(),
            before
        );
        recovery_authority.deny_publication = false;
        if matches!(scenario, "absent" | "disputed") {
            use whipplescript_store::effect_recovery::{DispositionEvidence, EvidenceDisposition};
            let events = f.facade.kernel().store().list_events(&instance).unwrap();
            let start = events
                .iter()
                .find(|event| event.event_type == "effect.run_started")
                .unwrap();
            let payload: Value = serde_json::from_str(&start.payload_json).unwrap();
            let marker: whipplescript_store::effect_recovery::DispatchMarker =
                serde_json::from_value(payload["external_dispatch"].clone()).unwrap();
            // Seed retained, authenticated investigation outcomes. A disputed
            // fold with Applied first independently exercises its dispute bit.
            let outcomes = if scenario == "disputed" {
                vec![
                    EvidenceDisposition::Applied,
                    EvidenceDisposition::NotApplied,
                ]
            } else {
                vec![EvidenceDisposition::NotApplied]
            };
            for disposition in outcomes {
                let evidence = DispositionEvidence {
                    frame: marker.frame.clone(),
                    disposition,
                    evidence_ref: format!("investigation:{disposition:?}"),
                    evidence_digest: "retained-investigation-digest".into(),
                    authority_ref: "person:investigator".into(),
                };
                f.facade
                    .kernel_mut()
                    .store_mut()
                    .append_event(whipplescript_store::NewEvent {
                        instance_id: &instance,
                        event_type: "effect.disposition.recorded",
                        payload_json: &serde_json::to_string(&evidence).unwrap(),
                        source: "kernel",
                        causation_id: Some(&recovery.run_id),
                        correlation_id: None,
                        idempotency_key: None,
                    })
                    .unwrap();
            }
            let before = f.facade.kernel().store().chain_head(&instance).unwrap();
            recovery_authority.checks.set(0);
            let error = f
                .facade
                .recover_tracker_filing(
                    recovery.clone(),
                    &f.action,
                    owner,
                    &recovery_authority,
                    b"recovery",
                    &f.binding,
                )
                .unwrap_err();
            assert!(matches!(
                error,
                HostFacadeError::Protocol(ProtocolError::Mismatch(
                    "tracker recovery disputed target evidence"
                ))
            ));
            assert_eq!(recovery_authority.checks.get(), 0);
            assert_eq!(
                f.facade.kernel().store().chain_head(&instance).unwrap(),
                before
            );
            assert_eq!(
                f.facade
                    .kernel()
                    .store()
                    .filing_receipt(&operation)
                    .unwrap(),
                Some(receipt)
            );
            assert!(!f
                .facade
                .kernel()
                .store()
                .list_facts(&instance)
                .unwrap()
                .iter()
                .any(|fact| fact.name == "tracker.file.completed"));
            drop(f);
            std::fs::remove_dir_all(root).unwrap();
            continue;
        }
        let delivered = f
            .facade
            .recover_tracker_filing(
                recovery.clone(),
                &f.action,
                owner,
                &recovery_authority,
                b"recovery",
                &f.binding,
            )
            .unwrap();
        assert_eq!(
            f.facade.kernel().store().list_runs(&instance).unwrap()[0].status,
            if expire { "lease_expired" } else { "completed" }
        );
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .filing_receipt(&operation)
                .unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .list_items(None, None)
                .unwrap()
                .len(),
            1
        );
        let events = f.facade.kernel().store().list_events(&instance).unwrap();
        let result_read = crate::host_protocol::action_result::ReadActionResult {
            protocol: crate::host_protocol::action_result::ACTION_RESULT_PROTOCOL.into(),
            issuer: recovery.issuer.clone(),
            scope: recovery.scope.clone(),
            policy: recovery.policy.clone(),
            provenance: recovery.provenance.clone(),
            admission: recovery.admission.clone(),
            evidence_handle: "result".into(),
            evidence_label_ref: "label:member".into(),
            through: None,
        };
        assert!(matches!(
            f.facade
                .read_action_result(result_read.clone(), &recovery_authority, b"forged"),
            Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
                "fixture recovered result read"
            )))
        ));
        let snapshot = f
            .facade
            .read_action_result(result_read, &recovery_authority, b"result read")
            .unwrap();
        let effect = snapshot
            .effects
            .iter()
            .find(|effect| effect.effect_id == recovery.effect_id)
            .unwrap();
        assert_eq!(effect.attempts.len(), 1);
        let attempt = &effect.attempts[0];
        assert_eq!(
            attempt.disposition,
            whipplescript_store::effect_recovery::ExternalDisposition::Applied
        );
        assert!(!attempt.disputed);
        assert_eq!(attempt.evidence.len(), 1);
        assert_eq!(attempt.evidence[0].evidence_ref, receipt.event_id);
        assert_eq!(
            attempt.evidence[0].evidence_digest,
            whipplescript_store::tracker_result::receipt_evidence_digest(&receipt)
        );
        assert_eq!(attempt.evidence[0].authority_ref, recovery.issuer);
        let recorded: Value = serde_json::from_str(
            &events
                .iter()
                .find(|event| event.event_id == delivered.event_id)
                .unwrap()
                .payload_json,
        )
        .unwrap();
        assert_eq!(
            recorded["delivery"]["recovery"]["provenance"]["executor"],
            "agent:assistant"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "effect.run_started")
                .count(),
            1
        );
        f.facade
            .kernel_mut()
            .store_mut()
            .rebuild_projections(&instance)
            .unwrap();
        crate::rule_pass::step_instance_generic(
            f.facade.kernel_mut(),
            &instance,
            f.action.program(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .get_instance(&instance)
                .unwrap()
                .unwrap()
                .status,
            "completed"
        );
        // An acknowledged delivery stays retrievable after the ordinary
        // workflow finishes; this neither reopens it nor derives another fact.
        let after = f.facade.kernel().store().chain_head(&instance).unwrap();
        assert_eq!(
            f.facade
                .recover_tracker_filing(
                    recovery,
                    &f.action,
                    owner,
                    &recovery_authority,
                    b"recovery",
                    &f.binding
                )
                .unwrap(),
            delivered
        );
        assert_eq!(
            f.facade.kernel().store().chain_head(&instance).unwrap(),
            after
        );
        drop(f);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn tracker_recovery_authenticates_and_authorizes_before_unavailable_history() {
    let mut f = fixture("person:learner");
    let recovery = RecoverTrackerFiling {
        protocol: TRACKER_RECOVERY_PROTOCOL.into(),
        issuer: f.request.issuer.clone(),
        scope: f.request.scope.clone(),
        admission: f.request.admission.clone(),
        policy: f.facade.policy_ref().clone(),
        provenance: f.request.provenance.clone(),
        effect_id: f.request.effect_id.clone(),
        run_id: "not-yet-dispatched".into(),
    };
    let mut authority = RecoveryAuthority {
        request: recovery.clone(),
        original: f.original.clone(),
        binding: f.binding.clone(),
        observation: false,
        deny_publication: false,
        checks: Cell::new(0),
    };
    f.facade.kernel_mut().store_mut().runtime =
        whipplescript_store::SqliteStore::open_in_memory().unwrap();
    for case in ["issuer", "authentication", "observation", "history"] {
        let mut request = recovery.clone();
        let mut proof = b"recovery".as_slice();
        let expected = match case {
            "issuer" => {
                request.issuer = "different-authority".into();
                "tracker recovery signed authority and epoch"
            }
            "authentication" => {
                proof = b"forged";
                "fixture recovery authentication"
            }
            "observation" => "fixture recovery observation",
            "history" => {
                authority.observation = true;
                ""
            }
            _ => unreachable!(),
        };
        let error = f
            .facade
            .recover_tracker_filing(request, &f.action, 1, &authority, proof, &f.binding)
            .unwrap_err();
        if case != "history" {
            assert!(
                matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message))
                if message == expected),
                "{case}: {error:?}"
            );
        }
        assert_eq!(authority.checks.get(), 0);
    }
}

#[test]
fn tracker_result_wake_ignores_external_names_and_refuses_another_instance() {
    use whipplescript_store::tracker_result::{
        RecordedTrackerResult, TrackerResultDelivery, DELIVERY_EVENT,
    };
    let mut f = fixture("person:learner");
    let instance = f.request.admission.instance_ref.clone();
    let record = RecordedTrackerResult {
        delivery: TrackerResultDelivery {
            instance_id: "another-instance".into(),
            effect_id: f.request.effect_id.clone(),
            run_id: "another-run".into(),
            queue: f.binding.queue.clone(),
            title: "Another task".into(),
            filing_receipt: whipplescript_store::tracker_filing::TrackerFilingReceipt {
                operation_id: "another-operation".into(),
                fingerprint: "another-fingerprint".into(),
                item_id: "WS-1".into(),
                event_id: "another-event".into(),
            },
            fact_id: "another-fact".into(),
            recovery: json!({}),
        },
        consumed_failure_facts: vec![],
        complete_running_attempt: false,
    };
    let payload = serde_json::to_string(&record).unwrap();
    for source in ["external", "kernel"] {
        f.facade
            .kernel_mut()
            .store_mut()
            .append_event(whipplescript_store::NewEvent {
                instance_id: &instance,
                event_type: DELIVERY_EVENT,
                payload_json: &payload,
                source,
                causation_id: None,
                correlation_id: None,
                idempotency_key: None,
            })
            .unwrap();
        let outcome = crate::rule_pass::step_instance_generic(
            f.facade.kernel_mut(),
            &instance,
            f.action.program(),
            None,
            None,
        );
        if source == "external" {
            outcome.expect("an external event cannot manufacture a recovery wake");
        } else {
            assert!(matches!(outcome, Err(StoreError::Conflict(message))
                if message == "tracker result wake belongs to another instance"));
        }
    }
}

#[path = "wait_tests.rs"]
mod governed_wait;

#[path = "recovery_tests.rs"]
mod recovery_refusals;

#[path = "closure_tests.rs"]
mod governed_closure;
