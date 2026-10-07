//! The governed external-effect door (HA-4) on both runtime stores: an
//! admitted action's `emit signal` reaches another instance only through
//! `execute_action_signal_effect`, with current authority and the exact
//! observation, and the delivered run records the executing principal and
//! delegation. Raw dispatch and the ordinary handler are refused before any
//! delivery.
use super::*;
use whipplescript_kernel::effect_handlers::{run_notify_effect_generic, DeliveryGovernance};
use whipplescript_kernel::host_facade::SignalDeliveryAuthority;

const SIGNAL_SOURCE: &str = r#"workflow AdmittedSignal
input content InputReference
output result Sent
failure error SendFailed
signal task.done { status string }
class InputReference { handle string version_ref string label_ref string }
class Sent { status string }
class SendFailed { reason string }
rule send
  when InputReference as reference
=> {
  emit signal task.done to reference.version_ref { status "ok" } as sent
  after sent succeeds as delivered {
    complete result { status "sent" }
  }
  after sent fails as failed {
    fail error { reason failed.reason }
  }
}
"#;

struct SignalAuthority {
    signed: Vec<u8>,
    revoked: Cell<bool>,
    target: String,
}
impl ActionExecutionVerifier for SignalAuthority {
    fn authenticate(
        &self,
        _: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if bytes != self.signed || proof != b"execution" || self.revoked.get() {
            return Err(ProtocolError::Mismatch("fixture execution authentication"));
        }
        Ok(())
    }
    fn authorize(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
    ) -> Result<(), ProtocolError> {
        if self.revoked.get()
            || request.provenance.initiator != original.provenance.initiator
            || effect.kind != "signal.emit"
        {
            return Err(ProtocolError::Mismatch("fixture current execution ceiling"));
        }
        Ok(())
    }
}
/// The file journey's authority, so it can prove the signal door refuses a
/// file effect on its own terms rather than on authentication.
impl SignalDeliveryAuthority for FixtureAuthority {
    fn authorize_delivery(
        &self,
        _: &ExecuteActionEffect,
        _: &HostActionCommand,
        _: &str,
        _: &str,
    ) -> Result<(), ProtocolError> {
        Ok(())
    }
}
impl SignalDeliveryAuthority for SignalAuthority {
    fn authorize_delivery(
        &self,
        _: &ExecuteActionEffect,
        _: &HostActionCommand,
        target_instance: &str,
        signal: &str,
    ) -> Result<(), ProtocolError> {
        if target_instance != self.target || signal != "task.done" {
            return Err(ProtocolError::Mismatch("fixture delivery target"));
        }
        Ok(())
    }
}
fn signal_authority(bytes: Vec<u8>, target: &str) -> SignalAuthority {
    SignalAuthority {
        signed: bytes,
        revoked: Cell::new(false),
        target: target.into(),
    }
}

pub(super) struct OpenDelivery;
impl DeliveryGovernance for OpenDelivery {
    fn any_internal_workflow(&self, _: &[String]) -> Result<bool, String> {
        Ok(false)
    }
}

fn register_signal_capability<S: RuntimeStore>(store: &S) {
    store
        .register_capability_schema(whipplescript_store::CapabilitySchemaRegistration {
            capability: "signal.emit",
            description: "signal execution fixture",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .expect("register signal capability");
    store
        .bind_capability(whipplescript_store::CapabilityBinding {
            binding_id: "signal.emit",
            program_id: None,
            capability: "signal.emit",
            provider: "notify",
            config_json: "{}",
        })
        .expect("bind signal capability");
    store
        .register_effect_provider(whipplescript_store::EffectProviderRegistration {
            provider_id: "signal.emit",
            effect_kind: "signal.emit",
            provider: "notify",
            capability: "signal.emit",
            config_json: "{}",
            registered_by_package_id: None,
        })
        .expect("register signal provider");
}

fn delivered<S: RuntimeStore>(store: &S, target: &str) -> usize {
    store
        .list_facts(target)
        .expect("target facts")
        .iter()
        .filter(|fact| fact.name == "task.done")
        .count()
}

fn signal_journey<S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead>(
    mut store: S,
    actor: &str,
) -> Value {
    register_signal_capability(&store);
    let version = whipplescript_store::host_actions::conformance::register(&mut store);
    let target = store
        .create_instance(whipplescript_store::NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("target instance")
        .instance_id;
    // The admitted input names the delivery target; the door still asks the
    // host to authorize that exact target before delivery.
    let action = CompiledHostAction::compile("signal.send", SIGNAL_SOURCE, None)
        .expect("compiled signal action");
    let mut facade = GovernedHostFacade::from_verified_store(store, 7, envelope(7))
        .expect("admission facade")
        .with_embedded_std_manifests(whipplescript_host_do::do_packages::EMBEDDED_STD_MANIFESTS)
        .with_compiler_artifact_digest(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        );
    let command = HostActionCommand {
        anchor: None,
        protocol: HOST_ACTION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace:1".into(),
        request_id: format!("signal:{actor}"),
        operation: "signal.send".into(),
        program_version_ref: action.version_ref().into(),
        input_schema_ref: action.input_schema_ref().into(),
        policy: facade.policy_ref().clone(),
        provenance: ActionProvenance {
            initiator: actor.into(),
            executor: actor.into(),
            delegation: vec![],
            origin: "fixture.signal".into(),
            causes: vec![],
        },
        inputs: BTreeMap::from([(
            "content".into(),
            ActionInput {
                handle: "admitted_input".into(),
                version_ref: target.clone(),
                label_ref: "private".into(),
            },
        )]),
        resources: BTreeMap::new(),
    };
    let admission = facade
        .admit_action(
            command.clone(),
            &action,
            &authority(command.signing_bytes().expect("admission bytes")),
            b"admission",
        )
        .expect("admit signal action");
    let mut facade =
        GovernedHostFacade::from_verified_store(facade.into_kernel().into_store(), 8, envelope(8))
            .expect("renewed facade");
    let instance = admission.instance_ref.clone();
    whipplescript_kernel::rule_pass::step_instance_generic(
        facade.kernel_mut(),
        &instance,
        action.program(),
        None,
        None,
    )
    .expect("ordinary rule pass");
    let mut effects = facade
        .kernel()
        .claimable_effects(&instance)
        .expect("claimable effects");
    assert_eq!(effects.len(), 1, "exactly the signal is queued");
    let effect = effects.remove(0);
    assert_eq!(effect.kind, "signal.emit");
    let before = facade
        .kernel()
        .store()
        .list_events(&instance)
        .expect("before dispatch");

    let run = RunStart {
        instance_id: &instance,
        effect_id: &effect.effect_id,
        run_id: "forged-run",
        provider: "notify",
        worker_id: "fixture",
        lease_id: "forged-lease",
        lease_expires_at: "2030-01-01T00:00:00Z",
        metadata_json: r#"{"action_execution":{"verified":true}}"#,
    };
    assert!(facade.kernel_mut().start_run(run).is_err());
    assert!(facade.kernel_mut().start_dispatch(run).is_err());
    assert!(facade
        .kernel_mut()
        .start_dispatch_observed(run, &effect)
        .is_err());
    // The ordinary handler is no bypass: without the facade's grant, its own
    // fresh dispatch refuses the action instance before any delivery.
    let bypass = run_notify_effect_generic(facade.kernel_mut(), &instance, &effect, &OpenDelivery)
        .expect_err("the ordinary handler cannot deliver an admitted action's signal");
    assert!(
        format!("{bypass:?}")
            .contains("action dispatch requires fresh verified execution authority"),
        "{bypass:?}"
    );

    let request = ExecuteActionEffect {
        protocol: ACTION_EXECUTION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace:1".into(),
        admission: admission.clone(),
        policy: PolicyEpochRef::from_verified(8, &envelope(8)).expect("current policy"),
        provenance: ActionProvenance {
            initiator: actor.into(),
            executor: "worker:current".into(),
            delegation: vec![ActionDelegation {
                grant_ref: "current-grant".into(),
                delegator: actor.into(),
                delegate: "worker:current".into(),
            }],
            origin: "fixture.resume".into(),
            causes: vec![],
        },
        effect_id: effect.effect_id.clone(),
        effect_fingerprint: effect_observation_fingerprint(&effect).expect("effect observation"),
    };
    let verifier = signal_authority(request.signing_bytes().expect("execution bytes"), &target);
    assert!(
        facade
            .execute_action_signal_effect(
                request.clone(),
                &action,
                &verifier,
                b"admission",
                &OpenDelivery
            )
            .is_err(),
        "admission proof is not execution proof"
    );
    verifier.revoked.set(true);
    assert!(
        facade
            .execute_action_signal_effect(
                request.clone(),
                &action,
                &verifier,
                b"execution",
                &OpenDelivery
            )
            .is_err(),
        "current revocation prevents delivery"
    );
    verifier.revoked.set(false);
    let elsewhere = signal_authority(request.signing_bytes().expect("execution bytes"), "other");
    let error = facade
        .execute_action_signal_effect(
            request.clone(),
            &action,
            &elsewhere,
            b"execution",
            &OpenDelivery,
        )
        .expect_err("an unauthorized target refuses");
    assert!(
        error.to_string().contains("fixture delivery target"),
        "{error}"
    );
    for changed in ["fingerprint", "admission", "principal"] {
        let mut bad = request.clone();
        match changed {
            "fingerprint" => bad.effect_fingerprint = "other-input".into(),
            "admission" => bad.admission.admitted_at.head_digest = "other-prefix".into(),
            "principal" => {
                bad.provenance.initiator = "other-principal".into();
                bad.provenance.delegation[0].delegator = "other-principal".into();
            }
            _ => unreachable!(),
        }
        let signed = signal_authority(bad.signing_bytes().expect("changed bytes"), &target);
        assert!(
            facade
                .execute_action_signal_effect(bad, &action, &signed, b"execution", &OpenDelivery)
                .is_err(),
            "changed {changed} must refuse"
        );
    }
    // The file door does not execute other families.
    let file_verifier = authority(request.signing_bytes().expect("execution bytes"));
    assert!(facade
        .execute_action_file_effect(
            request.clone(),
            &action,
            &file_verifier,
            b"execution",
            &NoFiles
        )
        .is_err());
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(&instance)
            .expect("after refusals"),
        before,
        "no refused call reaches the history"
    );
    assert_eq!(delivered(facade.kernel().store(), &target), 0);

    facade
        .execute_action_signal_effect(
            request.clone(),
            &action,
            &verifier,
            b"execution",
            &OpenDelivery,
        )
        .expect("currently authorized delivery");
    assert_eq!(delivered(facade.kernel().store(), &target), 1);
    let events = facade
        .kernel()
        .store()
        .list_events(&instance)
        .expect("execution history");
    let started: Vec<Value> = events
        .iter()
        .filter(|event| event.event_type == "effect.run_started")
        .map(|event| serde_json::from_str(&event.payload_json).expect("run payload"))
        .collect();
    assert_eq!(started.len(), 1);
    assert_eq!(
        started[0]["metadata"]["action_execution"]["request"],
        serde_json::to_value(&request).expect("execution record"),
        "the run records the executing principal, delegation and observation"
    );
    assert_eq!(
        started[0]["external_dispatch"]["frame"]["action_admission"]["fingerprint"],
        command
            .fingerprint()
            .expect("original authorship fingerprint")
    );
    assert!(
        facade
            .execute_action_signal_effect(
                request.clone(),
                &action,
                &verifier,
                b"execution",
                &OpenDelivery
            )
            .is_err(),
        "a delivered signal is not redispatched"
    );
    assert_eq!(delivered(facade.kernel().store(), &target), 1);
    whipplescript_kernel::rule_pass::step_instance_generic(
        facade.kernel_mut(),
        &instance,
        action.program(),
        None,
        None,
    )
    .expect("continuation pass");
    let status = facade
        .kernel()
        .store()
        .get_instance(&instance)
        .expect("instance")
        .expect("existing instance")
        .status;
    json!({"status": status, "delivered": delivered(facade.kernel().store(), &target), "attempts": started.len()})
}

/// A file binding that must never be touched by a signal execution.
struct NoFiles;
impl FileStore for NoFiles {
    fn read_to_string(&self, _: &Path) -> io::Result<String> {
        panic!("signal execution read a file")
    }
    fn exists(&self, _: &Path) -> bool {
        false
    }
    fn create_dir_all(&self, _: &Path) -> io::Result<()> {
        panic!("signal execution created a directory")
    }
    fn write(&self, _: &Path, _: &[u8]) -> io::Result<()> {
        panic!("signal execution wrote a file")
    }
    fn append(&self, _: &Path, _: &[u8]) -> io::Result<()> {
        panic!("signal execution appended a file")
    }
    fn remove(&self, _: &Path) -> io::Result<()> {
        panic!("signal execution removed a file")
    }
}

#[test]
fn admitted_signal_delivery_has_current_authority_on_both_hosts() {
    for actor in ["person:one", "agent:one"] {
        let native = signal_journey(NativeStores::open_in_memory().expect("native store"), actor);
        let hosted = signal_journey(
            DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
            actor,
        );
        assert_eq!(native, hosted);
        assert_eq!(
            native,
            json!({"status": "completed", "delivered": 1, "attempts": 1})
        );
    }
}
