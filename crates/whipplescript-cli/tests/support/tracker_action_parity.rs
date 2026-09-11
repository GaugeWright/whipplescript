//! Actual governed filing on native and deployed DO storage. Authentication is
//! a fixture; raw rule passes prepare/consume effects, not a product launch API.
use super::*;
use crate::host_action_contract_reports::record_tracker;
use whipplescript_kernel::{
    host_facade::{
        ActionInputResolver, HostFacadeError, TrackerExecutionAuthority, TrackerWaitAuthority,
    },
    host_protocol::{
        action::{ActionBasis, ActionResource, VerifiedActionAdmission},
        execution::{
            effect_observation_fingerprint, ActionExecutionVerifier, ExecuteActionEffect,
            ACTION_EXECUTION_PROTOCOL,
        },
        ResourceRef,
    },
    tracker_filing::{FilingDispatch, TrackerBinding},
};
use whipplescript_store::{
    tracker_filing::{TrackerFiling, TrackerFilings},
    ClaimableEffect,
};

const SOURCE: &str = r#"
workflow Tutorial(learner: Learner) -> string
class Learner { authority string }
tracker tutorials
rule begin when Learner as learner => {
  then task <- file issue into tutorials {
    title "Create a chat"
    body "PRIVATE_TASK_BODY"
    assigned_to learner.authority
  }
  complete result task.id
}
"#;

fn envelope() -> VerifiedEnvelope {
    let policy = json!({
        "parties": {"person:1": "Member", "agent:1": "Member"},
        "resources": {
            "input:learner": {"reader": "Member", "writer": "Member"},
            "fact:Learner": {"reader": "Member", "writer": "Member"},
            "tracker:1/tutorials": {"reader": "Member", "writer": "Member"},
            "result": {"reader": "Member", "writer": []},
            "error": {"reader": "Member", "writer": []}
        }, "bindings": {"tutorials": "tracker:1/tutorials"}
    });
    let signed = SignedEnvelope::from_external_signature_v2(
        &policy.to_string(),
        "fixture-signer",
        "fixture",
        "fixture-key",
        "fixture-attestation",
        7,
        "product",
    )
    .expect("sign tracker policy");
    VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &FixtureAuthority(vec![]))
        .expect("verify tracker policy")
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
            json!({"authority": "person:1"}),
        )])))
    }
}

struct Authority {
    request: ExecuteActionEffect,
    original: HostActionCommand,
    binding: TrackerBinding,
    allow: bool,
    report_filing: fn(&TrackerFiling),
}
impl ActionExecutionVerifier for Authority {
    fn authenticate(
        &self,
        request: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request == &self.request && bytes == request.signing_bytes()? && proof == b"execution" {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("tracker execution authentication"))
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
        _: &ExecuteActionEffect,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError> {
        if self.allow && binding == &self.binding {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("tracker observation denied"))
        }
    }
    fn authorize_filing(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerBinding,
        filing: &TrackerFiling,
    ) -> Result<(), ProtocolError> {
        assert_eq!(original, &self.original);
        assert_eq!(binding, &self.binding);
        assert_eq!(filing.actor, request.provenance.executor);
        assert_eq!(filing.assigned_to.as_deref(), Some("person:1"));
        assert_eq!(filing.queue, binding.queue);
        (self.report_filing)(filing);
        Ok(())
    }
}

struct Prepared<S: RuntimeStore> {
    facade: GovernedHostFacade<S>,
    action: CompiledHostAction,
    admission: whipplescript_kernel::host_protocol::action::ActionAdmissionReceipt,
    request: ExecuteActionEffect,
    binding: TrackerBinding,
    authority: Authority,
}

fn prepare<
    S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead + TrackerFilings,
>(
    store: S,
    actor: &str,
) -> Prepared<S> {
    prepare_source(store, actor, SOURCE)
}

fn prepare_source<
    S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead + TrackerFilings,
>(
    store: S,
    actor: &str,
    source: &str,
) -> Prepared<S> {
    prepare_source_with_custody(store, actor, source, &Custody)
}

fn prepare_source_with_custody<
    S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead + TrackerFilings,
>(
    store: S,
    actor: &str,
    source: &str,
    custody: &impl ActionInputResolver,
) -> Prepared<S> {
    let action = CompiledHostAction::compile_materialized_inputs("workflow.launch", source, None)
        .expect("compile tutorial filing");
    let mut facade = GovernedHostFacade::from_verified_store(store, 7, envelope())
        .expect("governed tracker facade");
    facade
        .kernel()
        .store()
        .register_package_manifest(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../std/manifests/tracker.json"
        )))
        .expect("register ordinary tracker package");
    let binding = TrackerBinding {
        scope: "workspace:1".into(),
        queue: "tutorials".into(),
        resource: ActionResource {
            resource: ResourceRef {
                handle: "tracker:1/tutorials".into(),
                kind: "tracker".into(),
                selector: Some("tutorials".into()),
                writable: Some(true),
            },
            basis: ActionBasis::Version {
                version_ref: "tracker-incarnation:1".into(),
            },
            label_ref: "label:member".into(),
        },
    };
    let original = HostActionCommand {
        protocol: HOST_ACTION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: binding.scope.clone(),
        request_id: format!("tutorial:{actor}"),
        operation: "workflow.launch".into(),
        program_version_ref: action.version_ref().into(),
        input_schema_ref: action.input_schema_ref().into(),
        policy: facade.policy_ref().clone(),
        provenance: ActionProvenance {
            initiator: actor.into(),
            executor: actor.into(),
            delegation: vec![],
            origin: "folder.whip".into(),
            causes: vec![],
        },
        inputs: BTreeMap::from([(
            "learner".into(),
            ActionInput {
                handle: "input:learner".into(),
                version_ref: "immutable:learner".into(),
                label_ref: "label:member".into(),
            },
        )]),
        resources: BTreeMap::from([("tutorials".into(), binding.resource.clone())]),
    };
    let admission = facade
        .admit_action_with_inputs(
            original.clone(),
            &action,
            &FixtureAuthority(original.signing_bytes().expect("admission bytes")),
            b"fixture-admission",
            custody,
        )
        .expect("admit ordinary workflow");
    whipplescript_kernel::rule_pass::step_instance_generic(
        facade.kernel_mut(),
        &admission.instance_ref,
        action.program(),
        None,
        None,
    )
    .expect("queue filing");
    let effects = facade
        .kernel()
        .claimable_effects(&admission.instance_ref)
        .expect("observe effect");
    assert_eq!(effects.len(), 1);
    let request = ExecuteActionEffect {
        protocol: ACTION_EXECUTION_PROTOCOL.into(),
        issuer: original.issuer.clone(),
        scope: original.scope.clone(),
        admission: admission.clone(),
        policy: facade.policy_ref().clone(),
        provenance: original.provenance.clone(),
        effect_id: effects[0].effect_id.clone(),
        effect_fingerprint: effect_observation_fingerprint(&effects[0])
            .expect("effect fingerprint"),
    };
    let authority = Authority {
        request: request.clone(),
        original,
        binding: binding.clone(),
        allow: false,
        report_filing: |filing| {
            record_tracker::<S, _>(&format!("{}/file", filing.actor), "TrackerFiling", filing)
        },
    };
    Prepared {
        facade,
        action,
        admission,
        request,
        binding,
        authority,
    }
}

impl TrackerWaitAuthority for Authority {
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError> {
        TrackerExecutionAuthority::authorize_observation(self, request, binding)
    }
    fn authorize_wait(
        &self,
        _: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerBinding,
        input: &Value,
    ) -> Result<(), ProtocolError> {
        assert_eq!(original, &self.original);
        assert_eq!(binding, &self.binding);
        assert_eq!(input["arguments"]["arg0"]["queue"], binding.queue);
        Ok(())
    }
}

fn journey<
    S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead + TrackerFilings,
>(
    make: impl Fn() -> S,
    wait_for_closure: bool,
) -> Vec<Value> {
    let mut outcomes = Vec::new();
    for actor in ["person:1", "agent:1"] {
        let source = if wait_for_closure {
            format!("use std.tracker\n{}", SOURCE.replace("  complete result task.id",
                "  then closing <- call tracker.wait_closed for task timeout 30d\n  complete result closing.id"))
        } else {
            SOURCE.into()
        };
        let Prepared {
            mut facade,
            action,
            admission,
            request,
            binding,
            mut authority,
        } = prepare_source(make(), actor, &source);
        let before = facade
            .kernel()
            .store()
            .chain_head(&admission.instance_ref)
            .expect("before denial");
        assert!(facade
            .execute_tracker_filing(request.clone(), &action, &authority, b"execution", &binding)
            .is_err());
        assert_eq!(
            facade
                .kernel()
                .store()
                .chain_head(&admission.instance_ref)
                .expect("after denial"),
            before
        );
        assert!(facade
            .kernel()
            .store()
            .list_items(None, None)
            .expect("no unauthorized target")
            .is_empty());
        authority.allow = true;
        assert!(facade
            .execute_tracker_filing(request.clone(), &action, &authority, b"forged", &binding)
            .is_err());
        let terminal = facade
            .execute_tracker_filing(request.clone(), &action, &authority, b"execution", &binding)
            .expect("governed filing");
        let prefix = facade
            .kernel()
            .store()
            .chain_prefix(&admission.instance_ref)
            .expect("committed prefix");
        let started = prefix
            .iter()
            .find(|event| event.event_type == "effect.run_started")
            .expect("dispatch");
        let payload: Value = serde_json::from_str(&started.payload_json).expect("dispatch payload");
        let dispatch: FilingDispatch =
            serde_json::from_value(payload["metadata"]["tracker_filing"].clone())
                .expect("retained filing coordinates");
        assert!(!serde_json::to_string(&dispatch)
            .expect("dispatch metadata")
            .contains("PRIVATE_TASK_BODY"));
        assert_eq!(
            payload["metadata"]["action_execution"]["request"]["provenance"]["executor"],
            actor
        );
        let receipt = facade
            .kernel()
            .store()
            .filing_receipt(&dispatch.operation_id)
            .expect("committed receipt")
            .expect("receipt exists");
        assert_eq!(receipt.fingerprint, dispatch.fingerprint);
        let scenario = format!("{actor}/file");
        record_tracker::<S, _>(&scenario, "HostActionCommand", &authority.original);
        record_tracker::<S, _>(&scenario, "ActionAdmissionReceipt", &admission);
        record_tracker::<S, _>(&scenario, "ExecuteActionEffect", &request);
        record_tracker::<S, _>(&scenario, "TrackerBinding", &binding);
        record_tracker::<S, _>(&scenario, "FilingDispatch", &dispatch);
        record_tracker::<S, _>(&scenario, "TrackerFilingReceipt", &receipt);
        assert!(prefix.iter().any(|event| event.event_type == "fact.derived"
            && event.causation_id.as_deref() == Some(terminal.event_id.as_str())));

        // Reconstruct the embedding and rebuild only runtime projections. The
        // target receipt is independent and must not be re-created by replay.
        facade = GovernedHostFacade::from_verified_store(
            facade.into_kernel().into_store(),
            7,
            envelope(),
        )
        .expect("restart embedding");
        facade
            .kernel_mut()
            .store_mut()
            .rebuild_projections(&admission.instance_ref)
            .expect("rebuild runtime");
        assert!(facade
            .execute_tracker_filing(request, &action, &authority, b"execution", &binding)
            .is_err());
        assert_eq!(
            facade
                .kernel()
                .store()
                .filing_receipt(&dispatch.operation_id)
                .expect("retained receipt"),
            Some(receipt.clone())
        );
        let items = facade
            .kernel()
            .store()
            .list_items(None, None)
            .expect("one original issue");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, receipt.item_id);
        assert_eq!(items[0].filed_by.as_deref(), Some(actor));
        assert_eq!(items[0].assigned_to.as_deref(), Some("person:1"));
        assert_eq!(items[0].body, "PRIVATE_TASK_BODY");
        let facts = facade
            .kernel()
            .store()
            .list_facts(&admission.instance_ref)
            .expect("replayed continuation");
        let completed = facts
            .iter()
            .filter(|fact| fact.name == "tracker.file.completed")
            .collect::<Vec<_>>();
        assert_eq!(completed.len(), 1);
        let value: Value =
            serde_json::from_str(&completed[0].value_json).expect("completed outcome");
        assert_eq!(
            value["value"],
            json!({"queue": "tutorials", "id": receipt.item_id, "title": "Create a chat"})
        );
        whipplescript_kernel::rule_pass::step_instance_generic(
            facade.kernel_mut(),
            &admission.instance_ref,
            action.program(),
            None,
            None,
        )
        .expect("ordinary continuation");
        if wait_for_closure {
            assert!(facade
                .kernel()
                .claimable_effects(&admission.instance_ref)
                .expect("pending closure")
                .is_empty());
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .list_runs(&admission.instance_ref)
                    .expect("pending runs")
                    .len(),
                1
            );
            facade
                .kernel_mut()
                .store_mut()
                .finish_item(&receipt.item_id, Some("Self-reported"), None)
                .expect("close fixture task");
            // The target closing survives reconstruction before it is projected
            // into the waiting workflow. This fixture grants no product close API.
            facade = GovernedHostFacade::from_verified_store(
                facade.into_kernel().into_store(),
                7,
                envelope(),
            )
            .expect("restart before closure delivery");
            let timed_before = facade
                .kernel()
                .store()
                .pending_time_effects(&admission.instance_ref)
                .expect("retained wait deadline");
            assert_eq!(timed_before.len(), 1);
            assert_eq!(timed_before[0].timeout_seconds, 30 * 24 * 60 * 60);
            facade
                .kernel_mut()
                .store_mut()
                .rebuild_projections(&admission.instance_ref)
                .expect("replay pending wait");
            let timed_after = facade
                .kernel()
                .store()
                .pending_time_effects(&admission.instance_ref)
                .expect("replayed wait deadline");
            assert_eq!(timed_after.len(), 1);
            assert_eq!(timed_after[0].effect_id, timed_before[0].effect_id);
            assert_eq!(
                timed_after[0].timeout_seconds,
                timed_before[0].timeout_seconds
            );
            whipplescript_kernel::rule_pass::step_instance_generic(
                facade.kernel_mut(),
                &admission.instance_ref,
                action.program(),
                None,
                None,
            )
            .expect("project closure");
            let effects = facade
                .kernel()
                .claimable_effects(&admission.instance_ref)
                .expect("ready wait");
            assert_eq!(effects.len(), 1);
            assert_eq!(effects[0].target.as_deref(), Some("tracker.wait_closed"));
            authority.request.effect_id = effects[0].effect_id.clone();
            authority.request.effect_fingerprint =
                effect_observation_fingerprint(&effects[0]).expect("wait fingerprint");
            let request = authority.request.clone();
            let before = facade
                .kernel()
                .store()
                .chain_head(&admission.instance_ref)
                .expect("before denied wait");
            authority.allow = false;
            assert!(facade
                .execute_tracker_wait(request.clone(), &action, &authority, b"execution", &binding)
                .is_err());
            authority.allow = true;
            assert!(facade
                .execute_tracker_wait(request.clone(), &action, &authority, b"forged", &binding)
                .is_err());
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .chain_head(&admission.instance_ref)
                    .expect("after denied wait"),
                before
            );
            facade
                .execute_tracker_wait(request.clone(), &action, &authority, b"execution", &binding)
                .expect("governed closure observation");
            let scenario = format!("{actor}/wait");
            record_tracker::<S, _>(&scenario, "ExecuteActionEffect", &request);
            record_tracker::<S, _>(&scenario, "TrackerBinding", &binding);
            let facts = facade
                .kernel()
                .store()
                .list_facts(&admission.instance_ref)
                .expect("wait outcome");
            let success = facts
                .iter()
                .find(|fact| fact.name == "capability.call.succeeded")
                .unwrap_or_else(|| panic!("ordinary capability success; facts: {facts:?}"));
            let value: Value = serde_json::from_str(&success.value_json).expect("closure result");
            assert_eq!(value["value"]["id"], receipt.item_id);
            let closing = facade
                .kernel()
                .store()
                .closings("tutorials")
                .expect("target closing");
            assert_eq!(closing.len(), 1);
            assert_eq!(value["value"]["event"], closing[0].event_id);
            facade
                .kernel_mut()
                .store_mut()
                .rebuild_projections(&admission.instance_ref)
                .expect("replay successful wait");
            assert!(facade
                .execute_tracker_wait(request, &action, &authority, b"execution", &binding)
                .is_err());
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .list_runs(&admission.instance_ref)
                    .expect("one filing and one wait")
                    .len(),
                2
            );
            whipplescript_kernel::rule_pass::step_instance_generic(
                facade.kernel_mut(),
                &admission.instance_ref,
                action.program(),
                None,
                None,
            )
            .expect("consume wait result");
        }
        let status = facade
            .kernel()
            .store()
            .get_instance(&admission.instance_ref)
            .expect("workflow status")
            .expect("workflow exists")
            .status;
        assert_eq!(status, "completed");
        outcomes.push(json!({"actor": actor, "assigned_to": items[0].assigned_to,
            "title": items[0].title, "body": items[0].body, "status": status}));
    }
    outcomes
}

#[test]
fn governed_tracker_human_and_agent_filing_matches_native_and_deployed_do_schema() {
    let native = journey(
        || NativeStores::open_in_memory().expect("native stores"),
        false,
    );
    let hosted = journey(
        || DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
        false,
    );
    assert_eq!(native, hosted);
}

#[test]
fn governed_tracker_wait_human_and_agent_matches_native_and_deployed_do_schema() {
    let native = journey(
        || NativeStores::open_in_memory().expect("native stores"),
        true,
    );
    let hosted = journey(
        || DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
        true,
    );
    assert_eq!(native, hosted);
}

impl whipplescript_kernel::host_facade::TrackerRecoveryAuthority for Authority {
    fn authenticate(
        &self,
        request: &whipplescript_kernel::host_protocol::tracker_recovery::RecoverTrackerFiling,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request.admission == self.request.admission
            && request.effect_id == self.request.effect_id
            && request.issuer == self.request.issuer
            && request.scope == self.request.scope
            && request.policy == self.request.policy
            && request.provenance == self.request.provenance
            && bytes == request.signing_bytes()?
            && proof == b"recover"
        {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("tracker recovery authentication"))
        }
    }

    fn authorize_observation(
        &self,
        request: &whipplescript_kernel::host_protocol::tracker_recovery::RecoverTrackerFiling,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError> {
        if self.allow && request.scope == self.binding.scope && binding == &self.binding {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch(
                "tracker recovery observation denied",
            ))
        }
    }

    fn authorize_recovery(
        &self,
        _: &whipplescript_kernel::host_protocol::tracker_recovery::RecoverTrackerFiling,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        dispatch: &FilingDispatch,
    ) -> Result<(), ProtocolError> {
        assert!(self.allow);
        assert_eq!(original, &self.original);
        assert_eq!(execution, &self.request);
        assert_eq!(dispatch.binding, self.binding);
        Ok(())
    }
}

type SettlementFault<S> = Box<dyn Fn(&S, bool)>;
struct RecoveryStore<S> {
    store: S,
    set_fault: SettlementFault<S>,
    scratch: Option<std::path::PathBuf>,
}

const TERMINAL_FAULT: &str = "CREATE TRIGGER tracker_recovery_fault AFTER INSERT ON events
    WHEN NEW.event_type = 'effect.terminal'
    BEGIN SELECT RAISE(ABORT, 'injected settlement failure'); END";
const CLEAR_TERMINAL_FAULT: &str = "DROP TRIGGER tracker_recovery_fault";

fn recovery_journey<S>(make: impl Fn() -> RecoveryStore<S>) -> Vec<Value>
where
    S: RuntimeStore
        + LogAppend
        + Coordination
        + WorkItems
        + FrontierRead
        + TrackerFilings
        + whipplescript_store::tracker_result::TrackerResultPublications,
{
    use whipplescript_kernel::host_protocol::tracker_recovery::{
        RecoverTrackerFiling, TRACKER_RECOVERY_PROTOCOL,
    };
    use whipplescript_store::effect_recovery::ExternalDisposition;
    let mut outcomes = vec![];
    for actor in ["person:1", "agent:1"] {
        for expired in [false, true] {
            let RecoveryStore {
                store,
                set_fault,
                scratch,
            } = make();
            let Prepared {
                mut facade,
                action,
                admission,
                request,
                binding,
                mut authority,
            } = prepare(store, actor);
            let instance = &admission.instance_ref;
            authority.allow = true;
            set_fault(facade.kernel().store(), true);
            assert!(facade
                .execute_tracker_filing(
                    request.clone(),
                    &action,
                    &authority,
                    b"execution",
                    &binding
                )
                .is_err());
            set_fault(facade.kernel().store(), false);
            let before = facade
                .kernel()
                .store()
                .list_events(instance)
                .expect("interrupted history");
            let started = before
                .iter()
                .find(|event| event.event_type == "effect.run_started")
                .expect("one original dispatch");
            let payload: Value =
                serde_json::from_str(&started.payload_json).expect("dispatch metadata");
            let dispatch: FilingDispatch =
                serde_json::from_value(payload["metadata"]["tracker_filing"].clone())
                    .expect("retained filing coordinates");
            let receipt = facade
                .kernel()
                .store()
                .filing_receipt(&dispatch.operation_id)
                .expect("target lookup")
                .expect("task was committed");
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .list_items(None, None)
                    .expect("committed task")
                    .len(),
                1
            );
            assert!(!facade
                .kernel()
                .store()
                .list_facts(instance)
                .expect("no published result")
                .iter()
                .any(|fact| fact.name == "tracker.file.completed"));
            facade = GovernedHostFacade::from_verified_store(
                facade.into_kernel().into_store(),
                7,
                envelope(),
            )
            .expect("reconstruct embedding");
            if expired {
                assert_eq!(
                    facade
                        .kernel_mut()
                        .expire_leases(instance, "2099-01-01T00:00:00Z")
                        .expect("expire original lease")
                        .len(),
                    1
                );
            }
            assert!(facade
                .execute_tracker_filing(
                    request.clone(),
                    &action,
                    &authority,
                    b"execution",
                    &binding
                )
                .is_err());
            let owner = facade
                .kernel_mut()
                .store_mut()
                .claim_instance_ownership(instance)
                .expect("own recovery");
            let run = facade
                .kernel()
                .store()
                .list_runs(instance)
                .expect("original run")[0]
                .run_id
                .clone();
            let recovery = RecoverTrackerFiling {
                protocol: TRACKER_RECOVERY_PROTOCOL.into(),
                issuer: request.issuer.clone(),
                scope: request.scope.clone(),
                admission: admission.clone(),
                policy: facade.policy_ref().clone(),
                provenance: request.provenance.clone(),
                effect_id: request.effect_id.clone(),
                run_id: run,
            };
            let head = facade
                .kernel()
                .store()
                .chain_head(instance)
                .expect("before denied recovery");
            assert!(matches!(
                facade.recover_tracker_filing(
                    recovery.clone(),
                    &action,
                    owner,
                    &authority,
                    b"forged",
                    &binding
                ),
                Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
                    "tracker recovery authentication"
                )))
            ));
            authority.allow = false;
            assert!(matches!(
                facade.recover_tracker_filing(
                    recovery.clone(),
                    &action,
                    owner,
                    &authority,
                    b"recover",
                    &binding
                ),
                Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
                    "tracker recovery observation denied"
                )))
            ));
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .chain_head(instance)
                    .expect("denials do not publish"),
                head
            );
            authority.allow = true;
            let delivered = facade
                .recover_tracker_filing(
                    recovery.clone(),
                    &action,
                    owner,
                    &authority,
                    b"recover",
                    &binding,
                )
                .expect("publish committed filing result");
            facade
                .kernel_mut()
                .store_mut()
                .rebuild_projections(instance)
                .expect("replay recovered result");
            let read = ReadActionResult {
                protocol: ACTION_RESULT_PROTOCOL.into(),
                issuer: request.issuer.clone(),
                scope: request.scope.clone(),
                policy: facade.policy_ref().clone(),
                provenance: request.provenance.clone(),
                admission: admission.clone(),
                evidence_handle: "result".into(),
                evidence_label_ref: "label:member".into(),
                through: None,
            };
            let snapshot = facade
                .read_action_result(
                    read.clone(),
                    &FixtureAuthority(read.signing_bytes().expect("result read bytes")),
                    b"fixture-read",
                )
                .expect("read standard action result");
            let scenario = format!(
                "{actor}/recover-file/{}",
                if expired { "expired" } else { "running" }
            );
            record_tracker::<S, _>(&scenario, "RecoverTrackerResult", &recovery);
            record_tracker::<S, _>(&scenario, "FilingDispatch", &dispatch);
            record_tracker::<S, _>(&scenario, "TrackerFilingReceipt", &receipt);
            record_tracker::<S, _>(&scenario, "ActionResultSnapshot", &snapshot);
            let attempt = &snapshot
                .effects
                .iter()
                .find(|effect| effect.effect_id == request.effect_id)
                .expect("original effect")
                .attempts[0];
            assert_eq!(attempt.disposition, ExternalDisposition::Applied);
            assert!(!attempt.disputed);
            assert_eq!(
                attempt.terminal_status.as_deref(),
                Some(if expired {
                    "lease_expired"
                } else {
                    "completed"
                })
            );
            assert_eq!(attempt.evidence.len(), 1);
            assert_eq!(attempt.evidence[0].evidence_ref, receipt.event_id);
            let items = facade
                .kernel()
                .store()
                .list_items(None, None)
                .expect("same original task");
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].filed_by.as_deref(), Some(actor));
            assert_eq!(items[0].assigned_to.as_deref(), Some("person:1"));
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .filing_receipt(&dispatch.operation_id)
                    .expect("unchanged receipt"),
                Some(receipt)
            );
            whipplescript_kernel::rule_pass::step_instance_generic(
                facade.kernel_mut(),
                instance,
                action.program(),
                None,
                None,
            )
            .expect("consume ordinary result");
            let status = facade
                .kernel()
                .store()
                .get_instance(instance)
                .expect("completed workflow")
                .expect("instance exists")
                .status;
            assert_eq!(status, "completed");
            let head = facade
                .kernel()
                .store()
                .chain_head(instance)
                .expect("completed history");
            assert_eq!(
                facade
                    .recover_tracker_filing(
                        recovery, &action, owner, &authority, b"recover", &binding
                    )
                    .expect("exact redelivery after completion"),
                delivered
            );
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .chain_head(instance)
                    .expect("no duplicate delivery"),
                head
            );
            let events = facade
                .kernel()
                .store()
                .list_events(instance)
                .expect("one dispatch");
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.event_type == "effect.run_started")
                    .count(),
                1
            );
            outcomes.push(json!({"actor": actor, "expired": expired, "assigned_to": items[0].assigned_to,
                "status": status, "disposition": attempt.disposition, "attempt_status": attempt.terminal_status}));
            drop(facade);
            if let Some(path) = scratch {
                std::fs::remove_dir_all(path).expect("remove native fixture stores");
            }
        }
    }
    outcomes
}

fn native_recovery_store() -> RecoveryStore<NativeStores> {
    let root = std::env::temp_dir().join(format!(
        "whip-tracker-parity-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("fixture time")
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).expect("create native fixture");
    let runtime = root.join("runtime.sqlite");
    let store = NativeStores::open(
        &runtime,
        root.join("coord.sqlite"),
        root.join("items.sqlite"),
    )
    .expect("native stores");
    RecoveryStore {
        store,
        set_fault: Box::new(move |_, armed| {
            rusqlite::Connection::open(&runtime)
                .expect("fault connection")
                .execute_batch(if armed {
                    TERMINAL_FAULT
                } else {
                    CLEAR_TERMINAL_FAULT
                })
                .expect("toggle native settlement fault");
        }),
        scratch: Some(root),
    }
}

fn hosted_recovery_store() -> RecoveryStore<DoSqliteStore<RusqliteDoSql>> {
    use whipplescript_host_do::do_store::DoSql;
    RecoveryStore {
        store: DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
        set_fault: Box::new(|store, armed| {
            store
                .sql
                .execute(
                    if armed {
                        TERMINAL_FAULT
                    } else {
                        CLEAR_TERMINAL_FAULT
                    },
                    &[],
                )
                .expect("toggle hosted settlement fault");
        }),
        scratch: None,
    }
}

#[test]
fn governed_tracker_recovery_matches_native_and_deployed_do_schema() {
    assert_eq!(
        recovery_journey(native_recovery_store),
        recovery_journey(hosted_recovery_store)
    );
}

#[path = "tracker_closure_parity.rs"]
mod closure_parity;
