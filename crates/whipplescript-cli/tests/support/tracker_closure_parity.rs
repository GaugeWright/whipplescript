//! One ordinary finish workflow through both actual storage embeddings. These
//! authorities and raw rule passes are fixtures, not production launch proof.
use super::*;
use whipplescript_kernel::{
    host_facade::TrackerClosureAuthority,
    tracker_closure::{closing_operation_id, TrackerClosureBinding},
};
use whipplescript_store::tracker_closure::{TrackerClosure, TrackerClosures};

const CLOSE_SOURCE: &str = r#"
workflow CompleteTask(learner: Learner) -> bool
class Learner { authority string queue string id string }
tracker tutorials
rule begin when Learner as learner => {
  then closed <- finish learner { summary "Self-reported completion" }
  complete result true
}
"#;

struct CloseCustody {
    id: String,
}
impl ActionInputResolver for CloseCustody {
    fn with_inputs<T>(
        &self,
        _: &VerifiedActionAdmission,
        consume: impl FnOnce(BTreeMap<String, Value>) -> T,
    ) -> Result<T, HostFacadeError> {
        Ok(consume(BTreeMap::from([(
            "learner".into(),
            json!({
                "authority": "person:1", "queue": "tutorials", "id": self.id
            }),
        )])))
    }
}

struct CloseAuthority {
    execution: Authority,
    binding: TrackerClosureBinding,
    close: bool,
    report_closure: fn(&TrackerClosure),
}
impl ActionExecutionVerifier for CloseAuthority {
    fn authenticate(
        &self,
        request: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        self.execution.authenticate(request, bytes, proof)
    }
    fn authorize(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
    ) -> Result<(), ProtocolError> {
        self.execution.authorize(request, original, effect)
    }
}
impl TrackerClosureAuthority for CloseAuthority {
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerClosureBinding,
    ) -> Result<(), ProtocolError> {
        assert_eq!(binding, &self.binding);
        TrackerExecutionAuthority::authorize_observation(&self.execution, request, &binding.tracker)
    }
    fn authorize_closure(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerClosureBinding,
        closure: &TrackerClosure,
    ) -> Result<(), ProtocolError> {
        assert_eq!(original, &self.execution.original);
        assert_eq!(binding, &self.binding);
        assert_eq!(closure.actor, request.provenance.executor);
        assert_eq!(closure.subject_id, binding.subject_id);
        assert_eq!(closure.expected_holder, binding.expected_holder);
        if self.close {
            (self.report_closure)(closure);
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture tracker closure denied"))
        }
    }
}

fn prepare_closing<
    S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead + TrackerFilings,
>(
    mut store: S,
    actor: &str,
) -> (Prepared<S>, TrackerClosureBinding) {
    let task = store
        .file_item(
            "tutorials",
            "Create a chat",
            "PRIVATE_TASK_BODY",
            &[],
            &json!({}),
            Some("person:author"),
            Some("person:1"),
        )
        .expect("existing assigned task");
    store
        .claim_item(&task.id, "workflow:holder", None)
        .expect("independent claim");
    let subject_id = store
        .subject_content_id(&task.id)
        .expect("resolve task")
        .expect("permanent subject");
    let Prepared {
        facade,
        action,
        admission,
        request,
        binding: tracker,
        authority: execution,
    } = prepare_source_with_custody(
        store,
        actor,
        CLOSE_SOURCE,
        &CloseCustody {
            id: task.id.clone(),
        },
    );
    let binding = TrackerClosureBinding {
        tracker,
        item_id: task.id.clone(),
        subject_id,
        expected_holder: Some("workflow:holder".into()),
    };
    let prepared = Prepared {
        facade,
        action,
        admission,
        request,
        binding: binding.tracker.clone(),
        authority: execution,
    };
    (prepared, binding)
}

fn closure_journey<
    S: RuntimeStore
        + LogAppend
        + Coordination
        + WorkItems
        + FrontierRead
        + TrackerFilings
        + TrackerClosures,
>(
    open: impl Fn() -> S,
    reopen: impl Fn(&mut S, &str),
) -> Vec<Value> {
    let mut outcomes = Vec::new();
    for actor in ["person:1", "agent:1"] {
        let (
            Prepared {
                mut facade,
                action,
                admission,
                request,
                authority: execution,
                ..
            },
            binding,
        ) = prepare_closing(open(), actor);
        let task_id = binding.item_id.clone();
        let mut authority = CloseAuthority {
            execution,
            binding: binding.clone(),
            close: false,
            report_closure: |closure| {
                record_tracker::<S, _>(
                    &format!("{}/close", closure.actor),
                    "TrackerClosure",
                    closure,
                )
            },
        };
        let before = facade
            .kernel()
            .store()
            .chain_head(&admission.instance_ref)
            .expect("initial history");
        let tracker_before = facade
            .kernel()
            .store()
            .event_position()
            .expect("initial tracker history");
        for case in ["authentication", "observation", "closure"] {
            authority.execution.allow = case != "observation";
            let proof = if case == "authentication" {
                b"forged".as_slice()
            } else {
                b"execution".as_slice()
            };
            let error = facade
                .execute_tracker_closure(request.clone(), &action, &authority, proof, &binding)
                .expect_err("denied closure");
            let expected = match case {
                "authentication" => "tracker execution authentication",
                "observation" => "tracker observation denied",
                _ => "fixture tracker closure denied",
            };
            assert!(
                matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message)) if message == expected),
                "{case}: {error:?}"
            );
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .chain_head(&admission.instance_ref)
                    .expect("unchanged history"),
                before
            );
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .event_position()
                    .expect("unchanged tracker"),
                tracker_before
            );
        }
        authority.close = true;
        facade
            .execute_tracker_closure(request.clone(), &action, &authority, b"execution", &binding)
            .expect("governed finish");
        let operation = closing_operation_id(&admission.instance_ref, &request.effect_id);
        let receipt = facade
            .kernel()
            .store()
            .closing_receipt(&operation)
            .expect("committed receipt")
            .expect("closing exists");
        assert_eq!(receipt.actor, actor);
        assert_eq!(receipt.subject_id, binding.subject_id);
        let events = facade
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .expect("closing dispatch history");
        let payload: Value = serde_json::from_str(
            &events
                .iter()
                .find(|event| event.event_type == "effect.run_started")
                .expect("original closing dispatch")
                .payload_json,
        )
        .expect("dispatch payload");
        let dispatch: whipplescript_kernel::tracker_closure::ClosureDispatch =
            serde_json::from_value(payload["metadata"]["tracker_closure"].clone())
                .expect("retained closing dispatch");
        let scenario = format!("{actor}/close");
        record_tracker::<S, _>(
            &scenario,
            "HostActionCommand",
            &authority.execution.original,
        );
        record_tracker::<S, _>(&scenario, "ActionAdmissionReceipt", &admission);
        record_tracker::<S, _>(&scenario, "ExecuteActionEffect", &request);
        record_tracker::<S, _>(&scenario, "TrackerClosureBinding", &binding);
        record_tracker::<S, _>(&scenario, "ClosureDispatch", &dispatch);
        record_tracker::<S, _>(&scenario, "TrackerClosureReceipt", &receipt);
        let item = facade
            .kernel()
            .store()
            .get_item(&task_id)
            .expect("completed task")
            .expect("task exists");
        assert_eq!(item.status, "closed");
        assert_eq!(item.assigned_to.as_deref(), Some("person:1"));
        assert!(item.claimed_by.is_none());
        let evidence = facade
            .kernel()
            .store()
            .evidence(&task_id)
            .expect("advisory finish evidence");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].added_by.as_deref(), Some(actor));
        let closings = facade
            .kernel()
            .store()
            .closings("tutorials")
            .expect("ordinary closing observations");
        assert_eq!(closings.len(), 1);
        assert_eq!(closings[0].event_id, receipt.event_id);
        assert_eq!(closings[0].closed_at, receipt.closed_at);
        // Reconstruct the embedding after target and runtime settlement, before
        // the ordinary continuation is consumed. Rebuilding is a real event fold.
        facade = GovernedHostFacade::from_verified_store(
            facade.into_kernel().into_store(),
            7,
            envelope(),
        )
        .expect("reconstruct closure embedding");
        facade
            .kernel_mut()
            .store_mut()
            .rebuild_projections(&admission.instance_ref)
            .expect("replay closure instance");
        assert_eq!(
            facade
                .kernel()
                .store()
                .closing_receipt(&operation)
                .expect("receipt after replay"),
            Some(receipt.clone())
        );
        let facts = facade
            .kernel()
            .store()
            .list_facts(&admission.instance_ref)
            .expect("replayed facts");
        let completed = facts
            .iter()
            .filter(|fact| fact.name == "tracker.finish.completed")
            .collect::<Vec<_>>();
        assert_eq!(completed.len(), 1);
        let value: Value =
            serde_json::from_str(&completed[0].value_json).expect("completion value");
        assert_eq!(
            value["value"],
            json!({"id": task_id, "status": "done", "summary": "Self-reported completion"})
        );
        whipplescript_kernel::rule_pass::step_instance_generic(
            facade.kernel_mut(),
            &admission.instance_ref,
            action.program(),
            None,
            None,
        )
        .expect("ordinary finish continuation");
        assert_eq!(
            facade
                .kernel()
                .store()
                .get_instance(&admission.instance_ref)
                .expect("workflow status")
                .expect("instance exists")
                .status,
            "completed"
        );
        // A later independent reopen cannot turn a retry into another closing.
        reopen(facade.kernel_mut().store_mut(), &task_id);
        let after_reopen = facade
            .kernel()
            .store()
            .event_position()
            .expect("reopen history");
        assert!(facade
            .execute_tracker_closure(request.clone(), &action, &authority, b"execution", &binding)
            .is_err());
        assert_eq!(
            facade
                .kernel()
                .store()
                .event_position()
                .expect("unchanged reopened history"),
            after_reopen
        );
        assert_eq!(
            facade
                .kernel()
                .store()
                .get_item(&task_id)
                .expect("reopened task")
                .expect("task exists")
                .status,
            "open"
        );
        assert_eq!(
            facade
                .kernel()
                .store()
                .closing_receipt(&operation)
                .expect("immutable receipt"),
            Some(receipt)
        );
        assert_eq!(
            facade
                .kernel()
                .store()
                .list_runs(&admission.instance_ref)
                .expect("single dispatch")
                .len(),
            1
        );
        outcomes.push(json!({"actor": actor, "assignment": item.assigned_to, "result": value["value"], "evidence_actor": evidence[0].added_by}));
    }
    outcomes
}

#[test]
fn governed_tracker_closure_human_and_agent_matches_native_and_deployed_do_schema() {
    let native = closure_journey(
        || NativeStores::open_in_memory().expect("native stores"),
        |store, id| {
            store
                .items
                .set_field(id, "status", "open")
                .expect("independent native reopen");
        },
    );
    let hosted = closure_journey(
        || DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
        |store, id| {
            store
                .set_field(id, "status", "open")
                .expect("independent hosted reopen");
        },
    );
    assert_eq!(native, hosted);
}

impl whipplescript_kernel::host_facade::TrackerClosureRecoveryAuthority for CloseAuthority {
    fn authenticate(
        &self,
        request: &whipplescript_kernel::host_protocol::tracker_recovery::RecoverTrackerClosure,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        whipplescript_kernel::host_facade::TrackerRecoveryAuthority::authenticate(
            &self.execution,
            request,
            bytes,
            proof,
        )
    }
    fn authorize_observation(
        &self,
        request: &whipplescript_kernel::host_protocol::tracker_recovery::RecoverTrackerClosure,
        binding: &TrackerClosureBinding,
    ) -> Result<(), ProtocolError> {
        assert_eq!(binding, &self.binding);
        whipplescript_kernel::host_facade::TrackerRecoveryAuthority::authorize_observation(
            &self.execution,
            request,
            &binding.tracker,
        )
    }
    fn authorize_recovery(
        &self,
        _: &whipplescript_kernel::host_protocol::tracker_recovery::RecoverTrackerClosure,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        dispatch: &whipplescript_kernel::tracker_closure::ClosureDispatch,
        closure: &TrackerClosure,
    ) -> Result<(), ProtocolError> {
        assert!(self.execution.allow);
        assert_eq!(original, &self.execution.original);
        assert_eq!(execution, &self.execution.request);
        assert_eq!(dispatch.binding, self.binding);
        assert_eq!(closure.actor, execution.provenance.executor);
        assert_eq!(closure.subject_id, self.binding.subject_id);
        assert_eq!(closure.expected_holder, self.binding.expected_holder);
        Ok(())
    }
}

fn closing_recovery_journey<S>(make: impl Fn() -> RecoveryStore<S>) -> Vec<Value>
where
    S: RuntimeStore
        + LogAppend
        + Coordination
        + WorkItems
        + FrontierRead
        + TrackerFilings
        + TrackerClosures
        + whipplescript_store::tracker_result::TrackerResultPublications,
{
    use whipplescript_kernel::host_protocol::tracker_recovery::{
        RecoverTrackerClosure, TRACKER_RECOVERY_PROTOCOL,
    };
    use whipplescript_store::effect_recovery::{fold_attempts, ExternalDisposition};
    let mut outcomes = vec![];
    for actor in ["person:1", "agent:1"] {
        for expired in [false, true] {
            let RecoveryStore {
                store,
                set_fault,
                scratch,
            } = make();
            let (
                Prepared {
                    mut facade,
                    action,
                    admission,
                    request,
                    authority: execution,
                    ..
                },
                binding,
            ) = prepare_closing(store, actor);
            let mut authority = CloseAuthority {
                execution,
                binding: binding.clone(),
                close: true,
                report_closure: |closure| {
                    record_tracker::<S, _>(
                        &format!("{}/close", closure.actor),
                        "TrackerClosure",
                        closure,
                    )
                },
            };
            authority.execution.allow = true;
            let instance = &admission.instance_ref;
            set_fault(facade.kernel().store(), true);
            assert!(facade
                .execute_tracker_closure(
                    request.clone(),
                    &action,
                    &authority,
                    b"execution",
                    &binding
                )
                .is_err());
            set_fault(facade.kernel().store(), false);
            let operation = closing_operation_id(instance, &request.effect_id);
            let receipt = facade
                .kernel()
                .store()
                .closing_receipt(&operation)
                .expect("target receipt")
                .expect("closing committed before fault");
            assert_eq!(receipt.actor, actor);
            assert!(!facade
                .kernel()
                .store()
                .list_facts(instance)
                .expect("interrupted facts")
                .iter()
                .any(|fact| fact.name == "tracker.finish.completed"));
            let target = facade
                .kernel()
                .store()
                .event_position()
                .expect("committed target history");
            facade = GovernedHostFacade::from_verified_store(
                facade.into_kernel().into_store(),
                7,
                envelope(),
            )
            .expect("reconstruct recovery embedding");
            if expired {
                assert_eq!(
                    facade
                        .kernel_mut()
                        .expire_leases(instance, "2099-01-01T00:00:00Z")
                        .expect("expire interrupted attempt")
                        .len(),
                    1
                );
            }
            let run_id = facade
                .kernel()
                .store()
                .list_runs(instance)
                .expect("original dispatch")[0]
                .run_id
                .clone();
            let recovery = RecoverTrackerClosure {
                protocol: TRACKER_RECOVERY_PROTOCOL.into(),
                issuer: request.issuer.clone(),
                scope: request.scope.clone(),
                admission: admission.clone(),
                policy: facade.policy_ref().clone(),
                provenance: request.provenance.clone(),
                effect_id: request.effect_id.clone(),
                run_id,
            };
            let owner = facade
                .kernel_mut()
                .store_mut()
                .claim_instance_ownership(instance)
                .expect("own recovery");
            let before = facade
                .kernel()
                .store()
                .chain_head(instance)
                .expect("before denied recovery");
            assert!(matches!(
                facade.recover_tracker_closure(
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
            authority.execution.allow = false;
            assert!(matches!(
                facade.recover_tracker_closure(
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
                    .expect("denials preserve history"),
                before
            );
            authority.execution.allow = true;
            let result = facade
                .recover_tracker_closure(
                    recovery.clone(),
                    &action,
                    owner,
                    &authority,
                    b"recover",
                    &binding,
                )
                .expect("publish actual closing result");
            facade
                .kernel_mut()
                .store_mut()
                .rebuild_projections(instance)
                .expect("replay recovered result");
            let events = facade
                .kernel()
                .store()
                .list_events(instance)
                .expect("recovered evidence");
            let attempts = fold_attempts(instance, &request.effect_id, &events)
                .expect("standard result disposition");
            assert_eq!(attempts.len(), 1);
            assert_eq!(attempts[0].disposition, ExternalDisposition::Applied);
            assert!(!attempts[0].disputed);
            assert_eq!(attempts[0].evidence[0].evidence_ref, receipt.event_id);
            let payload: Value = serde_json::from_str(
                &events
                    .iter()
                    .find(|event| event.event_type == "effect.run_started")
                    .expect("original closing dispatch")
                    .payload_json,
            )
            .expect("dispatch payload");
            let dispatch: whipplescript_kernel::tracker_closure::ClosureDispatch =
                serde_json::from_value(payload["metadata"]["tracker_closure"].clone())
                    .expect("retained closing dispatch");
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
                .expect("standard recovered closing result");
            assert_eq!(
                snapshot
                    .effects
                    .iter()
                    .find(|effect| effect.effect_id == request.effect_id)
                    .expect("closing result effect")
                    .attempts[0]
                    .disposition,
                ExternalDisposition::Applied
            );
            let scenario = format!(
                "{actor}/recover-close/{}",
                if expired { "expired" } else { "running" }
            );
            record_tracker::<S, _>(&scenario, "RecoverTrackerResult", &recovery);
            record_tracker::<S, _>(&scenario, "ClosureDispatch", &dispatch);
            record_tracker::<S, _>(&scenario, "TrackerClosureReceipt", &receipt);
            record_tracker::<S, _>(&scenario, "ActionResultSnapshot", &snapshot);
            let runs = facade
                .kernel()
                .store()
                .list_runs(instance)
                .expect("retained attempt");
            assert_eq!(runs.len(), 1);
            assert_eq!(
                runs[0].status,
                if expired {
                    "lease_expired"
                } else {
                    "completed"
                }
            );
            let facts = facade
                .kernel()
                .store()
                .list_facts(instance)
                .expect("recovered completion");
            let completed: Vec<_> = facts
                .iter()
                .filter(|fact| fact.name == "tracker.finish.completed")
                .collect();
            assert_eq!(completed.len(), 1);
            let value: Value =
                serde_json::from_str(&completed[0].value_json).expect("ordinary result");
            assert_eq!(
                value["value"],
                json!({"id": binding.item_id, "status": "done", "summary": "Self-reported completion"})
            );
            whipplescript_kernel::rule_pass::step_instance_generic(
                facade.kernel_mut(),
                instance,
                action.program(),
                None,
                None,
            )
            .expect("ordinary finish continuation");
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .get_instance(instance)
                    .expect("workflow")
                    .expect("exists")
                    .status,
                "completed"
            );
            let head = facade
                .kernel()
                .store()
                .chain_head(instance)
                .expect("completed history");
            assert_eq!(
                facade
                    .recover_tracker_closure(
                        recovery, &action, owner, &authority, b"recover", &binding
                    )
                    .expect("exact redelivery"),
                result
            );
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .chain_head(instance)
                    .expect("no duplicate result"),
                head
            );
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .event_position()
                    .expect("no target redispatch"),
                target
            );
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .closing_receipt(&operation)
                    .expect("original receipt"),
                Some(receipt)
            );
            outcomes.push(json!({"actor": actor, "expired": expired, "value": value["value"], "status": runs[0].status}));
            drop(facade);
            if let Some(path) = scratch {
                std::fs::remove_dir_all(path).expect("remove native fixture");
            }
        }
    }
    outcomes
}

#[test]
fn governed_tracker_closing_recovery_matches_native_and_deployed_do_schema() {
    assert_eq!(
        closing_recovery_journey(native_recovery_store),
        closing_recovery_journey(hosted_recovery_store)
    );
}
