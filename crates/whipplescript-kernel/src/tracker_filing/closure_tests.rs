use super::*;
use crate::{host_facade::TrackerClosureAuthority, tracker_closure::TrackerClosureBinding};
use whipplescript_store::tracker_closure::{TrackerClosure, TrackerClosures};

const CLOSE_SOURCE: &str = r#"
workflow CloseTask(learner: Learner) -> bool
class Learner { authority string queue string id string }
tracker tutorials
rule begin
  when Learner as learner
=> {
  then closed <- finish learner {
    summary "Self-reported completion"
  }
  complete result true
}
"#;

struct CloseCustody;
impl ActionInputResolver for CloseCustody {
    fn with_inputs<T>(
        &self,
        _: &VerifiedActionAdmission,
        consume: impl FnOnce(BTreeMap<String, Value>) -> T,
    ) -> Result<T, HostFacadeError> {
        Ok(consume(BTreeMap::from([(
            "learner".into(),
            json!({
                "authority": "person:learner", "queue": "tutorials", "id": "WS-1"
            }),
        )])))
    }
}

struct CloseAuthority {
    execution: Authority,
    binding: TrackerClosureBinding,
    observation: bool,
    close: bool,
    checked: Cell<usize>,
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
        _: &ExecuteActionEffect,
        binding: &TrackerClosureBinding,
    ) -> Result<(), ProtocolError> {
        if self.observation && binding == &self.binding {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture closure observation"))
        }
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
        self.checked.set(self.checked.get() + 1);
        if self.close {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture closure revoked"))
        }
    }
}

fn fixture_close(actor: &str) -> (Fixture, TrackerClosureBinding, CloseAuthority) {
    fixture_close_with(actor, CLOSE_SOURCE, |_| {})
}

fn fixture_close_with(
    actor: &str,
    source: &str,
    configure: impl FnOnce(&mut ActionResource),
) -> (Fixture, TrackerClosureBinding, CloseAuthority) {
    fixture_close_in(
        actor,
        source,
        configure,
        NativeStores::open_in_memory().expect("closure stores"),
    )
}

fn fixture_close_in(
    actor: &str,
    source: &str,
    configure: impl FnOnce(&mut ActionResource),
    mut store: NativeStores,
) -> (Fixture, TrackerClosureBinding, CloseAuthority) {
    let issue = store
        .file_item(
            "tutorials",
            "Create a chat",
            "PRIVATE_TASK_BODY",
            &[],
            &json!({}),
            Some("person:author"),
            Some("person:learner"),
        )
        .expect("existing task");
    store
        .claim_item(&issue.id, "workflow:holder", None)
        .expect("independent claim holder");
    let subject = store
        .subject_content_id(&issue.id)
        .expect("subject lookup")
        .expect("existing subject");
    let f = fixture_for_source(actor, store, source, &CloseCustody, configure);
    let binding = TrackerClosureBinding {
        tracker: f.binding.clone(),
        item_id: issue.id,
        subject_id: subject,
        expected_holder: Some("workflow:holder".into()),
    };
    let authority = CloseAuthority {
        execution: Authority::new(&f),
        binding: binding.clone(),
        observation: true,
        close: true,
        checked: Cell::new(0),
    };
    (f, binding, authority)
}

#[test]
fn governed_tracker_closure_uses_the_actual_actor_and_ordinary_continuation() {
    for actor in ["person:learner", "agent:assistant"] {
        let (mut f, binding, authority) = fixture_close(actor);
        f.facade
            .execute_tracker_closure(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &binding,
            )
            .unwrap();
        let instance = &f.request.admission.instance_ref;
        let operation =
            crate::tracker_closure::closing_operation_id(instance, &f.request.effect_id);
        let receipt = f
            .facade
            .kernel()
            .store()
            .closing_receipt(&operation)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.actor, actor);
        assert_eq!(receipt.subject_id, binding.subject_id);
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .get_item(&binding.item_id)
                .unwrap()
                .unwrap()
                .status,
            "closed"
        );
        let items = &f.facade.kernel().store().items;
        let evidence = items.evidence(&binding.item_id).unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].added_by.as_deref(), Some(actor));
        assert_eq!(
            items.event_effect_id(&evidence[0].id).unwrap(),
            Some(f.request.effect_id.clone())
        );
        let unrelated = f
            .facade
            .kernel_mut()
            .store_mut()
            .items
            .add_evidence(
                &binding.item_id,
                Some("manual"),
                Some("independent-observation"),
                None,
                Some(actor),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .items
                .event_effect_id(&unrelated)
                .unwrap(),
            None
        );
        let facts = f.facade.kernel().store().list_facts(instance).unwrap();
        assert!(facts
            .iter()
            .any(|fact| fact.name == "tracker.finish.completed"));
        crate::rule_pass::step_instance_generic(
            f.facade.kernel_mut(),
            instance,
            f.action.program(),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .status(instance)
                .unwrap()
                .unwrap()
                .instance
                .status,
            "completed"
        );
        assert_eq!(
            f.facade.kernel().store().list_runs(instance).unwrap().len(),
            1
        );
        assert!(f
            .facade
            .execute_tracker_closure(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &binding
            )
            .is_err());
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .closing_receipt(&operation)
                .unwrap(),
            Some(receipt)
        );
    }
}

#[test]
fn governed_tracker_closure_checks_current_authority_before_dispatch() {
    for case in ["authentication", "observation", "closure"] {
        let (mut f, binding, mut authority) = fixture_close("person:learner");
        authority.observation = case != "observation";
        authority.close = case != "closure";
        let proof = if case == "authentication" {
            b"forged".as_slice()
        } else {
            b"execution".as_slice()
        };
        let before = f.facade.kernel().store().event_position().unwrap();
        let error = f
            .facade
            .execute_tracker_closure(f.request.clone(), &f.action, &authority, proof, &binding)
            .unwrap_err();
        let expected = match case {
            "authentication" => "fixture execution proof",
            "observation" => "fixture closure observation",
            _ => "fixture closure revoked",
        };
        assert!(
            matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message)) if message == expected),
            "{error:?}"
        );
        assert!(f
            .facade
            .kernel()
            .store()
            .list_runs(&f.request.admission.instance_ref)
            .unwrap()
            .is_empty());
        assert_eq!(f.facade.kernel().store().event_position().unwrap(), before);
        assert_eq!(authority.checked.get(), usize::from(case == "closure"));
    }
}

#[test]
fn governed_tracker_closure_requires_original_resource_and_effect_bindings() {
    for case in [
        "kind",
        "selector",
        "writable",
        "rebound",
        "scope",
        "queue",
        "effect-kind",
    ] {
        let source = if case == "effect-kind" {
            SOURCE
        } else {
            CLOSE_SOURCE
        };
        // SOURCE's input schema is smaller, so use the same closure declaration
        // with the ordinary filing statement for the wrong-effect witness.
        let source = source.replace(
            "class Learner { authority string }",
            "class Learner { authority string queue string id string }",
        );
        let (mut f, mut binding, mut authority) =
            fixture_close_with("person:learner", &source, |resource| match case {
                "kind" => resource.resource.kind = "file".into(),
                "selector" => resource.resource.selector = Some("other".into()),
                "writable" => resource.resource.writable = Some(false),
                _ => {}
            });
        match case {
            "rebound" => {
                binding.tracker.resource.basis = ActionBasis::Version {
                    version_ref: "other-incarnation".into(),
                }
            }
            "scope" => binding.tracker.scope = "other-workspace".into(),
            "queue" => binding.tracker.queue = "other".into(),
            _ => {}
        }
        authority.binding = binding.clone();
        let before = f.facade.kernel().store().event_position().unwrap();
        let error = f
            .facade
            .execute_tracker_closure(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &binding,
            )
            .unwrap_err();
        assert!(
            matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message)) if message == "tracker closure original resource binding"),
            "{case}: {error:?}"
        );
        assert_eq!(authority.checked.get(), 0, "{case}");
        assert_eq!(f.facade.kernel().store().event_position().unwrap(), before);
        assert!(f
            .facade
            .kernel()
            .store()
            .list_runs(&f.request.admission.instance_ref)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn governed_tracker_closure_refuses_changed_current_object_and_raw_flows() {
    for case in [
        "alias",
        "result-reader",
        "result-writer",
        "error-reader",
        "tracker-writer",
    ] {
        let (mut f, binding, mut authority) = fixture_close("person:learner");
        let mut current = policy();
        match case {
            "alias" => {
                current["resources"]["tracker:other"] =
                    current["resources"]["tracker:1/tutorials"].clone();
                current["bindings"]["tutorials"] = json!("tracker:other");
            }
            "result-reader" => current["resources"]["result"]["reader"] = json!([]),
            "result-writer" => current["resources"]["result"]["writer"] = json!("NonMember"),
            "error-reader" => current["resources"]["error"]["reader"] = json!([]),
            "tracker-writer" => {
                current["resources"]["tracker:1/tutorials"]["writer"] = json!("NonMember")
            }
            _ => unreachable!(),
        }
        f.facade = GovernedHostFacade::from_verified_store(
            f.facade.into_kernel().into_store(),
            8,
            envelope(current, 8),
        )
        .unwrap();
        f.request.policy = f.facade.policy_ref().clone();
        authority.execution = Authority::new(&f);
        let before = f.facade.kernel().store().event_position().unwrap();
        let error = f
            .facade
            .execute_tracker_closure(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &binding,
            )
            .unwrap_err();
        assert!(
            matches!(
                error,
                HostFacadeError::PolicyRejected(_) | HostFacadeError::Ifc(_)
            ),
            "{case}: {error:?}"
        );
        assert_eq!(authority.checked.get(), 0);
        assert_eq!(f.facade.kernel().store().event_position().unwrap(), before);
        assert!(f
            .facade
            .kernel()
            .store()
            .list_runs(&f.request.admission.instance_ref)
            .unwrap()
            .is_empty());
    }
}

#[test]
fn governed_tracker_closure_binds_resolved_input_before_mutation() {
    let (mut f, mut binding, mut authority) = fixture_close("person:learner");
    binding.item_id = "WS-2".into();
    authority.binding = binding.clone();
    let before = f.facade.kernel().store().event_position().unwrap();
    let error = f
        .facade
        .execute_tracker_closure(
            f.request.clone(),
            &f.action,
            &authority,
            b"execution",
            &binding,
        )
        .unwrap_err();
    assert!(
        matches!(error, HostFacadeError::Protocol(ProtocolError::Invalid(message)) if message == "tracker closure input is invalid"),
        "{error:?}"
    );
    assert_eq!(authority.checked.get(), 0);
    assert_eq!(f.facade.kernel().store().event_position().unwrap(), before);
    assert!(f
        .facade
        .kernel()
        .store()
        .list_runs(&f.request.admission.instance_ref)
        .unwrap()
        .is_empty());
}

#[test]
fn governed_tracker_closure_target_refusals_have_fixed_body_free_failures() {
    for case in ["subject", "holder", "closed"] {
        let (mut f, mut binding, mut authority) = fixture_close("person:learner");
        match case {
            "subject" => binding.subject_id = "other-permanent-subject".into(),
            "holder" => binding.expected_holder = Some("other-holder".into()),
            "closed" => {
                f.facade
                    .kernel_mut()
                    .store_mut()
                    .finish_item(&binding.item_id, None, None)
                    .unwrap();
            }
            _ => unreachable!(),
        }
        authority.binding = binding.clone();
        let before = f.facade.kernel().store().event_position().unwrap();
        f.facade
            .execute_tracker_closure(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &binding,
            )
            .unwrap();
        assert_eq!(authority.checked.get(), 1);
        assert_eq!(f.facade.kernel().store().event_position().unwrap(), before);
        let instance = &f.request.admission.instance_ref;
        let facts = f.facade.kernel().store().list_facts(instance).unwrap();
        let failure = facts
            .iter()
            .find(|fact| fact.name == "tracker.finish.failed")
            .unwrap();
        let value: Value = serde_json::from_str(&failure.value_json).unwrap();
        assert_eq!(
            value["value"],
            json!({"reason": "tracker closure did not settle successfully"})
        );
        let history = f.facade.kernel().store().chain_prefix(instance).unwrap();
        let terminal = history
            .iter()
            .find(|event| event.event_type == "effect.terminal")
            .unwrap();
        assert!(!terminal.payload_json.contains("PRIVATE_TASK_BODY"));
        assert!(f
            .facade
            .kernel()
            .store()
            .closing_receipt(&crate::tracker_closure::closing_operation_id(
                instance,
                &f.request.effect_id
            ))
            .unwrap()
            .is_none());
    }
}

#[test]
fn governed_tracker_closure_recovers_its_committed_target_across_interrupted_publication() {
    for expire in [false, true] {
        let root = std::env::temp_dir().join(format!(
            "whip-closure-interruption-{}-{}",
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
            .expect("disk closure stores")
        };
        let (mut f, binding, authority) =
            fixture_close_in("person:learner", CLOSE_SOURCE, |_| {}, open());
        let fault = rusqlite::Connection::open(root.join("runtime.sqlite")).unwrap();
        fault.execute_batch("CREATE TRIGGER closure_settlement_fault AFTER INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'injected closure terminal fault'); END").unwrap();
        let error = f
            .facade
            .execute_tracker_closure(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &binding,
            )
            .unwrap_err();
        assert!(format!("{error:?}").contains("injected closure terminal fault"));
        let instance = f.request.admission.instance_ref.clone();
        let operation =
            crate::tracker_closure::closing_operation_id(&instance, &f.request.effect_id);
        let receipt = f
            .facade
            .kernel()
            .store()
            .closing_receipt(&operation)
            .unwrap()
            .unwrap();
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .get_item(&binding.item_id)
                .unwrap()
                .unwrap()
                .status,
            "closed"
        );
        assert!(!f
            .facade
            .kernel()
            .store()
            .list_facts(&instance)
            .unwrap()
            .iter()
            .any(|fact| fact.name == "tracker.finish.completed"));
        fault
            .execute_batch("DROP TRIGGER closure_settlement_fault")
            .unwrap();
        drop(fault);
        let Fixture {
            facade,
            action,
            original,
            request,
            binding: tracker,
        } = f;
        drop(facade);
        let mut f = Fixture {
            facade: GovernedHostFacade::from_verified_store(open(), 7, envelope(policy(), 7))
                .unwrap(),
            action,
            original,
            request,
            binding: tracker,
        };
        if expire {
            f.facade
                .kernel_mut()
                .expire_leases(&instance, "2099-01-01T00:00:00Z")
                .unwrap();
        }
        f.facade
            .kernel_mut()
            .store_mut()
            .rebuild_projections(&instance)
            .unwrap();
        let before = f.facade.kernel().store().event_position().unwrap();
        assert!(f
            .facade
            .execute_tracker_closure(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &binding
            )
            .is_err());
        assert_eq!(f.facade.kernel().store().event_position().unwrap(), before);
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .closing_receipt(&operation)
                .unwrap(),
            Some(receipt)
        );
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .list_runs(&instance)
                .unwrap()
                .len(),
            1
        );
        recovery::recover_and_continue(&mut f, &binding, expire);
        drop(f);
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[path = "closure_recovery_tests.rs"]
mod recovery;
