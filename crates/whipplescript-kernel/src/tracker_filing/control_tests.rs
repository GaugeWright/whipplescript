use super::*;
use crate::{host_facade::TrackerControlAuthority, tracker_control::TrackerControlBinding};
use whipplescript_store::tracker_control::{
    TrackerControl, TrackerControlOutcome, TrackerControls,
};

struct ControlCustody(Value);
impl ActionInputResolver for ControlCustody {
    fn with_inputs<T>(
        &self,
        _: &VerifiedActionAdmission,
        consume: impl FnOnce(BTreeMap<String, Value>) -> T,
    ) -> Result<T, HostFacadeError> {
        Ok(consume(BTreeMap::from([(
            "learner".into(),
            self.0.clone(),
        )])))
    }
}
struct ControlAuthority {
    execution: Authority,
    binding: TrackerControlBinding,
    observation: bool,
    control: bool,
    checked: Cell<usize>,
}
impl ActionExecutionVerifier for ControlAuthority {
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
impl TrackerControlAuthority for ControlAuthority {
    fn authorize_observation(
        &self,
        _: &ExecuteActionEffect,
        binding: &TrackerControlBinding,
    ) -> Result<(), ProtocolError> {
        if self.observation && binding == &self.binding {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture control observation"))
        }
    }
    fn authorize_control(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerControlBinding,
        control: &TrackerControl,
    ) -> Result<(), ProtocolError> {
        assert_eq!(original, &self.execution.original);
        assert_eq!(binding, &self.binding);
        assert_eq!(control.actor, request.provenance.executor);
        assert_eq!(control.subject_id, binding.subject_id);
        self.checked.set(self.checked.get() + 1);
        if self.control {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture control revoked"))
        }
    }
}

fn fixture_control(
    actor: &str,
    capability: &str,
    fields: &str,
    argument: Value,
    protected: bool,
    holder: Option<&str>,
) -> (Fixture, TrackerControlBinding, ControlAuthority) {
    fixture_control_in(
        actor,
        capability,
        fields,
        argument,
        protected_stores::memory(protected),
        holder,
    )
}

fn fixture_control_in(
    actor: &str,
    capability: &str,
    fields: &str,
    argument: Value,
    mut store: NativeStores,
    holder: Option<&str>,
) -> (Fixture, TrackerControlBinding, ControlAuthority) {
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
        .expect("tracker control fixture");
    if let Some(holder) = holder {
        store
            .claim_item(&issue.id, holder, None)
            .expect("tracker control fixture");
    }
    let subject_id = store
        .subject_content_id(&issue.id)
        .expect("tracker control fixture")
        .expect("tracker control fixture");
    let source = format!(
        r#"
use std.tracker
workflow ControlTask(learner: Learner) -> bool
class Learner {{ queue string id string {fields} }}
tracker tutorials
rule begin
  when Learner as learner
=> {{
  then controlled <- call {capability} for learner timeout 1m
  complete result true
}}
"#
    );
    let f = fixture_for_source(actor, store, &source, &ControlCustody(argument), |_| {});
    let binding = TrackerControlBinding {
        tracker: f.binding.clone(),
        item_id: issue.id,
        subject_id,
    };
    let authority = ControlAuthority {
        execution: Authority::new(&f),
        binding: binding.clone(),
        observation: true,
        control: true,
        checked: Cell::new(0),
    };
    (f, binding, authority)
}

fn lease_argument() -> Value {
    json!({"queue":"tutorials", "id":"WS-1", "expires_at":"2999-01-01 00:00:00"})
}

fn execute(
    f: &mut Fixture,
    binding: &TrackerControlBinding,
    authority: &ControlAuthority,
) -> Result<StoredEvent, HostFacadeError> {
    f.facade.execute_tracker_control(
        f.request.clone(),
        &f.action,
        authority,
        b"execution",
        binding,
    )
}

#[test]
fn governed_tracker_control_claim_survives_root_completion_and_never_assigns() {
    for protected in [false, true] {
        for actor in ["person:learner", "agent:assistant"] {
            let (mut f, binding, authority) = fixture_control(
                actor,
                "tracker.claim",
                "expires_at string",
                lease_argument(),
                protected,
                None,
            );
            execute(&mut f, &binding, &authority).unwrap();
            assert_eq!(authority.checked.get(), 1);
            let instance = f.request.admission.instance_ref.clone();
            let operation =
                crate::tracker_control::control_operation_id(&instance, &f.request.effect_id);
            let receipt = f
                .facade
                .kernel()
                .store()
                .control_receipt(&operation)
                .unwrap()
                .unwrap();
            assert_eq!(receipt.actor, actor);
            assert_eq!(
                receipt.outcome,
                TrackerControlOutcome::Claimed {
                    expires_at: "2999-01-01 00:00:00".into()
                }
            );
            let facts = f.facade.kernel().store().list_facts(&instance).unwrap();
            assert!(facts
                .iter()
                .any(|fact| fact.name == "capability.call.succeeded"));
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
                    .status(&instance)
                    .unwrap()
                    .unwrap()
                    .instance
                    .status,
                "completed"
            );
            let issue = f
                .facade
                .kernel()
                .store()
                .get_item(&binding.item_id)
                .unwrap()
                .unwrap();
            assert_eq!(issue.claimed_by.as_deref(), Some(actor));
            assert_eq!(issue.assigned_to.as_deref(), Some("person:learner"));
            assert!(execute(&mut f, &binding, &authority).is_err());
            assert_eq!(
                f.facade
                    .kernel()
                    .store()
                    .control_receipt(&operation)
                    .unwrap()
                    .unwrap(),
                receipt
            );
        }
    }
}

#[test]
fn governed_tracker_control_contention_is_a_completed_call_with_a_retained_outcome() {
    let (mut f, binding, authority) = fixture_control(
        "person:learner",
        "tracker.claim",
        "expires_at string",
        lease_argument(),
        false,
        Some("agent:assistant"),
    );
    execute(&mut f, &binding, &authority).unwrap();
    let instance = f.request.admission.instance_ref.clone();
    let operation = crate::tracker_control::control_operation_id(&instance, &f.request.effect_id);
    assert_eq!(
        f.facade
            .kernel()
            .store()
            .control_receipt(&operation)
            .unwrap()
            .unwrap()
            .outcome,
        TrackerControlOutcome::AlreadyClaimed {
            holder: "agent:assistant".into()
        }
    );
    assert_eq!(
        f.facade
            .kernel()
            .store()
            .get_item(&binding.item_id)
            .unwrap()
            .unwrap()
            .claimed_by
            .as_deref(),
        Some("agent:assistant")
    );
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
            .status(&instance)
            .unwrap()
            .unwrap()
            .instance
            .status,
        "completed"
    );
}

#[test]
fn governed_tracker_control_authority_denials_do_not_dispatch_or_touch_tracker() {
    for observation in [false, true] {
        let (mut f, binding, mut authority) = fixture_control(
            "person:learner",
            "tracker.claim",
            "expires_at string",
            lease_argument(),
            false,
            None,
        );
        authority.observation = observation;
        authority.control = false;
        let before = f.facade.kernel().store().event_position().unwrap();
        assert!(execute(&mut f, &binding, &authority).is_err());
        assert_eq!(authority.checked.get(), usize::from(observation));
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

#[path = "control_recovery_tests.rs"]
mod recovery;

#[test]
fn tracker_control_request_requires_explicit_preconditions_and_authenticated_actor() {
    let (f, binding, _) = fixture_control(
        "person:learner",
        "tracker.claim",
        "expires_at string",
        lease_argument(),
        false,
        None,
    );
    let mut effect = f
        .facade
        .kernel()
        .claimable_effects(&f.request.admission.instance_ref)
        .unwrap()
        .remove(0);
    let base = json!({"queue":"tutorials", "id":"WS-1"});
    for (capability, fields) in [
        ("tracker.claim", json!({"expires_at":"2999-01-01 00:00:00"})),
        ("tracker.renew", json!({"expires_at":"2999-01-01 00:00:00"})),
        ("tracker.release", json!({"expected_holder":null})),
        (
            "tracker.assign",
            json!({"expected_assignee":null, "assigned_to":null}),
        ),
    ] {
        effect.target = Some(capability.into());
        let mut argument = base.clone();
        argument
            .as_object_mut()
            .unwrap()
            .extend(fields.as_object().unwrap().clone());
        let decode = |arg: &Value| {
            crate::tracker_control::request(
                "instance:fixture",
                &effect,
                "agent:assistant",
                &json!({"arguments":{"arg0":arg}}).to_string(),
                &binding,
            )
        };
        let decoded = decode(&argument).expect("explicit null preconditions are valid");
        assert_eq!(decoded.actor, "agent:assistant");
        assert_eq!(decoded.capability(), capability);
        for field in fields
            .as_object()
            .unwrap()
            .keys()
            .chain(["queue".to_string(), "id".to_string()].iter())
        {
            let mut missing = argument.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(decode(&missing).is_err(), "{capability} requires {field}");
            let mut wrong_type = argument.clone();
            wrong_type[field] = json!(17);
            assert!(
                decode(&wrong_type).is_err(),
                "{capability} validates {field}"
            );
        }
        for field in ["actor", "unexpected"] {
            let mut extra = argument.clone();
            extra[field] = json!("person:forged");
            assert!(decode(&extra).is_err(), "{capability} refuses {field}");
        }
        for field in ["queue", "id"] {
            let mut foreign = argument.clone();
            foreign[field] = json!("foreign");
            assert!(decode(&foreign).is_err(), "{capability} binds {field}");
        }
    }
    // A well-formed lease argument cannot turn another capability into a
    // control. Assert the target refusal itself, not an unrelated input error.
    for target in [
        None,
        Some("tracker.wait_closed"),
        Some("tracker.finish"),
        Some("unknown"),
    ] {
        effect.target = target.map(str::to_owned);
        let error = crate::tracker_control::request(
            "instance:fixture",
            &effect,
            "person:learner",
            &json!({"arguments":{"arg0":lease_argument()}}).to_string(),
            &binding,
        )
        .expect_err("only the four principal controls decode");
        assert!(
            matches!(&error, whipplescript_store::StoreError::Conflict(message)
                if message == "tracker control capability is invalid"),
            "target {target:?}: {error:?}"
        );
    }
}

#[test]
fn governed_tracker_control_renew_release_and_assign_preserve_independent_ownership() {
    for protected in [false, true] {
        for (capability, fields, argument, expected_holder, expected_assignee) in [
            (
                "tracker.renew",
                "expires_at string",
                lease_argument(),
                Some("person:learner"),
                Some("person:learner"),
            ),
            (
                "tracker.release",
                "expected_holder string",
                json!({"queue":"tutorials", "id":"WS-1", "expected_holder":"person:learner"}),
                None,
                Some("person:learner"),
            ),
            (
                "tracker.assign",
                "expected_assignee string assigned_to string",
                json!({"queue":"tutorials", "id":"WS-1", "expected_assignee":"person:learner", "assigned_to":"agent:assistant"}),
                Some("person:learner"),
                Some("agent:assistant"),
            ),
        ] {
            let (mut f, binding, authority) = fixture_control(
                "person:learner",
                capability,
                fields,
                argument,
                protected,
                Some("person:learner"),
            );
            execute(&mut f, &binding, &authority).unwrap();
            let instance = f.request.admission.instance_ref.clone();
            let operation =
                crate::tracker_control::control_operation_id(&instance, &f.request.effect_id);
            let receipt = f
                .facade
                .kernel()
                .store()
                .control_receipt(&operation)
                .unwrap()
                .unwrap();
            assert_eq!(receipt.actor, "person:learner");
            let issue = f
                .facade
                .kernel()
                .store()
                .get_item(&binding.item_id)
                .unwrap()
                .unwrap();
            assert_eq!(issue.claimed_by.as_deref(), expected_holder, "{capability}");
            assert_eq!(
                issue.assigned_to.as_deref(),
                expected_assignee,
                "{capability}"
            );
            assert!(f
                .facade
                .kernel()
                .store()
                .list_facts(&instance)
                .unwrap()
                .iter()
                .any(|fact| fact.name == "capability.call.succeeded"));
        }
    }
}

#[test]
fn governed_tracker_control_assignment_does_not_grant_recipient_read_access() {
    let (mut f, binding, authority) = fixture_control(
        "person:learner",
        "tracker.assign",
        "expected_assignee string assigned_to string",
        json!({"queue":"tutorials", "id":"WS-1", "expected_assignee":"person:learner", "assigned_to":"person:unknown"}),
        false,
        None,
    );
    let before = f.facade.kernel().store().event_position().unwrap();
    let error = execute(&mut f, &binding, &authority).unwrap_err();
    assert!(
        matches!(error, HostFacadeError::PolicyRejected(message) if message == "resource exceeds recipient clearance")
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
fn governed_tracker_control_rejects_an_observable_but_unadmitted_tracker() {
    let (mut f, mut binding, mut authority) = fixture_control(
        "person:learner",
        "tracker.claim",
        "expires_at string",
        lease_argument(),
        false,
        None,
    );
    binding.tracker.scope = "another-workspace".into();
    authority.binding = binding.clone();
    let before = f.facade.kernel().store().event_position().unwrap();
    let error = execute(&mut f, &binding, &authority).unwrap_err();
    assert!(matches!(
        error,
        HostFacadeError::Protocol(ProtocolError::Mismatch(
            "tracker control original resource binding"
        ))
    ));
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
