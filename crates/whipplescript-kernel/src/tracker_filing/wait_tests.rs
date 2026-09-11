use super::*;
use crate::host_facade::TrackerWaitAuthority;

const WAIT_SOURCE: &str = r#"use std.tracker
workflow Wait(learner: Learner) -> bool
class Learner { id string queue string }
tracker tutorials
rule begin when Learner as learner => {
  then closing <- call tracker.wait_closed for learner timeout 30d
  complete result true
}
"#;

struct WaitInput(Value);
impl ActionInputResolver for WaitInput {
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

fn wait_fixture(
    actor: &str,
    input: impl FnOnce(&str) -> Value,
    configure: impl FnOnce(&mut ActionResource),
) -> (Fixture, String) {
    wait_fixture_in(
        NativeStores::open_in_memory().expect("wait fixture stores"),
        actor,
        input,
        configure,
    )
}

fn wait_fixture_in(
    mut store: NativeStores,
    actor: &str,
    input: impl FnOnce(&str) -> Value,
    configure: impl FnOnce(&mut ActionResource),
) -> (Fixture, String) {
    let item = store
        .file_item(
            "tutorials",
            "Complete this task",
            "Instructions",
            &[],
            &json!({}),
            Some(actor),
            Some("person:learner"),
        )
        .expect("fixture task");
    let custody = WaitInput(input(&item.id));
    let fixture = fixture_for_source(actor, store, WAIT_SOURCE, &custody, |resource| {
        resource.resource.writable = Some(false);
        configure(resource);
    });
    (fixture, item.id)
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
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerBinding,
        input: &Value,
    ) -> Result<(), ProtocolError> {
        assert_eq!(original, &self.original);
        assert_eq!(request.scope, binding.scope);
        assert_eq!(
            input
                .pointer("/arguments/arg0/queue")
                .and_then(Value::as_str),
            Some(binding.queue.as_str())
        );
        self.authorized.set(self.authorized.get() + 1);
        if self.filing {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture wait denied"))
        }
    }
}

fn close_and_project(f: &mut Fixture, issue: &str) {
    f.facade
        .kernel_mut()
        .store_mut()
        .finish_item(issue, Some("Self-reported"), None)
        .expect("close fixture issue");
    crate::rule_pass::step_instance_generic(
        f.facade.kernel_mut(),
        &f.request.admission.instance_ref,
        f.action.program(),
        None,
        None,
    )
    .expect("project closing");
}

#[test]
fn governed_tracker_wait_parks_then_consumes_closure_with_a_read_only_binding() {
    for actor in ["person:learner", "agent:assistant"] {
        let (mut f, issue) =
            wait_fixture(actor, |id| json!({"id": id, "queue": "tutorials"}), |_| {});
        let mut authority = Authority::new(&f);
        let instance = f.request.admission.instance_ref.clone();
        let before = f.facade.kernel().store().chain_head(&instance).unwrap();
        assert!(f
            .facade
            .execute_tracker_wait(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &f.binding
            )
            .is_err());
        assert_eq!(
            f.facade.kernel().store().chain_head(&instance).unwrap(),
            before
        );
        assert!(f
            .facade
            .kernel()
            .store()
            .list_runs(&instance)
            .unwrap()
            .is_empty());
        let queued = f.facade.kernel().store().list_effects(&instance).unwrap();
        let effect = ClaimableEffect {
            effect_id: queued[0].effect_id.clone(),
            kind: queued[0].kind.clone(),
            target: queued[0].target.clone(),
            profile: queued[0].profile.clone(),
            input_json: queued[0].input_json.clone(),
            required_capabilities_json: queued[0].required_capabilities_json.clone(),
            declared_profiles_json: queued[0].declared_profiles_json.clone(),
        };
        assert!(
            matches!(crate::tracker_wait::run_governed(f.facade.kernel_mut(), &instance, &effect),
            Err(StoreError::Conflict(message)) if message == "tracker closure is not ready")
        );
        close_and_project(&mut f, &issue);
        assert!(f
            .facade
            .execute_tracker_wait(
                f.request.clone(),
                &f.action,
                &authority,
                b"forged",
                &f.binding
            )
            .is_err());
        authority.filing = false;
        assert!(matches!(
            f.facade.execute_tracker_wait(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &f.binding
            ),
            Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
                "fixture wait denied"
            )))
        ));
        authority.filing = true;
        let terminal = f
            .facade
            .execute_tracker_wait(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &f.binding,
            )
            .unwrap();
        let runs = f.facade.kernel().store().list_runs(&instance).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, "completed");
        assert_eq!(runs[0].provider, "builtin-tracker");
        let facts = f.facade.kernel().store().list_facts(&instance).unwrap();
        let fact = facts
            .iter()
            .find(|fact| fact.name == "capability.call.succeeded")
            .unwrap();
        let value: Value = serde_json::from_str(&fact.value_json).unwrap();
        assert_eq!(value["value"]["id"], issue);
        assert_eq!(value["value"]["queue"], "tutorials");
        assert!(value["value"]["event"]
            .as_str()
            .is_some_and(|event| !event.is_empty()));
        let events = f.facade.kernel().store().chain_prefix(&instance).unwrap();
        assert!(events.iter().any(|event| event.event_type == "fact.derived"
            && event.causation_id.as_deref() == Some(&terminal.event_id)));
        let start: Value = serde_json::from_str(
            &events
                .iter()
                .find(|event| event.event_type == "effect.run_started")
                .unwrap()
                .payload_json,
        )
        .unwrap();
        assert_eq!(
            start["metadata"]["action_execution"]["request"]["provenance"]["executor"],
            actor
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
        assert!(f
            .facade
            .execute_tracker_wait(
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
                .list_runs(&instance)
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn governed_tracker_wait_malformed_input_settles_the_ordinary_failure() {
    let (mut f, _) = wait_fixture(
        "person:learner",
        |_| json!({"id": "", "queue": "tutorials"}),
        |_| {},
    );
    let authority = Authority::new(&f);
    let instance = f.request.admission.instance_ref.clone();
    f.facade
        .execute_tracker_wait(
            f.request.clone(),
            &f.action,
            &authority,
            b"execution",
            &f.binding,
        )
        .unwrap();
    assert_eq!(
        f.facade.kernel().store().list_runs(&instance).unwrap()[0].status,
        "failed"
    );
    assert!(f
        .facade
        .kernel()
        .store()
        .list_facts(&instance)
        .unwrap()
        .iter()
        .any(|fact| fact.name == "capability.call.failed"));
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
        "failed"
    );
}

#[test]
fn governed_tracker_wait_observation_denial_precedes_unavailable_history() {
    let (mut f, _) = wait_fixture(
        "person:learner",
        |id| json!({"id": id, "queue": "tutorials"}),
        |_| {},
    );
    let mut authority = Authority::new(&f);
    authority.observation = false;
    f.facade.kernel_mut().store_mut().runtime =
        whipplescript_store::SqliteStore::open_in_memory().unwrap();
    assert!(matches!(
        f.facade.execute_tracker_wait(
            f.request.clone(),
            &f.action,
            &authority,
            b"execution",
            &f.binding
        ),
        Err(HostFacadeError::Protocol(ProtocolError::Mismatch(
            "fixture observation denied"
        )))
    ));
    assert_eq!(authority.authorized.get(), 0);
}

#[test]
fn governed_tracker_wait_refuses_foreign_resources_and_reference_redirects() {
    for case in ["kind", "selector", "basis", "reference"] {
        let (mut f, issue) = wait_fixture(
            "person:learner",
            |id| json!({"id": id, "queue": if case == "reference" { "elsewhere" } else { "tutorials" }}),
            |resource| {
                if case == "kind" {
                    resource.resource.kind = "file".into();
                }
                if case == "selector" {
                    resource.resource.selector = Some("other".into());
                }
            },
        );
        let authority = Authority::new(&f);
        close_and_project(&mut f, &issue);
        if case == "basis" {
            f.binding.resource.basis = ActionBasis::Version {
                version_ref: "different".into(),
            };
        }
        if case == "reference" {
            let instance = f.request.admission.instance_ref.clone();
            f.facade.kernel_mut().derive_fact(&instance, "tracker.issue.closed", "foreign-closing",
                &json!({"id": issue, "queue": "elsewhere", "event": "foreign-event", "closed_at": "2026-09-10"}).to_string(), None, None).unwrap();
        }
        let error = f
            .facade
            .execute_tracker_wait(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &f.binding,
            )
            .unwrap_err();
        if case == "reference" {
            assert!(matches!(
                error,
                HostFacadeError::Protocol(ProtocolError::Mismatch(
                    "tracker wait reference names another tracker"
                ))
            ));
        } else if case != "basis" {
            assert!(matches!(
                error,
                HostFacadeError::Protocol(ProtocolError::Mismatch(
                    "tracker wait original resource binding"
                ))
            ));
        }
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
fn governed_tracker_wait_interruption_leaves_no_run_and_retries_after_disk_reopen() {
    for actor in ["person:learner", "agent:assistant"] {
        for event_type in ["effect.terminal", "fact.derived"] {
            let root = std::env::temp_dir().join(format!(
                "whip-wait-atomic-{}-{}",
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
            let (mut f, issue) = wait_fixture_in(
                open(),
                actor,
                |id| json!({"id": id, "queue": "tutorials"}),
                |_| {},
            );
            close_and_project(&mut f, &issue);
            let authority = Authority::new(&f);
            let instance = f.request.admission.instance_ref.clone();
            let before = f.facade.kernel().store().chain_prefix(&instance).unwrap();
            let fault = rusqlite::Connection::open(root.join("runtime.sqlite")).unwrap();
            fault
                .execute_batch(&format!(
                    "CREATE TRIGGER wait_publication_fault AFTER INSERT ON events
                WHEN NEW.event_type = '{event_type}'
                BEGIN SELECT RAISE(ABORT, 'injected wait publication failure'); END;"
                ))
                .unwrap();
            let error = f
                .facade
                .execute_tracker_wait(
                    f.request.clone(),
                    &f.action,
                    &authority,
                    b"execution",
                    &f.binding,
                )
                .unwrap_err();
            assert!(format!("{error:?}").contains("injected wait publication failure"));
            assert_eq!(
                f.facade.kernel().store().chain_prefix(&instance).unwrap(),
                before,
                "a local observation must not leave a started run after rollback"
            );
            assert!(f
                .facade
                .kernel()
                .store()
                .list_runs(&instance)
                .unwrap()
                .is_empty());
            fault
                .execute_batch("DROP TRIGGER wait_publication_fault")
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
            f.facade
                .kernel_mut()
                .store_mut()
                .rebuild_projections(&instance)
                .unwrap();
            assert_eq!(
                f.facade.kernel().store().chain_prefix(&instance).unwrap(),
                before
            );
            let authority = Authority::new(&f);
            f.facade
                .execute_tracker_wait(
                    f.request.clone(),
                    &f.action,
                    &authority,
                    b"execution",
                    &f.binding,
                )
                .unwrap();
            assert_eq!(
                f.facade
                    .kernel()
                    .store()
                    .list_runs(&instance)
                    .unwrap()
                    .len(),
                1
            );
            assert!(f
                .facade
                .kernel()
                .store()
                .list_facts(&instance)
                .unwrap()
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
                    .get_instance(&instance)
                    .unwrap()
                    .unwrap()
                    .status,
                "completed"
            );
            drop(f);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}
