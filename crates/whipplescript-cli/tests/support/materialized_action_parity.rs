//! Public typed-input admission on both storage implementations. The custody
//! authority is a fixture; this does not qualify a product or Worker transport.
use super::*;
use std::cell::Cell;
use whipplescript_kernel::host_facade::{ActionInputResolver, HostFacadeError};
use whipplescript_kernel::host_protocol::action::VerifiedActionAdmission;

fn envelope() -> VerifiedEnvelope {
    let policy = json!({
        "parties": {"person:1": "Member", "agent:1": "Member"},
        "resources": {
            "input:learner": {"reader": "Member", "writer": "Member"},
            "fact:Learner": {"reader": "Member", "writer": "Member"},
            "result": {"reader": "Member", "writer": []},
            "error": {"reader": "Member", "writer": []}
        }
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
    .expect("typed policy fixture");
    VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &FixtureAuthority(vec![]))
        .expect("verified typed policy")
}

struct Custody {
    command: HostActionCommand,
    reads: Cell<usize>,
    erased: Cell<bool>,
    lose_reply: bool,
}
impl ActionInputResolver for Custody {
    fn with_inputs<T>(
        &self,
        admission: &VerifiedActionAdmission,
        consume: impl FnOnce(BTreeMap<String, Value>) -> T,
    ) -> Result<T, HostFacadeError> {
        assert_eq!(admission.command(), &self.command);
        self.reads.set(self.reads.get() + 1);
        assert!(!self.erased.get(), "retry must not reload erased inputs");
        let response = consume(BTreeMap::from([(
            "learner".into(),
            json!({"authority": self.command.provenance.initiator}),
        )]));
        if self.lose_reply {
            return Err(HostFacadeError::Resolver(
                "lost custody reply after publication".into(),
            ));
        }
        Ok(response)
    }
}

fn journey<S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead>(
    store: S,
) -> Vec<Value> {
    let action = CompiledHostAction::compile_materialized_inputs(
        "workflow.launch",
        r#"
workflow Typed(learner: Learner) -> string
class Learner { authority string }
rule begin
  when Learner as learner
=> {
  done learner
  complete result learner.authority
}
"#,
        None,
    )
    .expect("ordinary typed source");
    let mut facade =
        GovernedHostFacade::from_verified_store(store, 7, envelope()).expect("typed facade");
    let mut outcomes = Vec::new();
    for actor in ["person:1", "agent:1"] {
        let command = HostActionCommand {
            protocol: HOST_ACTION_PROTOCOL.into(),
            issuer: "product".into(),
            scope: "workspace:typed".into(),
            request_id: format!("typed:{actor}"),
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
                    version_ref: format!("immutable:{actor}"),
                    label_ref: "label:member".into(),
                },
            )]),
            resources: BTreeMap::new(),
        };
        let authority = FixtureAuthority(command.signing_bytes().expect("typed signing"));
        let custody = Custody {
            command: command.clone(),
            reads: Cell::new(0),
            erased: Cell::new(false),
            lose_reply: actor == "person:1",
        };
        assert!(facade
            .admit_action_with_inputs(command.clone(), &action, &authority, b"forged", &custody,)
            .is_err());
        assert_eq!(custody.reads.get(), 0);
        let first = facade.admit_action_with_inputs(
            command.clone(),
            &action,
            &authority,
            b"fixture-admission",
            &custody,
        );
        let receipt = if custody.lose_reply {
            assert!(first.is_err(), "lost acknowledgement must remain an error");
            custody.erased.set(true);
            facade
                .admit_action_with_inputs(
                    command.clone(),
                    &action,
                    &authority,
                    b"fixture-admission",
                    &custody,
                )
                .expect("recover committed admission without its lost acknowledgement")
        } else {
            first.expect("typed admission")
        };
        receipt.validate_for(&command).expect("bound typed receipt");
        assert_eq!(custody.reads.get(), 1);
        let instance = facade
            .kernel()
            .store()
            .get_instance(&receipt.instance_ref)
            .expect("instance query")
            .expect("instance");
        assert_eq!(
            serde_json::from_str::<Value>(&instance.input_json).expect("retained references"),
            json!(command.inputs)
        );
        let input = facade
            .kernel()
            .store()
            .list_facts(&receipt.instance_ref)
            .expect("input facts")
            .into_iter()
            .find(|fact| fact.name == "Learner")
            .expect("typed fact was admitted atomically");
        assert_eq!(
            serde_json::from_str::<Value>(&input.value_json).expect("typed value"),
            json!({"authority": actor})
        );

        // Reconstruct the embedding context and remove custody availability.
        // Native disk reopening is covered separately; this covers both hosts'
        // shared public API and their actual admission/projection transactions.
        custody.erased.set(true);
        facade = GovernedHostFacade::from_verified_store(
            facade.into_kernel().into_store(),
            7,
            envelope(),
        )
        .expect("reconstructed embedding");
        assert_eq!(
            facade
                .admit_action_with_inputs(
                    command.clone(),
                    &action,
                    &authority,
                    b"fixture-admission",
                    &custody,
                )
                .expect("pre-consumption retry"),
            receipt
        );
        whipplescript_kernel::rule_pass::step_instance_generic(
            facade.kernel_mut(),
            &receipt.instance_ref,
            action.program(),
            None,
            None,
        )
        .expect("consume typed input through ordinary rules");
        facade
            .kernel_mut()
            .store_mut()
            .rebuild_projections(&receipt.instance_ref)
            .expect("rebuild typed projection");
        let facts = facade
            .kernel()
            .store()
            .list_facts(&receipt.instance_ref)
            .expect("active facts");
        assert!(!facts.iter().any(|fact| fact.name == "Learner"));
        assert_eq!(
            facade
                .kernel()
                .store()
                .get_instance(&receipt.instance_ref)
                .expect("terminal query")
                .expect("terminal instance")
                .status,
            "completed"
        );
        let events = facade
            .kernel()
            .store()
            .list_events(&receipt.instance_ref)
            .expect("events");
        assert_eq!(
            facade
                .admit_action_with_inputs(
                    command.clone(),
                    &action,
                    &authority,
                    b"fixture-admission",
                    &custody,
                )
                .expect("post-consumption retry"),
            receipt
        );
        assert_eq!(custody.reads.get(), 1);
        assert_eq!(
            facade
                .kernel()
                .store()
                .list_facts(&receipt.instance_ref)
                .expect("retry facts"),
            facts
        );
        assert_eq!(
            facade
                .kernel()
                .store()
                .list_events(&receipt.instance_ref)
                .expect("retry events"),
            events
        );
        outcomes.push(json!({"instance": receipt.instance_ref, "fingerprint": receipt.fingerprint,
            "command": command, "typed": serde_json::from_str::<Value>(&input.value_json).expect("input")}));
    }
    outcomes
}

#[test]
fn typed_human_and_agent_admission_matches_native_and_deployed_do_schema() {
    let native = journey(NativeStores::open_in_memory().expect("native stores"));
    let hosted = journey(DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()));
    assert_eq!(native, hosted);
}
