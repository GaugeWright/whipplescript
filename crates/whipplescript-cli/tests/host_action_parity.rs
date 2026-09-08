//! The same compiled action/admission/execution journey on both store hosts.
//! This exercises the public embedding API; the DO half uses its deployed SQL
//! schema. It does not claim to exercise the Worker transport or a file sink.

use serde_json::{json, Value};
#[path = "support/host_action_contract_reports.rs"]
mod host_action_contract_reports;
use std::collections::BTreeMap;
use whipplescript_host_do::do_store::{test_support::RusqliteDoSql, DoSqliteStore};
use whipplescript_kernel::gov::{
    ExternalAttestation, GovernanceAttestationVerifier, SignedEnvelope,
};
use whipplescript_kernel::host_action::CompiledHostAction;
use whipplescript_kernel::host_facade::GovernedHostFacade;
use whipplescript_kernel::host_protocol::action::{
    ActionAdmissionVerifier, ActionInput, ActionProvenance, HostActionCommand, HOST_ACTION_PROTOCOL,
};
use whipplescript_kernel::host_protocol::action_result::{
    ActionInstanceStatus, ActionResultVerifier, ReadActionResult, ACTION_RESULT_PROTOCOL,
};
use whipplescript_kernel::host_protocol::ProtocolError;
use whipplescript_kernel::ifc::VerifiedEnvelope;
use whipplescript_store::log_append::LogAppend;
use whipplescript_store::native_stores::NativeStores;
use whipplescript_store::{
    coordination::Coordination, items::WorkItems, vcs::FrontierRead, RuntimeStore,
};

struct FixtureAuthority(Vec<u8>);
impl GovernanceAttestationVerifier for FixtureAuthority {
    fn verify(&self, _: &[u8], attestation: &ExternalAttestation) -> Result<(), String> {
        if attestation.signature == "fixture-attestation" {
            Ok(())
        } else {
            Err("fixture governance proof mismatch".into())
        }
    }
}
impl ActionAdmissionVerifier for FixtureAuthority {
    fn verify(
        &self,
        _: &HostActionCommand,
        signing: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if signing == self.0 && proof == b"fixture-admission" {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture action proof"))
        }
    }
}

impl ActionResultVerifier for FixtureAuthority {
    fn verify(
        &self,
        _: &ReadActionResult,
        signing: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if signing == self.0 && proof == b"fixture-read" {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture action read proof"))
        }
    }
}

fn journey<S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead>(
    store: S,
) -> Vec<Value> {
    let signed = SignedEnvelope::from_external_signature_v2(
        "grant file_store ledger -> file:/srv/ledger.db readable by Operator\n",
        "fixture-signer",
        "fixture",
        "fixture-key",
        "fixture-attestation",
        7,
        "product",
    )
    .expect("policy fixture");
    let envelope =
        VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &FixtureAuthority(vec![]))
            .expect("verified policy");
    let mut facade = GovernedHostFacade::from_verified_store(store, 7, envelope).expect("facade");
    let action = CompiledHostAction::compile(
        "reference.echo",
        r#"
workflow ParityAction
input content InputReference
output result Result
class InputReference { handle string version_ref string label_ref string }
class Result { handle string }
rule echo
  when InputReference as r
=> { complete result { handle r.handle } }
"#,
        None,
    )
    .expect("ordinary compiled action");
    let mut outcomes = Vec::new();
    for (actor, origin) in [("person:1", "editor.save"), ("agent:1", "tool.call")] {
        let command = HostActionCommand {
            protocol: HOST_ACTION_PROTOCOL.into(),
            issuer: "product".into(),
            scope: "workspace:1".into(),
            request_id: format!("action:{actor}"),
            operation: "reference.echo".into(),
            program_version_ref: action.version_ref().into(),
            input_schema_ref: action.input_schema_ref().into(),
            policy: facade.policy_ref().clone(),
            provenance: ActionProvenance {
                initiator: actor.into(),
                executor: actor.into(),
                delegation: vec![],
                origin: origin.into(),
                causes: vec![],
            },
            inputs: BTreeMap::from([(
                "content".into(),
                ActionInput {
                    handle: "ledger".into(),
                    version_ref: "content:version:1".into(),
                    label_ref: "label:private".into(),
                },
            )]),
            resources: BTreeMap::new(),
        };
        let authority = FixtureAuthority(command.signing_bytes().expect("signing bytes"));
        let count = facade
            .kernel()
            .store()
            .list_instances()
            .expect("instances")
            .len();
        assert!(facade
            .admit_action(command.clone(), &action, &authority, b"forged")
            .is_err());
        assert_eq!(
            facade
                .kernel()
                .store()
                .list_instances()
                .expect("instances")
                .len(),
            count
        );
        let first = facade
            .admit_action(command.clone(), &action, &authority, b"fixture-admission")
            .expect("admit");
        first.validate_for(&command).expect("bound receipt");
        let mut query = ReadActionResult {
            protocol: ACTION_RESULT_PROTOCOL.into(),
            issuer: command.issuer.clone(),
            scope: command.scope.clone(),
            policy: command.policy.clone(),
            provenance: command.provenance.clone(),
            admission: first.clone(),
            evidence_handle: "ledger".into(),
            evidence_label_ref: "label:private".into(),
            through: None,
        };
        let reader = FixtureAuthority(query.signing_bytes().expect("read signing"));
        assert!(facade
            .read_action_result(query.clone(), &reader, b"fixture-admission")
            .is_err());
        let pending = facade
            .read_action_result(query.clone(), &reader, b"fixture-read")
            .expect("pending result");
        host_action_contract_reports::record::<S, _>(actor, "ReadActionResult", &query);
        host_action_contract_reports::record::<S, _>(actor, "ActionResultSnapshot", &pending);
        assert_eq!(pending.instance_status, ActionInstanceStatus::Running);
        assert!(pending.terminal.is_none());
        let before = facade
            .kernel()
            .store()
            .list_events(&first.instance_ref)
            .expect("events");
        assert_eq!(
            facade
                .admit_action(command.clone(), &action, &authority, b"fixture-admission")
                .expect("duplicate"),
            first
        );
        assert_eq!(
            facade
                .kernel()
                .store()
                .list_events(&first.instance_ref)
                .expect("events"),
            before
        );
        let mut changed = command.clone();
        changed.provenance.origin = "another-surface".into();
        let renewed = FixtureAuthority(changed.signing_bytes().expect("changed signing bytes"));
        assert!(facade
            .admit_action(changed, &action, &renewed, b"fixture-admission")
            .is_err());
        whipplescript_kernel::rule_pass::step_instance_generic(
            facade.kernel_mut(),
            &first.instance_ref,
            action.program(),
            None,
            None,
        )
        .expect("ordinary kernel execution");
        let result = facade
            .read_action_result(query.clone(), &reader, b"fixture-read")
            .expect("completed result");
        host_action_contract_reports::record::<S, _>(actor, "ActionResultSnapshot", &result);
        assert_eq!(result.instance_status, ActionInstanceStatus::Completed);
        assert!(result.terminal.is_some());
        assert_eq!(result.admission, first);
        let events = facade
            .kernel()
            .store()
            .list_events(&first.instance_ref)
            .expect("terminal events");
        assert_eq!(
            facade
                .kernel()
                .store()
                .get_instance(&first.instance_ref)
                .expect("instance")
                .expect("recorded")
                .status,
            "completed"
        );
        assert!(facade
            .kernel()
            .store()
            .list_effects(&first.instance_ref)
            .expect("effects")
            .is_empty());
        let admitted: Value = serde_json::from_str(
            &events
                .iter()
                .find(|e| e.event_type == "host.action.admitted")
                .expect("admission event")
                .payload_json,
        )
        .expect("admission payload");
        assert_eq!(
            admitted["command"],
            serde_json::to_value(&command).expect("command")
        );
        let terminal: Value = serde_json::from_str(
            &events
                .iter()
                .find(|e| e.event_type == "workflow.completed")
                .expect("terminal event")
                .payload_json,
        )
        .expect("terminal payload");
        facade
            .kernel_mut()
            .store_mut()
            .rebuild_projections(&first.instance_ref)
            .expect("rebuild");
        assert_eq!(
            facade
                .read_action_result(query.clone(), &reader, b"fixture-read")
                .expect("rebuilt result"),
            result
        );
        query.through = Some(pending.observed_at.clone());
        let historical_reader =
            FixtureAuthority(query.signing_bytes().expect("pinned read signing"));
        assert_eq!(
            facade
                .read_action_result(query, &historical_reader, b"fixture-read")
                .expect("historical pending result"),
            pending
        );
        assert_eq!(
            facade
                .admit_action(command.clone(), &action, &authority, b"fixture-admission")
                .expect("terminal reattachment"),
            first
        );
        assert_eq!(
            facade
                .kernel()
                .store()
                .list_events(&first.instance_ref)
                .expect("events after replay"),
            events
        );
        outcomes.push(
            json!({"instance": first.instance_ref, "fingerprint": first.fingerprint,
            "command": admitted["command"], "terminal": terminal}),
        );
    }
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_instances()
            .expect("instances")
            .len(),
        2
    );
    outcomes
}

#[test]
fn host_action_human_and_agent_journey_matches_on_native_and_deployed_do_schema() {
    let native = journey(NativeStores::open_in_memory().expect("native stores"));
    let hosted = journey(DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()));
    assert_eq!(native, hosted);
}
