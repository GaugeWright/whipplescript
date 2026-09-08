//! The public admitted-action execution door on both runtime stores, using
//! the deployed SQL file backend as its sink. This does not qualify the VCS
//! save adapter, product transport, or a live authentication root.
use serde_json::{json, Value};
#[path = "support/host_action_contract_reports.rs"]
mod host_action_contract_reports;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;
use whipplescript_host_do::{
    do_store::{test_support::RusqliteDoSql, DoSqlStorage, DoSqliteStore},
    DoFileStore,
};
use whipplescript_kernel::gov::{
    ExternalAttestation, GovernanceAttestationVerifier, SignedEnvelope,
};
use whipplescript_kernel::host_action::CompiledHostAction;
use whipplescript_kernel::host_facade::GovernedHostFacade;
use whipplescript_kernel::host_protocol::action::*;
use whipplescript_kernel::host_protocol::execution::*;
use whipplescript_kernel::host_protocol::{PolicyEpochRef, ProtocolError, ResourceRef};
use whipplescript_kernel::ifc::VerifiedEnvelope;
use whipplescript_store::files::FileStore;
use whipplescript_store::native_stores::NativeStores;
use whipplescript_store::{
    coordination::Coordination, items::WorkItems, log_append::LogAppend, vcs::FrontierRead,
    ClaimableEffect, RunStart, RuntimeStore,
};

const SOURCE: &str = r#"use std.files
workflow AdmittedFileSave
input content InputReference
output result Saved
failure error SaveFailed
class InputReference { handle string version_ref string label_ref string }
class Saved { content_hash string }
class SaveFailed { reason string }
file store admitted_input {
  root "/action/input"
  allow read ["content"]
}
file store admitted_target {
  root "/action/output"
  allow write ["target"]
}
rule save
  when InputReference as reference
=> {
  read text from admitted_input at "content" as loaded
  after loaded succeeds as draft {
    write text to admitted_target at "target" {
      body draft.content
      mode upsert
    } as written
    after written succeeds as saved {
      complete result { content_hash saved.content_hash }
    }
    after written fails as failed {
      fail error { reason failed.reason }
    }
  }
  after loaded fails as unavailable {
    fail error { reason unavailable.reason }
  }
}
"#;
const BODY: &str = "an immutable admitted draft";

struct FixtureAuthority {
    signed: Vec<u8>,
    revoked: Cell<bool>,
}
impl GovernanceAttestationVerifier for FixtureAuthority {
    fn verify(&self, _: &[u8], attestation: &ExternalAttestation) -> Result<(), String> {
        if attestation.signature == "execution-fixture" {
            Ok(())
        } else {
            Err("fixture policy signature mismatch".into())
        }
    }
}
impl ActionAdmissionVerifier for FixtureAuthority {
    fn verify(
        &self,
        _: &HostActionCommand,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if bytes == self.signed && proof == b"admission" {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture admission proof"))
        }
    }
}
impl ActionExecutionVerifier for FixtureAuthority {
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
            || original.inputs["content"].version_ref != whipplescript_store::stable_hash_hex(BODY)
            || !matches!(effect.kind.as_str(), "file.read" | "file.write")
        {
            return Err(ProtocolError::Mismatch("fixture current execution ceiling"));
        }
        Ok(())
    }
}

fn authority(bytes: Vec<u8>) -> FixtureAuthority {
    FixtureAuthority {
        signed: bytes,
        revoked: Cell::new(false),
    }
}
fn envelope(epoch: u64) -> VerifiedEnvelope {
    let signed = SignedEnvelope::from_external_signature_v2(
        "grant file_store admitted_input -> file:/action/input readable by Operator\n\
         grant file_store admitted_target -> file:/action/output readable by Operator\n\
         grant output result -> result readable by Operator\n\
         grant output error -> error readable by Operator\n",
        "fixture-signer",
        "fixture",
        "fixture-key",
        "execution-fixture",
        epoch,
        "product",
    )
    .expect("signed policy");
    VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &authority(vec![]))
        .expect("verified policy")
}
struct CountedFiles {
    inner: DoFileStore<DoSqlStorage<RusqliteDoSql>>,
    reads: Cell<usize>,
    writes: Cell<usize>,
    interrupt_write: Cell<bool>,
}
impl FileStore for CountedFiles {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        self.reads.set(self.reads.get() + 1);
        self.inner.read_to_string(path)
    }
    fn exists(&self, path: &Path) -> bool {
        self.inner.exists(path)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.writes.set(self.writes.get() + 1);
        self.inner.write(path, bytes)?;
        assert!(
            !self.interrupt_write.replace(false),
            "interrupt after target application"
        );
        Ok(())
    }
    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        self.writes.set(self.writes.get() + 1);
        self.inner.append(path, bytes)
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        self.writes.set(self.writes.get() + 1);
        self.inner.remove(path)
    }
}
fn register_file_capabilities<S: RuntimeStore>(store: &S) {
    for capability in ["file.read", "file.write"] {
        store
            .register_capability_schema(whipplescript_store::CapabilitySchemaRegistration {
                capability,
                description: "execution fixture",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .expect("register capability");
        store
            .bind_capability(whipplescript_store::CapabilityBinding {
                binding_id: capability,
                program_id: None,
                capability,
                provider: "files",
                config_json: "{}",
            })
            .expect("bind capability");
        store
            .register_effect_provider(whipplescript_store::EffectProviderRegistration {
                provider_id: capability,
                effect_kind: capability,
                provider: "files",
                capability,
                config_json: "{}",
                registered_by_package_id: None,
            })
            .expect("register provider");
    }
}

fn journey<S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead>(
    store: S,
    actor: &str,
    interrupted: bool,
) -> Value {
    register_file_capabilities(&store);
    let action =
        CompiledHostAction::compile("file.save", SOURCE, None).expect("compiled file action");
    let mut facade =
        GovernedHostFacade::from_verified_store(store, 7, envelope(7)).expect("admission facade");
    let command = HostActionCommand {
        protocol: HOST_ACTION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace:1".into(),
        request_id: format!("save:{actor}"),
        operation: "file.save".into(),
        program_version_ref: action.version_ref().into(),
        input_schema_ref: action.input_schema_ref().into(),
        policy: facade.policy_ref().clone(),
        provenance: ActionProvenance {
            initiator: actor.into(),
            executor: actor.into(),
            delegation: vec![],
            origin: "fixture.save".into(),
            causes: vec![],
        },
        inputs: BTreeMap::from([(
            "content".into(),
            ActionInput {
                handle: "admitted_input".into(),
                version_ref: whipplescript_store::stable_hash_hex(BODY),
                label_ref: "private".into(),
            },
        )]),
        resources: BTreeMap::from([(
            "target".into(),
            ActionResource {
                resource: ResourceRef {
                    handle: "admitted_target".into(),
                    kind: "file_store".into(),
                    selector: Some("target".into()),
                    writable: Some(true),
                },
                basis: ActionBasis::Absent,
                label_ref: "private".into(),
            },
        )]),
    };
    assert!(
        facade
            .admit_action(
                command.clone(),
                &action,
                &authority(command.signing_bytes().expect("admission bytes")),
                b"execution",
            )
            .is_err(),
        "execution proof cannot admit an original command"
    );
    assert!(facade
        .kernel()
        .store()
        .list_instances()
        .expect("instances after invalid admission")
        .is_empty());
    let admission = facade
        .admit_action(
            command.clone(),
            &action,
            &authority(command.signing_bytes().expect("admission bytes")),
            b"admission",
        )
        .expect("admit action");
    // Admission remains at epoch seven; current execution independently advances.
    let mut facade =
        GovernedHostFacade::from_verified_store(facade.into_kernel().into_store(), 8, envelope(8))
            .expect("renewed facade");
    let files = CountedFiles {
        inner: DoFileStore::new(DoSqlStorage::new(RusqliteDoSql::with_runtime_schema())),
        reads: Cell::new(0),
        writes: Cell::new(0),
        interrupt_write: Cell::new(false),
    };
    files
        .inner
        .write(Path::new("/action/input/content"), BODY.as_bytes())
        .expect("seed immutable input fixture");
    let mut requests = Vec::new();
    'drive: for _ in 0..8 {
        whipplescript_kernel::rule_pass::step_instance_generic(
            facade.kernel_mut(),
            &admission.instance_ref,
            action.program(),
            None,
            None,
        )
        .expect("ordinary rule pass");
        let effects = facade
            .kernel()
            .claimable_effects(&admission.instance_ref)
            .expect("claimable effects");
        if effects.is_empty() {
            break;
        }
        for effect in effects {
            let before = facade
                .kernel()
                .store()
                .list_events(&admission.instance_ref)
                .expect("before dispatch");
            let run = RunStart {
                instance_id: &admission.instance_ref,
                effect_id: &effect.effect_id,
                run_id: "forged-run",
                provider: "files",
                worker_id: "fixture",
                lease_id: "forged-lease",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: r#"{"action_execution":{"verified":true}}"#,
            };
            assert!(
                facade.kernel_mut().start_run(run).is_err(),
                "an original admission is not current run authority"
            );
            assert!(
                facade.kernel_mut().start_dispatch(run).is_err(),
                "an original admission is not fresh dispatch authority"
            );
            assert!(
                facade
                    .kernel_mut()
                    .start_dispatch_observed(run, &effect)
                    .is_err(),
                "matching the effect is not authentication"
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
                effect_fingerprint: effect_observation_fingerprint(&effect)
                    .expect("effect observation"),
            };
            let verifier = authority(request.signing_bytes().expect("execution bytes"));
            let calls = (files.reads.get(), files.writes.get());
            assert!(
                facade
                    .execute_action_file_effect(
                        request.clone(),
                        &action,
                        &verifier,
                        b"admission",
                        &files
                    )
                    .is_err(),
                "admission proof is not execution proof"
            );
            let mut unavailable = request.clone();
            unavailable.admission.instance_ref = "ins_action_unavailable".into();
            unavailable.admission.admitted_at.instance_ref =
                unavailable.admission.instance_ref.clone();
            let unauthenticated = authority(
                unavailable
                    .signing_bytes()
                    .expect("unavailable request bytes"),
            );
            let error = facade
                .execute_action_file_effect(
                    unavailable,
                    &action,
                    &unauthenticated,
                    b"admission",
                    &files,
                )
                .expect_err("authenticate before stored command inspection");
            assert!(error
                .to_string()
                .contains("fixture execution authentication"));
            verifier.revoked.set(true);
            assert!(
                facade
                    .execute_action_file_effect(
                        request.clone(),
                        &action,
                        &verifier,
                        b"execution",
                        &files
                    )
                    .is_err(),
                "current revocation prevents I/O"
            );
            verifier.revoked.set(false);
            for changed in ["effect", "fingerprint", "admission", "program", "principal"] {
                let mut bad = request.clone();
                match changed {
                    "effect" => bad.effect_id = "unknown-effect".into(),
                    "fingerprint" => bad.effect_fingerprint = "other-input".into(),
                    "admission" => bad.admission.admitted_at.head_digest = "other-prefix".into(),
                    "principal" => {
                        bad.provenance.initiator = "other-principal".into();
                        bad.provenance.delegation[0].delegator = "other-principal".into();
                    }
                    _ => (),
                }
                let wrong_action = CompiledHostAction::compile("different.operation", SOURCE, None)
                    .expect("other registered operation");
                let selected = if changed == "program" {
                    &wrong_action
                } else {
                    &action
                };
                let signed = authority(bad.signing_bytes().expect("changed signing bytes"));
                let error = facade
                    .execute_action_file_effect(bad, selected, &signed, b"execution", &files)
                    .expect_err("changed execution request must refuse");
                if changed == "effect" {
                    assert!(error.to_string().contains("execution effect is not claimable"),
                        "an unavailable effect must be distinguished from a bad signature or mismatched input: {error}");
                }
            }
            assert_eq!(
                (files.reads.get(), files.writes.get()),
                calls,
                "no refused call reaches the sink"
            );
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .list_events(&admission.instance_ref)
                    .expect("after refusals"),
                before
            );
            if interrupted && effect.kind == "file.write" {
                files.interrupt_write.set(true);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    facade.execute_action_file_effect(
                        request.clone(),
                        &action,
                        &verifier,
                        b"execution",
                        &files,
                    )
                }));
                assert!(outcome.is_err(), "interrupt inside the authorized sink");
                requests.push(request);
                break 'drive;
            }
            facade
                .execute_action_file_effect(
                    request.clone(),
                    &action,
                    &verifier,
                    b"execution",
                    &files,
                )
                .expect("currently authorized file effect");
            requests.push(request);
        }
    }
    assert_eq!(
        facade
            .kernel()
            .store()
            .get_instance(&admission.instance_ref)
            .expect("instance")
            .expect("existing instance")
            .status,
        if interrupted { "running" } else { "completed" }
    );
    assert_eq!(
        files
            .inner
            .read_to_string(Path::new("/action/output/target"))
            .expect("saved file"),
        BODY
    );
    assert_eq!((files.reads.get(), files.writes.get()), (1, 1));
    let events = facade
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .expect("execution history");
    let started: Vec<Value> = events
        .iter()
        .filter(|event| event.event_type == "effect.run_started")
        .map(|event| serde_json::from_str(&event.payload_json).expect("run payload"))
        .collect();
    assert_eq!(started.len(), 2);
    for (run, request) in started.iter().zip(&requests) {
        assert_eq!(
            run["external_dispatch"]["frame"]["action_admission"]["fingerprint"],
            command
                .fingerprint()
                .expect("original authorship fingerprint")
        );
        let attempts = whipplescript_store::effect_recovery::fold_attempts(
            &admission.instance_ref,
            &request.effect_id,
            &events,
        )
        .expect("attempt dispositions");
        assert_eq!(
            attempts[0].disposition,
            whipplescript_store::effect_recovery::ExternalDisposition::Unknown,
            "execution authority is not target outcome proof"
        );

        assert_eq!(
            run["metadata"]["action_execution"]["request"],
            serde_json::to_value(request).expect("execution record")
        );
    }
    facade
        .kernel_mut()
        .store_mut()
        .rebuild_projections(&admission.instance_ref)
        .expect("rebuild");
    let mut facade =
        GovernedHostFacade::from_verified_store(facade.into_kernel().into_store(), 8, envelope(8))
            .expect("reopen");
    for request in requests {
        let verifier = authority(request.signing_bytes().expect("retry signing bytes"));
        assert!(
            facade
                .execute_action_file_effect(request, &action, &verifier, b"execution", &files)
                .is_err(),
            "completed action cannot redispatch"
        );
    }
    assert_eq!((files.reads.get(), files.writes.get()), (1, 1));
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .expect("history after reopen"),
        events
    );
    json!({"body": BODY, "reads": files.reads.get(), "writes": files.writes.get(), "attempts": started.len(), "interrupted": interrupted})
}
#[test]
fn admitted_file_execution_has_current_authority_on_both_hosts() {
    for actor in ["person:one", "agent:one"] {
        for interrupted in [false, true] {
            let native = journey(
                NativeStores::open_in_memory().expect("native store"),
                actor,
                interrupted,
            );
            let hosted = journey(
                DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
                actor,
                interrupted,
            );
            assert_eq!(native, hosted);
        }
    }
}

#[test]
fn execution_fixture_rejects_a_forged_policy_signature() {
    let signed = SignedEnvelope::from_external_signature_v2(
        "grant file_store admitted_input -> file:/action/input readable by Operator\n",
        "fixture-signer",
        "fixture",
        "fixture-key",
        "forged-policy",
        8,
        "product",
    )
    .expect("well-formed forged policy");
    assert!(
        VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &authority(vec![])).is_err()
    );
}

#[path = "admitted_file_execution/save_reconciliation.rs"]
mod save_reconciliation;
#[path = "admitted_file_execution/versioned_save.rs"]
mod versioned_save;
