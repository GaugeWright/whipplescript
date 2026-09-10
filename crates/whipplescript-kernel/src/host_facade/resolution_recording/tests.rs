//! Actual compiled admission and execution with synthetic host authority. The
//! content observer checks the committed dispatch through a separate connection.
mod recovery;
use super::*;
use crate::{
    gov::{ExternalAttestation, GovernanceAttestationVerifier, SignedEnvelope},
    host_protocol::{
        action::{
            tests::ExactAdmission, ActionInput, ActionProvenance, ActionResource,
            HOST_ACTION_PROTOCOL,
        },
        execution::{effect_observation_fingerprint, ACTION_EXECUTION_PROTOCOL},
        ResourceRef,
    },
    ifc::VerifiedEnvelope,
    resolution_recording::RECORDING_FAILURE,
};
use serde_json::Value;
use std::{
    cell::Cell,
    collections::BTreeMap,
    path::PathBuf,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};
use whipplescript_store::{
    branches::BranchStore, content::ContentStore, file_settlement::RESOLUTION_RECORDING_PROVIDER,
    native_stores::NativeStores, text_merge::RegionResolution, vcs::WorkspaceVcs,
    vcs_resolution_recording::ResolutionRecordingInput, SqliteStore, StoreError, StoreResult,
};

struct Root(PathBuf);
impl Drop for Root {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct PolicyFixture;
impl GovernanceAttestationVerifier for PolicyFixture {
    fn verify(&self, _: &[u8], _: &ExternalAttestation) -> Result<(), String> {
        Ok(())
    }
}
struct Authority {
    bytes: Vec<u8>,
    original: HostActionCommand,
    binding: ResolutionRecordingBinding,
    case: String,
    recording_calls: Cell<usize>,
}
#[cfg(test)]
impl ActionExecutionVerifier for Authority {
    fn authenticate(
        &self,
        _: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if self.case == "authentication" || bytes != self.bytes || proof != b"execute" {
            return Err(ProtocolError::Mismatch(
                "fixture recording authentication denied",
            ));
        }
        Ok(())
    }
    fn authorize(
        &self,
        _: &ExecuteActionEffect,
        original: &HostActionCommand,
        _: &ClaimableEffect,
    ) -> Result<(), ProtocolError> {
        if self.case == "execution-authority" || original != &self.original {
            return Err(ProtocolError::Mismatch(
                "fixture recording execution denied",
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
impl ResolutionRecordingAuthority for Authority {
    fn authorize_recording(
        &self,
        _: &ExecuteActionEffect,
        original: &HostActionCommand,
        _: &ClaimableEffect,
        binding: &ResolutionRecordingBinding,
    ) -> Result<(), ProtocolError> {
        self.recording_calls.set(self.recording_calls.get() + 1);
        if self.case == "memory-authority" || original != &self.original || binding != &self.binding
        {
            return Err(ProtocolError::Mismatch(
                "fixture exact input or memory authority denied",
            ));
        }
        Ok(())
    }
}

struct ObservedContent {
    inner: ContentStore,
    runtime: SqliteStore,
    instance: String,
    binding: ResolutionRecordingBinding,
    calls: Rc<Cell<usize>>,
    failure: String,
}
impl ObservedContent {
    fn observe(&self) {
        self.calls.set(self.calls.get() + 1);
        let prefix = self
            .runtime
            .chain_prefix(&self.instance)
            .expect("committed runtime prefix");
        let dispatch = prefix
            .iter()
            .find(|entry| entry.event_type == "effect.run_started")
            .expect("dispatch is committed before content access");
        let payload: Value =
            serde_json::from_str(&dispatch.payload_json).expect("dispatch payload");
        assert_eq!(
            payload["metadata"]["resolution_recording"],
            json!(self.binding)
        );
        assert!(payload["metadata"]["action_execution"]["request"].is_object());
        assert!(!prefix
            .iter()
            .any(|entry| entry.event_type == "effect.terminal"));
    }
}
#[cfg(test)]
impl ContentBlobs for ObservedContent {
    fn put(&self, body: &[u8]) -> StoreResult<String> {
        self.observe();
        if self.failure == "target-failure" {
            return Err(StoreError::Conflict("SECRET_BACKEND_DETAIL".into()));
        }
        self.inner.put(body)
    }
    fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
        self.observe();
        self.inner.get(id)
    }
    fn publish_retained<T>(
        &self,
        ids: &[String],
        publish: impl FnOnce() -> StoreResult<T>,
    ) -> StoreResult<T> {
        self.observe();
        if self.failure == "interrupt-before-publication" {
            panic!("interrupt before target commit");
        }
        let result = self.inner.publish_retained(ids, publish)?;
        if self.failure == "interrupt-after-publication" {
            panic!("interrupt after target commit");
        }
        if self.failure == "failure-after-publication" {
            return Err(StoreError::Conflict("SECRET_BACKEND_DETAIL".into()));
        }
        Ok(result)
    }
}

struct Fixture {
    facade: GovernedHostFacade<NativeStores>,
    action: ResolutionRecordingAction,
    request: ExecuteActionEffect,
    authority: Authority,
    target: BoundResolutionRecording<BranchStore, ObservedContent>,
    branches: BranchStore,
    calls: Rc<Cell<usize>>,
    _root: Root,
}
impl Fixture {
    fn execute(&mut self) -> Result<StoredEvent, HostFacadeError> {
        self.facade.execute_resolution_recording(
            self.request.clone(),
            &self.action,
            &self.authority,
            b"execute",
            &mut self.target,
        )
    }
}

fn setup(case: &str, actor: &str) -> Fixture {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = Root(std::env::temp_dir().join(format!(
        "whip-recording-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir_all(&root.0).expect("fixture root");
    let runtime = root.0.join("runtime.sqlite");
    let store = NativeStores::open(
        &runtime,
        root.0.join("coord.sqlite"),
        root.0.join("items.sqlite"),
    )
    .expect("runtime");
    store
        .register_capability_schema(whipplescript_store::CapabilitySchemaRegistration {
            capability: RESOLUTION_RECORDING_CAPABILITY,
            description: "fixture",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .expect("declare capability");
    store
        .bind_capability(whipplescript_store::CapabilityBinding {
            binding_id: "recording",
            program_id: None,
            capability: RESOLUTION_RECORDING_CAPABILITY,
            provider: RESOLUTION_RECORDING_PROVIDER,
            config_json: "{}",
        })
        .expect("explicit host binding");
    let mut policy = json!({"resources": {"memory:/corrections": {}, "memory:/resolutions": {}, "result": {}, "error": {}},
        "bindings": {"admitted_corrections": "memory:/corrections", "admitted_resolutions": "memory:/resolutions"}});
    match case {
        "input-confidentiality" => {
            policy["resources"]["memory:/corrections"]["reader"] = json!(["Private"])
        }
        "input-integrity" => {
            policy["resources"]["memory:/resolutions"]["writer_sink"] = json!(["Trusted"])
        }
        "result-confidentiality" | "error-confidentiality" => {
            for name in ["memory:/resolutions", "result", "error"] {
                policy["resources"][name]["reader"] = json!(["Private"]);
            }
            policy["resources"][if case == "result-confidentiality" {
                "result"
            } else {
                "error"
            }]["reader"] = json!([]);
        }
        "result-integrity" | "error-integrity" => {
            policy["resources"][if case == "result-integrity" {
                "result"
            } else {
                "error"
            }]["writer_sink"] = json!(["Trusted"]);
        }
        _ => {}
    }
    let signed = SignedEnvelope::from_external_signature_v2(
        &policy.to_string(),
        "fixture",
        "fixture",
        "fixture",
        "fixture",
        7,
        "product",
    )
    .expect("signed policy");
    let envelope = VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &PolicyFixture)
        .expect("verify fixture policy");
    let mut facade = GovernedHostFacade::from_verified_store(store, 7, envelope).expect("facade");
    let action = ResolutionRecordingAction::compile().expect("fixed recording workflow");
    let input = serde_json::to_string(
        &ResolutionRecordingInput::new(vec![RegionResolution {
            base_text: "BASE_PRIVATE".into(),
            ours_text: "OURS_PRIVATE".into(),
            theirs_text: "THEIRS_PRIVATE".into(),
            resolution_text: "SECRET_CORRECTION".into(),
        }])
        .expect("input"),
    )
    .expect("input JSON");
    let scope =
        ResolutionMemoryScope::new("home".into(), "target:path".into(), "compartment".into())
            .expect("scope");
    let mut command = HostActionCommand {
        protocol: HOST_ACTION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace".into(),
        request_id: "request".into(),
        operation: RECORDING_OPERATION.into(),
        program_version_ref: action.action().version_ref().into(),
        input_schema_ref: action.action().input_schema_ref().into(),
        policy: facade.policy_ref().clone(),
        provenance: ActionProvenance {
            initiator: actor.into(),
            executor: actor.into(),
            delegation: vec![],
            origin: "fixture".into(),
            causes: vec![],
        },
        inputs: BTreeMap::from([(
            "corrections".into(),
            ActionInput {
                handle: "admitted_corrections".into(),
                version_ref: whipplescript_store::stable_hash_hex(&input),
                label_ref: "input-label".into(),
            },
        )]),
        resources: BTreeMap::from([(
            "resolutions".into(),
            ActionResource {
                resource: ResourceRef {
                    handle: "admitted_resolutions".into(),
                    kind: "resolution_memory".into(),
                    writable: Some(true),
                    selector: Some(serde_json::to_string(&scope).expect("scope selector")),
                },
                basis: ActionBasis::Version {
                    version_ref: scope.version_ref(),
                },
                label_ref: "memory-label".into(),
            },
        )]),
    };
    match case {
        "missing-memory" => {
            command.resources.clear();
        }
        "readonly" => {
            command
                .resources
                .get_mut("resolutions")
                .expect("memory")
                .resource
                .writable = Some(false)
        }
        "wrong-kind" => {
            command
                .resources
                .get_mut("resolutions")
                .expect("memory")
                .resource
                .kind = "file_store".into()
        }
        "wrong-scope" => {
            command
                .resources
                .get_mut("resolutions")
                .expect("memory")
                .resource
                .selector = Some("{}".into())
        }
        "wrong-version" => {
            command
                .resources
                .get_mut("resolutions")
                .expect("memory")
                .basis = ActionBasis::Version {
                version_ref: "other".into(),
            }
        }
        "wrong-label" => {
            command
                .inputs
                .get_mut("corrections")
                .expect("input")
                .label_ref = "other-label".into()
        }
        _ => {}
    }
    let admission = facade
        .admit_action(
            command.clone(),
            action.action(),
            &ExactAdmission(command.signing_bytes().expect("sign command")),
            b"authenticated fixture",
        )
        .expect("actual admission");
    crate::rule_pass::step_instance_generic(
        facade.kernel_mut(),
        &admission.instance_ref,
        action.action().program(),
        None,
        None,
    )
    .expect("ordinary lowering");
    let effect = facade
        .kernel()
        .claimable_effects(&admission.instance_ref)
        .expect("claimable effects")
        .into_iter()
        .next()
        .expect("recording call");
    let request = ExecuteActionEffect {
        protocol: ACTION_EXECUTION_PROTOCOL.into(),
        issuer: command.issuer.clone(),
        scope: command.scope.clone(),
        admission,
        policy: facade.policy_ref().clone(),
        provenance: command.provenance.clone(),
        effect_id: effect.effect_id.clone(),
        effect_fingerprint: effect_observation_fingerprint(&effect).expect("effect fingerprint"),
    };
    let operation = recording_operation_id(&request.admission.instance_ref, &effect.effect_id);
    let intent = command.fingerprint().expect("intent");
    let binding = ResolutionRecordingBinding::prepare(
        &input,
        "input-label",
        scope.clone(),
        &operation,
        actor,
        &intent,
        "2026-09-10T12:00:00Z",
    )
    .expect("binding");
    let authority = Authority {
        bytes: request.signing_bytes().expect("execution bytes"),
        original: command,
        binding: binding.clone(),
        case: case.into(),
        recording_calls: Cell::new(0),
    };
    let input = if case == "wrong-input" {
        input.replace("SECRET_CORRECTION", "OTHER_SECRET_CORRECTION")
    } else {
        input
    };
    let binding = ResolutionRecordingBinding::prepare(
        &input,
        "input-label",
        scope,
        if case == "wrong-operation" {
            "other-operation"
        } else {
            &operation
        },
        if case == "wrong-actor" {
            "other-actor"
        } else {
            actor
        },
        if case == "wrong-intent" {
            "other-intent"
        } else {
            &intent
        },
        "2026-09-10T12:00:00Z",
    )
    .expect("actual adapter binding");
    let calls = Rc::new(Cell::new(0));
    let branch_path = root.0.join("branches.sqlite");
    let branches = BranchStore::open(&branch_path).expect("branch store");
    let content = ObservedContent {
        inner: ContentStore::open(root.0.join("content.sqlite")).expect("content store"),
        runtime: SqliteStore::open(&runtime).expect("independent runtime observer"),
        instance: request.admission.instance_ref.clone(),
        binding: binding.clone(),
        calls: calls.clone(),
        failure: case.into(),
    };
    let target =
        BoundResolutionRecording::new(WorkspaceVcs::from_parts(branches, content), binding, &input)
            .expect("I/O-free adapter");
    assert_eq!(calls.get(), 0);
    Fixture {
        facade,
        action,
        request,
        authority,
        target,
        branches: BranchStore::open_read_only(&branch_path).expect("target observer"),
        calls,
        _root: root,
    }
}

#[test]
fn governed_recording_retains_original_dispatch_then_settles_for_both_actors() {
    for actor in ["human:one", "agent:one"] {
        for case in ["success", "target-failure", "failure-after-publication"] {
            let mut f = setup(case, actor);
            f.execute().expect("recording settles");
            assert!(f.calls.get() > 0);
            let status = if case == "success" {
                "completed"
            } else {
                "failed"
            };
            let instance = &f.request.admission.instance_ref;
            let receipt = f
                .branches
                .resolution_batch(&f.target.binding().batch().operation_id)
                .expect("target receipt");
            assert_eq!(receipt.is_some(), case != "target-failure");
            if let Some(receipt) = receipt {
                assert_eq!(receipt.request, *f.target.binding().batch());
            }
            assert_eq!(
                f.facade.kernel().store().list_runs(instance).expect("runs")[0].status,
                status
            );
            let history = f
                .facade
                .kernel()
                .store()
                .list_events(instance)
                .expect("history");
            let text = format!("{history:?}");
            for secret in [
                "SECRET_CORRECTION",
                "SECRET_BACKEND_DETAIL",
                "BASE_PRIVATE",
                "OURS_PRIVATE",
                "THEIRS_PRIVATE",
            ] {
                assert!(!text.contains(secret), "history leaked {secret}");
            }
            if case != "success" {
                assert!(text.contains(RECORDING_FAILURE));
            }
            let attempts = whipplescript_store::effect_recovery::fold_attempts(
                instance,
                &f.request.effect_id,
                &history,
            )
            .expect("attempt disposition");
            assert_eq!(
                attempts[0].disposition,
                whipplescript_store::effect_recovery::ExternalDisposition::Unknown
            );
            crate::rule_pass::step_instance_generic(
                f.facade.kernel_mut(),
                instance,
                f.action.action().program(),
                None,
                None,
            )
            .expect("ordinary continuation");
            assert_eq!(
                f.facade
                    .kernel()
                    .store()
                    .get_instance(instance)
                    .expect("instance")
                    .expect("exists")
                    .status,
                status
            );
            let calls = f.calls.get();
            assert!(f.execute().is_err(), "settled effect cannot execute again");
            assert_eq!(f.calls.get(), calls);
        }
    }
}

#[test]
fn governed_recording_refuses_authority_binding_and_raw_flows_before_dispatch() {
    for actor in ["human:one", "agent:one"] {
        for case in [
            "authentication",
            "execution-authority",
            "memory-authority",
            "wrong-input",
            "missing-memory",
            "readonly",
            "wrong-kind",
            "wrong-scope",
            "wrong-version",
            "wrong-label",
            "wrong-operation",
            "wrong-actor",
            "wrong-intent",
            "input-confidentiality",
            "input-integrity",
            "result-confidentiality",
            "error-confidentiality",
            "result-integrity",
            "error-integrity",
        ] {
            let mut f = setup(case, actor);
            let before = f
                .facade
                .kernel()
                .store()
                .list_events(&f.request.admission.instance_ref)
                .expect("before");
            let error = f.execute().expect_err("must refuse");
            let expected = match case {
                "authentication" => "fixture recording authentication denied",
                "execution-authority" => "fixture recording execution denied",
                "memory-authority" | "wrong-input" => {
                    "fixture exact input or memory authority denied"
                }
                "missing-memory" => "recording requires admitted corrections and resolutions",
                value if value.ends_with("confidentiality") || value.ends_with("integrity") => {
                    assert!(
                        matches!(error, HostFacadeError::PolicyRejected(_)),
                        "{case}: {error:?}"
                    );
                    ""
                }
                _ => "recording command does not bind the target adapter",
            };
            if !expected.is_empty() {
                assert!(
                    matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message)) if message == expected),
                    "{case}: {error:?}"
                );
            }
            assert_eq!(f.calls.get(), 0, "{case}");
            assert_eq!(
                f.facade
                    .kernel()
                    .store()
                    .list_events(&f.request.admission.instance_ref)
                    .expect("after"),
                before,
                "{case}"
            );
            assert!(
                f.branches
                    .resolution_batch(&f.target.binding().batch().operation_id)
                    .expect("receipt")
                    .is_none(),
                "{case}"
            );
        }
    }
}

#[test]
fn recording_profile_checks_the_actual_lowered_reference_and_capability() {
    let f = setup("success", "human:one");
    let original = &f.authority.original;
    let effect = f
        .facade
        .kernel()
        .claimable_effects(&f.request.admission.instance_ref)
        .expect("effects")
        .remove(0);
    for case in [
        "kind",
        "target",
        "capabilities",
        "reference",
        "extra-binding",
    ] {
        let mut changed = effect.clone();
        let mut input: Value = serde_json::from_str(&changed.input_json).expect("input");
        match case {
            "kind" => changed.kind = "file.write".into(),
            "target" => changed.target = Some("vcs.promote".into()),
            "capabilities" => changed.required_capabilities_json = "[]".into(),
            "reference" => input["bindings"]["reference"]["version_ref"] = json!("other"),
            "extra-binding" => input["bindings"]["extra"] = json!("unexamined"),
            _ => unreachable!(),
        }
        changed.input_json = input.to_string();
        let error = resources(original, &f.request, &changed, f.target.binding())
            .expect_err("exact call refuses substitution");
        assert_eq!(
            error,
            ProtocolError::Mismatch("recording effect differs from its admitted reference"),
            "{case}"
        );
    }
}

#[test]
fn governed_recording_interruption_retains_uncertainty_and_clears_the_execution_grant() {
    for actor in ["human:one", "agent:one"] {
        for case in [
            "interrupt-before-publication",
            "interrupt-after-publication",
        ] {
            let mut f = setup(case, actor);
            let interrupted =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f.execute()));
            assert!(interrupted.is_err());
            assert!(f.facade.kernel().action_execution.is_none());
            let instance = &f.request.admission.instance_ref;
            let receipt = f
                .branches
                .resolution_batch(&f.target.binding().batch().operation_id)
                .expect("original target outcome");
            assert_eq!(receipt.is_some(), case == "interrupt-after-publication");
            let events = f
                .facade
                .kernel()
                .store()
                .list_events(instance)
                .expect("interrupted history");
            assert!(!events
                .iter()
                .any(|event| event.event_type == "effect.terminal"));
            let attempts = whipplescript_store::effect_recovery::fold_attempts(
                instance,
                &f.request.effect_id,
                &events,
            )
            .expect("attempts");
            assert_eq!(
                attempts[0].disposition,
                whipplescript_store::effect_recovery::ExternalDisposition::Unknown
            );
            let calls = f.calls.get();
            assert!(
                f.execute().is_err(),
                "an unresolved attempt cannot be blindly repeated"
            );
            assert_eq!(calls, f.calls.get());
        }
    }
}

#[test]
fn recording_content_observer_satisfies_the_content_contract() {
    let mut fixture = setup("interrupt-before-publication", "human:one");
    // Leave a real authenticated dispatch open. The observer's ordering checks
    // remain enabled during every conformance read and write.
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fixture.execute())).is_err());
    whipplescript_store::content::conformance::run_suite(|| ObservedContent {
        inner: ContentStore::open(":memory:").expect("fresh content store"),
        runtime: SqliteStore::open(fixture._root.0.join("runtime.sqlite"))
            .expect("dispatch observer"),
        instance: fixture.request.admission.instance_ref.clone(),
        binding: fixture.target.binding().clone(),
        calls: Rc::new(Cell::new(0)),
        failure: "success".into(),
    })
    .expect("observing adapter content conformance");
}
