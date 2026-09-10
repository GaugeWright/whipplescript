//! One governed recording journey on native and deployed DO SQL schemas. Host
//! authentication is synthetic; this does not qualify product transport.
#[path = "support/host_action_contract_reports.rs"]
mod host_action_contract_reports;
use host_action_contract_reports::record_recording as record;
use serde_json::json;
use std::collections::BTreeMap;
use whipplescript_host_do::{
    do_branches::{compose_vcs_shared, DoBranches, DoContentBlobs},
    do_store::{test_support::RusqliteDoSql, DoSqliteStore},
};
use whipplescript_kernel::{
    gov::{ExternalAttestation, GovernanceAttestationVerifier, SignedEnvelope},
    host_facade::{
        GovernedHostFacade, ResolutionRecordingAuthority, ResolutionRecordingEvidenceSource,
        ResolutionRecordingReconciliationAuthority,
    },
    host_protocol::{
        action::*, action_result::*, execution::*, recovery::*, ProtocolError, ResourceRef,
    },
    ifc::VerifiedEnvelope,
    resolution_recording::{
        recording_operation_id, ResolutionRecordingAction, RECORDING_OPERATION,
    },
};
use whipplescript_store::{
    branches::{
        resolution_batch::ResolutionMemoryReceipt, BranchStore, Branches, MAINLINE_BRANCH_ID,
    },
    content::{ContentBlobs, ContentStore},
    coordination::Coordination,
    effect_recovery::{
        fold_attempts, DispositionEvidence, EvidenceDisposition, ExternalDisposition,
    },
    file_settlement::{RESOLUTION_RECORDING_CAPABILITY, RESOLUTION_RECORDING_PROVIDER},
    items::{sha256_hex, WorkItems},
    log_append::LogAppend,
    native_stores::NativeStores,
    vcs::{FrontierRead, WorkspaceVcs},
    vcs_resolution_recording::{
        conformance::{input, scope},
        BoundResolutionRecording, ResolutionRecordingBinding, ResolutionRecordingInput,
    },
    ClaimableEffect, RuntimeStore,
};

struct Policy;
impl GovernanceAttestationVerifier for Policy {
    fn verify(&self, _: &[u8], _: &ExternalAttestation) -> Result<(), String> {
        Ok(())
    }
}
struct Authority {
    original: HostActionCommand,
    execution: ExecuteActionEffect,
    binding: ResolutionRecordingBinding,
    investigator: ActionProvenance,
}
struct Admission(HostActionCommand);
struct PostCommitContent<C> {
    inner: C,
    mode: &'static str,
}
#[cfg(test)]
impl<C: ContentBlobs> ContentBlobs for PostCommitContent<C> {
    fn put(&self, body: &[u8]) -> whipplescript_store::StoreResult<String> {
        self.inner.put(body)
    }
    fn get(&self, id: &str) -> whipplescript_store::StoreResult<Option<Vec<u8>>> {
        self.inner.get(id)
    }
    fn publish_retained<T>(
        &self,
        ids: &[String],
        publish: impl FnOnce() -> whipplescript_store::StoreResult<T>,
    ) -> whipplescript_store::StoreResult<T> {
        let result = self.inner.publish_retained(ids, publish)?;
        if self.mode == "interrupted" {
            panic!("interrupt after target commit");
        }
        if self.mode == "failed" {
            return Err(whipplescript_store::StoreError::Conflict(
                "private backend failure".into(),
            ));
        }
        Ok(result)
    }
}

#[test]
fn post_commit_content_satisfies_native_and_hosted_content_contracts() {
    whipplescript_store::content::conformance::run_suite(|| PostCommitContent {
        inner: ContentStore::open(":memory:").expect("native content"),
        mode: "success",
    })
    .expect("native observing content conformance");
    whipplescript_store::content::conformance::run_suite(|| PostCommitContent {
        inner: DoContentBlobs::new(RusqliteDoSql::with_runtime_schema()).expect("hosted content"),
        mode: "success",
    })
    .expect("hosted observing content conformance");
}

#[cfg(test)]
impl ResolutionRecordingReconciliationAuthority for Authority {
    fn authenticate(
        &self,
        command: &ReconcileEffectCommand,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if command.issuer == self.original.issuer
            && command.scope == self.original.scope
            && command.provenance == self.investigator
            && bytes == command.signing_bytes()?
            && proof == b"recover"
        {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch(
                "fixture current recording recovery authority",
            ))
        }
    }
    fn authorize(
        &self,
        _: &ReconcileEffectCommand,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        binding: &ResolutionRecordingBinding,
    ) -> Result<(), ProtocolError> {
        if original == &self.original && execution == &self.execution && binding == &self.binding {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch(
                "fixture exact historical recording authority",
            ))
        }
    }
}

#[cfg(test)]
impl ActionResultVerifier for Authority {
    fn verify(
        &self,
        request: &ReadActionResult,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request.issuer == self.original.issuer
            && request.scope == self.original.scope
            && request.admission == self.execution.admission
            && request.provenance == self.investigator
            && request.evidence_handle == "resolutions_ref"
            && request.evidence_label_ref == "memory-label"
            && bytes == request.signing_bytes()?
            && proof == b"inspect"
        {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch(
                "fixture current recording investigation authority",
            ))
        }
    }
}

fn recover<S: RuntimeStore + LogAppend, B: Branches, C: ContentBlobs>(
    facade: &mut GovernedHostFacade<S>,
    action: &ResolutionRecordingAction,
    authority: &Authority,
    workspace: &WorkspaceVcs<B, C>,
    batch: &ResolutionMemoryReceipt,
    scenario: &str,
) {
    let instance = &authority.execution.admission.instance_ref;
    let effect = &authority.execution.effect_id;
    let before = facade
        .kernel()
        .store()
        .list_events(instance)
        .expect("events before recovery");
    let attempts = fold_attempts(instance, effect, &before).expect("attempts");
    assert_eq!(attempts[0].disposition, ExternalDisposition::Unknown);
    let command = ReconcileEffectCommand {
        protocol: EFFECT_RECONCILIATION_PROTOCOL.into(),
        issuer: authority.original.issuer.clone(),
        scope: authority.original.scope.clone(),
        request_id: "recover".into(),
        policy: facade.policy_ref().clone(),
        provenance: authority.investigator.clone(),
        evidence_label_ref: "memory-label".into(),
        evidence: DispositionEvidence {
            frame: attempts[0]
                .dispatch
                .as_ref()
                .expect("dispatch")
                .frame
                .clone(),
            disposition: EvidenceDisposition::Applied,
            evidence_ref: "resolutions_ref".into(),
            authority_ref: "target-authority".into(),
            evidence_digest: sha256_hex(&batch.encode().expect("proof JSON").0),
        },
    };
    let source = ResolutionRecordingEvidenceSource {
        action,
        admission: &authority.execution.admission,
        workspace,
        authority_ref: "target-authority",
    };
    let epoch = facade
        .kernel_mut()
        .store_mut()
        .claim_instance_ownership(instance)
        .expect("ownership");
    let runs = facade.kernel().store().list_runs(instance).expect("runs");
    let facts = facade.kernel().store().list_facts(instance).expect("facts");
    let state = facade
        .kernel()
        .store()
        .get_instance(instance)
        .expect("state");
    let receipt = facade
        .reconcile_resolution_recording(command.clone(), epoch, &source, authority, b"recover")
        .expect("governed historical recovery");
    record::<S, _>(scenario, "ReconcileEffectCommand", &command);
    record::<S, _>(scenario, "ReconciliationReceipt", &receipt);
    let after = facade
        .kernel()
        .store()
        .list_events(instance)
        .expect("reconciled");
    assert_eq!(after.len(), before.len() + 1);
    let reconciled: RecordedReconciliation =
        serde_json::from_str(&after.last().expect("new evidence").payload_json)
            .expect("recorded reconciliation");
    assert_eq!(reconciled.command.provenance, authority.investigator);
    assert_ne!(reconciled.command.provenance.executor, batch.request.actor);
    assert_eq!(batch.request.actor, authority.execution.provenance.executor);
    assert_eq!(
        fold_attempts(instance, effect, &after).expect("applied evidence")[0].disposition,
        ExternalDisposition::Applied
    );
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_runs(instance)
            .expect("same runs"),
        runs
    );
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_facts(instance)
            .expect("same facts"),
        facts
    );
    assert_eq!(
        facade
            .kernel()
            .store()
            .get_instance(instance)
            .expect("same state"),
        state
    );
    facade
        .kernel_mut()
        .store_mut()
        .rebuild_projections(instance)
        .expect("rebuild from events");
    assert_eq!(
        facade
            .reconcile_resolution_recording(command.clone(), epoch, &source, authority, b"recover")
            .expect("redelivery"),
        receipt
    );
    assert!(facade
        .reconcile_resolution_recording(command, epoch, &source, authority, b"revoked")
        .is_err());
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(instance)
            .expect("same history"),
        after
    );
    let query = ReadActionResult {
        protocol: ACTION_RESULT_PROTOCOL.into(),
        issuer: authority.original.issuer.clone(),
        scope: authority.original.scope.clone(),
        policy: facade.policy_ref().clone(),
        provenance: authority.investigator.clone(),
        admission: authority.execution.admission.clone(),
        evidence_handle: "resolutions_ref".into(),
        evidence_label_ref: "memory-label".into(),
        through: None,
    };
    let snapshot = facade
        .read_action_result(query.clone(), authority, b"inspect")
        .expect("governed investigation");
    assert_eq!(snapshot.command.provenance, authority.original.provenance);
    assert_eq!(snapshot.effects.len(), 1);
    assert_eq!(
        snapshot.effects[0].attempts[0].disposition,
        ExternalDisposition::Applied
    );
    let mode = scenario.rsplit_once('/').expect("scenario mode").1;
    assert_eq!(
        snapshot.instance_status,
        match mode {
            "interrupted" => ActionInstanceStatus::Running,
            "failed" => ActionInstanceStatus::Failed,
            _ => ActionInstanceStatus::Completed,
        }
    );
    assert_eq!(snapshot.terminal.is_some(), mode != "interrupted");
    assert_eq!(
        snapshot.effects[0].attempts[0].terminal_status.as_deref(),
        match mode {
            "interrupted" => None,
            "failed" => Some("failed"),
            _ => Some("completed"),
        }
    );
    assert!(!serde_json::to_string(&snapshot)
        .expect("snapshot JSON")
        .contains("human correction"));
    record::<S, _>(scenario, "ReadActionResult", &query);
    record::<S, _>(scenario, "ActionResultSnapshot", &snapshot);
    assert!(facade
        .read_action_result(query, authority, b"revoked")
        .is_err());
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(instance)
            .expect("investigation does not append"),
        after
    );
}

#[cfg(test)]
impl ActionAdmissionVerifier for Admission {
    fn verify(
        &self,
        command: &HostActionCommand,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if command == &self.0 && bytes == command.signing_bytes()? && proof == b"admit" {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture recording admission"))
        }
    }
}
#[cfg(test)]
impl ActionExecutionVerifier for Authority {
    fn authenticate(
        &self,
        request: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request == &self.execution && bytes == request.signing_bytes()? && proof == b"execute" {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch("fixture recording execution"))
        }
    }
    fn authorize(
        &self,
        _: &ExecuteActionEffect,
        original: &HostActionCommand,
        _: &ClaimableEffect,
    ) -> Result<(), ProtocolError> {
        if original == &self.original {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch(
                "fixture recording original ceiling",
            ))
        }
    }
}
#[cfg(test)]
impl ResolutionRecordingAuthority for Authority {
    fn authorize_recording(
        &self,
        _: &ExecuteActionEffect,
        _: &HostActionCommand,
        _: &ClaimableEffect,
        binding: &ResolutionRecordingBinding,
    ) -> Result<(), ProtocolError> {
        if binding == &self.binding {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch(
                "fixture recording exact input and target",
            ))
        }
    }
}

fn journey<S, B, C>(
    store: S,
    mut target: impl FnMut() -> (B, C),
    mode: &'static str,
    observer: &WorkspaceVcs<B, C>,
) -> Vec<ResolutionMemoryReceipt>
where
    S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead,
    B: Branches,
    C: ContentBlobs,
{
    let (branches, content) = target();
    WorkspaceVcs::from_parts(branches, content)
        .init("2026-09-10T12:00:00Z")
        .expect("initialize workspace");
    let head = observer
        .get_branch(MAINLINE_BRANCH_ID)
        .expect("mainline")
        .expect("exists")
        .head_cut_id;
    let manifest = include_str!("../../../std/manifests/vcs.json");
    store
        .register_package_manifest(manifest)
        .expect("actual std.vcs capability declaration");
    let manifest: serde_json::Value = serde_json::from_str(manifest).expect("manifest");
    for field in ["providers", "bindings"] {
        assert!(
            manifest[field]
                .as_array()
                .expect("manifest array")
                .iter()
                .all(|entry| entry["capability"] != RESOLUTION_RECORDING_CAPABILITY),
            "recording has no ambient or fixture binding"
        );
    }
    store
        .bind_capability(whipplescript_store::CapabilityBinding {
            binding_id: "recording",
            program_id: None,
            capability: RESOLUTION_RECORDING_CAPABILITY,
            provider: RESOLUTION_RECORDING_PROVIDER,
            config_json: "{}",
        })
        .expect("explicit confined binding");
    let policy = json!({"resources": {"memory:/corrections": {}, "memory:/resolutions": {}, "result": {}, "error": {}},
        "bindings": {"corrections_ref": "memory:/corrections", "resolutions_ref": "memory:/resolutions"}});
    let signed = SignedEnvelope::from_external_signature_v2(
        &policy.to_string(),
        "fixture",
        "fixture",
        "fixture",
        "fixture",
        7,
        "product",
    )
    .expect("policy");
    let envelope = VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &Policy)
        .expect("fixture policy");
    let mut facade = GovernedHostFacade::from_verified_store(store, 7, envelope).expect("facade");
    let action = ResolutionRecordingAction::compile().expect("recording profile");
    let mut receipts = Vec::new();
    for (actor, body) in [
        ("human:one", "first human correction"),
        ("agent:one", "later agent correction"),
    ] {
        let scenario = format!("{actor}/{mode}");
        let input = input(body);
        record::<S, _>(
            &scenario,
            "ResolutionRecordingInput",
            &serde_json::from_str::<ResolutionRecordingInput>(&input)
                .expect("actual correction input"),
        );
        let scope = scope();
        let command = HostActionCommand {
            protocol: HOST_ACTION_PROTOCOL.into(),
            issuer: "product".into(),
            scope: "workspace".into(),
            request_id: actor.into(),
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
                    handle: "corrections_ref".into(),
                    version_ref: whipplescript_store::stable_hash_hex(&input),
                    label_ref: "input-label".into(),
                },
            )]),
            resources: BTreeMap::from([(
                "resolutions".into(),
                ActionResource {
                    resource: ResourceRef {
                        handle: "resolutions_ref".into(),
                        kind: "resolution_memory".into(),
                        selector: Some(serde_json::to_string(&scope).expect("scope")),
                        writable: Some(true),
                    },
                    basis: ActionBasis::Version {
                        version_ref: scope.version_ref(),
                    },
                    label_ref: "memory-label".into(),
                },
            )]),
        };
        let admission = facade
            .admit_action(
                command.clone(),
                action.action(),
                &Admission(command.clone()),
                b"admit",
            )
            .expect("actual admission");
        record::<S, _>(&scenario, "HostActionCommand", &command);
        record::<S, _>(&scenario, "ActionAdmissionReceipt", &admission);
        whipplescript_kernel::rule_pass::step_instance_generic(
            facade.kernel_mut(),
            &admission.instance_ref,
            action.action().program(),
            None,
            None,
        )
        .expect("lower recording");
        let effect = facade
            .kernel()
            .claimable_effects(&admission.instance_ref)
            .expect("effects")
            .remove(0);
        let execution = ExecuteActionEffect {
            protocol: ACTION_EXECUTION_PROTOCOL.into(),
            issuer: command.issuer.clone(),
            scope: command.scope.clone(),
            admission,
            policy: command.policy.clone(),
            provenance: command.provenance.clone(),
            effect_id: effect.effect_id.clone(),
            effect_fingerprint: effect_observation_fingerprint(&effect)
                .expect("effect fingerprint"),
        };
        record::<S, _>(&scenario, "ExecuteActionEffect", &execution);
        let binding = ResolutionRecordingBinding::prepare(
            &input,
            "input-label",
            scope,
            &recording_operation_id(&execution.admission.instance_ref, &effect.effect_id),
            actor,
            &command.fingerprint().expect("intent"),
            "2026-09-10T12:00:00Z",
        )
        .expect("exact binding");
        let (branches, content) = target();
        let mut bound = BoundResolutionRecording::new(
            WorkspaceVcs::from_parts(
                branches,
                PostCommitContent {
                    inner: content,
                    mode,
                },
            ),
            binding.clone(),
            &input,
        )
        .expect("bound target");
        let mut investigator = execution.provenance.clone();
        let principal = if actor == "human:one" {
            "agent:investigator"
        } else {
            "human:investigator"
        };
        investigator.initiator = principal.into();
        investigator.executor = principal.into();
        investigator.origin = "investigation".into();
        let authority = Authority {
            original: command,
            execution: execution.clone(),
            binding: binding.clone(),
            investigator,
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            facade.execute_resolution_recording(
                execution.clone(),
                &action,
                &authority,
                b"execute",
                &mut bound,
            )
        }));
        if mode == "interrupted" {
            assert!(outcome.is_err());
        } else {
            outcome
                .expect("returned")
                .expect("governed recording settles");
        }
        let receipt = observer
            .resolution_receipt(&binding.batch().operation_id)
            .expect("retained receipt")
            .expect("committed");
        assert_eq!(receipt.request, *binding.batch());
        record::<S, _>(&scenario, "ResolutionMemoryReceipt", &receipt);
        assert!(receipt
            .outcomes
            .iter()
            .all(|outcome| outcome.inserted == receipts.is_empty()));
        assert!(receipt.outcomes.iter().all(|outcome| outcome.resolution
            == whipplescript_store::stable_hash_hex("first human correction")));
        assert_eq!(
            observer
                .get_branch(MAINLINE_BRANCH_ID)
                .expect("mainline")
                .expect("exists")
                .head_cut_id,
            head
        );
        let history = facade
            .kernel()
            .store()
            .list_events(&execution.admission.instance_ref)
            .expect("history");
        assert!(!format!("{history:?}").contains(body));
        assert!(!format!("{history:?}").contains("private backend failure"));
        let dispatch: serde_json::Value = serde_json::from_str(
            &history
                .iter()
                .find(|event| event.event_type == "effect.run_started")
                .expect("dispatch")
                .payload_json,
        )
        .expect("dispatch payload");
        assert_eq!(dispatch["metadata"]["resolution_recording"], json!(binding));
        let recorded: ResolutionRecordingBinding =
            serde_json::from_value(dispatch["metadata"]["resolution_recording"].clone())
                .expect("actual dispatch binding");
        record::<S, _>(&scenario, "ResolutionRecordingBinding", &recorded);
        record::<S, _>(&scenario, "ResolutionMemoryScope", recorded.scope());
        if mode != "interrupted" {
            whipplescript_kernel::rule_pass::step_instance_generic(
                facade.kernel_mut(),
                &execution.admission.instance_ref,
                action.action().program(),
                None,
                None,
            )
            .expect("continue workflow");
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .get_instance(&execution.admission.instance_ref)
                    .expect("instance")
                    .expect("exists")
                    .status,
                if mode == "failed" {
                    "failed"
                } else {
                    "completed"
                }
            );
        }
        recover(
            &mut facade,
            &action,
            &authority,
            observer,
            &receipt,
            &scenario,
        );
        assert!(facade
            .execute_resolution_recording(execution, &action, &authority, b"execute", &mut bound)
            .is_err());
        receipts.push(receipt);
    }
    assert_eq!(
        observer
            .resolution_receipt(&receipts[0].request.operation_id)
            .expect("original receipt"),
        Some(receipts[0].clone())
    );
    receipts
}

#[test]
fn governed_resolution_recording_has_the_same_native_and_hosted_journey() {
    for mode in ["success", "failed", "interrupted"] {
        let dir = std::env::temp_dir().join(format!(
            "whip-recording-parity-{}-{}-{mode}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("fixture directory");
        let native = || {
            (
                BranchStore::open(dir.join("branches.sqlite")).expect("branches"),
                ContentStore::open(dir.join("content.sqlite")).expect("content"),
            )
        };
        let (branches, content) = native();
        let observer = WorkspaceVcs::from_parts(branches, content);
        let receipts = journey(
            NativeStores::open_in_memory().expect("native runtime"),
            native,
            mode,
            &observer,
        );
        drop(observer);
        std::fs::remove_dir_all(&dir).expect("remove fixture");
        let sql = RusqliteDoSql::with_runtime_schema();
        let hosted = || {
            (
                DoBranches::new(sql.clone()).expect("hosted branches"),
                DoContentBlobs::new(sql.clone()).expect("hosted content"),
            )
        };
        let do_receipts = journey(
            DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
            hosted,
            mode,
            &compose_vcs_shared(&sql).expect("hosted observer"),
        );
        // Existing effect keys include the store-local program-version registration
        // (rule_lowering.rs). Exact operation binding is checked inside each journey;
        // independently registered stores agree on meaning, not generated row IDs.
        assert_eq!(do_receipts.len(), receipts.len());
        for (hosted, native) in do_receipts.iter().zip(&receipts) {
            assert_eq!(hosted.request.actor, native.request.actor);
            assert_eq!(hosted.request.intent, native.request.intent);
            assert_eq!(hosted.request.recorded_at, native.request.recorded_at);
            assert_eq!(hosted.request.entries, native.request.entries);
            assert_eq!(hosted.outcomes, native.outcomes);
        }
    }
}
