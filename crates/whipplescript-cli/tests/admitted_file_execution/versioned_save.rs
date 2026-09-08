//! The actual compiled file workflow against the versioned target adapter.
//! Fixture signatures are deliberately local; product authentication/transport
//! and target-outcome reconciliation remain separate campaign obligations.
use super::*;
use whipplescript_store::branches::{BranchStore, Branches, MAINLINE_BRANCH_ID};
use whipplescript_store::content::{ContentBlobs, ContentStore};
use whipplescript_store::files::{FileWriteAccepted, FileWriteContext, FileWriteFailure};
use whipplescript_store::vcs::{NativeWorkspaceVcs, WorkspaceVcs};
use whipplescript_store::vcs_file_save::*;

struct SaveFiles<B: Branches, C: ContentBlobs> {
    inner: VersionedSaveFileStore<B, C>,
    interrupted: bool,
    failed_after_apply: bool,
    calls: Cell<usize>,
}
impl<B: Branches, C: ContentBlobs> FileStore for SaveFiles<B, C> {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        self.inner.read_to_string(path)
    }
    fn exists(&self, path: &Path) -> bool {
        self.inner.exists(path)
    }
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }
    fn write(&self, path: &Path, body: &[u8]) -> io::Result<()> {
        self.inner.write(path, body)
    }
    fn append(&self, path: &Path, body: &[u8]) -> io::Result<()> {
        self.inner.append(path, body)
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        self.inner.remove(path)
    }
    fn write_text_with_context(
        &self,
        path: &Path,
        body: &str,
        context: FileWriteContext<'_>,
    ) -> Result<FileWriteAccepted, FileWriteFailure> {
        self.calls.set(self.calls.get() + 1);
        let result = self.inner.write_text_with_context(path, body, context);
        assert!(
            !self.interrupted,
            "interrupted after versioned target application"
        );
        if self.failed_after_apply && result.is_ok() {
            return Err(io::Error::other("lost success after target application").into());
        }
        result
    }
}
struct BoundAuthority<'a> {
    proof: FixtureAuthority,
    binding: &'a VersionedSaveBinding,
}
impl ActionExecutionVerifier for BoundAuthority<'_> {
    fn authenticate(
        &self,
        request: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        self.proof.authenticate(request, bytes, proof)
    }
    fn authorize(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
    ) -> Result<(), ProtocolError> {
        self.proof.authorize(request, original, effect)?;
        let target = &original.resources["target"];
        let expected_selector = format!("{}:{}", self.binding.branch_id, self.binding.path);
        let input: Value = serde_json::from_str(&effect.input_json).expect("effect input");
        let expected_path = if effect.kind == "file.read" {
            ("/action/input", "content")
        } else {
            ("/action/output", "target")
        };
        if target.resource.selector.as_deref() != Some(expected_selector.as_str())
            || target.basis
                != (ActionBasis::Version {
                    version_ref: self.binding.base_cut_id.clone(),
                })
            || target.label_ref != self.binding.evidence_label
            || original.inputs["content"].version_ref != self.binding.draft_hash
            || request.provenance.executor != self.binding.executing_principal
            || input["root"] != expected_path.0
            || input["path"] != expected_path.1
            || (effect.kind == "file.write" && input["mode"] != "upsert")
        {
            return Err(ProtocolError::Mismatch("fixture exact versioned binding"));
        }
        Ok(())
    }
}

fn run<S, B, C>(
    store: S,
    mut target: WorkspaceVcs<B, C>,
    mut observe: WorkspaceVcs<B, C>,
    actor: &str,
    mode: &str,
) where
    S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead,
    B: Branches,
    C: ContentBlobs,
{
    register_file_capabilities(&store);
    target.init("t0").expect("init target");
    target
        .write(
            MAINLINE_BRANCH_ID,
            "test.txt",
            Some("original"),
            "base",
            "t0",
        )
        .expect("base");
    if mode == "conflict" {
        target
            .write(
                MAINLINE_BRANCH_ID,
                "test.txt",
                Some("competing"),
                "head",
                "t1",
            )
            .expect("concurrent head");
    }
    let binding = VersionedSaveBinding {
        branch_id: MAINLINE_BRANCH_ID.into(),
        path: "test.txt".into(),
        base_cut_id: "base".into(),
        draft: BODY.into(),
        draft_hash: whipplescript_store::stable_hash_hex(BODY),
        executing_principal: actor.into(),
        evidence_label: "private".into(),
        recorded_at: "2026-09-06T00:00:00Z".into(),
    };
    let action =
        CompiledHostAction::compile("file.save", SOURCE, None).expect("compile ordinary workflow");
    let mut facade =
        GovernedHostFacade::from_verified_store(store, 7, envelope(7)).expect("facade");
    let command = HostActionCommand {
        protocol: HOST_ACTION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace:1".into(),
        request_id: "versioned-save".into(),
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
                version_ref: binding.draft_hash.clone(),
                label_ref: "private".into(),
            },
        )]),
        resources: BTreeMap::from([(
            "target".into(),
            ActionResource {
                resource: ResourceRef {
                    handle: "admitted_target".into(),
                    kind: "file_store".into(),
                    selector: Some(format!("{}:{}", binding.branch_id, binding.path)),
                    writable: Some(true),
                },
                basis: ActionBasis::Version {
                    version_ref: "base".into(),
                },
                label_ref: "private".into(),
            },
        )]),
    };
    let admission = facade
        .admit_action(
            command.clone(),
            &action,
            &authority(command.signing_bytes().expect("sign")),
            b"admission",
        )
        .expect("admit save");
    let scenario = format!("{actor}/{mode}");
    host_action_contract_reports::record::<S, _>(&scenario, "HostActionCommand", &command);
    host_action_contract_reports::record::<S, _>(&scenario, "ActionAdmissionReceipt", &admission);
    let files = SaveFiles {
        inner: VersionedSaveFileStore::new(target, binding.clone()).expect("confined target"),
        interrupted: mode == "interrupted",
        failed_after_apply: mode == "failed-after-apply",
        calls: Cell::new(0),
    };
    let mut written_request = None;
    'drive: for _ in 0..8 {
        whipplescript_kernel::rule_pass::step_instance_generic(
            facade.kernel_mut(),
            &admission.instance_ref,
            action.program(),
            None,
            None,
        )
        .expect("ordinary pass");
        let effects = facade
            .kernel()
            .claimable_effects(&admission.instance_ref)
            .expect("effects");
        if effects.is_empty() {
            break;
        }
        for effect in effects {
            let request = ExecuteActionEffect {
                protocol: ACTION_EXECUTION_PROTOCOL.into(),
                issuer: "product".into(),
                scope: "workspace:1".into(),
                admission: admission.clone(),
                policy: facade.policy_ref().clone(),
                provenance: command.provenance.clone(),
                effect_id: effect.effect_id.clone(),
                effect_fingerprint: effect_observation_fingerprint(&effect).expect("observation"),
            };
            let verifier = BoundAuthority {
                proof: authority(request.signing_bytes().expect("sign")),
                binding: &binding,
            };
            let mut wrong = binding.clone();
            wrong.path = "other.txt".into();
            let wrong_verifier = BoundAuthority {
                proof: authority(request.signing_bytes().expect("sign")),
                binding: &wrong,
            };
            assert!(
                facade
                    .execute_action_file_effect(
                        request.clone(),
                        &action,
                        &wrong_verifier,
                        b"execution",
                        &files
                    )
                    .is_err(),
                "authority must bind the actual target descriptor"
            );
            if effect.kind == "file.write" {
                written_request = Some(request.clone());
            }
            host_action_contract_reports::record::<S, _>(
                &scenario,
                "ExecuteActionEffect",
                &request,
            );
            if effect.kind == "file.write" && mode == "interrupted" {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| facade
                        .execute_action_file_effect(
                            request,
                            &action,
                            &verifier,
                            b"execution",
                            &files
                        )))
                    .is_err()
                );
                break 'drive;
            }
            facade
                .execute_action_file_effect(request, &action, &verifier, b"execution", &files)
                .expect("execute authorized effect");
        }
    }
    assert_eq!(files.calls.get(), 1);
    let request = written_request.expect("write dispatched");
    let cut_id = save_cut_id(&admission.instance_ref, &request.effect_id);
    let cut = observe.get_cut(&cut_id).expect("independent target query");
    let committed_attempt = cut.as_ref().map(|cut| {
        serde_json::from_str::<SaveAttempt>(cut.intent.as_deref().expect("committed attempt"))
            .expect("attempt")
    });
    let events = facade
        .kernel()
        .store()
        .list_events(&admission.instance_ref)
        .expect("events");
    let attempts = whipplescript_store::effect_recovery::fold_attempts(
        &admission.instance_ref,
        &request.effect_id,
        &events,
    )
    .expect("attempt");
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts[0].disposition,
        whipplescript_store::effect_recovery::ExternalDisposition::Unknown
    );
    if mode == "conflict" {
        assert!(cut.is_none());
        assert_eq!(
            observe
                .read(MAINLINE_BRANCH_ID, "test.txt")
                .expect("head")
                .as_deref(),
            Some("competing")
        );
    } else {
        let cut = cut.expect("durable cut survives missing runtime receipt");
        assert_eq!(cut.actor.as_deref(), Some(actor));
        let at: SaveAttempt =
            serde_json::from_str(cut.intent.as_deref().expect("intent")).expect("exact dispatch");
        assert_eq!(at.instance_id, admission.instance_ref);
        assert_eq!(at.effect_id, request.effect_id);
        assert!(events
            .iter()
            .any(|e| e.event_id == at.started_event_id && e.event_type == "effect.run_started"));
        assert!(observe
            .get_op(&format!("op-{cut_id}"))
            .expect("op")
            .is_some());
        assert_eq!(
            observe
                .read_at_cut(&cut_id, "test.txt")
                .expect("retained cut")
                .as_deref(),
            Some(BODY)
        );
    }
    let status = facade
        .kernel()
        .store()
        .get_instance(&admission.instance_ref)
        .expect("instance")
        .expect("admitted")
        .status;
    assert_eq!(
        status,
        match mode {
            "conflict" | "failed-after-apply" => "failed",
            "interrupted" => "running",
            _ => "completed",
        }
    );
    if mode != "interrupted" && mode != "failed-after-apply" {
        let receipts: Vec<Value> = events
            .iter()
            .filter(|e| e.event_type == "effect.terminal")
            .filter_map(|e| {
                let p: Value = serde_json::from_str(&e.payload_json).expect("terminal");
                let receipt = if mode == "conflict" {
                    &p["metadata"]["failure"]["receipt"]
                } else {
                    &p["metadata"]["value"]["receipt"]
                };
                (!receipt.is_null()).then(|| receipt.clone())
            })
            .collect();
        assert_eq!(receipts.len(), 1, "one retained save result: {events:?}");
        assert_eq!(receipts[0]["label_ref"], "private");
        let body = facade
            .kernel()
            .store()
            .get_content(receipts[0]["content_hash"].as_str().expect("hash"))
            .expect("content query")
            .expect("retained receipt");
        let receipt: SaveReceipt = serde_json::from_str(&body).expect("receipt schema");
        host_action_contract_reports::record::<S, _>(&scenario, "SaveReceipt", &receipt);
        assert_eq!(receipt.attempt.effect_id, request.effect_id);
        assert_eq!(receipt.executing_principal, actor);
        match receipt.result {
            SaveResult::Conflicted { .. } => assert_eq!(mode, "conflict"),
            SaveResult::Written { .. } => assert_eq!(mode, "saved"),
            _ => panic!("unexpected merge"),
        }
    }
    // Advance today's target before rebuilding. Neither inspection nor retry
    // may turn this later state into the earlier input or produce another cut.
    observe
        .write(
            MAINLINE_BRANCH_ID,
            "test.txt",
            Some("later edit"),
            "later",
            "t3",
        )
        .expect("later observed write");
    if let Some(attempt) = &committed_attempt {
        // Recover through the independently reopened target handle after the
        // head has changed. The original base body is no longer available.
        observe
            .content_store()
            .erase(&whipplescript_store::stable_hash_hex("original"), "t4")
            .expect("erase base");
        let recovered = read_committed_save(&observe, &SaveResultBinding::from(&binding), attempt)
            .expect("read exact target result")
            .expect("committed result");
        host_action_contract_reports::record::<S, _>(&scenario, "SaveReceipt", &recovered.receipt);
        host_action_contract_reports::record::<S, _>(
            &scenario,
            "WriteEvidenceRef",
            &recovered.reference,
        );
        assert_eq!(recovered.accepted_content, BODY);
        assert_eq!(recovered.receipt.attempt, *attempt);
        assert_eq!(recovered.receipt.draft_hash, binding.draft_hash);
        assert_eq!(recovered.reference.label_ref, "private");
        assert_eq!(
            recovered.reference.content_hash,
            whipplescript_store::stable_hash_hex(&recovered.receipt_json)
        );
    }
    facade
        .kernel_mut()
        .store_mut()
        .rebuild_projections(&admission.instance_ref)
        .expect("rebuild");
    let mut facade =
        GovernedHostFacade::from_verified_store(facade.into_kernel().into_store(), 7, envelope(7))
            .expect("reopen facade");
    let verifier = BoundAuthority {
        proof: authority(request.signing_bytes().expect("sign")),
        binding: &binding,
    };
    assert!(facade
        .execute_action_file_effect(request, &action, &verifier, b"execution", &files)
        .is_err());
    assert_eq!(files.calls.get(), 1);
    assert_eq!(
        observe
            .read(MAINLINE_BRANCH_ID, "test.txt")
            .expect("latest")
            .as_deref(),
        Some("later edit")
    );
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(&admission.instance_ref)
            .expect("events"),
        events
    );
    let mut facade =
        GovernedHostFacade::from_verified_store(facade.into_kernel().into_store(), 8, envelope(8))
            .expect("renewed recovery policy");
    super::save_reconciliation::check(
        &mut facade,
        &observe,
        &binding,
        &admission,
        &committed_attempt.as_ref().map_or_else(
            || {
                attempts[0]
                    .dispatch
                    .as_ref()
                    .expect("dispatch")
                    .frame
                    .effect_id
                    .clone()
            },
            |attempt| attempt.effect_id.clone(),
        ),
        &command.provenance,
        mode,
    );
    assert_eq!(files.calls.get(), 1, "reconciliation never writes");
}

#[test]
fn admitted_versioned_save_survives_target_commit_and_retains_conflicts_on_both_hosts() {
    for actor in ["person:one", "agent:one"] {
        for mode in ["saved", "conflict", "interrupted", "failed-after-apply"] {
            let dir = std::env::temp_dir().join(format!(
                "whip-admitted-vcs-{}-{}-{mode}",
                std::process::id(),
                actor.replace(':', "-")
            ));
            std::fs::create_dir_all(&dir).expect("fixture directory");
            let make = || {
                NativeWorkspaceVcs::from_parts(
                    BranchStore::open(dir.join("branches.sqlite")).expect("branches"),
                    ContentStore::open(dir.join("content.sqlite")).expect("content"),
                )
            };
            run(
                NativeStores::open_in_memory().expect("runtime"),
                make(),
                make(),
                actor,
                mode,
            );
            std::fs::remove_dir_all(&dir).expect("clean fixture");
            let sql = RusqliteDoSql::with_runtime_schema();
            let make = || {
                whipplescript_host_do::do_branches::compose_vcs_shared(&sql).expect("hosted target")
            };
            run(
                DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
                make(),
                make(),
                actor,
                mode,
            );
        }
    }
}
