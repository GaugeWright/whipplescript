//! Shared native/DO recovery journeys over actual admitted file effects and v2
//! target receipts. Synthetic authorities qualify call order and exact binding;
//! they are not product authentication or a remembered-input IFC proof.
use super::*;
use whipplescript_kernel::host_facade::ScopedSaveExecutionAuthority;
use whipplescript_kernel::host_protocol::recovery::{
    ReconcileEffectCommand, EFFECT_RECONCILIATION_PROTOCOL,
};
use whipplescript_kernel::save_reconciliation::{
    SaveReconciliationAuthority, ScopedSaveReconciliationAuthority,
    ScopedVersionedSaveEvidenceSource, VersionedSaveEvidenceSource,
};
use whipplescript_store::effect_recovery::{
    fold_attempts, DispositionEvidence, EvidenceDisposition, ExternalDisposition,
};
use whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope;

fn scoped_envelope(epoch: u64) -> VerifiedEnvelope {
    scoped_envelope_with_memory(epoch, "Operator")
}

fn scoped_envelope_with_memory(epoch: u64, memory: &str) -> VerifiedEnvelope {
    let config = format!(
        "grant file_store admitted_input -> file:/action/input readable by Operator\n\
         grant file_store admitted_target -> file:/action/output readable by Operator\n\
         grant memory admitted_resolutions -> memory:/action/resolutions readable by {memory}\n\
         grant output result -> result readable by Operator\n\
         grant output error -> error readable by Operator\n"
    );
    let signed = SignedEnvelope::from_external_signature_v2(
        &config,
        "fixture-signer",
        "fixture",
        "fixture-key",
        "execution-fixture",
        epoch,
        "product",
    )
    .expect("scoped signed policy");
    VerifiedEnvelope::verify_signed_text_with(&signed.to_json(), &authority(vec![]))
        .expect("scoped policy")
}

struct ScopedExecutionAuthority<'a> {
    inner: BoundAuthority<'a>,
    scope: &'a ResolutionMemoryScope,
    denied: Cell<bool>,
}
impl ActionExecutionVerifier for ScopedExecutionAuthority<'_> {
    fn authenticate(
        &self,
        request: &ExecuteActionEffect,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        self.inner.authenticate(request, bytes, proof)
    }
    fn authorize(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
    ) -> Result<(), ProtocolError> {
        self.inner.authorize(request, original, effect)
    }
}
impl ScopedSaveExecutionAuthority for ScopedExecutionAuthority<'_> {
    fn authorize_scoped_save(
        &self,
        _: &ExecuteActionEffect,
        original: &HostActionCommand,
        _: &ClaimableEffect,
        _: &VersionedSaveBinding,
        scope: &ResolutionMemoryScope,
    ) -> Result<(), ProtocolError> {
        if self.denied.get()
            || scope != self.scope
            || original.resources["resolutions"].label_ref != "memory-private"
        {
            return Err(ProtocolError::Mismatch(
                "fixture scoped execution authority",
            ));
        }
        Ok(())
    }
}

struct ScopedAuthority {
    signed: Vec<u8>,
    original: HostActionCommand,
    binding: SaveResultBinding,
    original_scope: ResolutionMemoryScope,
    current_scope: ResolutionMemoryScope,
    revoked: Cell<bool>,
    target_denied: Cell<bool>,
    scope_denied: Cell<bool>,
    scope_checks: Cell<usize>,
}
impl SaveReconciliationAuthority for ScopedAuthority {
    fn authenticate(
        &self,
        _: &ReconcileEffectCommand,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if self.revoked.get() || bytes != self.signed || proof != b"recovery" {
            return Err(ProtocolError::Mismatch("fixture scoped authentication"));
        }
        Ok(())
    }
    fn authorize(
        &self,
        _: &ReconcileEffectCommand,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        binding: &SaveResultBinding,
    ) -> Result<(), ProtocolError> {
        if self.target_denied.get()
            || original != &self.original
            || binding != &self.binding
            || execution.provenance.executor != self.binding.executing_principal
        {
            return Err(ProtocolError::Mismatch("fixture scoped target authority"));
        }
        Ok(())
    }
}
impl ScopedSaveReconciliationAuthority for ScopedAuthority {
    fn authorize_resolution_scope(
        &self,
        _: &ReconcileEffectCommand,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        binding: &SaveResultBinding,
        scope: &ResolutionMemoryScope,
    ) -> Result<(), ProtocolError> {
        self.scope_checks.set(self.scope_checks.get() + 1);
        if self.scope_denied.get()
            || original != &self.original
            || binding != &self.binding
            || execution.provenance.executor != self.binding.executing_principal
            || scope != &self.original_scope
            || scope != &self.current_scope
        {
            return Err(ProtocolError::Mismatch(
                "fixture original and current knowledge scope",
            ));
        }
        Ok(())
    }
}

fn run_scoped<S, B, C>(
    store: S,
    mut target: WorkspaceVcs<B, C>,
    observe: WorkspaceVcs<B, C>,
    actor: &str,
    mode: &str,
) where
    S: RuntimeStore + LogAppend + Coordination + WorkItems + FrontierRead,
    B: Branches,
    C: ContentBlobs,
{
    let scenario = format!("{actor}/{mode}");
    register_file_capabilities(&store);
    target.init("t0").expect("target");
    target
        .write(MAINLINE_BRANCH_ID, "test.txt", Some("dog"), "base", "t0")
        .expect("base");
    target
        .write(MAINLINE_BRANCH_ID, "test.txt", Some("tiger"), "head", "t1")
        .expect("head");
    let scope = ResolutionMemoryScope::new(
        "fixture-target-authority".into(),
        "mainline:test.txt".into(),
        "Operator".into(),
    )
    .expect("scope");
    target.set_actor(Some("person:original".into()));
    target.set_intent(Some("original human correction".into()));
    let knowledge = target
        .record_region_resolutions_in_scope(
            &scope,
            "original-correction",
            &[
                whipplescript_store::vcs::resolution_recording::conformance::resolution(
                    "remembered correction",
                ),
            ],
            "t2",
        )
        .expect("fixture knowledge");
    host_action_contract_reports::record_scoped::<S, _>(&scenario, "ResolutionMemoryScope", &scope);
    host_action_contract_reports::record_scoped::<S, _>(
        &scenario,
        "ResolutionMemoryReceipt",
        &knowledge,
    );
    let binding = VersionedSaveBinding {
        branch_id: MAINLINE_BRANCH_ID.into(),
        path: "test.txt".into(),
        base_cut_id: "base".into(),
        draft: "lion".into(),
        draft_hash: whipplescript_store::stable_hash_hex("lion"),
        input_label: "input-private".into(),
        executing_principal: actor.into(),
        evidence_label: "private".into(),
        recorded_at: "t3".into(),
    };
    let action = CompiledHostAction::compile("file.save", SOURCE, None).expect("compiled workflow");
    let mut facade =
        GovernedHostFacade::from_verified_store(store, 7, scoped_envelope(7)).expect("facade");
    let original = HostActionCommand {
        protocol: HOST_ACTION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace:1".into(),
        request_id: "scoped-save".into(),
        operation: "file.save".into(),
        program_version_ref: action.version_ref().into(),
        input_schema_ref: action.input_schema_ref().into(),
        policy: facade.policy_ref().clone(),
        provenance: ActionProvenance {
            initiator: actor.into(),
            executor: actor.into(),
            delegation: vec![],
            origin: "fixture.scoped-save".into(),
            causes: vec![],
        },
        inputs: BTreeMap::from([(
            "content".into(),
            ActionInput {
                handle: "admitted_input".into(),
                version_ref: input_version(&binding, true),
                label_ref: binding.input_label.clone(),
            },
        )]),
        resources: BTreeMap::from([
            (
                "target".into(),
                ActionResource {
                    resource: ResourceRef {
                        handle: "admitted_target".into(),
                        kind: "file_store".into(),
                        selector: Some(target_selector(&binding, true)),
                        writable: Some(true),
                    },
                    basis: ActionBasis::Version {
                        version_ref: binding.base_cut_id.clone(),
                    },
                    label_ref: binding.evidence_label.clone(),
                },
            ),
            (
                "resolutions".into(),
                ActionResource {
                    resource: ResourceRef {
                        handle: "admitted_resolutions".into(),
                        kind: "resolution_memory".into(),
                        selector: Some(serde_json::to_string(&scope).expect("scope selector")),
                        writable: Some(false),
                    },
                    basis: ActionBasis::Version {
                        version_ref: scope.version_ref(),
                    },
                    label_ref: "memory-private".into(),
                },
            ),
        ]),
    };
    let admission = facade
        .admit_action(
            original.clone(),
            &action,
            &authority(original.signing_bytes().expect("sign admission")),
            b"admission",
        )
        .expect("admission");
    host_action_contract_reports::record_scoped::<S, _>(&scenario, "HostActionCommand", &original);
    host_action_contract_reports::record_scoped::<S, _>(
        &scenario,
        "ActionAdmissionReceipt",
        &admission,
    );
    let files = SaveFiles {
        inner: VersionedSaveFileStore::new_in_resolution_scope(
            target,
            binding.clone(),
            scope.clone(),
        )
        .expect("scoped adapter"),
        interrupted: mode == "interrupted",
        failed_after_apply: mode == "failed-after-apply",
        calls: Cell::new(0),
        reads: Cell::new(0),
    };
    let mut written = None;
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
                issuer: original.issuer.clone(),
                scope: original.scope.clone(),
                admission: admission.clone(),
                policy: facade.policy_ref().clone(),
                provenance: original.provenance.clone(),
                effect_id: effect.effect_id.clone(),
                effect_fingerprint: effect_observation_fingerprint(&effect).expect("effect"),
            };
            let verifier = ScopedExecutionAuthority {
                inner: BoundAuthority {
                    proof: authority(request.signing_bytes().expect("sign execution")),
                    binding: &binding,
                    enveloped: true,
                },
                scope: &scope,
                denied: Cell::new(false),
            };
            let before_io = (files.reads.get(), files.calls.get());
            let before_head = facade
                .kernel()
                .store()
                .chain_head(&admission.instance_ref)
                .expect("head before refusals");
            let refused = facade
                .execute_action_file_effect(
                    request.clone(),
                    &action,
                    &verifier,
                    b"execution",
                    &files,
                )
                .expect_err("legacy dispatch cannot omit memory authority");
            assert!(format!("{refused:?}")
                .contains("scoped save requires verified memory execution authority"));
            assert!(facade
                .execute_scoped_save_file_effect(
                    request.clone(),
                    &action,
                    &verifier,
                    b"wrong",
                    &files
                )
                .is_err());
            verifier.denied.set(true);
            let refused = facade
                .execute_scoped_save_file_effect(
                    request.clone(),
                    &action,
                    &verifier,
                    b"execution",
                    &files,
                )
                .expect_err("scope refusal precedes adapter access");
            assert!(format!("{refused:?}").contains("fixture scoped execution authority"));
            verifier.denied.set(false);
            // A newer policy restricts the remembered input beyond the target.
            // The synthetic host accepts the descriptor, leaving the runtime's
            // actual flow check to refuse before either backend enters I/O.
            facade = GovernedHostFacade::from_verified_store(
                facade.into_kernel().into_store(),
                8,
                scoped_envelope_with_memory(8, "Restricted"),
            )
            .expect("restricted current policy");
            let mut restricted = request.clone();
            restricted.policy = facade.policy_ref().clone();
            let restricted_authority = ScopedExecutionAuthority {
                inner: BoundAuthority {
                    proof: authority(
                        restricted
                            .signing_bytes()
                            .expect("sign restricted execution"),
                    ),
                    binding: &binding,
                    enveloped: true,
                },
                scope: &scope,
                denied: Cell::new(false),
            };
            let refused = facade
                .execute_scoped_save_file_effect(
                    restricted,
                    &action,
                    &restricted_authority,
                    b"execution",
                    &files,
                )
                .expect_err("private memory cannot flow to the target");
            assert!(format!("{refused:?}").contains("resource flow violates confidentiality"));
            facade = GovernedHostFacade::from_verified_store(
                facade.into_kernel().into_store(),
                7,
                scoped_envelope(7),
            )
            .expect("original fixture policy");
            assert_eq!((files.reads.get(), files.calls.get()), before_io);
            assert_eq!(
                facade
                    .kernel()
                    .store()
                    .chain_head(&admission.instance_ref)
                    .expect("unchanged head"),
                before_head
            );
            host_action_contract_reports::record_scoped::<S, _>(
                &scenario,
                "ExecuteActionEffect",
                &request,
            );
            if effect.kind == "file.write" {
                written = Some(request.effect_id.clone());
            }
            if effect.kind == "file.write" && mode == "interrupted" {
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| facade
                        .execute_scoped_save_file_effect(
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
                .execute_scoped_save_file_effect(request, &action, &verifier, b"execution", &files)
                .expect("execute");
        }
    }
    assert_eq!(files.calls.get(), 1);
    let effect_id = written.expect("write dispatched");
    let cut = observe
        .get_cut(&save_cut_id(&admission.instance_ref, &effect_id))
        .expect("cut query")
        .expect("committed");
    let attempt: SaveAttempt =
        serde_json::from_str(cut.intent.as_deref().expect("intent")).expect("original attempt");
    let expected = SaveResultBinding::from(&binding);
    let saved = read_committed_scoped_save(&observe, &expected, &scope, &attempt)
        .expect("fixture read")
        .expect("receipt");
    assert_eq!(saved.accepted_content, "remembered correction");
    host_action_contract_reports::record_scoped::<S, _>(
        &scenario,
        "ScopedSaveReceipt",
        &saved.receipt,
    );
    assert!(matches!(&saved.receipt.observations[0].observed,
        whipplescript_store::branches::resolution_origin::ResolutionObservation::Recorded { origin, .. } if origin.operation_id == "original-correction"));
    // Recreate the facade at a newer policy epoch, while preserving the exact
    // original dispatch and target receipt rather than executing a new save.
    let mut facade = GovernedHostFacade::from_verified_store(
        facade.into_kernel().into_store(),
        8,
        scoped_envelope(8),
    )
    .expect("renewed facade");
    let instance = &admission.instance_ref;
    let before = facade
        .kernel()
        .store()
        .list_events(instance)
        .expect("events");
    let attempts = fold_attempts(instance, &effect_id, &before).expect("attempts");
    let frame = attempts[0]
        .dispatch
        .as_ref()
        .expect("dispatch")
        .frame
        .clone();
    let command = ReconcileEffectCommand {
        protocol: EFFECT_RECONCILIATION_PROTOCOL.into(),
        issuer: original.issuer.clone(),
        scope: original.scope.clone(),
        request_id: "recover-scoped".into(),
        policy: facade.policy_ref().clone(),
        provenance: original.provenance.clone(),
        evidence: DispositionEvidence {
            frame,
            disposition: EvidenceDisposition::Applied,
            evidence_ref: "admitted_target".into(),
            evidence_digest: whipplescript_store::items::sha256_hex(&saved.receipt_json),
            authority_ref: "fixture-target-authority".into(),
        },
        evidence_label_ref: binding.evidence_label.clone(),
    };
    let auth = |command: &ReconcileEffectCommand| ScopedAuthority {
        signed: command.signing_bytes().expect("sign recovery"),
        original: original.clone(),
        binding: expected.clone(),
        original_scope: scope.clone(),
        current_scope: scope.clone(),
        revoked: Cell::new(false),
        target_denied: Cell::new(false),
        scope_denied: Cell::new(false),
        scope_checks: Cell::new(0),
    };
    let source_for = |scope| ScopedVersionedSaveEvidenceSource {
        save: VersionedSaveEvidenceSource {
            admission: &admission,
            workspace: &observe,
            binding: &expected,
            input_name: "content",
            resource_name: "target",
            authority_ref: "fixture-target-authority",
        },
        resolution_scope: scope,
    };
    let source = source_for(&scope);
    let epoch = facade
        .kernel_mut()
        .store_mut()
        .claim_instance_ownership(instance)
        .expect("ownership");
    for case in ["revoked", "target", "scope", "proof"] {
        let denied = auth(&command);
        denied.revoked.set(case == "revoked");
        denied.target_denied.set(case == "target");
        denied.scope_denied.set(case == "scope");
        let error = facade
            .reconcile_scoped_versioned_save(
                command.clone(),
                epoch,
                &source,
                &denied,
                if case == "proof" {
                    b"wrong"
                } else {
                    b"recovery"
                },
            )
            .expect_err(case);
        let diagnostic = match case {
            "target" => "fixture scoped target authority",
            "scope" => "fixture original and current knowledge scope",
            _ => "fixture scoped authentication",
        };
        assert!(
            format!("{error:?}").contains(diagnostic),
            "{case}: {error:?}"
        );
    }
    let foreign = ResolutionMemoryScope::new(
        "fixture-target-authority".into(),
        "other-path".into(),
        "Operator".into(),
    )
    .expect("foreign scope");
    let mut broader = auth(&command);
    broader.current_scope = foreign.clone();
    assert!(format!(
        "{:?}",
        facade
            .reconcile_scoped_versioned_save(
                command.clone(),
                epoch,
                &source_for(&foreign),
                &broader,
                b"recovery"
            )
            .expect_err("today's grant cannot rewrite original scope")
    )
    .contains("fixture original and current knowledge scope"));
    // Even a permissive fixture authority cannot replace target verification.
    broader.original_scope = foreign.clone();
    assert!(format!(
        "{:?}",
        facade
            .reconcile_scoped_versioned_save(
                command.clone(),
                epoch,
                &source_for(&foreign),
                &broader,
                b"recovery"
            )
            .expect_err("retained scope remains exact")
    )
    .contains("scoped versioned save retained target evidence is unavailable"));
    let mut wrong_digest = command.clone();
    wrong_digest.evidence.evidence_digest = "a".repeat(64);
    assert!(facade
        .reconcile_scoped_versioned_save(
            wrong_digest.clone(),
            epoch,
            &source,
            &auth(&wrong_digest),
            b"recovery"
        )
        .is_err());
    assert!(
        facade
            .reconcile_versioned_save(
                command.clone(),
                epoch,
                &source.save,
                &auth(&command),
                b"recovery"
            )
            .is_err(),
        "legacy recovery cannot discard scope"
    );
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(instance)
            .expect("unchanged"),
        before
    );
    let runs = facade.kernel().store().list_runs(instance).expect("runs");
    let facts = facade.kernel().store().list_facts(instance).expect("facts");
    let workflow = facade
        .kernel()
        .store()
        .get_instance(instance)
        .expect("instance");
    let allowed = auth(&command);
    let receipt = facade
        .reconcile_scoped_versioned_save(command.clone(), epoch, &source, &allowed, b"recovery")
        .expect("scoped reconciliation");
    host_action_contract_reports::record_scoped::<S, _>(
        &scenario,
        "ReconcileEffectCommand",
        &command,
    );
    host_action_contract_reports::record_scoped::<S, _>(
        &scenario,
        "ReconciliationReceipt",
        &receipt,
    );
    assert_eq!(allowed.scope_checks.get(), 1);
    let after = facade
        .kernel()
        .store()
        .list_events(instance)
        .expect("recorded");
    assert_eq!(after.len(), before.len() + 1);
    assert_eq!(
        fold_attempts(instance, &effect_id, &after).expect("fold")[0].disposition,
        ExternalDisposition::Applied
    );
    assert_eq!(
        facade.kernel().store().list_runs(instance).expect("runs"),
        runs
    );
    assert_eq!(
        facade.kernel().store().list_facts(instance).expect("facts"),
        facts
    );
    assert_eq!(
        facade
            .kernel()
            .store()
            .get_instance(instance)
            .expect("instance"),
        workflow
    );
    facade
        .kernel_mut()
        .store_mut()
        .rebuild_projections(instance)
        .expect("read-only rebuild");
    assert_eq!(
        facade
            .reconcile_scoped_versioned_save(command.clone(), epoch, &source, &allowed, b"recovery")
            .expect("redelivery"),
        receipt
    );
    assert_eq!(
        allowed.scope_checks.get(),
        2,
        "redelivery repeats current scope authorization"
    );
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(instance)
            .expect("same history"),
        after
    );
    observe
        .content_store()
        .erase(&saved.reference.content_hash, "t4")
        .expect("erase receipt");
    for case in ["revoked", "target", "scope"] {
        let denied = auth(&command);
        denied.revoked.set(case == "revoked");
        denied.target_denied.set(case == "target");
        denied.scope_denied.set(case == "scope");
        let error = facade
            .reconcile_scoped_versioned_save(command.clone(), epoch, &source, &denied, b"recovery")
            .expect_err("authorization precedes unavailable target read");
        let diagnostic = match case {
            "target" => "fixture scoped target authority",
            "scope" => "fixture original and current knowledge scope",
            _ => "fixture scoped authentication",
        };
        assert!(
            format!("{error:?}").contains(diagnostic),
            "{case}: {error:?}"
        );
    }
    assert!(format!(
        "{:?}",
        facade
            .reconcile_scoped_versioned_save(command, epoch, &source, &allowed, b"recovery")
            .expect_err("erasure cannot reuse earlier proof")
    )
    .contains("scoped versioned save retained target evidence is unavailable"));
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(instance)
            .expect("unchanged history"),
        after
    );
    assert_eq!(
        files.calls.get(),
        1,
        "reconciliation and rebuild never dispatch a sink"
    );
}

#[test]
fn scoped_save_reconciliation_checks_current_scope_before_target_reads_on_both_hosts() {
    for actor in ["person:one", "agent:one"] {
        for mode in ["saved", "interrupted", "failed-after-apply"] {
            let dir = std::env::temp_dir().join(format!(
                "whip-scoped-reconcile-{}-{}-{mode}",
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
            run_scoped(
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
            run_scoped(
                DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
                make(),
                make(),
                actor,
                mode,
            );
        }
    }
}
