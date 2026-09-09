use super::*;
use whipplescript_kernel::host_protocol::action::ActionAdmissionReceipt;
use whipplescript_kernel::host_protocol::recovery::{
    ReconcileEffectCommand, EFFECT_RECONCILIATION_PROTOCOL,
};
use whipplescript_kernel::save_reconciliation::{
    SaveReconciliationAuthority, VersionedSaveEvidenceSource,
};
use whipplescript_store::branches::{Branches, MAINLINE_BRANCH_ID};
use whipplescript_store::content::ContentBlobs;
use whipplescript_store::effect_recovery::{
    fold_attempts, DispositionEvidence, EvidenceDisposition, ExternalDisposition,
};
use whipplescript_store::vcs::WorkspaceVcs;
use whipplescript_store::vcs_file_save::*;

struct RecoveryAuthority {
    signing: Vec<u8>,
    revoked: Cell<bool>,
    denied: Cell<bool>,
    input: ActionInput,
    resource: ActionResource,
    binding: SaveResultBinding,
}
impl SaveReconciliationAuthority for RecoveryAuthority {
    fn authenticate(
        &self,
        _: &ReconcileEffectCommand,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if self.revoked.get() || bytes != self.signing || proof != b"recovery" {
            return Err(ProtocolError::Mismatch("fixture recovery authentication"));
        }
        Ok(())
    }
    fn authorize(
        &self,
        command: &ReconcileEffectCommand,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        binding: &SaveResultBinding,
    ) -> Result<(), ProtocolError> {
        if self.denied.get()
            || command.provenance.initiator != original.provenance.initiator
            || original.inputs.get("content") != Some(&self.input)
            || original.resources.get("target") != Some(&self.resource)
            || binding.branch_id != self.binding.branch_id
            || binding.path != self.binding.path
            || binding.base_cut_id != self.binding.base_cut_id
            || binding.draft_hash != self.binding.draft_hash
            || binding.evidence_label != self.binding.evidence_label
            || binding.executing_principal != execution.provenance.executor
        {
            return Err(ProtocolError::Mismatch("fixture current recovery ceiling"));
        }
        Ok(())
    }
}

pub(super) fn check<S, B, C>(
    facade: &mut GovernedHostFacade<S>,
    target: &WorkspaceVcs<B, C>,
    binding: &VersionedSaveBinding,
    admission: &ActionAdmissionReceipt,
    effect_id: &str,
    original: &HostActionCommand,
    mode: &str,
) where
    S: RuntimeStore + LogAppend,
    B: Branches,
    C: ContentBlobs,
{
    let provenance = &original.provenance;
    let instance = &admission.instance_ref;
    let before = facade
        .kernel()
        .store()
        .list_events(instance)
        .expect("history");
    let attempts = fold_attempts(instance, effect_id, &before).expect("attempts");
    let frame = attempts[0]
        .dispatch
        .as_ref()
        .expect("dispatch")
        .frame
        .clone();
    let cut = target
        .get_cut(&save_cut_id(instance, effect_id))
        .expect("cut lookup");
    let recovered = cut.map(|cut| {
        let attempt: SaveAttempt =
            serde_json::from_str(cut.intent.as_deref().expect("intent")).expect("attempt");
        read_committed_save(target, &SaveResultBinding::from(binding), &attempt)
            .expect("authorized fixture target read")
            .expect("result")
    });
    let proof = recovered
        .as_ref()
        .map_or("missing", |saved| saved.receipt_json.as_str());
    let command = ReconcileEffectCommand {
        protocol: EFFECT_RECONCILIATION_PROTOCOL.into(),
        issuer: "product".into(),
        scope: "workspace:1".into(),
        request_id: "recover-versioned-save".into(),
        policy: facade.policy_ref().clone(),
        provenance: provenance.clone(),
        evidence: DispositionEvidence {
            frame,
            disposition: EvidenceDisposition::Applied,
            evidence_ref: "admitted_target".into(),
            evidence_digest: whipplescript_store::items::sha256_hex(proof),
            authority_ref: "fixture-target-authority".into(),
        },
        evidence_label_ref: "private".into(),
    };
    let authority = |command: &ReconcileEffectCommand| RecoveryAuthority {
        signing: command.signing_bytes().expect("signing"),
        revoked: Cell::new(false),
        denied: Cell::new(false),
        input: original.inputs["content"].clone(),
        resource: original.resources["target"].clone(),
        binding: SaveResultBinding::from(binding),
    };
    let expected_binding = SaveResultBinding::from(binding);
    let source = VersionedSaveEvidenceSource {
        admission,
        workspace: target,
        binding: &expected_binding,
        input_name: "content",
        resource_name: "target",
        authority_ref: "fixture-target-authority",
    };
    let epoch = facade
        .kernel_mut()
        .store_mut()
        .claim_instance_ownership(instance)
        .expect("ownership");

    for case in ["proof", "revoked", "denied"] {
        let auth = authority(&command);
        auth.revoked.set(case == "revoked");
        auth.denied.set(case == "denied");
        let error = facade
            .reconcile_versioned_save(
                command.clone(),
                epoch,
                &source,
                &auth,
                if case == "proof" {
                    b"wrong"
                } else {
                    b"recovery"
                },
            )
            .expect_err("current permission required");
        let diagnostic = if case == "denied" {
            "fixture current recovery ceiling"
        } else {
            "fixture recovery authentication"
        };
        assert!(
            format!("{error:?}").contains(diagnostic),
            "{case}: {error:?}"
        );
    }
    for case in ["input-version", "target-selector"] {
        let mut auth = authority(&command);
        if case == "input-version" {
            auth.input.version_ref.push_str("-substituted");
        } else {
            auth.resource.resource.selector = Some("substituted".into());
        }
        let error = facade
            .reconcile_versioned_save(command.clone(), epoch, &source, &auth, b"recovery")
            .expect_err("a host mapping must bind the original admitted identities");
        assert!(format!("{error:?}").contains("fixture current recovery ceiling"));
    }
    for case in ["input", "resource"] {
        let changed = VersionedSaveEvidenceSource {
            input_name: if case == "input" {
                "missing"
            } else {
                "content"
            },
            resource_name: if case == "resource" {
                "missing"
            } else {
                "target"
            },
            ..source
        };
        let error = facade
            .reconcile_versioned_save(
                command.clone(),
                epoch,
                &changed,
                &authority(&command),
                b"recovery",
            )
            .expect_err("the runtime independently requires both original ceilings");
        assert!(format!("{error:?}").contains("versioned save original resource and input ceiling"));
    }
    for case in [
        "absence",
        "label",
        "authority",
        "kind",
        "provider",
        "input-fingerprint",
        "missing-run",
        "resource",
        "digest",
    ] {
        let mut changed = command.clone();
        match case {
            "absence" => changed.evidence.disposition = EvidenceDisposition::NotApplied,
            "label" => changed.evidence_label_ref = "other".into(),
            "authority" => changed.evidence.authority_ref = "other".into(),
            "kind" => changed.evidence.frame.kind = "file.read".into(),
            "provider" => changed.evidence.frame.provider = "other".into(),
            "input-fingerprint" => changed.evidence.frame.input_fingerprint = "other".into(),
            "missing-run" => changed.evidence.frame.run_id = "other".into(),
            "resource" => changed.evidence.evidence_ref = "admitted_input".into(),
            "digest" => changed.evidence.evidence_digest = "other".into(),
            _ => unreachable!(),
        }
        let auth = authority(&changed);
        let error = facade
            .reconcile_versioned_save(changed, epoch, &source, &auth, b"recovery")
            .expect_err(case);
        if case == "missing-run" {
            assert!(
                format!("{error:?}").contains("versioned save dispatch is unavailable"),
                "{case}: {error:?}"
            );
        }
    }
    for case in ["branch", "path", "base", "draft", "executor"] {
        let mut changed = expected_binding.clone();
        match case {
            "branch" => changed.branch_id = "other".into(),
            "path" => changed.path = "other".into(),
            "base" => changed.base_cut_id = "other".into(),
            "draft" => changed.draft_hash = "other".into(),
            "executor" => changed.executing_principal = "other".into(),
            _ => unreachable!(),
        }
        let source = VersionedSaveEvidenceSource {
            binding: &changed,
            ..source
        };
        assert!(
            facade
                .reconcile_versioned_save(
                    command.clone(),
                    epoch,
                    &source,
                    &authority(&command),
                    b"recovery"
                )
                .is_err(),
            "{case}"
        );
    }
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(instance)
            .expect("refused history"),
        before
    );
    let states = facade
        .kernel()
        .store()
        .list_runs(instance)
        .expect("run states");
    let workflow = facade
        .kernel()
        .store()
        .get_instance(instance)
        .expect("instance")
        .expect("present");
    let facts = facade.kernel().store().list_facts(instance).expect("facts");
    let outcome = facade.reconcile_versioned_save(
        command.clone(),
        epoch,
        &source,
        &authority(&command),
        b"recovery",
    );
    if mode == "conflict" {
        assert!(format!(
            "{:?}",
            outcome.expect_err("missing cut never proves application")
        )
        .contains("versioned save target has no committed result"));
        return;
    }
    whipplescript_kernel::save_reconciliation::conformance::check(
        &command,
        &source,
        &facade
            .kernel()
            .store()
            .chain_prefix(instance)
            .expect("prefix"),
        &authority(&command),
        b"recovery",
    );
    let receipt = outcome.expect("actual target result reconciles");
    let scenario = format!("{}/{mode}", provenance.initiator);
    host_action_contract_reports::record::<S, _>(&scenario, "ReconcileEffectCommand", &command);
    host_action_contract_reports::record::<S, _>(&scenario, "ReconciliationReceipt", &receipt);
    let after = facade
        .kernel()
        .store()
        .list_events(instance)
        .expect("reconciled history");
    assert_eq!(after.len(), before.len() + 1);
    let attempts = fold_attempts(instance, effect_id, &after).expect("resolved");
    assert_eq!(attempts[0].disposition, ExternalDisposition::Applied);
    assert!(!attempts[0].disputed);
    assert_eq!(
        facade.kernel().store().list_runs(instance).expect("runs"),
        states
    );
    assert_eq!(
        facade
            .kernel()
            .store()
            .get_instance(instance)
            .expect("instance")
            .expect("present"),
        workflow
    );
    assert_eq!(
        facade.kernel().store().list_facts(instance).expect("facts"),
        facts
    );
    facade
        .kernel_mut()
        .store_mut()
        .rebuild_projections(instance)
        .expect("rebuild");
    assert_eq!(
        facade
            .reconcile_versioned_save(
                command.clone(),
                epoch,
                &source,
                &authority(&command),
                b"recovery"
            )
            .expect("redeliver"),
        receipt
    );
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(instance)
            .expect("stable history"),
        after
    );
    let revoked = authority(&command);
    revoked.revoked.set(true);
    assert!(facade
        .reconcile_versioned_save(command.clone(), epoch, &source, &revoked, b"recovery")
        .is_err());
    target
        .content_store()
        .erase(
            &recovered.expect("committed result").reference.content_hash,
            "t5",
        )
        .expect("erase target result");
    let error = facade
        .reconcile_versioned_save(
            command.clone(),
            epoch,
            &source,
            &authority(&command),
            b"recovery",
        )
        .expect_err("erased proof cannot be redelivered");
    assert!(format!("{error:?}").contains("versioned save retained target evidence is unavailable"));
    assert_eq!(
        facade
            .kernel()
            .store()
            .list_events(instance)
            .expect("erasure leaves metadata"),
        after
    );
    assert_eq!(
        target
            .read(MAINLINE_BRANCH_ID, "test.txt")
            .expect("head")
            .as_deref(),
        Some("later edit")
    );
}
