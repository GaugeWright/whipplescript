use super::*;
use crate::{
    host_facade::TrackerClosureRecoveryAuthority,
    host_protocol::tracker_recovery::RecoverTrackerClosure, tracker_closure::ClosureDispatch,
};

struct CloseRecoveryAuthority {
    request: RecoverTrackerClosure,
    original: HostActionCommand,
    execution: ExecuteActionEffect,
    binding: TrackerClosureBinding,
    observation: bool,
    deny_publication: bool,
    checks: Cell<usize>,
}
impl TrackerClosureRecoveryAuthority for CloseRecoveryAuthority {
    fn authenticate(
        &self,
        request: &RecoverTrackerClosure,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request == &self.request
            && bytes == request.signing_bytes()?
            && proof == b"closing-recovery"
        {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch(
                "fixture closing recovery authentication",
            ))
        }
    }
    fn authorize_observation(
        &self,
        _: &RecoverTrackerClosure,
        binding: &TrackerClosureBinding,
    ) -> Result<(), ProtocolError> {
        assert_eq!(binding, &self.binding);
        if self.observation {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch(
                "fixture closing recovery observation",
            ))
        }
    }
    fn authorize_recovery(
        &self,
        request: &RecoverTrackerClosure,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        dispatch: &ClosureDispatch,
        closure: &TrackerClosure,
    ) -> Result<(), ProtocolError> {
        assert_eq!(request, &self.request);
        assert_eq!(original, &self.original);
        assert_eq!(execution, &self.execution);
        assert_eq!(dispatch.binding, self.binding);
        assert_eq!(closure.actor, execution.provenance.executor);
        assert_eq!(closure.expected_holder, self.binding.expected_holder);
        self.checks.set(self.checks.get() + 1);
        if self.deny_publication && self.checks.get() > 1 {
            Err(ProtocolError::Mismatch("fixture closing recovery revoked"))
        } else {
            Ok(())
        }
    }
}

fn recovery_authority(
    f: &Fixture,
    binding: &TrackerClosureBinding,
    run_id: &str,
) -> CloseRecoveryAuthority {
    let mut provenance = f.request.provenance.clone();
    provenance.executor = "agent:assistant".into();
    provenance.delegation = vec![ActionDelegation {
        grant_ref: "grant:closing-recovery".into(),
        delegator: "person:learner".into(),
        delegate: "agent:assistant".into(),
    }];
    let request = RecoverTrackerClosure {
        protocol: TRACKER_RECOVERY_PROTOCOL.into(),
        issuer: f.request.issuer.clone(),
        scope: f.request.scope.clone(),
        admission: f.request.admission.clone(),
        policy: f.facade.policy_ref().clone(),
        provenance,
        effect_id: f.request.effect_id.clone(),
        run_id: run_id.into(),
    };
    CloseRecoveryAuthority {
        request,
        original: f.original.clone(),
        execution: f.request.clone(),
        binding: binding.clone(),
        observation: true,
        deny_publication: false,
        checks: Cell::new(0),
    }
}

pub(super) fn recover_and_continue(
    f: &mut Fixture,
    binding: &TrackerClosureBinding,
    expired: bool,
) {
    let instance = f.request.admission.instance_ref.clone();
    let runs = f
        .facade
        .kernel()
        .store()
        .list_runs(&instance)
        .expect("original closing attempt");
    assert_eq!(runs.len(), 1);
    let mut authority = recovery_authority(f, binding, &runs[0].run_id);
    let owner = f
        .facade
        .kernel_mut()
        .store_mut()
        .claim_instance_ownership(&instance)
        .expect("own closing recovery");
    let before = f
        .facade
        .kernel()
        .store()
        .chain_head(&instance)
        .expect("original recovery history");
    let tracker_before = f
        .facade
        .kernel()
        .store()
        .event_position()
        .expect("target history");
    for case in ["authentication", "observation", "revocation"] {
        authority.observation = case != "observation";
        authority.deny_publication = case == "revocation";
        authority.checks.set(0);
        let proof = if case == "authentication" {
            b"forged".as_slice()
        } else {
            b"closing-recovery".as_slice()
        };
        let error = f
            .facade
            .recover_tracker_closure(
                authority.request.clone(),
                &f.action,
                owner,
                &authority,
                proof,
                binding,
            )
            .expect_err("denied closing recovery");
        let expected = match case {
            "authentication" => "fixture closing recovery authentication",
            "observation" => "fixture closing recovery observation",
            _ => "fixture closing recovery revoked",
        };
        assert!(
            matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message)) if message == expected),
            "{case}: {error:?}"
        );
        assert_eq!(
            authority.checks.get(),
            if case == "revocation" { 2 } else { 0 }
        );
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .chain_head(&instance)
                .expect("unchanged refused history"),
            before
        );
        assert_eq!(
            f.facade
                .kernel()
                .store()
                .event_position()
                .expect("unchanged target"),
            tracker_before
        );
    }
    authority.deny_publication = false;
    authority.checks.set(0);
    let result = f
        .facade
        .recover_tracker_closure(
            authority.request.clone(),
            &f.action,
            owner,
            &authority,
            b"closing-recovery",
            binding,
        )
        .expect("publish original closing result");
    assert_eq!(authority.checks.get(), 2);
    assert_eq!(
        f.facade
            .kernel()
            .store()
            .event_position()
            .expect("read-only target recovery"),
        tracker_before
    );
    let runs_after = f
        .facade
        .kernel()
        .store()
        .list_runs(&instance)
        .expect("retained attempt history");
    assert_eq!(runs_after.len(), 1);
    assert_eq!(
        runs_after[0].status,
        if expired {
            "lease_expired"
        } else {
            "completed"
        }
    );
    let events = f
        .facade
        .kernel()
        .store()
        .list_events(&instance)
        .expect("standard recovered evidence");
    let attempts = whipplescript_store::effect_recovery::fold_attempts(
        &instance,
        &f.request.effect_id,
        &events,
    )
    .expect("standard disposition fold");
    assert_eq!(
        attempts[0].disposition,
        whipplescript_store::effect_recovery::ExternalDisposition::Applied
    );
    assert!(!attempts[0].disputed);
    crate::rule_pass::step_instance_generic(
        f.facade.kernel_mut(),
        &instance,
        f.action.program(),
        None,
        None,
    )
    .expect("ordinary finish continuation");
    assert_eq!(
        f.facade
            .kernel()
            .store()
            .get_instance(&instance)
            .expect("workflow status")
            .expect("workflow exists")
            .status,
        "completed"
    );
    // `then` observes its result; it does not consume the completion fact.
    // Replay and exact redelivery must preserve that projection and the final
    // workflow status, rather than manufacturing another continuation.
    let completed_facts = f
        .facade
        .kernel()
        .store()
        .list_facts(&instance)
        .expect("completed workflow facts");
    f.facade
        .kernel_mut()
        .store_mut()
        .rebuild_projections(&instance)
        .expect("replay recovered completion");
    let head = f
        .facade
        .kernel()
        .store()
        .chain_head(&instance)
        .expect("completed history");
    assert_eq!(
        f.facade
            .recover_tracker_closure(
                authority.request.clone(),
                &f.action,
                owner,
                &authority,
                b"closing-recovery",
                binding
            )
            .expect("exact redelivery after workflow completion"),
        result
    );
    assert_eq!(
        f.facade
            .kernel()
            .store()
            .chain_head(&instance)
            .expect("unchanged redelivery"),
        head
    );
    assert_eq!(
        f.facade
            .kernel()
            .store()
            .list_facts(&instance)
            .expect("unchanged completion facts"),
        completed_facts
    );
    assert_eq!(
        f.facade
            .kernel()
            .store()
            .get_instance(&instance)
            .expect("replayed workflow status")
            .expect("workflow remains present")
            .status,
        "completed"
    );
}

#[test]
fn tracker_closing_recovery_denies_observation_before_unavailable_history() {
    let (mut f, binding, _) = fixture_close("person:learner");
    let mut authority = recovery_authority(&f, &binding, "missing-run");
    authority.observation = false;
    f.facade.kernel_mut().store_mut().runtime =
        whipplescript_store::SqliteStore::open_in_memory().unwrap();
    let before = f.facade.kernel().store().event_position().unwrap();
    let error = f
        .facade
        .recover_tracker_closure(
            authority.request.clone(),
            &f.action,
            0,
            &authority,
            b"closing-recovery",
            &binding,
        )
        .unwrap_err();
    assert!(
        matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message)) if message == "fixture closing recovery observation")
    );
    assert_eq!(f.facade.kernel().store().event_position().unwrap(), before);
    assert_eq!(authority.checks.get(), 0);
}

fn refuse_closing_recovery(
    f: &mut Fixture,
    binding: &TrackerClosureBinding,
    authority: &CloseRecoveryAuthority,
    expected: &str,
    checks: usize,
) {
    let instance = &authority.request.admission.instance_ref;
    let owner = f
        .facade
        .kernel_mut()
        .store_mut()
        .claim_instance_ownership(instance)
        .expect("own closing recovery fixture");
    let before = f
        .facade
        .kernel()
        .store()
        .chain_head(instance)
        .expect("original history");
    let target = f
        .facade
        .kernel()
        .store()
        .event_position()
        .expect("original target");
    let error = f
        .facade
        .recover_tracker_closure(
            authority.request.clone(),
            &f.action,
            owner,
            authority,
            b"closing-recovery",
            binding,
        )
        .expect_err("invalid closing recovery refuses");
    assert!(
        matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message))
        if message == expected),
        "expected {expected}, got {error:?}"
    );
    assert_eq!(authority.checks.get(), checks);
    assert_eq!(
        f.facade
            .kernel()
            .store()
            .chain_head(instance)
            .expect("refused history"),
        before
    );
    assert_eq!(
        f.facade
            .kernel()
            .store()
            .event_position()
            .expect("refused target"),
        target
    );
}

#[test]
fn tracker_closing_recovery_requires_original_resources_before_dispatch_reads() {
    for case in ["kind", "selector", "writable", "rebound", "scope", "queue"] {
        let (mut f, mut binding, _) =
            fixture_close_with("person:learner", CLOSE_SOURCE, |resource| match case {
                "kind" => resource.resource.kind = "file".into(),
                "selector" => resource.resource.selector = Some("other".into()),
                "writable" => resource.resource.writable = Some(false),
                _ => {}
            });
        match case {
            "rebound" => {
                binding.tracker.resource.basis = ActionBasis::Version {
                    version_ref: "different-incarnation".into(),
                }
            }
            "scope" => binding.tracker.scope = "another-workspace".into(),
            "queue" => binding.tracker.queue = "other".into(),
            _ => {}
        }
        let authority = recovery_authority(&f, &binding, "not-yet-dispatched");
        refuse_closing_recovery(
            &mut f,
            &binding,
            &authority,
            "tracker closing recovery original resource binding",
            0,
        );
    }
}

#[test]
fn tracker_closing_recovery_requires_one_exact_dispatch_and_actual_receipt() {
    for case in [
        "missing",
        "duplicate",
        "fingerprint",
        "effect",
        "receipt-missing",
        "receipt-different",
        "not-applied",
        "disputed",
    ] {
        let (mut f, binding, closing) = fixture_close("person:learner");
        f.facade
            .execute_tracker_closure(
                f.request.clone(),
                &f.action,
                &closing,
                b"execution",
                &binding,
            )
            .unwrap();
        let instance = f.request.admission.instance_ref.clone();
        let events = f.facade.kernel().store().list_events(&instance).unwrap();
        let start = events
            .iter()
            .find(|event| event.event_type == "effect.run_started" && event.source == "kernel")
            .unwrap();
        let payload: Value = serde_json::from_str(&start.payload_json).unwrap();
        let mut authority = recovery_authority(&f, &binding, payload["run_id"].as_str().unwrap());
        let (expected, checks) = match case {
            "missing" => {
                authority.request.run_id = "another-run".into();
                ("tracker closing recovery dispatch is unavailable", 0)
            }
            "duplicate" => {
                f.facade
                    .kernel()
                    .store()
                    .append_event(whipplescript_store::NewEvent {
                        instance_id: &instance,
                        event_type: "effect.run_started",
                        payload_json: &start.payload_json,
                        source: "kernel",
                        causation_id: None,
                        correlation_id: None,
                        idempotency_key: None,
                    })
                    .unwrap();
                ("tracker closing recovery duplicate dispatch", 0)
            }
            "fingerprint" => {
                // A correctly chained but inconsistent retained dispatch must
                // fail its fingerprint check before consulting target evidence.
                let mut altered = payload.clone();
                authority.request.run_id = "another-recorded-run".into();
                altered["run_id"] = json!(authority.request.run_id);
                altered["external_dispatch"]["frame"]["run_id"] = json!(authority.request.run_id);
                altered["metadata"]["tracker_closure"]["fingerprint"] = json!("different");
                f.facade
                    .kernel()
                    .store()
                    .append_event(whipplescript_store::NewEvent {
                        instance_id: &instance,
                        event_type: "effect.run_started",
                        payload_json: &altered.to_string(),
                        source: "kernel",
                        causation_id: None,
                        correlation_id: None,
                        idempotency_key: None,
                    })
                    .unwrap();
                ("tracker closing recovery original request fingerprint", 0)
            }
            "effect" => {
                authority.request.effect_id = "another-effect".into();
                ("tracker closing recovery exact original dispatch", 0)
            }
            "receipt-missing" => {
                f.facade.kernel_mut().store_mut().items =
                    whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
                (
                    "tracker closing recovery has no committed closing receipt",
                    1,
                )
            }
            "receipt-different" => {
                let mut items =
                    whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
                let mut closure = whipplescript_store::tracker_closure::conformance::setup(
                    &mut items,
                    "agent:other",
                );
                closure.operation_id =
                    crate::tracker_closure::closing_operation_id(&instance, &f.request.effect_id);
                items.close_issue_once(&closure).unwrap();
                f.facade.kernel_mut().store_mut().items = items;
                ("tracker closing recovery receipt differs from dispatch", 1)
            }
            "not-applied" | "disputed" => {
                use whipplescript_store::effect_recovery::{
                    DispatchMarker, DispositionEvidence, EvidenceDisposition,
                };
                let marker: DispatchMarker =
                    serde_json::from_value(payload["external_dispatch"].clone()).unwrap();
                let outcomes = if case == "disputed" {
                    vec![
                        EvidenceDisposition::Applied,
                        EvidenceDisposition::NotApplied,
                    ]
                } else {
                    vec![EvidenceDisposition::NotApplied]
                };
                for disposition in outcomes {
                    let evidence = DispositionEvidence {
                        frame: marker.frame.clone(),
                        disposition,
                        evidence_ref: format!("investigation:{disposition:?}"),
                        evidence_digest: "retained-investigation-digest".into(),
                        authority_ref: "person:investigator".into(),
                    };
                    f.facade
                        .kernel()
                        .store()
                        .append_event(whipplescript_store::NewEvent {
                            instance_id: &instance,
                            event_type: "effect.disposition.recorded",
                            payload_json: &serde_json::to_string(&evidence).unwrap(),
                            source: "kernel",
                            causation_id: Some(&authority.request.run_id),
                            correlation_id: None,
                            idempotency_key: None,
                        })
                        .unwrap();
                }
                ("tracker closing recovery disputed target evidence", 0)
            }
            _ => unreachable!(),
        };
        refuse_closing_recovery(&mut f, &binding, &authority, expected, checks);
    }
}

#[test]
fn tracker_closing_recovery_requires_the_signed_authority_before_history() {
    let (mut f, binding, _) = fixture_close("person:learner");
    let mut authority = recovery_authority(&f, &binding, "not-yet-dispatched");
    authority.request.issuer = "another-issuer".into();
    refuse_closing_recovery(
        &mut f,
        &binding,
        &authority,
        "tracker closing recovery signed authority and epoch",
        0,
    );
}
