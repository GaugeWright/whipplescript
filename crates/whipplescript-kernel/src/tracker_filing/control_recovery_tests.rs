use super::*;
use crate::{
    host_facade::TrackerControlRecoveryAuthority,
    host_protocol::tracker_recovery::RecoverTrackerControl, tracker_control::ControlDispatch,
};

struct ControlRecoveryAuthority {
    request: RecoverTrackerControl,
    original: HostActionCommand,
    execution: ExecuteActionEffect,
    binding: TrackerControlBinding,
    observation: bool,
    deny_publication: bool,
    checks: Cell<usize>,
}
impl TrackerControlRecoveryAuthority for ControlRecoveryAuthority {
    fn authenticate(
        &self,
        request: &RecoverTrackerControl,
        bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if request == &self.request
            && bytes == request.signing_bytes()?
            && proof == b"control-recovery"
        {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch(
                "fixture control recovery authentication",
            ))
        }
    }
    fn authorize_observation(
        &self,
        _: &RecoverTrackerControl,
        binding: &TrackerControlBinding,
    ) -> Result<(), ProtocolError> {
        assert_eq!(binding, &self.binding);
        if self.observation {
            Ok(())
        } else {
            Err(ProtocolError::Mismatch(
                "fixture control recovery observation",
            ))
        }
    }
    fn authorize_recovery(
        &self,
        request: &RecoverTrackerControl,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        dispatch: &ControlDispatch,
        control: &TrackerControl,
    ) -> Result<(), ProtocolError> {
        assert_eq!(request, &self.request);
        assert_eq!(original, &self.original);
        assert_eq!(execution, &self.execution);
        assert_eq!(dispatch.binding, self.binding);
        assert_eq!(control.actor, execution.provenance.executor);
        self.checks.set(self.checks.get() + 1);
        if self.deny_publication && self.checks.get() > 1 {
            Err(ProtocolError::Mismatch("fixture control recovery revoked"))
        } else {
            Ok(())
        }
    }
}

fn recovery_authority(
    f: &Fixture,
    binding: &TrackerControlBinding,
    run_id: &str,
) -> ControlRecoveryAuthority {
    let mut provenance = f.request.provenance.clone();
    provenance.executor = "agent:assistant".into();
    provenance.delegation = vec![ActionDelegation {
        grant_ref: "grant:control-recovery".into(),
        delegator: "person:learner".into(),
        delegate: "agent:assistant".into(),
    }];
    let request = RecoverTrackerControl {
        protocol: TRACKER_RECOVERY_PROTOCOL.into(),
        issuer: f.request.issuer.clone(),
        scope: f.request.scope.clone(),
        admission: f.request.admission.clone(),
        policy: f.facade.policy_ref().clone(),
        provenance,
        effect_id: f.request.effect_id.clone(),
        run_id: run_id.into(),
    };
    ControlRecoveryAuthority {
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
    binding: &TrackerControlBinding,
    expired: bool,
) {
    let instance = f.request.admission.instance_ref.clone();
    let runs = f
        .facade
        .kernel()
        .store()
        .list_runs(&instance)
        .expect("original control attempt");
    assert_eq!(runs.len(), 1);
    let mut authority = recovery_authority(f, binding, &runs[0].run_id);
    let owner = f
        .facade
        .kernel_mut()
        .store_mut()
        .claim_instance_ownership(&instance)
        .expect("own control recovery");
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
            b"control-recovery".as_slice()
        };
        let error = f
            .facade
            .recover_tracker_control(
                authority.request.clone(),
                &f.action,
                owner,
                &authority,
                proof,
                binding,
            )
            .expect_err("denied control recovery");
        let expected = match case {
            "authentication" => "fixture control recovery authentication",
            "observation" => "fixture control recovery observation",
            _ => "fixture control recovery revoked",
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
        .recover_tracker_control(
            authority.request.clone(),
            &f.action,
            owner,
            &authority,
            b"control-recovery",
            binding,
        )
        .expect("publish original control result");
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
            .recover_tracker_control(
                authority.request.clone(),
                &f.action,
                owner,
                &authority,
                b"control-recovery",
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
fn governed_tracker_control_recovers_original_positive_and_negative_outcomes_after_restart() {
    for protected in [false, true] {
        for expired in [false, true] {
            for held in [false, true] {
                let root = std::env::temp_dir().join(format!(
                    "whip-control-recovery-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_nanos()
                ));
                std::fs::create_dir_all(&root).unwrap();
                let (mut f, binding, authority) = fixture_control_in(
                    "person:learner",
                    "tracker.claim",
                    "expires_at string",
                    lease_argument(),
                    protected_stores::create(&root, protected),
                    held.then_some("agent:assistant"),
                );
                let fault = rusqlite::Connection::open(root.join("runtime.sqlite")).unwrap();
                fault.execute_batch("CREATE TRIGGER control_settlement_fault AFTER INSERT ON events WHEN NEW.event_type = 'effect.terminal' BEGIN SELECT RAISE(ABORT, 'injected control terminal fault'); END").unwrap();
                let error = execute(&mut f, &binding, &authority).unwrap_err();
                assert!(format!("{error:?}").contains("injected control terminal fault"));
                let instance = f.request.admission.instance_ref.clone();
                let operation =
                    crate::tracker_control::control_operation_id(&instance, &f.request.effect_id);
                let receipt = f
                    .facade
                    .kernel()
                    .store()
                    .control_receipt(&operation)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    receipt.outcome,
                    if held {
                        TrackerControlOutcome::AlreadyClaimed {
                            holder: "agent:assistant".into(),
                        }
                    } else {
                        TrackerControlOutcome::Claimed {
                            expires_at: "2999-01-01 00:00:00".into(),
                        }
                    }
                );
                // Change the task after its outcome was committed. Recovery must
                // retain that historical outcome and never reacquire the task.
                f.facade
                    .kernel_mut()
                    .store_mut()
                    .release_item(&binding.item_id, None)
                    .unwrap();
                fault
                    .execute_batch("DROP TRIGGER control_settlement_fault")
                    .unwrap();
                drop(fault);
                let Fixture {
                    facade,
                    action,
                    original,
                    request,
                    binding: tracker,
                } = f;
                drop(facade);
                let mut f = Fixture {
                    facade: GovernedHostFacade::from_verified_store(
                        protected_stores::reopen(&root, protected),
                        7,
                        envelope(policy(), 7),
                    )
                    .unwrap(),
                    action,
                    original,
                    request,
                    binding: tracker,
                };
                if expired {
                    f.facade
                        .kernel_mut()
                        .expire_leases(&instance, "2099-01-01T00:00:00Z")
                        .unwrap();
                }
                f.facade
                    .kernel_mut()
                    .store_mut()
                    .rebuild_projections(&instance)
                    .unwrap();
                recover_and_continue(&mut f, &binding, expired);
                assert_eq!(
                    f.facade
                        .kernel()
                        .store()
                        .control_receipt(&operation)
                        .unwrap()
                        .unwrap(),
                    receipt
                );
                assert_eq!(
                    f.facade
                        .kernel()
                        .store()
                        .get_item(&binding.item_id)
                        .unwrap()
                        .unwrap()
                        .claimed_by,
                    None
                );
                drop(f);
                protected_stores::assert_sealed(&root, protected);
                std::fs::remove_dir_all(root).unwrap();
            }
        }
    }
}

#[test]
fn tracker_control_recovery_denies_observation_before_unavailable_history() {
    let (mut f, binding, _) = fixture_control(
        "person:learner",
        "tracker.claim",
        "expires_at string",
        lease_argument(),
        false,
        None,
    );
    let mut authority = recovery_authority(&f, &binding, "missing-run");
    authority.observation = false;
    f.facade.kernel_mut().store_mut().runtime =
        whipplescript_store::SqliteStore::open_in_memory().unwrap();
    let before = f.facade.kernel().store().event_position().unwrap();
    let error = f
        .facade
        .recover_tracker_control(
            authority.request.clone(),
            &f.action,
            0,
            &authority,
            b"control-recovery",
            &binding,
        )
        .unwrap_err();
    assert!(
        matches!(error, HostFacadeError::Protocol(ProtocolError::Mismatch(message)) if message == "fixture control recovery observation")
    );
    assert_eq!(f.facade.kernel().store().event_position().unwrap(), before);
    assert_eq!(authority.checks.get(), 0);
}

fn refuse_control_recovery(
    f: &mut Fixture,
    binding: &TrackerControlBinding,
    authority: &ControlRecoveryAuthority,
    expected: &str,
    checks: usize,
) {
    let instance = &authority.request.admission.instance_ref;
    let owner = f
        .facade
        .kernel_mut()
        .store_mut()
        .claim_instance_ownership(instance)
        .expect("own control recovery fixture");
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
        .recover_tracker_control(
            authority.request.clone(),
            &f.action,
            owner,
            authority,
            b"control-recovery",
            binding,
        )
        .expect_err("invalid control recovery refuses");
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
fn tracker_control_recovery_requires_one_exact_dispatch_and_actual_receipt() {
    for case in [
        "missing",
        "duplicate",
        "fingerprint",
        "coordinates",
        "effect",
        "receipt-missing",
        "receipt-different",
        "not-applied",
        "disputed",
    ] {
        let (mut f, binding, control) = fixture_control(
            "person:learner",
            "tracker.claim",
            "expires_at string",
            lease_argument(),
            false,
            None,
        );
        f.facade
            .execute_tracker_control(
                f.request.clone(),
                &f.action,
                &control,
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
                ("tracker control recovery dispatch is unavailable", 0)
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
                ("tracker control recovery duplicate dispatch", 0)
            }
            "fingerprint" | "coordinates" => {
                // A correctly chained but inconsistent retained dispatch must
                // fail its fingerprint check before consulting target evidence.
                let mut altered = payload.clone();
                authority.request.run_id = "another-recorded-run".into();
                altered["run_id"] = json!(authority.request.run_id);
                altered["external_dispatch"]["frame"]["run_id"] = json!(authority.request.run_id);
                if case == "coordinates" {
                    altered["metadata"]["tracker_control"]["request"]["actor"] =
                        json!("agent:foreign");
                } else {
                    altered["metadata"]["tracker_control"]["fingerprint"] = json!("different");
                }
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
                (
                    if case == "coordinates" {
                        "tracker control recovery original request coordinates"
                    } else {
                        "tracker control recovery original request fingerprint"
                    },
                    0,
                )
            }
            "effect" => {
                authority.request.effect_id = "another-effect".into();
                ("tracker control recovery exact original dispatch", 0)
            }
            "receipt-missing" => {
                f.facade.kernel_mut().store_mut().items =
                    whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
                (
                    "tracker control recovery has no committed control receipt",
                    1,
                )
            }
            "receipt-different" => {
                let mut items =
                    whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
                let mut control =
                    whipplescript_store::tracker_control::conformance::setup(&mut items);
                control.operation_id =
                    crate::tracker_control::control_operation_id(&instance, &f.request.effect_id);
                items.control_issue_once(&control).unwrap();
                f.facade.kernel_mut().store_mut().items = items;
                ("tracker control recovery receipt differs from dispatch", 1)
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
                ("tracker control recovery disputed target evidence", 0)
            }
            _ => unreachable!(),
        };
        refuse_control_recovery(&mut f, &binding, &authority, expected, checks);
    }
}

#[test]
fn tracker_control_recovery_requires_the_signed_authority_before_history() {
    let (mut f, binding, _) = fixture_control(
        "person:learner",
        "tracker.claim",
        "expires_at string",
        lease_argument(),
        false,
        None,
    );
    let mut authority = recovery_authority(&f, &binding, "not-yet-dispatched");
    authority.request.issuer = "another-issuer".into();
    refuse_control_recovery(
        &mut f,
        &binding,
        &authority,
        "tracker control recovery signed authority and epoch",
        0,
    );
}

#[test]
fn tracker_control_recovery_requires_original_resources_before_dispatch_reads() {
    let (mut f, mut binding, _) = fixture_control(
        "person:learner",
        "tracker.claim",
        "expires_at string",
        lease_argument(),
        false,
        None,
    );
    binding.tracker.scope = "another-workspace".into();
    let authority = recovery_authority(&f, &binding, "not-yet-dispatched");
    refuse_control_recovery(
        &mut f,
        &binding,
        &authority,
        "tracker control recovery original resource binding",
        0,
    );
}
