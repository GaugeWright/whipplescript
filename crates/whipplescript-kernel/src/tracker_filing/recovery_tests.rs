use super::*;

fn request(f: &Fixture, run_id: &str) -> RecoverTrackerFiling {
    let mut provenance = f.request.provenance.clone();
    provenance.executor = "agent:assistant".into();
    provenance.delegation = vec![ActionDelegation {
        grant_ref: "grant:recover".into(),
        delegator: "person:learner".into(),
        delegate: "agent:assistant".into(),
    }];
    RecoverTrackerFiling {
        protocol: TRACKER_RECOVERY_PROTOCOL.into(),
        issuer: f.request.issuer.clone(),
        scope: f.request.scope.clone(),
        admission: f.request.admission.clone(),
        policy: f.facade.policy_ref().clone(),
        provenance,
        effect_id: f.request.effect_id.clone(),
        run_id: run_id.into(),
    }
}

fn refuse(f: &mut Fixture, request: RecoverTrackerFiling, expected: &str, checks: usize) {
    let authority = RecoveryAuthority {
        request: request.clone(),
        original: f.original.clone(),
        binding: f.binding.clone(),
        observation: true,
        deny_publication: false,
        checks: Cell::new(0),
    };
    let instance = request.admission.instance_ref.clone();
    let owner = f
        .facade
        .kernel_mut()
        .store_mut()
        .claim_instance_ownership(&instance)
        .expect("own recovery fixture");
    let before = f
        .facade
        .kernel()
        .store()
        .chain_head(&instance)
        .expect("read original fixture head");
    let error = f
        .facade
        .recover_tracker_filing(
            request,
            &f.action,
            owner,
            &authority,
            b"recovery",
            &f.binding,
        )
        .expect_err("invalid recovery must refuse");
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
            .chain_head(&instance)
            .expect("read head after refusal"),
        before
    );
}

#[test]
fn tracker_recovery_requires_the_original_tracker_resource_before_dispatch_reads() {
    for case in ["kind", "selector", "writable", "rebound", "scope", "queue"] {
        let mut f = fixture_in(
            "person:learner",
            NativeStores::open_in_memory().unwrap(),
            |resource| match case {
                "kind" => resource.resource.kind = "file".into(),
                "selector" => resource.resource.selector = Some("other".into()),
                "writable" => resource.resource.writable = Some(false),
                _ => {}
            },
        );
        match case {
            "rebound" => {
                f.binding.resource.basis = ActionBasis::Version {
                    version_ref: "different-incarnation".into(),
                }
            }
            "scope" => f.binding.scope = "another-workspace".into(),
            "queue" => f.binding.queue = "other".into(),
            _ => {}
        }
        let recovery = request(&f, "not-yet-dispatched");
        refuse(
            &mut f,
            recovery,
            "tracker recovery original resource binding",
            0,
        );
    }
}

#[test]
fn tracker_recovery_requires_one_exact_dispatch_and_its_actual_receipt() {
    for case in [
        "missing",
        "duplicate",
        "effect",
        "receipt-missing",
        "receipt-different",
    ] {
        let mut f = fixture("person:learner");
        let authority = Authority::new(&f);
        f.facade
            .execute_tracker_filing(
                f.request.clone(),
                &f.action,
                &authority,
                b"execution",
                &f.binding,
            )
            .unwrap();
        let instance = f.request.admission.instance_ref.clone();
        let events = f.facade.kernel().store().list_events(&instance).unwrap();
        let start = events
            .iter()
            .find(|event| event.event_type == "effect.run_started" && event.source == "kernel")
            .unwrap();
        let payload: Value = serde_json::from_str(&start.payload_json).unwrap();
        let mut recovery = request(&f, payload["run_id"].as_str().unwrap());
        let (expected, checks) = match case {
            "missing" => {
                recovery.run_id = "another-run".into();
                ("tracker recovery dispatch is unavailable", 0)
            }
            "duplicate" => {
                // An internally inconsistent but correctly chained history must
                // fail before target lookup; a second copy is not new evidence.
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
                ("tracker recovery duplicate dispatch", 0)
            }
            "effect" => {
                recovery.effect_id = "another-effect".into();
                ("tracker recovery exact original dispatch", 0)
            }
            "receipt-missing" => {
                f.facade.kernel_mut().store_mut().items =
                    whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
                ("tracker recovery has no committed filing receipt", 1)
            }
            "receipt-different" => {
                let mut items =
                    whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
                let mut filing = whipplescript_store::tracker_filing::conformance::request();
                filing.operation_id = filing_operation_id(&instance, &f.request.effect_id);
                items.file_issue_once(&filing).unwrap();
                f.facade.kernel_mut().store_mut().items = items;
                ("tracker recovery receipt differs from dispatch", 1)
            }
            _ => unreachable!(),
        };
        refuse(&mut f, recovery, expected, checks);
    }
}
