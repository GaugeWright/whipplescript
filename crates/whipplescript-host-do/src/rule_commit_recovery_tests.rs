//! The same replay/deadline contract runs against both real SQLite adapters.
use whipplescript_store::*;

pub(crate) fn version(source: &str) -> NewProgramVersion<'_> {
    NewProgramVersion {
        program_name: "enqueue-recovery",
        source_hash: source,
        ir_hash: source,
        ir_snapshot: None,
        compiler_version: "fixture",
        declared_capabilities_json: "[]",
        declared_profiles_json: "[]",
        declared_skills_json: "[]",
        declared_schemas_json: "[]",
        analysis_summary_json: r#"{"workflow":"enqueue-recovery","workflow_contracts":[],"schemas":[]}"#,
        generated_artifacts_json: "[]",
        artifact_root: None,
    }
}
pub(crate) fn effect(timeout: Option<i64>) -> NewEffect<'static> {
    NewEffect {
        effect_id: "observe",
        kind: "exec.command",
        target: None,
        input_json: "{}",
        status: "queued",
        idempotency_key: "observe",
        required_capabilities_json: r#"["script.observer"]"#,
        profile: None,
        correlation_id: None,
        source_span_json: None,
        timeout_seconds: timeout,
    }
}
pub(crate) fn commit<'a>(instance: &'a str, effects: &'a [NewEffect<'a>]) -> RuleCommit<'a> {
    RuleCommit {
        instance_id: instance,
        rule: "norm.execute",
        trigger_event_id: None,
        facts: &[],
        consumed_fact_ids: &[],
        effects,
        dependencies: &[],
        terminal: None,
        idempotency_key: Some("norm.enqueue"),
        marks: &[],
        context_json: None,
    }
}
fn assert_recovery<S: RuntimeStore>(mut store: S) {
    const {
        assert!(
            SUPPORTED_EVENT_FORMAT_VERSION >= 2,
            "deadline-bearing events require a reader that preserves deadlines"
        );
    }
    let v1 = store
        .create_program_version(version("v1"))
        .expect("version");
    let v2 = store
        .create_program_version(version("v2"))
        .expect("version");
    let instance = store
        .create_instance(NewInstance {
            program_id: &v1.program_id,
            version_id: &v1.version_id,
            input_json: "{}",
        })
        .expect("instance");
    let instance = instance.instance_id;
    let guard = RuleCommitRevisionGuard {
        program_version_id: &v1.version_id,
        revision_epoch: 0,
    };
    let effects = [effect(Some(60))];
    let original = store
        .commit_rule_with_revision_guard(commit(&instance, &effects), guard)
        .expect("commit");
    let before = store.list_events(&instance).expect("events");
    // A different firing may not steal an existing global effect identity or
    // leave a partial rule event behind when the unique insert would fail.
    let mut collision = commit(&instance, &effects);
    collision.idempotency_key = Some("other-firing");
    assert!(store
        .commit_rule_with_revision_guard(collision, guard)
        .is_err());
    assert_eq!(
        store.list_events(&instance).expect("collision is atomic"),
        before
    );
    let mut repeated = [effect(Some(60)), effect(Some(60))];
    for effect in &mut repeated {
        effect.effect_id = "duplicate-new";
    }
    collision.effects = &repeated;
    assert!(store
        .commit_rule_with_revision_guard(collision, guard)
        .is_err());
    assert_eq!(
        store
            .list_events(&instance)
            .expect("duplicate IDs are atomic"),
        before
    );
    assert_eq!(store.list_effects(&instance).expect("one effect").len(), 1);

    assert_eq!(
        store
            .commit_rule_with_revision_guard(commit(&instance, &effects), guard)
            .expect("retry"),
        original
    );
    assert_eq!(store.list_events(&instance).expect("events"), before);
    assert_eq!(
        store.pending_time_effects(&instance).expect("deadlines")[0].timeout_seconds,
        60
    );
    store.rebuild_projections(&instance).expect("rebuild");
    assert_eq!(
        store
            .pending_time_effects(&instance)
            .expect("restored deadline")[0]
            .timeout_seconds,
        60
    );
    // Due-time evaluation retains the event's creation anchor, not rebuild time.
    let created = &before
        .iter()
        .find(|e| e.event_id == original.event_id)
        .expect("commit event")
        .occurred_at;
    assert!(store
        .due_time_effects(&instance, created)
        .expect("at creation")
        .is_empty());
    assert_eq!(
        store
            .due_time_effects(&instance, "2099-01-01T00:00:00Z")
            .expect("expired")
            .len(),
        1
    );

    store
        .activate_revision(RevisionActivation {
            instance_id: &instance,
            from_version_id: &v1.version_id,
            to_version_id: &v2.version_id,
            activation_policy_json: "{}",
            cancellation_policy: "keep",
            rule_carries_json: "[]",
            rule_correspondence_json: "null",
            idempotency_key: Some("revision"),
        })
        .expect("revision");
    assert_eq!(
        store
            .commit_rule_with_revision_guard(commit(&instance, &effects), guard)
            .expect("old acknowledgment"),
        original
    );
    let mut fresh = commit(&instance, &[]);
    fresh.idempotency_key = Some("fresh");
    assert!(matches!(
        store.commit_rule_with_revision_guard(fresh, guard),
        Err(StoreError::Conflict(_))
    ));
    // Changing only a deadline must conflict, not silently return the old event.
    for timeout in [None, Some(61)] {
        assert!(matches!(
            store.commit_rule_with_revision_guard(commit(&instance, &[effect(timeout)]), guard),
            Err(StoreError::Conflict(_))
        ));
    }
    let mut changed = effect(Some(60));
    changed.input_json = r#"{"changed":true}"#;
    assert!(matches!(
        store.commit_rule_with_revision_guard(commit(&instance, &[changed]), guard),
        Err(StoreError::Conflict(_))
    ));
    changed = effect(Some(60));
    changed.required_capabilities_json = "[]";
    assert!(matches!(
        store.commit_rule_with_revision_guard(commit(&instance, &[changed]), guard),
        Err(StoreError::Conflict(_))
    ));

    let mut terminal = commit(&instance, &[]);
    terminal.idempotency_key = Some("done");
    terminal.terminal = Some(WorkflowTerminal {
        kind: WorkflowTerminalKind::Completed,
        name: "done",
        payload_json: "{}",
        idempotency_key: Some("terminal"),
    });
    store.commit_rule(terminal).expect("complete workflow");
    let settled_events = store.list_events(&instance).expect("events");
    let settled_effects = store.list_effects(&instance).expect("effects");
    assert_eq!(
        store
            .commit_rule_with_revision_guard(commit(&instance, &effects), guard)
            .expect("completed acknowledgment"),
        original
    );
    assert_eq!(
        store.list_events(&instance).expect("unchanged journal"),
        settled_events
    );
    assert_eq!(
        store.list_effects(&instance).expect("unchanged effects"),
        settled_effects
    );
    let current = RuleCommitRevisionGuard {
        program_version_id: &v2.version_id,
        revision_epoch: 1,
    };
    assert!(matches!(
        store.commit_rule_with_revision_guard(fresh, current),
        Err(StoreError::Conflict(_))
    ));
    store
        .rebuild_projections(&instance)
        .expect("rebuild completed");
    assert_eq!(
        store
            .commit_rule_with_revision_guard(commit(&instance, &effects), guard)
            .expect("rebuilt acknowledgment"),
        original
    );
    assert_eq!(store.list_effects(&instance).expect("one effect").len(), 1);
}
#[test]
fn native_guarded_commit_recovery_retains_deadline() {
    assert_recovery(SqliteStore::open_in_memory().expect("native store"));
}
#[test]
fn hosted_guarded_commit_recovery_retains_deadline() {
    assert_recovery(crate::do_store::test_support::store());
}

#[test]
fn native_concurrent_enqueue_commits_one_identity() {
    let path = std::env::temp_dir().join(format!(
        "norm-enqueue-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (v, instance) = {
        let mut store = SqliteStore::open(&path).unwrap();
        let v = store.create_program_version(version("v1")).unwrap();
        let instance = store
            .create_instance(NewInstance {
                program_id: &v.program_id,
                version_id: &v.version_id,
                input_json: "{}",
            })
            .unwrap();
        (v, instance)
    };
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let stores: Vec<_> = (0..2)
        .map(|_| SqliteStore::open(&path).expect("independent connection"))
        .collect();
    let handles: Vec<_> = stores
        .into_iter()
        .map(|mut store| {
            let barrier = barrier.clone();
            let v = v.clone();
            let instance = instance.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .commit_rule_with_revision_guard(
                        commit(&instance.instance_id, &[effect(Some(60))]),
                        RuleCommitRevisionGuard {
                            program_version_id: &v.version_id,
                            revision_epoch: 0,
                        },
                    )
                    .expect("atomic enqueue")
            })
        })
        .collect();
    let events: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(events[0], events[1]);
    {
        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.list_effects(&instance.instance_id).unwrap().len(), 1);
        assert_eq!(
            store
                .list_events(&instance.instance_id)
                .unwrap()
                .iter()
                .filter(|e| e.event_type == "rule.committed")
                .count(),
            1
        );
    }
    std::fs::remove_file(path).unwrap();
}

#[test]
fn rule_commit_recovery_checks_transaction_bridge_completion() {
    use crate::do_store::validate_transaction_completion;
    assert!(validate_transaction_completion(true, Ok(())).is_ok());
    assert!(validate_transaction_completion(false, Ok(())).is_err());
    assert!(validate_transaction_completion(true, Err("host commit failed".into())).is_err());
    assert!(validate_transaction_completion(false, Err("host did not start".into())).is_err());
}

/// Record the absence a fenced observation would prove, for one recorded run.
///
/// These fixtures exercise retry, replay and rollback mechanics rather than the
/// recovery contract, but a terminated attempt is not retryable until its
/// absence is proved -- and absence proved for one attempt says nothing about
/// the next. Production callers cannot assert this label; the kernel records it
/// from a fenced observation.
pub(crate) fn prove_absence<S: RuntimeStore>(
    store: &mut S,
    instance: &str,
    run_id: &str,
    key: &str,
) {
    let started = store
        .list_events(instance)
        .unwrap()
        .into_iter()
        .find(|event| {
            event.event_type == "effect.run_started"
                && event
                    .payload_json
                    .contains(&format!("\"run_id\":\"{run_id}\""))
        })
        .expect("the attempt was recorded");
    let payload: serde_json::Value = serde_json::from_str(&started.payload_json).unwrap();
    let dispatch: whipplescript_store::effect_recovery::DispatchMarker =
        serde_json::from_value(payload["external_dispatch"].clone()).unwrap();
    let absent = whipplescript_store::effect_recovery::DispositionEvidence {
        frame: dispatch.frame,
        disposition: whipplescript_store::effect_recovery::EvidenceDisposition::NotApplied,
        evidence_ref: "fixture:absence".into(),
        evidence_digest: "fixture:digest".into(),
        authority_ref: "fixture:target".into(),
    };
    store
        .append_event(NewEvent {
            instance_id: instance,
            event_type: "effect.disposition.recorded",
            payload_json: &serde_json::to_string(&absent).unwrap(),
            source: "kernel",
            causation_id: Some(run_id),
            correlation_id: None,
            idempotency_key: Some(key),
        })
        .unwrap();
}

pub(crate) fn seed_retry_rebuild<S: RuntimeStore>(store: &mut S) -> (String, StoredEvent) {
    let v = store
        .create_program_version(version("retry-replay"))
        .unwrap();
    let instance = store
        .create_instance(NewInstance {
            program_id: &v.program_id,
            version_id: &v.version_id,
            input_json: "{}",
        })
        .unwrap()
        .instance_id;
    store
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "script.observer",
            description: "fixture",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    store
        .bind_capability(CapabilityBinding {
            binding_id: "observer",
            program_id: Some(&v.program_id),
            capability: "script.observer",
            provider: "builtin-script",
            config_json: "{}",
        })
        .unwrap();
    let declaration = effect(None);
    store
        .commit_rule(commit(&instance, &[declaration]))
        .unwrap();
    store
        .start_run_for_admission(crate::run_reattach_tests::request(&instance), None)
        .unwrap();
    store
        .complete_effect(EffectCompletion {
            instance_id: &instance,
            effect_id: "observe",
            run_id: "run",
            provider: "exec",
            worker_id: "worker",
            status: "failed",
            exit_code: Some(1),
            summary: Some("failed"),
            metadata_json: "{}",
            idempotency_key: Some("first-terminal"),
        })
        .unwrap();
    prove_absence(store, &instance, "run", "fixture:absence");
    let receipt = store
        .retry_effect(RetryEffect {
            instance_id: &instance,
            effect_id: "observe",
            retry_after: None,
            idempotency_key: Some("retry"),
        })
        .unwrap();
    (instance, receipt)
}

fn retry_replay<S: RuntimeStore>(mut store: S) {
    let (instance, receipt) = seed_retry_rebuild(&mut store);
    let selected = store
        .claimable_effects(&instance)
        .unwrap()
        .into_iter()
        .find(|effect| effect.effect_id == "observe")
        .expect("queued effect snapshot");
    assert_eq!(
        selected.attempt_admission_event_id.as_deref(),
        Some(receipt.event_id.as_str())
    );
    let repeat = || RetryEffect {
        instance_id: &instance,
        effect_id: "observe",
        retry_after: None,
        idempotency_key: Some("retry"),
    };
    assert_eq!(
        store.retry_effect(repeat()).expect("lost acknowledgement"),
        receipt
    );
    assert!(
        store
            .retry_effect(RetryEffect {
                retry_after: Some("2099-01-01T00:00:00Z"),
                ..repeat()
            })
            .is_err(),
        "a retry key cannot change its request"
    );
    let before_refusal = store.list_events(&instance).unwrap();
    assert!(
        store
            .retry_effect(RetryEffect {
                idempotency_key: Some("queued-retry"),
                ..repeat()
            })
            .is_err(),
        "a fresh retry of a queued effect must be refused"
    );
    assert_eq!(store.list_events(&instance).unwrap(), before_refusal);
    assert_eq!(store.list_effects(&instance).unwrap()[0].status, "queued");
    let mut second = crate::run_reattach_tests::request(&instance);
    second.run_id = "second-run";
    second.lease_id = "second-lease";
    let before_stale = store.list_events(&instance).unwrap();
    for stale in [None, Some("fabricated-admission")] {
        assert!(
            store.start_run_for_admission(second, stale).is_err(),
            "stale attempt must be refused"
        );
        assert_eq!(store.list_events(&instance).unwrap(), before_stale);
        assert_eq!(store.list_runs(&instance).unwrap().len(), 1);
    }
    assert_eq!(
        store
            .effect_attempt_admission(&instance, "observe")
            .unwrap()
            .as_deref(),
        Some(receipt.event_id.as_str())
    );
    let started = store
        .start_run_for_admission(second, Some(&receipt.event_id))
        .unwrap();
    assert_eq!(
        store
            .start_run_for_admission(second, Some(&receipt.event_id))
            .unwrap(),
        started
    );

    store
        .complete_effect(EffectCompletion {
            instance_id: &instance,
            effect_id: "observe",
            run_id: "second-run",
            provider: "exec",
            worker_id: "worker",
            status: "failed",
            exit_code: Some(1),
            summary: Some("failed again"),
            metadata_json: "{}",
            idempotency_key: Some("second-terminal"),
        })
        .unwrap();
    // The second attempt is its own unproved attempt: absence for the first
    // says nothing about it, so the old key is not replayable until this one
    // is settled too.
    prove_absence(
        &mut store,
        &instance,
        "second-run",
        "fixture:absence-second",
    );
    assert_eq!(
        store.retry_effect(repeat()).expect("old acknowledgement"),
        receipt
    );
    assert_eq!(
        store.list_effects(&instance).unwrap()[0].status,
        "failed",
        "old retry must not requeue a later failure"
    );
    let next = store
        .retry_effect(RetryEffect {
            idempotency_key: Some("second-retry"),
            ..repeat()
        })
        .unwrap();
    assert_ne!(next, receipt);
    let refreshed = store
        .claimable_effects(&instance)
        .unwrap()
        .into_iter()
        .find(|effect| effect.effect_id == "observe")
        .expect("next retry snapshot");
    assert_eq!(
        refreshed.attempt_admission_event_id.as_deref(),
        Some(next.event_id.as_str())
    );
    assert_eq!(
        selected.attempt_admission_event_id.as_deref(),
        Some(receipt.event_id.as_str()),
        "held request must retain its original admission"
    );
    let events = store.list_events(&instance).unwrap();
    for _ in 0..2 {
        store
            .rebuild_projections(&instance)
            .expect("admitted retry replays");
        assert_eq!(store.list_effects(&instance).unwrap()[0].status, "queued");
        assert_eq!(store.list_runs(&instance).unwrap()[0].status, "failed");
        assert_eq!(store.list_events(&instance).unwrap(), events);
    }
    let mut third = crate::run_reattach_tests::request(&instance);
    third.run_id = "third-run";
    third.lease_id = "third-lease";
    let before_third = store.list_events(&instance).unwrap();
    assert!(
        store
            .start_run_for_admission(third, Some(&receipt.event_id))
            .is_err(),
        "an earlier retry cannot authorize the third attempt"
    );
    assert_eq!(store.list_events(&instance).unwrap(), before_third);
    assert_eq!(
        store
            .effect_attempt_admission(&instance, "observe")
            .unwrap()
            .as_deref(),
        Some(next.event_id.as_str())
    );
    let third_started = store
        .start_run_for_admission(third, Some(&next.event_id))
        .unwrap();
    assert_eq!(
        store
            .start_run_for_admission(third, Some(&next.event_id))
            .unwrap(),
        third_started
    );
    assert_eq!(store.list_runs(&instance).unwrap().len(), 3);
    // This journal entry has no retryable predecessor. Rebuild must refuse it
    // after earlier replay writes and roll back to the complete prior view.
    store
        .append_event(NewEvent {
            instance_id: &instance,
            event_type: "effect.retried",
            payload_json: r#"{"effect_id":"missing","retry_after":null}"#,
            source: "kernel",
            causation_id: Some("missing"),
            correlation_id: None,
            idempotency_key: Some("invalid-retry"),
        })
        .unwrap();
    let effects = store.list_effects(&instance).unwrap();
    let runs = store.list_runs(&instance).unwrap();
    assert!(store.rebuild_projections(&instance).is_err());
    assert_eq!(store.list_effects(&instance).unwrap(), effects);
    assert_eq!(store.list_runs(&instance).unwrap(), runs);
}

#[test]
fn retry_replay_native_preserves_admission_and_rolls_back_invalid_prefix() {
    retry_replay(SqliteStore::open_in_memory().unwrap());
}

#[test]
fn retry_replay_hosted_preserves_admission_and_rolls_back_invalid_prefix() {
    retry_replay(crate::do_store::test_support::store());
}

fn retry_terminal_selection<S: RuntimeStore>(mut store: S) {
    let (instance, admitted) = seed_retry_rebuild(&mut store);
    let old_terminal = store
        .effect_terminal_event(&instance, "observe")
        .unwrap()
        .unwrap();
    let mut run = crate::run_reattach_tests::request(&instance);
    run.run_id = "terminal-second";
    run.lease_id = "terminal-second-lease";
    store
        .start_run_for_admission(run, Some(&admitted.event_id))
        .unwrap();
    let failure = |run_id, key| EffectCompletion {
        instance_id: &instance,
        effect_id: "observe",
        run_id,
        provider: "exec",
        worker_id: "worker",
        status: "failed",
        exit_code: Some(1),
        summary: Some("failed"),
        metadata_json: "{}",
        idempotency_key: Some(key),
    };
    let terminal = store
        .complete_effect(failure(run.run_id, "terminal-second-failure"))
        .unwrap();
    let request = |key| RetryEffect {
        instance_id: &instance,
        effect_id: "observe",
        retry_after: None,
        idempotency_key: Some(key),
    };
    let before = store.list_events(&instance).unwrap();
    assert!(store
        .retry_effect_at_terminal(request("stale-command"), &old_terminal)
        .is_err());
    assert_eq!(store.list_events(&instance).unwrap(), before);
    assert_eq!(store.list_effects(&instance).unwrap()[0].status, "failed");
    // The second attempt is unproved until observed; selecting a terminal
    // says which attempt is expected, not that it was safe to repeat.
    prove_absence(
        &mut store,
        &instance,
        "terminal-second",
        "fixture:absence-second",
    );
    let receipt = store
        .retry_effect_at_terminal(request("command"), &terminal.event_id)
        .unwrap();
    assert_eq!(
        store
            .retry_effect_at_terminal(request("command"), &terminal.event_id)
            .unwrap(),
        receipt
    );
    assert!(
        store
            .retry_effect_at_terminal(request("command"), &old_terminal)
            .is_err(),
        "one request key cannot change its pinned terminal"
    );
    run.run_id = "terminal-third";
    run.lease_id = "terminal-third-lease";
    store
        .start_run_for_admission(run, Some(&receipt.event_id))
        .unwrap();
    let third = store
        .complete_effect(failure(run.run_id, "terminal-third-failure"))
        .unwrap();
    // A third attempt, unproved like the others.
    prove_absence(
        &mut store,
        &instance,
        "terminal-third",
        "fixture:absence-third",
    );
    assert_eq!(
        store
            .retry_effect_at_terminal(request("command"), &terminal.event_id)
            .unwrap(),
        receipt
    );
    assert_eq!(
        store.list_effects(&instance).unwrap()[0].status,
        "failed",
        "old acknowledgement must not requeue the latest failure"
    );
    let next = store
        .retry_effect_at_terminal(request("next-command"), &third.event_id)
        .unwrap();
    assert_ne!(next, receipt);
    store.rebuild_projections(&instance).unwrap();
    assert_eq!(store.list_effects(&instance).unwrap()[0].status, "queued");
    assert_eq!(store.list_runs(&instance).unwrap().len(), 3);
}

#[test]
fn retry_terminal_selection_native() {
    retry_terminal_selection(SqliteStore::open_in_memory().unwrap());
}
#[test]
fn retry_terminal_selection_hosted() {
    retry_terminal_selection(crate::do_store::test_support::store());
}
