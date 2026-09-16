use super::*;
use crate::*;

pub struct Fixture {
    pub instance: String,
    pub status: String,
    pub value: String,
}
impl Fixture {
    pub fn completion(&self) -> EffectCompletion<'_> {
        EffectCompletion {
            instance_id: &self.instance,
            effect_id: "settle-effect",
            run_id: "settle-run",
            provider: "coerce-fixture",
            worker_id: "fixture",
            status: &self.status,
            exit_code: Some(0),
            summary: Some("safe summary"),
            metadata_json: r#"{"value":{"kind":"object","keys":["answer"]}}"#,
            idempotency_key: Some("settle-terminal"),
        }
    }
    pub fn fact(&self) -> CoerceSettlementFact<'_> {
        CoerceSettlementFact {
            fact_id: "settle-fact",
            result_event_key: "settle-result-event",
            fact_event_key: "settle-fact-event",
            name: match self.status.as_str() {
                "completed" => "schema.coerce.succeeded",
                "failed" => "schema.coerce.failed",
                "timed_out" => "schema.coerce.timed_out",
                _ => unreachable!(),
            },
            output_type: "Answer",
            value_json: &self.value,
        }
    }
    pub fn diagnostic(&self) -> Option<TerminalDiagnosticRecord> {
        (self.status != "completed").then(|| TerminalDiagnosticRecord {
            program_id: None,
            program_version_id: None,
            severity: Severity::Error,
            code: None,
            message: "safe summary".into(),
            source_span_json: None,
            subject_type: None,
            subject_id: None,
            assertion_id: None,
            evidence_ids_json: "[]".into(),
            artifact_ids_json: "[]".into(),
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("settle-diagnostic".into()),
        })
    }
}
pub fn setup(store: &mut impl RuntimeStore, kind: &str, status: &str) -> Fixture {
    let version = host_actions::conformance::register(store);
    store
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: kind,
            description: "settlement",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .expect("settlement fixture operation");
    store
        .bind_capability(CapabilityBinding {
            binding_id: "settle-coerce",
            program_id: Some(&version.program_id),
            capability: kind,
            provider: "coerce-fixture",
            config_json: "{}",
        })
        .expect("settlement fixture operation");
    store
        .register_effect_provider(EffectProviderRegistration {
            provider_id: "settle-coerce",
            effect_kind: kind,
            provider: "coerce-fixture",
            capability: kind,
            config_json: "{}",
            registered_by_package_id: None,
        })
        .expect("settlement fixture operation");
    let instance = store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("settlement fixture operation")
        .instance_id;
    store
        .commit_rule(RuleCommit {
            instance_id: &instance,
            rule: "settle",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &[
                NewEffect {
                    effect_id: "settle-dependent",
                    kind,
                    target: None,
                    input_json: "{}",
                    status: "blocked_by_dependency",
                    idempotency_key: "settle-dependent",
                    required_capabilities_json: "[]",
                    profile: None,
                    correlation_id: None,
                    source_span_json: None,
                    timeout_seconds: None,
                },
                NewEffect {
                    effect_id: "settle-effect",
                    kind,
                    target: None,
                    input_json: "{}",
                    status: "queued",
                    idempotency_key: "settle-effect",
                    required_capabilities_json: "[]",
                    profile: None,
                    correlation_id: None,
                    source_span_json: None,
                    timeout_seconds: None,
                },
            ],
            dependencies: &[NewEffectDependency {
                dependency_id: "settle-dependency",
                upstream_effect_id: "settle-effect",
                downstream_effect_id: "settle-dependent",
                predicate: "completes",
            }],
            terminal: None,
            idempotency_key: Some("settle-rule"),
            marks: &[],
            context_json: None,
        })
        .expect("settlement fixture operation");
    store
        .start_dispatch(RunStart {
            instance_id: &instance,
            effect_id: "settle-effect",
            run_id: "settle-run",
            provider: "coerce-fixture",
            worker_id: "fixture",
            lease_id: "settle-lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        })
        .expect("settlement fixture operation");
    Fixture {
        instance,
        status: status.into(),
        value: serde_json::json!({
            "effect_id":"settle-effect", "run_id":"settle-run", "status":status,
            "function_name":"classify", "output_type":"Answer",
            "value":{"answer":"actual output"}, "error":null, "summary":"safe summary"
        })
        .to_string(),
    }
}

pub fn assert_running(store: &impl RuntimeStore, fixture: &Fixture) {
    let id = &fixture.instance;
    assert_eq!(
        store.list_runs(id).expect("coerce settlement fixture")[0].status,
        "running"
    );
    let effects = store.list_effects(id).expect("coerce settlement fixture");
    assert_eq!(
        effects
            .iter()
            .find(|e| e.effect_id == "settle-dependent")
            .expect("coerce settlement fixture")
            .status,
        "blocked_by_dependency"
    );
    assert!(store
        .list_facts(id)
        .expect("coerce settlement fixture")
        .is_empty());
    assert!(store
        .list_diagnostics(Some(id))
        .expect("coerce settlement fixture")
        .is_empty());
}

pub fn run_suite(store: &mut (impl RuntimeStore + crate::log_append::LogAppend), status: &str) {
    let fixture = setup(store, "schema.coerce", status);
    let id = &fixture.instance;
    let before = store.list_events(id).expect("coerce settlement fixture");
    for changed in [
        "status",
        "name",
        "fact-id",
        "result-key",
        "fact-key",
        "terminal-key",
        "same-result-fact",
        "same-result-terminal",
        "same-fact-terminal",
        "output-type",
        "effect",
        "run",
        "value-status",
        "value-type",
        "function",
        "missing-value",
    ] {
        let mut completion = fixture.completion();
        let mut fact = fixture.fact();
        let mut value: serde_json::Value =
            serde_json::from_str(&fixture.value).expect("coerce settlement fixture");
        match changed {
            "status" => completion.status = "cancelled",
            "name" => fact.name = "schema.coerce.unknown",
            "fact-id" => fact.fact_id = " ",
            "result-key" => fact.result_event_key = " ",
            "fact-key" => fact.fact_event_key = " ",
            "terminal-key" => completion.idempotency_key = None,
            "same-result-fact" => fact.result_event_key = fact.fact_event_key,
            "same-result-terminal" => completion.idempotency_key = Some(fact.result_event_key),
            "same-fact-terminal" => completion.idempotency_key = Some(fact.fact_event_key),
            "output-type" => fact.output_type = " ",
            "effect" => value["effect_id"] = "other".into(),
            "run" => value["run_id"] = "other".into(),
            "value-status" => value["status"] = "other".into(),
            "value-type" => value["output_type"] = "Other".into(),
            "function" => value["function_name"] = " ".into(),
            "missing-value" => {
                value
                    .as_object_mut()
                    .expect("coerce settlement fixture")
                    .remove("value");
            }
            _ => unreachable!(),
        }
        let wire = value.to_string();
        fact.value_json = &wire;
        let error = store
            .settle_coerce_effect(completion, fixture.diagnostic(), fact)
            .expect_err("coerce settlement must refuse");
        assert!(
            matches!(error, StoreError::Conflict(ref reason) if reason == "coerce settlement result does not bind its terminal"),
            "{changed}: {error:?}"
        );
        assert_eq!(
            store.list_events(id).expect("coerce settlement fixture"),
            before,
            "{changed}"
        );
        assert_running(store, &fixture);
    }
    // JSON null is a real value (unlike an omitted value).
    let mut null_value: serde_json::Value =
        serde_json::from_str(&fixture.value).expect("coerce settlement fixture");
    null_value["value"] = serde_json::Value::Null;
    CoerceSettlementFact {
        value_json: &null_value.to_string(),
        ..fixture.fact()
    }
    .validate(fixture.completion())
    .expect("coerce settlement fixture");
    // A conflicting result or fact event must not leave a terminal/dependency release.
    store
        .append_event(NewEvent {
            instance_id: id,
            event_type: "fixture.used",
            payload_json: "{}",
            source: "kernel",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("spent-key"),
        })
        .expect("coerce settlement fixture");
    for result_key in [true, false] {
        let mut fact = fixture.fact();
        if result_key {
            fact.result_event_key = "spent-key";
        } else {
            fact.fact_event_key = "spent-key";
        }
        assert!(store
            .settle_coerce_effect(fixture.completion(), fixture.diagnostic(), fact)
            .is_err());
        assert_running(store, &fixture);
        assert!(!store
            .list_events(id)
            .expect("coerce settlement fixture")
            .iter()
            .any(|event| event.event_type == "effect.terminal"
                || event.event_type == fixture.fact().name));
    }
    let terminal = store
        .settle_coerce_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
        .expect("coerce settlement fixture");
    let prefix = store.chain_prefix(id).expect("coerce settlement fixture");
    let result = prefix
        .iter()
        .find(|e| e.idempotency_key.as_deref() == Some("settle-result-event"))
        .expect("coerce settlement fixture");
    let fact_event = prefix
        .iter()
        .find(|e| e.idempotency_key.as_deref() == Some("settle-fact-event"))
        .expect("coerce settlement fixture");
    assert_eq!(result.sequence, terminal.sequence + 1);
    assert_eq!(fact_event.sequence, terminal.sequence + 2);
    assert_eq!(result.event_type, fixture.fact().name);
    assert_eq!(result.payload_json, fixture.value);
    assert_eq!(result.causation_id.as_deref(), Some("settle-run"));
    assert_eq!(result.correlation_id.as_deref(), Some("settle-effect"));
    assert_eq!(fact_event.event_type, "fact.derived");
    let facts = store.list_facts(id).expect("coerce settlement fixture");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].value_json, fixture.value);
    assert_eq!(facts[0].key, "settle-run");
    let admitted: serde_json::Value =
        serde_json::from_str(&fact_event.payload_json).expect("coerce settlement fixture");
    assert_eq!(admitted["schema_id"], "Answer");
    assert_eq!(facts[0].provenance_class, "effect");
    assert_eq!(admitted["correlation_id"], "settle-effect");
    assert_eq!(
        store.list_runs(id).expect("coerce settlement fixture")[0].status,
        status
    );
    assert_eq!(
        store
            .list_diagnostics(Some(id))
            .expect("coerce settlement fixture")
            .len(),
        usize::from(status != "completed")
    );
    assert_eq!(
        store
            .list_effects(id)
            .expect("coerce settlement fixture")
            .iter()
            .find(|e| e.effect_id == "settle-dependent")
            .expect("coerce settlement fixture")
            .status,
        "queued"
    );
    assert!(!prefix
        .iter()
        .find(|e| e.event_type == "effect.terminal")
        .expect("coerce settlement fixture")
        .payload_json
        .contains("actual output"));
    assert!(store
        .settle_coerce_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
        .is_err());
    store
        .rebuild_projections(id)
        .expect("coerce settlement fixture");
    assert_eq!(
        store.list_facts(id).expect("coerce settlement fixture")[0].value_json,
        fixture.value
    );
    store
        .commit_rule(RuleCommit {
            instance_id: id,
            rule: "consume",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &["settle-fact"],
            effects: &[],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("consume"),
            marks: &[],
            context_json: None,
        })
        .expect("coerce settlement fixture");
    store
        .rebuild_projections(id)
        .expect("coerce settlement fixture");
    let before = store.chain_prefix(id).expect("coerce settlement fixture");
    assert!(store
        .settle_coerce_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
        .is_err());
    assert_eq!(
        store.chain_prefix(id).expect("coerce settlement fixture"),
        before
    );
    assert!(store
        .list_facts(id)
        .expect("coerce settlement fixture")
        .is_empty());
    assert_eq!(
        store
            .list_events(id)
            .expect("coerce settlement fixture")
            .iter()
            .find(|e| e.event_type == fixture.fact().name)
            .expect("coerce settlement fixture")
            .payload_json,
        fixture.value
    );
}

pub fn wrong_kind(store: &mut impl RuntimeStore) {
    let fixture = setup(store, "file.write", "failed");
    let error = store
        .settle_coerce_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
        .expect_err("coerce settlement must refuse");
    assert!(
        matches!(error, StoreError::Conflict(ref reason) if reason == "coerce settlement requires a recorded schema.coerce effect")
    );
    assert_running(store, &fixture);
    assert!(fixture.fact().check_kind(None).is_err());
}

pub fn occupied_fact(store: &mut impl RuntimeStore) {
    let fixture = setup(store, "schema.coerce", "failed");
    store
        .derive_fact(DerivedFact {
            instance_id: &fixture.instance,
            fact: NewFact {
                fact_id: "prior-fact",
                value_json: "{}",
                ..fixture.fact().fact(fixture.completion())
            },
            source: "kernel",
            causation_id: None,
            idempotency_key: Some("prior-fact-event"),
        })
        .expect("coerce settlement fixture");
    let facts = store
        .list_facts(&fixture.instance)
        .expect("coerce settlement fixture");
    let error = store
        .settle_coerce_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
        .expect_err("coerce settlement must refuse");
    assert!(
        matches!(error, StoreError::Conflict(ref reason) if reason == "coerce settlement fact is already active")
    );
    assert_eq!(
        store
            .list_facts(&fixture.instance)
            .expect("coerce settlement fixture"),
        facts
    );
    assert_eq!(
        store
            .list_runs(&fixture.instance)
            .expect("coerce settlement fixture")[0]
            .status,
        "running"
    );
    assert!(store
        .list_diagnostics(Some(&fixture.instance))
        .expect("coerce settlement fixture")
        .is_empty());
    assert!(!store
        .list_events(&fixture.instance)
        .expect("coerce settlement fixture")
        .iter()
        .any(|e| e.event_type == "effect.terminal"));
}
