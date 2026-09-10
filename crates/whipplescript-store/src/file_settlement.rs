//! A local effect terminal and its ordinary workflow fact are one transaction.
//! File APIs retain their shipped names; resolution recording shares this
//! transaction with an exact provider/target profile. Target application remains
//! a separate boundary; this primitive never repeats I/O.
use crate::{EffectCompletion, NewFact, StoreError, StoreResult};

#[derive(Clone, Copy, Debug)]
pub struct FileSettlementFact<'a> {
    pub fact_id: &'a str,
    pub event_key: &'a str,
    pub name: &'a str,
    pub value_json: &'a str,
}

/// Shared local settlement descriptor. The file name is retained for source
/// compatibility; the provider and recorded effect determine the allowed profile.
pub type LocalEffectSettlementFact<'a> = FileSettlementFact<'a>;

pub const RESOLUTION_RECORDING_PROVIDER: &str = "resolution-memory";
pub const RESOLUTION_RECORDING_CAPABILITY: &str = "vcs.record_resolutions";

impl<'a> FileSettlementFact<'a> {
    pub fn validate(&self, completion: EffectCompletion<'_>) -> StoreResult<()> {
        let value: serde_json::Value = serde_json::from_str(self.value_json)?;
        let metadata: serde_json::Value = serde_json::from_str(completion.metadata_json)?;
        let recording = completion.provider == RESOLUTION_RECORDING_PROVIDER;
        let valid_name = if recording {
            self.name == format!("capability.call.{}", completion.status)
        } else {
            ["file.read", "file.write", "file.import", "file.export"]
                .iter()
                .any(|kind| self.name == format!("{kind}.{}", completion.status))
        };
        if (!recording && completion.provider != "files")
            || !matches!(completion.status, "completed" | "failed")
            || !valid_name
            || self.fact_id.trim().is_empty()
            || self.event_key.trim().is_empty()
            || completion
                .idempotency_key
                .is_none_or(|key| key.trim().is_empty() || key == self.event_key)
            || value.get("effect_id").and_then(serde_json::Value::as_str)
                != Some(completion.effect_id)
            || value.get("run_id").and_then(serde_json::Value::as_str) != Some(completion.run_id)
            || value.get("status").and_then(serde_json::Value::as_str) != Some(completion.status)
            || ((completion.status == "completed" || recording)
                && (value.get("value").is_none() || value.get("value") != metadata.get("value")))
        {
            return Err(StoreError::Conflict(
                "file settlement fact does not bind its terminal".into(),
            ));
        }
        Ok(())
    }

    pub fn check_kind(&self, status: &str, recorded_kind: Option<&str>) -> StoreResult<()> {
        if recorded_kind.is_none_or(|kind| self.name != format!("{kind}.{status}")) {
            return Err(StoreError::Conflict(
                "file settlement fact differs from the recorded effect kind".into(),
            ));
        }
        Ok(())
    }

    /// Checked inside settlement's transaction against the actual queued effect
    /// and running attempt, never against a caller's claimed capability/provider.
    pub fn check_effect(
        &self,
        completion: EffectCompletion<'_>,
        recorded_kind: Option<&str>,
        recorded_target: Option<&str>,
        recorded_provider: Option<&str>,
    ) -> StoreResult<()> {
        self.check_kind(completion.status, recorded_kind)?;
        if recorded_provider != Some(completion.provider)
            || (completion.provider == RESOLUTION_RECORDING_PROVIDER
                && recorded_target != Some(RESOLUTION_RECORDING_CAPABILITY))
        {
            return Err(StoreError::Conflict(
                "local settlement differs from the recorded target or run provider".into(),
            ));
        }
        Ok(())
    }

    pub fn require_fresh_fact(&self, already_active: bool) -> StoreResult<()> {
        if already_active {
            return Err(StoreError::Conflict(
                "file settlement fact is already active".into(),
            ));
        }
        Ok(())
    }

    pub fn fact(&self, effect_id: &'a str) -> NewFact<'a> {
        NewFact {
            fact_id: self.fact_id,
            name: self.name,
            key: effect_id,
            value_json: self.value_json,
            schema_id: None,
            provenance_class: "external",
            correlation_id: None,
            source_span_json: None,
        }
    }

    pub fn payload(&self, effect_id: &str) -> StoreResult<String> {
        Ok(serde_json::json!({
            "fact_id": self.fact_id,
            "name": self.name,
            "key": effect_id,
            "value": serde_json::from_str::<serde_json::Value>(self.value_json)?,
            "schema_id": null,
            "provenance_class": "external",
            "correlation_id": null,
        })
        .to_string())
    }
}

#[cfg(feature = "native")]
pub(crate) fn append_fact(
    connection: &rusqlite::Connection,
    completion: EffectCompletion<'_>,
    terminal: &crate::StoredEvent,
    fact: FileSettlementFact<'_>,
) -> StoreResult<()> {
    use rusqlite::OptionalExtension;
    let recorded: Option<(String, Option<String>, String)> = connection
        .query_row(
            "SELECT e.kind, e.target, r.provider FROM effects e JOIN runs r \
             ON r.instance_id = e.instance_id AND r.effect_id = e.effect_id \
             WHERE e.instance_id = ?1 AND e.effect_id = ?2 AND r.run_id = ?3",
            [
                completion.instance_id,
                completion.effect_id,
                completion.run_id,
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    fact.check_effect(
        completion,
        recorded.as_ref().map(|(kind, _, _)| kind.as_str()),
        recorded
            .as_ref()
            .and_then(|(_, target, _)| target.as_deref()),
        recorded.as_ref().map(|(_, _, provider)| provider.as_str()),
    )?;
    let active = connection.query_row(
        "SELECT 1 FROM facts WHERE instance_id = ?1 AND name = ?2 AND key = ?3 AND consumed_at IS NULL",
        [completion.instance_id, fact.name, completion.effect_id], |_| Ok(()),
    ).optional()?.is_some();
    fact.require_fresh_fact(active)?;
    let payload = fact.payload(completion.effect_id)?;
    let event = crate::append_event_on(
        connection,
        crate::NewEvent {
            instance_id: completion.instance_id,
            event_type: "fact.derived",
            payload_json: &payload,
            source: "kernel",
            causation_id: Some(&terminal.event_id),
            correlation_id: None,
            idempotency_key: Some(fact.event_key),
        },
    )?;
    let (version, epoch) = crate::active_revision_on(connection, completion.instance_id)?;
    crate::insert_fact(
        connection,
        completion.instance_id,
        "kernel",
        &event.event_id,
        version.as_deref(),
        epoch,
        &fact.fact(completion.effect_id),
    )
}

/// The same settlement/replay fixture runs against both runtime stores.
#[doc(hidden)]
pub mod conformance {
    use super::*;
    use crate::*;

    pub struct Fixture {
        pub instance: String,
        pub name: String,
        pub status: String,
        pub value: String,
        pub provider: String,
    }

    impl Fixture {
        pub fn completion(&self) -> EffectCompletion<'_> {
            EffectCompletion {
                instance_id: &self.instance,
                effect_id: "settle-effect",
                run_id: "settle-run",
                provider: &self.provider,
                worker_id: "fixture",
                status: &self.status,
                exit_code: Some(0),
                summary: Some("settlement fixture"),
                metadata_json: r#"{"value":{"bytes":4},"failure":{"message":"failed"}}"#,
                idempotency_key: Some("settle-terminal"),
            }
        }
        pub fn fact(&self) -> FileSettlementFact<'_> {
            FileSettlementFact {
                fact_id: "settle-fact",
                event_key: "settle-fact-event",
                name: &self.name,
                value_json: &self.value,
            }
        }
        pub fn diagnostic(&self) -> Option<TerminalDiagnosticRecord> {
            (self.status == "failed").then(|| TerminalDiagnosticRecord {
                program_id: None,
                program_version_id: None,
                severity: Severity::Error,
                code: None,
                message: "failed".into(),
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
        setup_profile(store, kind, status, "files", None)
    }

    pub fn setup_recording(
        store: &mut impl RuntimeStore,
        status: &str,
        provider: &str,
        target: Option<&str>,
    ) -> Fixture {
        setup_profile(store, "capability.call", status, provider, target)
    }

    fn setup_profile(
        store: &mut impl RuntimeStore,
        kind: &str,
        status: &str,
        provider: &str,
        target: Option<&str>,
    ) -> Fixture {
        let capability = target.unwrap_or(kind);
        let version = host_actions::conformance::register(store);
        store
            .register_capability_schema(CapabilitySchemaRegistration {
                capability,
                description: "settlement",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .expect("settlement fixture operation");
        store
            .bind_capability(CapabilityBinding {
                binding_id: "settle-files",
                program_id: Some(&version.program_id),
                capability,
                provider,
                config_json: "{}",
            })
            .expect("settlement fixture operation");
        store
            .register_effect_provider(EffectProviderRegistration {
                provider_id: "settle-files",
                effect_kind: kind,
                provider,
                capability,
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
                effects: &[NewEffect {
                    effect_id: "settle-effect",
                    kind,
                    target,
                    input_json: "{}",
                    status: "queued",
                    idempotency_key: "settle-effect",
                    required_capabilities_json: &serde_json::json!([capability]).to_string(),
                    profile: None,
                    correlation_id: None,
                    source_span_json: None,
                    timeout_seconds: None,
                }],
                dependencies: &[],
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
                provider,
                worker_id: "fixture",
                lease_id: "settle-lease",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("settlement fixture operation");
        Fixture { instance, provider: provider.into(), name: format!("{kind}.{status}"), status: status.into(),
            value: serde_json::json!({"effect_id":"settle-effect", "run_id":"settle-run", "status":status,
                "value":{"bytes":4}}).to_string() }
    }

    fn assert_refusal_evidence(
        store: &impl RuntimeStore,
        fixture: &Fixture,
        before: &[EventView],
        error: &StoreError,
    ) {
        let StoreError::Conflict(reason) = error else {
            panic!("expected a semantic refusal: {error:?}");
        };
        let events = store
            .list_events(&fixture.instance)
            .expect("refusal history");
        assert_eq!(
            events.len(),
            before.len() + 1,
            "refusal leaves one evidence event"
        );
        assert_eq!(&events[..before.len()], before);
        let event = events.last().expect("refusal event");
        assert_eq!(event.event_type, "run.terminal_refused");
        let payload: serde_json::Value =
            serde_json::from_str(&event.payload_json).expect("refusal payload");
        assert_eq!(
            payload,
            serde_json::json!({
                "run_id": "settle-run", "effect_id": "settle-effect",
                "attempted_status": fixture.status, "reason": reason,
            })
        );
    }

    pub fn run_suite(
        store: &mut (impl RuntimeStore + crate::log_append::LogAppend),
        kind: &str,
        status: &str,
    ) {
        let fixture = setup(store, kind, status);
        let id = &fixture.instance;
        let before = store.list_events(id).expect("settlement fixture operation");
        let effects = store
            .list_effects(id)
            .expect("settlement fixture operation");
        for wrong in ["file.unknown.completed", "file.write.cancelled"] {
            let error = store
                .settle_file_effect(
                    fixture.completion(),
                    None,
                    FileSettlementFact {
                        name: wrong,
                        ..fixture.fact()
                    },
                )
                .expect_err("invalid settlement must refuse");
            assert!(
                matches!(error, StoreError::Conflict(ref message) if message == "file settlement fact does not bind its terminal")
            );
            assert_eq!(
                store.list_events(id).expect("settlement fixture operation"),
                before
            );
            assert_eq!(
                store
                    .list_effects(id)
                    .expect("settlement fixture operation"),
                effects
            );
        }
        let wrong_kind = if kind == "file.read" {
            "file.write"
        } else {
            "file.read"
        };
        let wrong_name = format!("{wrong_kind}.{status}");
        let error = store
            .settle_file_effect(
                fixture.completion(),
                fixture.diagnostic(),
                FileSettlementFact {
                    name: &wrong_name,
                    ..fixture.fact()
                },
            )
            .expect_err("invalid settlement must refuse");
        assert!(
            matches!(error, StoreError::Conflict(ref message) if message == "file settlement fact differs from the recorded effect kind")
        );
        assert_refusal_evidence(store, &fixture, &before, &error);
        assert_eq!(
            store.list_runs(id).expect("settlement fixture operation")[0].status,
            "running"
        );
        assert!(store
            .list_facts(id)
            .expect("settlement fixture operation")
            .is_empty());
        assert!(store
            .list_diagnostics(Some(id))
            .expect("settlement fixture operation")
            .is_empty());

        // A reused fact-event key must roll back even an otherwise valid terminal.
        store
            .append_event(NewEvent {
                instance_id: id,
                event_type: "fixture.used",
                payload_json: "{}",
                source: "kernel",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some("spent-fact-key"),
            })
            .expect("settlement fixture operation");
        let before = store.list_events(id).expect("settlement fixture operation");
        let error = store
            .settle_file_effect(
                fixture.completion(),
                fixture.diagnostic(),
                FileSettlementFact {
                    event_key: "spent-fact-key",
                    ..fixture.fact()
                },
            )
            .expect_err("spent fact-event key refuses");
        assert_refusal_evidence(store, &fixture, &before, &error);
        assert_eq!(
            store.list_runs(id).expect("settlement fixture operation")[0].status,
            "running"
        );

        // An already active fact cannot silently absorb a different result.
        store
            .derive_fact(DerivedFact {
                instance_id: id,
                fact: NewFact {
                    fact_id: "prior-fact",
                    value_json: "{}",
                    ..fixture.fact().fact("settle-effect")
                },
                source: "kernel",
                causation_id: None,
                idempotency_key: Some("prior-fact-event"),
            })
            .expect("settlement fixture operation");
        let before = store.list_events(id).expect("settlement fixture operation");
        let error = store
            .settle_file_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
            .expect_err("invalid settlement must refuse");
        assert!(
            matches!(error, StoreError::Conflict(ref message) if message == "file settlement fact is already active")
        );
        assert_refusal_evidence(store, &fixture, &before, &error);
        assert_eq!(
            store.list_runs(id).expect("settlement fixture operation")[0].status,
            "running"
        );
        store
            .commit_rule(RuleCommit {
                instance_id: id,
                rule: "consume-prior-fact",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &["prior-fact"],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("consume-prior-fact"),
                marks: &[],
                context_json: None,
            })
            .expect("settlement fixture operation");

        let terminal = store
            .settle_file_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
            .expect("settlement fixture operation");
        let prefix = store
            .chain_prefix(id)
            .expect("settlement fixture operation");
        let fact_event = prefix
            .iter()
            .find(|event| event.idempotency_key.as_deref() == Some("settle-fact-event"))
            .expect("settlement fixture operation");
        assert_eq!(fact_event.event_type, "fact.derived");
        assert_eq!(
            fact_event.causation_id.as_deref(),
            Some(terminal.event_id.as_str())
        );
        assert_eq!(fact_event.sequence, terminal.sequence + 1);
        let facts = store.list_facts(id).expect("settlement fixture operation");
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].name, fixture.name);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&facts[0].value_json)
                .expect("settlement fixture operation"),
            serde_json::from_str::<serde_json::Value>(&fixture.value)
                .expect("settlement fixture operation")
        );
        assert_eq!(
            store.list_runs(id).expect("settlement fixture operation")[0].status,
            status
        );
        assert_eq!(
            store
                .list_diagnostics(Some(id))
                .expect("settlement fixture operation")
                .len(),
            usize::from(status == "failed")
        );
        let before = store.list_events(id).expect("settled history");
        let error = store
            .settle_file_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
            .expect_err("a duplicate settlement is refused");
        assert_refusal_evidence(store, &fixture, &before, &error);
        let prefix = store.chain_prefix(id).expect("refused history");
        assert!(store
            .settle_file_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
            .is_err());
        assert_eq!(
            store.chain_prefix(id).expect("deduplicated refusal"),
            prefix
        );
        store
            .rebuild_projections(id)
            .expect("settlement fixture operation");
        assert_eq!(
            store.list_facts(id).expect("settlement fixture operation")[0].value_json,
            facts[0].value_json
        );
        assert_eq!(
            store.list_runs(id).expect("settlement fixture operation")[0].status,
            status
        );
        store
            .commit_rule(RuleCommit {
                instance_id: id,
                rule: "consume-settlement",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &["settle-fact"],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("consume-settlement"),
                marks: &[],
                context_json: None,
            })
            .expect("settlement fixture operation");
        store
            .rebuild_projections(id)
            .expect("settlement fixture operation");
        assert!(store
            .list_facts(id)
            .expect("settlement fixture operation")
            .is_empty());
        let prefix = store
            .chain_prefix(id)
            .expect("settlement fixture operation");
        assert!(store
            .settle_file_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
            .is_err());
        assert_eq!(
            store
                .chain_prefix(id)
                .expect("settlement fixture operation"),
            prefix
        );
        assert!(store
            .list_facts(id)
            .expect("settlement fixture operation")
            .is_empty());
    }
}

#[doc(hidden)]
pub mod recording_conformance;

#[cfg(all(test, feature = "native"))]
mod tests;
