//! Durable knowledge of an external operation, independent of run status.
//!
//! Both stores record the same marker before yielding to a sink. This fold
//! consumes only recorded events: it neither queries a target nor dispatches.
//! Reconciliation records may be appended only after the kernel has verified
//! target evidence and the caller's current authority.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{EventView, RunStart, StoreError, StoreResult};

pub const EFFECT_RECOVERY_PROTOCOL: &str = "whipplescript.effect-recovery.v1";

pub const RECOVERY_EVENTS_SQL: &str = "SELECT event_id, sequence, event_type, payload_json, source, occurred_at FROM events WHERE instance_id = ?1 AND event_type IN ('effect.run_started', 'effect.terminal', 'lease.expired', 'effect.disposition.recorded', 'effect.disposition.reconciled') ORDER BY sequence";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalDisposition {
    NotDispatched,
    #[default]
    Unknown,
    Applied,
    NotApplied,
}

/// A stronger declaration requires evidence for the actual adapter/target.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryCeiling {
    RepeatableRead,
    Transactional,
    Deduplicated,
    Reconcilable,
    #[default]
    Unverifiable,
}

/// Exact attempt coordinates. Input bodies remain in their governed stores;
/// this marker binds their canonical digest and the resolved execution digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchFrame {
    pub protocol: String,
    pub instance_id: String,
    pub effect_id: String,
    pub run_id: String,
    pub idempotency_key: String,
    pub kind: String,
    pub target: Option<String>,
    pub provider: String,
    pub input_fingerprint: String,
    pub execution_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_admission: Option<crate::host_actions::ActionAdmissionBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchMarker {
    pub frame: DispatchFrame,
    pub ceiling: RecoveryCeiling,
}

/// Only positive target evidence can make either assertion. No error label or
/// caller-selected run status converts into this type during the event fold.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDisposition {
    Applied,
    NotApplied,
}

impl From<EvidenceDisposition> for ExternalDisposition {
    fn from(value: EvidenceDisposition) -> Self {
        match value {
            EvidenceDisposition::Applied => Self::Applied,
            EvidenceDisposition::NotApplied => Self::NotApplied,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispositionEvidence {
    pub frame: DispatchFrame,
    pub disposition: EvidenceDisposition,
    /// Opaque, labeled target receipt; never a response or credential body.
    pub evidence_ref: String,
    pub evidence_digest: String,
    pub authority_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptDisposition {
    pub run_id: String,
    /// Absent for legacy history whose exact dispatch was not recorded.
    pub dispatch: Option<DispatchMarker>,
    pub terminal_status: Option<String>,
    pub disposition: ExternalDisposition,
    pub evidence: Vec<DispositionEvidence>,
    pub disputed: bool,
}

/// Canonical structured hashing is independent of serde's preserve_order
/// feature. Every nested object is explicitly sorted before serialization.
pub fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut names: Vec<_> = object.keys().collect();
            names.sort();
            let mut ordered = serde_json::Map::new();
            for name in names {
                ordered.insert(name.clone(), canonical_value(&object[name]));
            }
            Value::Object(ordered)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        other => other.clone(),
    }
}

/// The legacy entry point has no proved recovery contract. Recording a
/// stronger ceiling in arbitrary metadata cannot promote it.
pub fn unverified_dispatch_marker(
    run: RunStart<'_>,
    kind: &str,
    target: Option<&str>,
    input_json: &str,
    idempotency_key: &str,
    execution_fingerprint: &str,
) -> StoreResult<DispatchMarker> {
    let input: Value = serde_json::from_str(input_json)?;
    let input_fingerprint = crate::items::sha256_hex(
        &json!([EFFECT_RECOVERY_PROTOCOL, "input", canonical_value(&input)]).to_string(),
    );
    Ok(DispatchMarker {
        frame: DispatchFrame {
            protocol: EFFECT_RECOVERY_PROTOCOL.into(),
            instance_id: run.instance_id.into(),
            effect_id: run.effect_id.into(),
            run_id: run.run_id.into(),
            idempotency_key: idempotency_key.into(),
            kind: kind.into(),
            target: target.map(str::to_owned),
            provider: run.provider.into(),
            input_fingerprint,
            execution_fingerprint: execution_fingerprint.into(),
            action_admission: None,
        },
        ceiling: RecoveryCeiling::Unverifiable,
    })
}

#[cfg(feature = "native")]
pub(crate) fn native_dispatch_marker(
    connection: &rusqlite::Connection,
    run: RunStart<'_>,
    fingerprint: &str,
) -> StoreResult<DispatchMarker> {
    let (kind, target, input, key): (String, Option<String>, String, String) = connection.query_row(
        "SELECT kind, target, whip_payload_open('runtime.effects.input_json', effects.effect_id, input_json), idempotency_key FROM effects WHERE instance_id = ?1 AND effect_id = ?2",
        [run.instance_id, run.effect_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let mut marker =
        unverified_dispatch_marker(run, &kind, target.as_deref(), &input, &key, fingerprint)?;
    marker.frame.action_admission =
        crate::host_actions::native_dispatch_admission_binding(connection, run.instance_id)?;
    Ok(marker)
}

#[cfg(feature = "native")]
pub(crate) fn native_attempts(
    connection: &rusqlite::Connection,
    instance_id: &str,
    effect_id: &str,
) -> StoreResult<Vec<AttemptDisposition>> {
    let mut statement = connection.prepare(RECOVERY_EVENTS_SQL)?;
    let events = statement
        .query_map([instance_id], |row| {
            Ok(EventView {
                event_id: row.get(0)?,
                sequence: row.get(1)?,
                event_type: row.get(2)?,
                payload_json: crate::runtime_protection::read_event_payload(
                    connection, row, 0, 2, 3,
                )?,
                source: row.get(4)?,
                occurred_at: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    fold_attempts(instance_id, effect_id, &events)
}

/// Fold one effect's dispatches and verified evidence in durable order.
/// Malformed or mismatched records refuse rather than becoming absence.
pub fn fold_attempts(
    instance_id: &str,
    effect_id: &str,
    events: &[EventView],
) -> StoreResult<Vec<AttemptDisposition>> {
    let mut attempts: Vec<AttemptDisposition> = Vec::new();
    for event in events {
        // External event admission fixes its source to `external`; a workflow
        // emitting a reserved-looking name cannot manufacture kernel evidence.
        if event.source != "kernel" {
            continue;
        }
        if !matches!(
            event.event_type.as_str(),
            "effect.run_started"
                | "effect.terminal"
                | "lease.expired"
                | "effect.disposition.recorded"
                | "effect.disposition.reconciled"
        ) {
            continue;
        }
        let payload: Value = serde_json::from_str(&event.payload_json)?;
        if matches!(
            event.event_type.as_str(),
            "effect.disposition.recorded" | "effect.disposition.reconciled"
        ) {
            let evidence: DispositionEvidence =
                serde_json::from_value(if event.event_type == "effect.disposition.reconciled" {
                    payload
                        .pointer("/command/evidence")
                        .cloned()
                        .unwrap_or(Value::Null)
                } else {
                    payload
                })?;
            if evidence.frame.effect_id != effect_id {
                continue;
            }
            let attempt = attempts
                .iter_mut()
                .find(|attempt| attempt.run_id == evidence.frame.run_id);
            let Some(attempt) = attempt.filter(|attempt| {
                attempt
                    .dispatch
                    .as_ref()
                    .is_some_and(|dispatch| dispatch.frame == evidence.frame)
            }) else {
                let message: String = "external evidence does not bind a recorded dispatch".into();
                // MUTATION-SUCCESS-EXPR: Ok(Vec::new())
                return Err(StoreError::Conflict(message));
            };
            if !attempt.evidence.contains(&evidence) {
                let outcome = ExternalDisposition::from(evidence.disposition);
                if attempt.disposition == ExternalDisposition::Unknown {
                    attempt.disposition = outcome;
                } else if attempt.disposition != outcome {
                    attempt.disputed = true;
                }
                attempt.evidence.push(evidence);
            }
            continue;
        }
        if payload.get("effect_id").and_then(Value::as_str) != Some(effect_id) {
            continue;
        }
        let run_id = payload.get("run_id").and_then(Value::as_str).unwrap_or("");
        if event.event_type == "effect.run_started" {
            let dispatch: Option<DispatchMarker> = payload
                .get("external_dispatch")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?;
            if run_id.is_empty()
                || dispatch.as_ref().is_some_and(|dispatch| {
                    dispatch.frame.protocol != EFFECT_RECOVERY_PROTOCOL
                        || dispatch.frame.instance_id != instance_id
                        || dispatch.frame.effect_id != effect_id
                        || dispatch.frame.run_id != run_id
                })
                || attempts.iter().any(|attempt| attempt.run_id == run_id)
            {
                return Err(StoreError::Conflict(
                    "invalid or duplicate external dispatch identity".into(),
                ));
            }
            attempts.push(AttemptDisposition {
                run_id: run_id.into(),
                dispatch,
                terminal_status: None,
                disposition: ExternalDisposition::Unknown,
                evidence: Vec::new(),
                disputed: false,
            });
        } else {
            // A terminal describes worker execution, never target knowledge.
            let terminal_status = if event.event_type == "lease.expired" {
                Some("lease_expired".to_owned())
            } else {
                payload
                    .get("status")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            };
            if let Some(attempt) = attempts.iter_mut().find(|attempt| attempt.run_id == run_id) {
                attempt.terminal_status = terminal_status;
            } else {
                // A legacy terminal without its dispatch cannot prove that
                // no attempt happened. Preserve the explicit evidence gap.
                attempts.push(AttemptDisposition {
                    run_id: run_id.into(),
                    dispatch: None,
                    terminal_status,
                    disposition: ExternalDisposition::Unknown,
                    evidence: Vec::new(),
                    disputed: false,
                });
            }
        }
    }
    Ok(attempts)
}

/// The ordinary dispatch door may resubmit only after every earlier attempt
/// is proved absent. Stronger target recovery uses its separate adapter path.
pub fn require_proved_absence(attempts: &[AttemptDisposition]) -> StoreResult<()> {
    if attempts
        .iter()
        .any(|attempt| attempt.disputed || attempt.disposition != ExternalDisposition::NotApplied)
    {
        return Err(StoreError::Conflict(
            "external outcome does not prove safe resubmission".into(),
        ));
    }
    Ok(())
}

/// Legacy uncertainty used metadata before it gained its own recorded column.
pub fn terminal_run_status(payload: &Value) -> &str {
    payload
        .get("run_status")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            if payload
                .pointer("/metadata/recovery")
                .and_then(Value::as_str)
                == Some("uncertain")
            {
                "uncertain"
            } else {
                payload
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("completed")
            }
        })
}

/// Executable storage contract, run by both native and hosted backends.
pub mod conformance {
    use super::*;
    use crate::{EffectCompletion, NewEffect, NewInstance, RuleCommit, RuntimeStore};

    pub fn check(store: &mut impl RuntimeStore) {
        let version = crate::host_actions::conformance::register(store);
        store
            .register_capability_schema(crate::CapabilitySchemaRegistration {
                capability: "event.emit",
                description: "recovery fixture",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .expect("register the fixture capability");
        store
            .bind_capability(crate::CapabilityBinding {
                binding_id: "recovery-fixture-binding",
                program_id: Some(&version.program_id),
                capability: "event.emit",
                provider: "fixture",
                config_json: "{}",
            })
            .expect("bind the fixture capability");
        store
            .register_effect_provider(crate::EffectProviderRegistration {
                provider_id: "recovery-fixture-provider",
                effect_kind: "event.emit",
                provider: "fixture",
                capability: "event.emit",
                config_json: "{}",
                registered_by_package_id: None,
            })
            .expect("register the fixture adapter on both stores");
        for status in ["completed", "failed", "timed_out", "cancelled", "uncertain"] {
            let instance = store
                .create_instance(NewInstance {
                    program_id: &version.program_id,
                    version_id: &version.version_id,
                    input_json: "{}",
                })
                .expect("create recovery fixture");
            let effect_id = format!("recovery-effect-{status}");
            let run_id = format!("recovery-run-{status}");
            let lease_id = format!("recovery-lease-{status}");
            store
                .commit_rule(RuleCommit {
                    instance_id: &instance.instance_id,
                    rule: "fixture",
                    trigger_event_id: None,
                    facts: &[],
                    consumed_fact_ids: &[],
                    effects: &[NewEffect {
                        effect_id: &effect_id,
                        kind: "event.emit",
                        target: Some("target:1"),
                        input_json: r#"{"handle":"content:1"}"#,
                        status: "queued",
                        idempotency_key: &effect_id,
                        required_capabilities_json: "[]",
                        profile: None,
                        correlation_id: None,
                        source_span_json: None,
                        timeout_seconds: None,
                    }],
                    dependencies: &[],
                    terminal: None,
                    idempotency_key: Some("fixture-commit"),
                    marks: &[],
                    context_json: None,
                })
                .expect("commit an ordinary effect");
            store
                .start_run(RunStart {
                    instance_id: &instance.instance_id,
                    effect_id: &effect_id,
                    run_id: &run_id,
                    provider: "fixture",
                    worker_id: "worker",
                    lease_id: &lease_id,
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    metadata_json: r#"{"recovery_ceiling":"deduplicated"}"#,
                })
                .expect("dispatch marker commits before the sink");
            let events = store
                .list_events(&instance.instance_id)
                .expect("read dispatch");
            let started =
                fold_attempts(&instance.instance_id, &effect_id, &events).expect("fold dispatch");
            assert_eq!(started.len(), 1);
            let dispatch = started[0]
                .dispatch
                .as_ref()
                .expect("new dispatch has exact coordinates");
            assert_eq!(dispatch.ceiling, RecoveryCeiling::Unverifiable);
            assert_eq!(dispatch.frame.idempotency_key, effect_id);
            assert_eq!(dispatch.frame.target.as_deref(), Some("target:1"));
            assert_eq!(dispatch.frame.provider, "fixture");
            assert_eq!(dispatch.frame.input_fingerprint.len(), 64);
            assert!(!dispatch.frame.execution_fingerprint.is_empty());
            let completion = EffectCompletion {
                instance_id: &instance.instance_id,
                effect_id: &effect_id,
                run_id: &run_id,
                provider: "fixture",
                worker_id: "worker",
                status: if status == "uncertain" {
                    "failed"
                } else {
                    status
                },
                exit_code: None,
                summary: None,
                metadata_json: "{}",
                idempotency_key: Some("fixture-terminal"),
            };
            if status == "uncertain" {
                store
                    .resolve_effect_uncertain(completion, None)
                    .expect("resolve worker uncertainty");
            } else {
                store
                    .complete_effect(completion)
                    .expect("record worker terminal");
            }
            let terminal = store
                .list_events(&instance.instance_id)
                .expect("read terminal");
            let attempts =
                fold_attempts(&instance.instance_id, &effect_id, &terminal).expect("fold terminal");
            assert_eq!(attempts[0].dispatch.as_ref(), Some(dispatch));
            assert_eq!(attempts[0].disposition, ExternalDisposition::Unknown);
            assert_eq!(
                attempts[0].terminal_status.as_deref(),
                Some(completion.status)
            );
            store
                .rebuild_projections(&instance.instance_id)
                .expect("rebuild without target I/O");
            let replayed = store
                .list_events(&instance.instance_id)
                .expect("read rebuilt log");
            assert_eq!(terminal, replayed, "inspection and rebuild append nothing");
            assert_eq!(
                attempts,
                fold_attempts(&instance.instance_id, &effect_id, &replayed).expect("fold replay")
            );
            assert_eq!(
                store
                    .list_runs(&instance.instance_id)
                    .expect("rebuilt runs")[0]
                    .status,
                status
            );
            let retry = crate::RetryEffect {
                instance_id: &instance.instance_id,
                effect_id: &effect_id,
                retry_after: None,
                idempotency_key: Some("retry-after-absence"),
            };
            assert!(
                store.retry_effect(retry).is_err(),
                "{status} does not prove absence"
            );
            assert_eq!(
                store
                    .list_events(&instance.instance_id)
                    .expect("refusal is inert"),
                terminal
            );
            if status == "failed" {
                // Storage fixture for evidence the kernel has already checked.
                // Production callers cannot assert this label via event.emit.
                let absent = DispositionEvidence {
                    frame: dispatch.frame.clone(),
                    disposition: EvidenceDisposition::NotApplied,
                    evidence_ref: "fixture:absence".into(),
                    evidence_digest: "fixture:digest".into(),
                    authority_ref: "fixture:target".into(),
                };
                store
                    .append_event(crate::NewEvent {
                        instance_id: &instance.instance_id,
                        event_type: "effect.disposition.recorded",
                        payload_json: &serde_json::to_string(&absent)
                            .expect("encode fixture evidence"),
                        source: "kernel",
                        causation_id: Some(&run_id),
                        correlation_id: None,
                        idempotency_key: Some("fixture:absence"),
                    })
                    .expect("admit fixture evidence");
                store
                    .retry_effect(retry)
                    .expect("proof of absence permits a retry");
                let next_run = format!("{run_id}:next");
                let next_lease = format!("{lease_id}:next");
                store
                    .start_run(RunStart {
                        instance_id: &instance.instance_id,
                        effect_id: &effect_id,
                        run_id: &next_run,
                        provider: "fixture",
                        worker_id: "worker",
                        lease_id: &next_lease,
                        lease_expires_at: "2030-01-01T00:00:00Z",
                        metadata_json: "{}",
                    })
                    .expect("new attempt under the original effect identity");
                let renewed = fold_attempts(
                    &instance.instance_id,
                    &effect_id,
                    &store
                        .list_events(&instance.instance_id)
                        .expect("new attempt"),
                )
                .expect("fold new attempt");
                assert_eq!(renewed.len(), 2);
                assert_eq!(renewed[0].disposition, ExternalDisposition::NotApplied);
                assert_eq!(renewed[1].disposition, ExternalDisposition::Unknown);
                assert_eq!(
                    renewed[1]
                        .dispatch
                        .as_ref()
                        .expect("new marker")
                        .frame
                        .idempotency_key,
                    dispatch.frame.idempotency_key
                );
                store
                    .expire_leases(&instance.instance_id, "2030-01-02T00:00:00Z")
                    .expect("release expired worker lease");
                assert_eq!(
                    store
                        .list_effects(&instance.instance_id)
                        .expect("effect status")[0]
                        .status,
                    "failed"
                );
                assert!(store
                    .claimable_effects(&instance.instance_id)
                    .expect("held effect")
                    .is_empty());
                assert!(
                    store.retry_effect(retry).is_err(),
                    "absence for an older attempt is not absence for this one"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "native")]
    #[test]
    fn external_recovery_native_conformance() {
        conformance::check(&mut crate::SqliteStore::open_in_memory().unwrap());
    }

    fn marker() -> DispatchMarker {
        unverified_dispatch_marker(
            RunStart {
                instance_id: "instance",
                effect_id: "effect",
                run_id: "attempt",
                provider: "adapter",
                worker_id: "worker",
                lease_id: "lease",
                lease_expires_at: "later",
                metadata_json: "{}",
            },
            "send",
            Some("target:1"),
            r#"{"ref":"input:1"}"#,
            "stable-key",
            "execution:1",
        )
        .unwrap()
    }

    fn event(kind: &str, payload: Value) -> EventView {
        EventView {
            event_id: "event".into(),
            sequence: 1,
            event_type: kind.into(),
            payload_json: payload.to_string(),
            source: "kernel".into(),
            occurred_at: "recorded".into(),
        }
    }

    fn started() -> EventView {
        event(
            "effect.run_started",
            json!({ "effect_id": "effect", "run_id": "attempt", "external_dispatch": marker() }),
        )
    }

    fn evidence(disposition: EvidenceDisposition, evidence_ref: &str) -> DispositionEvidence {
        DispositionEvidence {
            frame: marker().frame,
            disposition,
            evidence_ref: evidence_ref.into(),
            evidence_digest: format!("digest:{evidence_ref}"),
            authority_ref: "target-authority:1".into(),
        }
    }

    fn recorded(evidence: &DispositionEvidence) -> EventView {
        event(
            "effect.disposition.recorded",
            serde_json::to_value(evidence).unwrap(),
        )
    }

    #[test]
    fn external_disposition_is_not_a_terminal_status() {
        assert!(require_proved_absence(&[]).is_ok());
        for status in ["completed", "failed", "timed_out", "cancelled", "uncertain"] {
            let events = vec![
                started(),
                event(
                    "effect.terminal",
                    json!({
                        "effect_id": "effect", "run_id": "attempt", "status": status,
                        "metadata": { "disposition": "not_applied", "recovery_ceiling": "deduplicated" }
                    }),
                ),
            ];
            let attempts = fold_attempts("instance", "effect", &events).unwrap();
            assert_eq!(attempts[0].disposition, ExternalDisposition::Unknown);
            assert_eq!(attempts[0].terminal_status.as_deref(), Some(status));
            assert_eq!(
                attempts[0].dispatch.as_ref().unwrap().ceiling,
                RecoveryCeiling::Unverifiable
            );
            assert!(require_proved_absence(&attempts).is_err(), "{status}");
        }
    }

    #[test]
    fn late_evidence_is_retained_and_contradiction_stops_recovery() {
        let absent = evidence(EvidenceDisposition::NotApplied, "receipt:absent");
        let applied = evidence(EvidenceDisposition::Applied, "receipt:applied");
        let mut events = vec![started(), recorded(&absent), recorded(&absent)];
        let attempts = fold_attempts("instance", "effect", &events).unwrap();
        assert_eq!(attempts[0].evidence, vec![absent.clone()]);
        assert!(require_proved_absence(&attempts).is_ok());
        events.push(recorded(&applied));
        let attempts = fold_attempts("instance", "effect", &events).unwrap();
        assert_eq!(attempts[0].disposition, ExternalDisposition::NotApplied);
        assert!(attempts[0].disputed);
        assert_eq!(attempts[0].evidence, vec![absent, applied.clone()]);
        assert!(require_proved_absence(&attempts).is_err());
        let applied_only =
            fold_attempts("instance", "effect", &[started(), recorded(&applied)]).unwrap();
        assert_eq!(applied_only[0].disposition, ExternalDisposition::Applied);
        assert!(require_proved_absence(&applied_only).is_err());
    }

    #[test]
    fn an_external_event_cannot_settle_a_dispatch() {
        let mut forged = recorded(&evidence(EvidenceDisposition::NotApplied, "forged"));
        forged.source = "external".into();
        let attempts = fold_attempts("instance", "effect", &[started(), forged]).unwrap();
        assert_eq!(attempts[0].disposition, ExternalDisposition::Unknown);
        assert!(attempts[0].evidence.is_empty());
        assert!(require_proved_absence(&attempts).is_err());
    }

    #[test]
    fn evidence_must_bind_every_dispatch_coordinate() {
        let original = evidence(EvidenceDisposition::Applied, "receipt");
        let encoded = serde_json::to_value(&original.frame).unwrap();
        for field in encoded.as_object().unwrap().keys() {
            let mut altered = encoded.clone();
            altered[field] = json!("another");
            let changed = DispositionEvidence {
                frame: serde_json::from_value(altered).unwrap(),
                ..original.clone()
            };
            let result = fold_attempts("instance", "effect", &[started(), recorded(&changed)]);
            // Another effect is outside this reader's selected stream.
            if field == "effect_id" {
                assert_eq!(result.unwrap()[0].disposition, ExternalDisposition::Unknown);
            } else {
                assert!(result.is_err(), "{field}");
            }
        }
        assert!(fold_attempts("instance", "effect", &[recorded(&original)]).is_err());
    }

    #[test]
    fn evidence_cannot_change_or_drop_the_original_action_admission() {
        let legacy = marker();
        let encoded = serde_json::to_value(&legacy).unwrap();
        assert!(encoded["frame"].get("action_admission").is_none());
        assert_eq!(
            serde_json::from_value::<DispatchMarker>(encoded).unwrap(),
            legacy
        );
        let mut bound = marker();
        bound.frame.action_admission = Some(crate::host_actions::ActionAdmissionBinding {
            fingerprint: "original-command".into(),
            sequence: 2,
            head_digest: "original-prefix".into(),
        });
        let started = event(
            "effect.run_started",
            json!({"effect_id":"effect", "run_id":"attempt", "external_dispatch":bound}),
        );
        let original = DispositionEvidence {
            frame: bound.frame.clone(),
            disposition: EvidenceDisposition::Applied,
            evidence_ref: "target-receipt".into(),
            evidence_digest: "target-digest".into(),
            authority_ref: "target-authority".into(),
        };
        assert_eq!(
            fold_attempts(
                "instance",
                "effect",
                &[started.clone(), recorded(&original)]
            )
            .unwrap()[0]
                .disposition,
            ExternalDisposition::Applied
        );
        for field in ["fingerprint", "sequence", "head_digest", "absent"] {
            let mut changed = original.clone();
            match field {
                "fingerprint" => {
                    changed.frame.action_admission.as_mut().unwrap().fingerprint =
                        "another-command".into()
                }
                "sequence" => changed.frame.action_admission.as_mut().unwrap().sequence = 3,
                "head_digest" => {
                    changed.frame.action_admission.as_mut().unwrap().head_digest =
                        "another-prefix".into()
                }
                "absent" => changed.frame.action_admission = None,
                _ => unreachable!(),
            }
            assert!(
                fold_attempts("instance", "effect", &[started.clone(), recorded(&changed)])
                    .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn duplicate_or_mismatched_dispatch_cannot_become_evidence() {
        for field in ["protocol", "instance_id", "effect_id", "run_id"] {
            let mut broken = serde_json::to_value(marker()).unwrap();
            broken["frame"][field] = json!("another");
            let event = event(
                "effect.run_started",
                json!({
                    "effect_id": "effect", "run_id": "attempt", "external_dispatch": broken
                }),
            );
            assert!(
                fold_attempts("instance", "effect", &[event]).is_err(),
                "{field}"
            );
        }
        assert!(fold_attempts("instance", "effect", &[started(), started()]).is_err());
        let legacy = event(
            "effect.run_started",
            json!({"effect_id": "effect", "run_id": "legacy"}),
        );
        let attempts = fold_attempts("instance", "effect", &[legacy]).unwrap();
        assert!(attempts[0].dispatch.is_none());
        assert_eq!(attempts[0].disposition, ExternalDisposition::Unknown);
        assert!(require_proved_absence(&attempts).is_err());
    }

    #[test]
    fn uncertainty_rebuild_preserves_legacy_and_new_run_status() {
        assert_eq!(
            terminal_run_status(&json!({"status":"failed", "run_status":"uncertain"})),
            "uncertain"
        );
        assert_eq!(
            terminal_run_status(&json!({"status":"failed", "metadata":{"recovery":"uncertain"}})),
            "uncertain"
        );
        assert_eq!(
            terminal_run_status(&json!({"status":"timed_out"})),
            "timed_out"
        );
    }
}
