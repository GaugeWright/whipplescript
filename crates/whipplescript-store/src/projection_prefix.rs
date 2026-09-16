//! Read-only fact/effect reconstruction at one event frontier.
//!
//! The append-only instance log remains the only durable history. This module
//! folds a retained prefix into the small read model needed by captured action
//! projection; it creates no tables and mutates no live projection rows.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::{EffectView, EventView, FactView, StoreError, StoreResult};

/// The fact fields consumed by a captured action projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionFact {
    pub fact_id: String,
    pub program_version_id: Option<String>,
    pub revision_epoch: i64,
    pub name: String,
    pub key: String,
    pub value_json: String,
    pub provenance_class: String,
    pub source_span_json: Option<String>,
    pub validity_json: Option<String>,
    pub source_event_id: String,
}

impl From<&FactView> for ProjectionFact {
    fn from(fact: &FactView) -> Self {
        Self {
            fact_id: fact.fact_id.clone(),
            program_version_id: fact.program_version_id.clone(),
            revision_epoch: fact.revision_epoch,
            name: fact.name.clone(),
            key: fact.key.clone(),
            value_json: fact.value_json.clone(),
            provenance_class: fact.provenance_class.clone(),
            source_span_json: fact.source_span_json.clone(),
            validity_json: fact.validity_json.clone(),
            source_event_id: fact.source_event_id.clone(),
        }
    }
}

/// The operation fields consumed by a captured action projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionEffect {
    pub effect_id: String,
    pub kind: String,
    pub target: Option<String>,
    pub input_json: String,
    pub status: String,
    pub created_by_rule: String,
    pub program_version_id: Option<String>,
    pub revision_epoch: i64,
    pub profile: Option<String>,
    pub cancel_requested: bool,
}

impl From<&EffectView> for ProjectionEffect {
    fn from(effect: &EffectView) -> Self {
        Self {
            effect_id: effect.effect_id.clone(),
            kind: effect.kind.clone(),
            target: effect.target.clone(),
            input_json: effect.input_json.clone(),
            status: effect.status.clone(),
            created_by_rule: effect.created_by_rule.clone(),
            program_version_id: effect.program_version_id.clone(),
            revision_epoch: effect.revision_epoch,
            profile: effect.profile.clone(),
            cancel_requested: effect.cancel_requested,
        }
    }
}

/// One exact, retained event prefix and its event-sourced live projections.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionPrefix {
    pub frontier: i64,
    pub events: Vec<EventView>,
    pub facts: Vec<ProjectionFact>,
    pub effects: Vec<ProjectionEffect>,
}

#[derive(Clone)]
struct FactState {
    active: bool,
    view: ProjectionFact,
}

#[derive(Clone)]
struct EffectState {
    admitted_at: i64,
    view: ProjectionEffect,
}

#[derive(Clone)]
struct Dependency {
    upstream: String,
    downstream: String,
    predicate: String,
}

fn conflict(message: impl Into<String>) -> StoreError {
    StoreError::Conflict(message.into())
}

fn object(event: &EventView) -> StoreResult<Value> {
    serde_json::from_str(&event.payload_json).map_err(|error| {
        conflict(format!(
            "event `{}` at sequence {} has unreadable JSON: {error}",
            event.event_id, event.sequence
        ))
    })
}

fn optional_json(value: &Value, field: &str) -> Option<String> {
    value
        .get(field)
        .filter(|value| !value.is_null())
        .map(Value::to_string)
}

fn insert_fact(
    facts: &mut BTreeMap<(String, String), FactState>,
    event: &EventView,
    fact: &Value,
    fallback_version: Option<&str>,
    fallback_epoch: i64,
    fallback_provenance: &str,
) {
    let fact_id = fact
        .get("fact_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name = fact.get("name").and_then(Value::as_str).unwrap_or_default();
    let key = fact.get("key").and_then(Value::as_str).unwrap_or_default();
    if fact_id.is_empty() || name.is_empty() || key.is_empty() {
        return;
    }
    let value_json = fact
        .get("value")
        .cloned()
        .unwrap_or(Value::Null)
        .to_string();
    let source_span = optional_json(fact, "source_span");
    let validity_json = optional_json(fact, "validity");
    let program_version_id = fact
        .get("program_version_id")
        .and_then(Value::as_str)
        .or(fallback_version)
        .map(str::to_owned);
    let revision_epoch = fact
        .get("revision_epoch")
        .and_then(Value::as_i64)
        .unwrap_or(fallback_epoch);
    let slot = (name.to_owned(), key.to_owned());
    match facts.get_mut(&slot) {
        Some(existing) if existing.active => {}
        Some(existing) => {
            // Mirrors the durable fact row's revive rule: identity, value and
            // admission coordinates move; declaration metadata stays with the
            // set slot that is being revived.
            existing.active = true;
            existing.view.fact_id = fact_id.to_owned();
            existing.view.program_version_id = program_version_id;
            existing.view.revision_epoch = revision_epoch;
            existing.view.value_json = value_json;
            existing.view.source_event_id = event.event_id.clone();
            existing.view.validity_json = validity_json;
        }
        None => {
            facts.insert(
                slot,
                FactState {
                    active: true,
                    view: ProjectionFact {
                        fact_id: fact_id.to_owned(),
                        program_version_id,
                        revision_epoch,
                        name: name.to_owned(),
                        key: key.to_owned(),
                        value_json,
                        provenance_class: fact
                            .get("provenance_class")
                            .and_then(Value::as_str)
                            .unwrap_or(fallback_provenance)
                            .to_owned(),
                        source_span_json: source_span,
                        validity_json,
                        source_event_id: event.event_id.clone(),
                    },
                },
            );
        }
    }
}

fn dependency_satisfied(predicate: &str, status: &str) -> bool {
    match predicate {
        "succeeds" => status == "completed",
        "fails" => matches!(status, "failed" | "timed_out"),
        "timed_out" => status == "timed_out",
        "cancelled" => status == "cancelled",
        "completes" => matches!(status, "completed" | "failed" | "timed_out" | "cancelled"),
        _ => false,
    }
}

fn satisfy_dependencies(effects: &mut BTreeMap<String, EffectState>, dependencies: &[Dependency]) {
    let ready = effects
        .iter()
        .filter(|(_, effect)| effect.view.status == "blocked_by_dependency")
        .filter_map(|(effect_id, _)| {
            let satisfied = dependencies
                .iter()
                .filter(|dependency| dependency.downstream == *effect_id)
                .all(|dependency| {
                    effects.get(&dependency.upstream).is_some_and(|upstream| {
                        dependency_satisfied(&dependency.predicate, &upstream.view.status)
                    })
                });
            satisfied.then(|| effect_id.clone())
        })
        .collect::<Vec<_>>();
    for effect_id in ready {
        if let Some(effect) = effects.get_mut(&effect_id) {
            effect.view.status = "queued".into();
        }
    }
}

fn remove_open_requests(open: &mut BTreeMap<String, String>, effect_id: &str) {
    open.retain(|_, requested_effect| requested_effect != effect_id);
}

/// Fold an instance's complete event list to an inclusive event frontier.
///
/// The input may extend beyond `frontier`; the returned events cannot. A
/// missing sequence refuses instead of treating a truncated read as complete.
/// Restore markers remove their abandoned pre-marker suffix while remaining in
/// the returned event vector as the exact frontier anchor.
pub fn fold(events: &[EventView], frontier: i64) -> StoreResult<ProjectionPrefix> {
    if frontier < 0 {
        return Err(conflict("projection prefix frontier cannot be negative"));
    }
    let raw = events
        .iter()
        .filter(|event| event.sequence <= frontier)
        .collect::<Vec<_>>();
    if frontier == 0 {
        if raw.is_empty() {
            return Ok(ProjectionPrefix {
                frontier,
                events: Vec::new(),
                facts: Vec::new(),
                effects: Vec::new(),
            });
        }
        return Err(conflict("frontier zero requires an empty event prefix"));
    }
    if raw.last().map(|event| event.sequence) != Some(frontier) {
        return Err(conflict(format!(
            "instance log has no complete prefix ending at event {frontier}"
        )));
    }
    for (index, event) in raw.iter().enumerate() {
        let expected = i64::try_from(index).unwrap_or(i64::MAX) + 1;
        if event.sequence != expected {
            return Err(conflict(format!(
                "instance log prefix is incomplete at event {expected}"
            )));
        }
    }

    let mut retained = Vec::with_capacity(raw.len());
    for event in raw {
        if event.event_type == "context.restored" {
            if let Some(target) = crate::restore_marker_target(&event.payload_json) {
                retained.retain(|kept: &EventView| kept.sequence <= target);
            }
        }
        retained.push(event.clone());
    }

    let mut active_version = None::<String>;
    let mut active_epoch = 0i64;
    let mut facts = BTreeMap::<(String, String), FactState>::new();
    let mut effects = BTreeMap::<String, EffectState>::new();
    let mut dependencies = Vec::<Dependency>::new();
    let mut open_requests = BTreeMap::<String, String>::new();

    for event in &retained {
        match event.event_type.as_str() {
            "context.restored" => {}
            "instance.created" => {
                let payload = object(event)?;
                active_version = payload
                    .get("version_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                active_epoch = payload
                    .get("revision_epoch")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
            }
            "workflow.revision_activated" => {
                let payload = object(event)?;
                if let Some(version) = payload.get("to_version_id").and_then(Value::as_str) {
                    active_version = Some(version.to_owned());
                }
                active_epoch = payload
                    .get("to_epoch")
                    .and_then(Value::as_i64)
                    .or_else(|| payload.get("revision_epoch").and_then(Value::as_i64))
                    .unwrap_or(active_epoch);
            }
            "rule.committed" => {
                let payload = object(event)?;
                let rule = payload
                    .get("rule")
                    .and_then(Value::as_str)
                    .unwrap_or("<unknown>");
                let commit_version = payload
                    .get("program_version_id")
                    .and_then(Value::as_str)
                    .or(active_version.as_deref());
                let commit_epoch = payload
                    .get("revision_epoch")
                    .and_then(Value::as_i64)
                    .unwrap_or(active_epoch);
                for fact in payload
                    .get("facts")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    insert_fact(
                        &mut facts,
                        event,
                        fact,
                        commit_version,
                        commit_epoch,
                        "replayed",
                    );
                }
                for consumed in payload
                    .get("consumed_facts")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let fact_id = consumed
                        .get("fact_id")
                        .and_then(Value::as_str)
                        .or_else(|| consumed.as_str())
                        .unwrap_or_default();
                    if let Some(fact) = facts
                        .values_mut()
                        .find(|fact| fact.active && fact.view.fact_id == fact_id)
                    {
                        fact.active = false;
                    }
                }
                for effect in payload
                    .get("effects")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let effect_id = effect
                        .get("effect_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if effect_id.is_empty() || effects.contains_key(effect_id) {
                        return Err(conflict(format!(
                            "rule commit at event {} has an invalid or repeated effect identity",
                            event.sequence
                        )));
                    }
                    effects.insert(
                        effect_id.to_owned(),
                        EffectState {
                            admitted_at: event.sequence,
                            view: ProjectionEffect {
                                effect_id: effect_id.to_owned(),
                                kind: effect
                                    .get("kind")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .to_owned(),
                                target: effect
                                    .get("target")
                                    .and_then(Value::as_str)
                                    .map(str::to_owned),
                                input_json: effect
                                    .get("input")
                                    .cloned()
                                    .unwrap_or(Value::Null)
                                    .to_string(),
                                status: effect
                                    .get("status")
                                    .and_then(Value::as_str)
                                    .unwrap_or("queued")
                                    .to_owned(),
                                created_by_rule: rule.to_owned(),
                                program_version_id: effect
                                    .get("program_version_id")
                                    .and_then(Value::as_str)
                                    .or(commit_version)
                                    .map(str::to_owned),
                                revision_epoch: effect
                                    .get("revision_epoch")
                                    .and_then(Value::as_i64)
                                    .unwrap_or(commit_epoch),
                                profile: effect
                                    .get("profile")
                                    .and_then(Value::as_str)
                                    .map(str::to_owned),
                                cancel_requested: false,
                            },
                        },
                    );
                }
                for dependency in payload
                    .get("dependencies")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    dependencies.push(Dependency {
                        upstream: dependency
                            .get("upstream_effect_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        downstream: dependency
                            .get("downstream_effect_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        predicate: dependency
                            .get("predicate")
                            .and_then(Value::as_str)
                            .unwrap_or("succeeds")
                            .to_owned(),
                    });
                }
            }
            "fact.derived" => {
                let payload = object(event)?;
                insert_fact(
                    &mut facts,
                    event,
                    &payload,
                    active_version.as_deref(),
                    active_epoch,
                    "derived",
                );
            }
            "effect.blocked" => {
                let payload = object(event)?;
                let effect_id = payload
                    .get("effect_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(effect) = effects.get_mut(effect_id) {
                    if matches!(
                        effect.view.status.as_str(),
                        "queued"
                            | "blocked"
                            | "blocked_by_admission"
                            | "blocked_by_dependency"
                            | "blocked_by_capacity"
                            | "blocked_by_capability"
                            | "blocked_by_profile"
                    ) {
                        effect.view.status = payload
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("blocked")
                            .to_owned();
                    }
                }
            }
            "effect.run_started" => {
                let payload = object(event)?;
                let effect_id = payload
                    .get("effect_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(effect) = effects.get_mut(effect_id) {
                    if !matches!(
                        effect.view.status.as_str(),
                        "completed" | "failed" | "timed_out" | "cancelled"
                    ) {
                        effect.view.status = "running".into();
                    }
                }
            }
            "effect.cancellation_requested" => {
                let payload = object(event)?;
                let request_id = payload
                    .get("request_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let effect_id = payload
                    .get("effect_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if !request_id.is_empty() && effects.contains_key(effect_id) {
                    open_requests.insert(request_id.to_owned(), effect_id.to_owned());
                }
            }
            "effect.terminal" => {
                let payload = object(event)?;
                let effect_id = payload
                    .get("effect_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(effect) = effects.get_mut(effect_id) {
                    effect.view.status = payload
                        .get("status")
                        .and_then(Value::as_str)
                        .unwrap_or("completed")
                        .to_owned();
                    remove_open_requests(&mut open_requests, effect_id);
                    satisfy_dependencies(&mut effects, &dependencies);
                }
            }
            "effect.cancelled" => {
                let payload = object(event)?;
                let effect_id = payload
                    .get("effect_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(effect) = effects.get_mut(effect_id) {
                    if !matches!(
                        effect.view.status.as_str(),
                        "completed" | "failed" | "timed_out" | "cancelled"
                    ) {
                        effect.view.status = "cancelled".into();
                    }
                    remove_open_requests(&mut open_requests, effect_id);
                    satisfy_dependencies(&mut effects, &dependencies);
                }
            }
            "effect.retried" => {
                let payload = object(event)?;
                let effect_id = payload
                    .get("effect_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(effect) = effects.get_mut(effect_id) {
                    if matches!(effect.view.status.as_str(), "failed" | "timed_out") {
                        effect.view.status = "queued".into();
                    }
                }
            }
            "lease.expired" => {
                let payload = object(event)?;
                let effect_id = payload
                    .get("effect_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(effect) = effects.get_mut(effect_id) {
                    if effect.view.status == "running" {
                        effect.view.status = payload
                            .get("effect_status")
                            .and_then(Value::as_str)
                            .unwrap_or("queued")
                            .to_owned();
                    }
                }
            }
            _ => {}
        }
    }

    let facts = facts
        .into_values()
        .filter(|fact| fact.active)
        .map(|fact| fact.view)
        .collect();
    let mut effects = effects.into_values().collect::<Vec<_>>();
    effects.sort_by(|left, right| {
        (left.admitted_at, &left.view.effect_id).cmp(&(right.admitted_at, &right.view.effect_id))
    });
    let effects = effects
        .into_iter()
        .map(|mut effect| {
            effect.view.cancel_requested = open_requests
                .values()
                .any(|requested| requested == &effect.view.effect_id);
            effect.view
        })
        .collect();
    Ok(ProjectionPrefix {
        frontier,
        events: retained,
        facts,
        effects,
    })
}

#[cfg(test)]
mod tests;

/// One executable provider contract run unchanged by native SQLite and the
/// Durable Object SQLite adapter.
pub mod conformance {
    use crate::{
        EffectCancellation, NewEffect, NewFact, NewInstance, NewProgramVersion, RuleCommit,
        RuntimeStore,
    };

    /// Historical reads select their own event-sourced rows and leave today's
    /// event/fact/effect projections byte-for-byte unchanged.
    pub fn run<S: RuntimeStore>(mut store: S) {
        let version = store
            .create_program_version(NewProgramVersion {
                program_name: "ProjectionPrefix",
                source_hash: "projection-prefix-source",
                ir_hash: "projection-prefix-ir",
                ir_snapshot: None,
                compiler_version: "test",
                declared_capabilities_json: "[]",
                declared_profiles_json: "[]",
                declared_skills_json: "[]",
                declared_schemas_json: "[]",
                analysis_summary_json: "{}",
                generated_artifacts_json: "[]",
                artifact_root: None,
            })
            .expect("prefix fixture version");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("prefix fixture instance");
        let fact = NewFact {
            fact_id: "prefix-fact",
            name: "Ticket",
            key: "one",
            value_json: r#"{"status":"open"}"#,
            schema_id: None,
            provenance_class: "rule",
            correlation_id: None,
            source_span_json: None,
            validity_json: None,
        };
        let effect = NewEffect {
            effect_id: "prefix-effect",
            kind: "timer.wait",
            target: None,
            input_json: r#"{"duration":"1s"}"#,
            status: "queued",
            idempotency_key: "prefix-effect-key",
            required_capabilities_json: "[]",
            profile: None,
            correlation_id: None,
            source_span_json: None,
            timeout_seconds: None,
        };
        let admitted = store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "review",
                trigger_event_id: None,
                facts: &[fact],
                consumed_fact_ids: &[],
                effects: &[effect],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("prefix-admit"),
                marks: &[],
                context_json: None,
            })
            .expect("prefix fixture admits");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "consume",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &["prefix-fact"],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("prefix-consume"),
                marks: &[],
                context_json: None,
            })
            .expect("prefix fixture consumes");
        store
            .cancel_effect(EffectCancellation {
                instance_id: &instance.instance_id,
                effect_id: "prefix-effect",
                reason: Some("test"),
                idempotency_key: Some("prefix-cancel"),
            })
            .expect("prefix fixture settles");

        let before_events = store
            .list_events(&instance.instance_id)
            .expect("current events");
        let before_facts = store
            .list_facts(&instance.instance_id)
            .expect("current facts");
        let before_effects = store
            .list_effects(&instance.instance_id)
            .expect("current effects");
        let prefix = store
            .projection_prefix(&instance.instance_id, admitted.sequence)
            .expect("historical prefix reads");
        assert_eq!(prefix.frontier, admitted.sequence);
        assert_eq!(prefix.facts.len(), 1, "future consumption is excluded");
        assert_eq!(prefix.effects.len(), 1);
        assert_eq!(
            prefix.effects[0].status, "queued",
            "future terminal is excluded"
        );
        let current_frontier = before_events.last().expect("current frontier").sequence;
        let current = store
            .projection_prefix(&instance.instance_id, current_frontier)
            .expect("current prefix reads");
        assert!(current.facts.is_empty());
        assert_eq!(
            current.effects,
            before_effects
                .iter()
                .map(super::ProjectionEffect::from)
                .collect::<Vec<_>>(),
            "the event fold agrees with the host's current operation projection"
        );
        assert_eq!(
            store
                .list_events(&instance.instance_id)
                .expect("events unchanged"),
            before_events
        );
        assert_eq!(
            store
                .list_facts(&instance.instance_id)
                .expect("facts unchanged"),
            before_facts
        );
        assert_eq!(
            store
                .list_effects(&instance.instance_id)
                .expect("effects unchanged"),
            before_effects
        );
    }
}
