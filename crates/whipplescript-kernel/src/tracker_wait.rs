//! Bounded closure observation through the ordinary package-call surface.
//!
//! Waiting is a readiness condition, not a running provider invocation. The
//! source's declared trackers already project closure facts into this instance;
//! this module never opens a tracker or manufactures another observation log.

use serde_json::{json, Value};
use whipplescript_store::{ClaimableEffect, RuntimeStore, StoreError, StoreResult, StoredEvent};

use crate::effect_config::EffectConfig;
use crate::effect_handlers::{
    resolve_effect_input_after_bindings_generic, run_capability_effect_generic, CapabilityContract,
    CapabilityOutcome, CapabilityProvider,
};
use crate::RuntimeKernel;

pub const CAPABILITY: &str = "tracker.wait_closed";

pub fn is_tracker_wait(effect: &ClaimableEffect) -> bool {
    effect.kind == "capability.call" && effect.target.as_deref() == Some(CAPABILITY)
}

enum Observation {
    Pending,
    Closed(Value),
    Invalid(&'static str),
}

fn observe<S: RuntimeStore>(
    store: &S,
    instance_id: &str,
    effect: &ClaimableEffect,
) -> StoreResult<Observation> {
    // Check the store's actual deadline, not an input field that could claim a
    // timeout without scheduling one. Do this before looking at a closing: an
    // already closed issue does not make an unbounded call a valid program.
    if !store
        .pending_time_effects(instance_id)?
        .iter()
        .any(|timed| timed.effect_id == effect.effect_id && timed.timeout_seconds > 0)
    {
        return Ok(Observation::Invalid(
            "tracker.wait_closed requires a positive timeout",
        ));
    }
    let resolved = resolve_effect_input_after_bindings_generic(store, instance_id, effect)?;
    let input: Value = serde_json::from_str(&resolved)?;
    let Some(issue) = input.get("arguments").and_then(|args| args.get("arg0")) else {
        return Ok(Observation::Invalid(
            "tracker.wait_closed requires an issue reference",
        ));
    };
    let Some((id, queue)) = issue
        .get("id")
        .and_then(Value::as_str)
        .zip(issue.get("queue").and_then(Value::as_str))
        .filter(|(id, queue)| !id.is_empty() && !queue.is_empty())
    else {
        return Ok(Observation::Invalid(
            "tracker.wait_closed requires nonempty id and queue",
        ));
    };
    for fact in store.list_facts_including_consumed(instance_id)? {
        if fact.name != "tracker.issue.closed" {
            continue;
        }
        let closing: Value = serde_json::from_str(&fact.value_json)?;
        if closing.get("id").and_then(Value::as_str) != Some(id)
            || closing.get("queue").and_then(Value::as_str) != Some(queue)
        {
            continue;
        }
        let Some((event, closed_at)) = closing
            .get("event")
            .and_then(Value::as_str)
            .zip(closing.get("closed_at").and_then(Value::as_str))
            .filter(|(event, closed_at)| !event.is_empty() && !closed_at.is_empty())
        else {
            continue;
        };
        return Ok(Observation::Closed(json!({
            "id": id, "queue": queue, "event": event, "closed_at": closed_at,
        })));
    }
    Ok(Observation::Pending)
}

/// Filter only observation calls which genuinely have nothing to do yet.
/// Malformed calls remain eligible so they settle as failures, not silent waits.
/// Other ready effects are never hidden behind an earlier pending observation.
pub fn ready<S: RuntimeStore>(
    store: &S,
    instance_id: &str,
    effect: &ClaimableEffect,
) -> StoreResult<bool> {
    if !is_tracker_wait(effect) {
        return Ok(true);
    }
    Ok(!matches!(
        observe(store, instance_id, effect)?,
        Observation::Pending
    ))
}

struct Observed(Observation);

impl CapabilityContract for Observed {
    fn validate_output(&self, _effect: &ClaimableEffect, value: &Value) -> Option<String> {
        ["id", "queue", "event", "closed_at"]
            .iter()
            .find_map(|field| {
                value
                    .get(field)
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .is_none()
                    .then(|| format!("closure lacks {field}"))
            })
    }
}

impl CapabilityProvider for Observed {
    fn produce(&self, _effect: &ClaimableEffect, _config: &EffectConfig) -> CapabilityOutcome {
        match &self.0 {
            Observation::Closed(value) => CapabilityOutcome::Produced(value.clone()),
            Observation::Invalid(message) => CapabilityOutcome::Failed {
                error_kind: "tracker_wait_input".to_owned(),
                message: (*message).to_owned(),
            },
            Observation::Pending => unreachable!("pending observations never start a provider run"),
        }
    }

    fn label(&self) -> &'static str {
        "builtin-tracker"
    }
}

/// Settle a ready observation through ordinary capability admission and evidence.
pub fn run<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance_id: &str,
    effect: &ClaimableEffect,
    config: &EffectConfig,
) -> StoreResult<StoredEvent> {
    let observation = observe(kernel.store(), instance_id, effect)?;
    if matches!(observation, Observation::Pending) {
        return Err(StoreError::Conflict(
            "tracker closure is not ready".to_owned(),
        ));
    }
    let observed = Observed(observation);
    run_capability_effect_generic(kernel, instance_id, effect, config, &observed, &observed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_closure_identity_field_is_required_at_the_output_boundary() {
        let effect = ClaimableEffect {
            effect_id: "wait".to_owned(),
            kind: "capability.call".to_owned(),
            target: Some(CAPABILITY.to_owned()),
            profile: None,
            input_json: "{}".to_owned(),
            required_capabilities_json: "[]".to_owned(),
            declared_profiles_json: "[]".to_owned(),
        };
        let value = json!({"id":"issue", "queue":"inbox", "event":"closing", "closed_at":"now"});
        let contract = Observed(Observation::Closed(value.clone()));
        assert!(contract.validate_output(&effect, &value).is_none());
        for field in ["id", "queue", "event", "closed_at"] {
            for invalid in [Value::Null, json!(""), json!(42)] {
                let mut malformed = value.clone();
                malformed[field] = invalid;
                assert!(contract.validate_output(&effect, &malformed).is_some());
            }
        }
    }
}
