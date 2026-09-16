//! Managed timer projection over the same retained prefix as the action driver.
//! Drafts use the existing time-pass contract; projection never reads a clock.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt};
use whipplescript_store::{projection_prefix::ProjectionEffect, EventView};

use super::arguments::{Argument, State};
use super::journal::Frame;
use super::progression::{Leaf, Statement};
use super::{Cause, CauseId, Disposition, FailureKind, ObservedCause, OwnedWork, WorkState};
use crate::lowering::{OwnedEffect, OwnedLowering};

/// `effects` and ordered `events` must come from the driver's single retained
/// prefix. The driver owns firing/version selection and the guarded commit.
pub fn project(
    statement: Statement<'_>,
    frame: &Frame,
    effects: &[ProjectionEffect],
    events: &[EventView],
    source_path: Option<&Path>,
) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("timer projector requires an effect statement".into());
    };
    let BodyEffectKind::Timer {
        duration_source,
        until,
        ..
    } = &effect.kind
    else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("timer projector requires a timer statement".into());
    };
    let contract = whipplescript_parser::effect_contract::Contract::from_statement(effect);
    if contract.timeout_seconds.is_some() {
        return Err("managed timer with an independent timeout is not implemented".into());
    }
    if let Some(existing) = effects.iter().find(|e| e.effect_id == statement.identity) {
        let different = existing.kind != "timer.wait"
            || existing.created_by_rule != frame.rule
            || existing.program_version_id.as_deref() != Some(frame.version.as_str());
        if different {
            return Err("recorded timer differs from its source operation".into());
        }
        return observed(existing, events);
    }

    let operand = until.as_ref().unwrap_or(duration_source);
    // The body AST stores an absolute literal without its source quotes.
    let source = if until.is_some() && chrono::DateTime::parse_from_rfc3339(operand).is_ok() {
        json!(operand).to_string()
    } else {
        operand.clone()
    };
    let expr = whipplescript_parser::parse_expression(&source)?;
    let mut value = statement.evaluate(&expr);
    if matches!(value.state, State::Absent) {
        value.state = State::Invalid(Box::new("timer operand cannot be absent".to_owned().into()));
    }
    let State::Ready(ref operand) = value.state else {
        // Includes Invalid: traversal attaches the evaluation and source span.
        return Ok(Leaf::Waiting(value));
    };
    let text = operand
        .as_str()
        .ok_or("timer operand must be a duration or time value")?;
    let (mut input, timeout_seconds) = if until.is_some() {
        chrono::DateTime::parse_from_rfc3339(text)
            .map_err(|_| "timer deadline must be a valid recorded instant")?;
        (json!({"deadline_at":text,"rule":frame.rule}), None)
    } else {
        let seconds = duration_seconds(text).ok_or(
            "timer duration must be canonical positive whole seconds within the store range",
        )?;
        (
            json!({"duration":text,"duration_seconds":seconds,"rule":frame.rule}),
            Some(seconds),
        )
    };
    input["action_argument"] = json!(Argument {
        value: operand.clone(),
        sources: value.sources,
        subjects: value.subjects,
        validity: value.validity,
    });
    let capabilities = &contract.required_capabilities;
    let lowering = OwnedLowering {
        effects: vec![OwnedEffect {
            effect_id: statement.identity.clone(),
            kind: "timer.wait".into(),
            target: None,
            input_json: input.to_string(),
            status: "queued".into(),
            idempotency_key: statement.identity,
            required_capabilities_json: json!(capabilities).to_string(),
            profile: None,
            correlation_id: frame.identity.clone(),
            source_span_json: Some(crate::rule_lowering::source_span_json(
                source_path,
                effect.span,
                "effect",
            )),
            timeout_seconds,
        }],
        ..Default::default()
    };
    Ok(leaf(lowering, WorkState::Pending, None, BTreeMap::new()))
}

fn duration_seconds(text: &str) -> Option<i64> {
    // The duration type's stored representation is PT<n>S (spec/time.md).
    // Parsing its integer directly preserves the full store range exactly.
    let seconds = text
        .strip_prefix("PT")
        .and_then(|s| s.strip_suffix('S'))
        .and_then(|s| s.parse::<i64>().ok())?;
    (seconds > 0 && whipplescript_parser::canonical_duration(seconds) == text).then_some(seconds)
}

fn leaf(
    lowering: OwnedLowering,
    state: WorkState,
    value: Option<Argument>,
    causes: BTreeMap<CauseId, ObservedCause>,
) -> Leaf {
    Leaf::Ready {
        lowering: Box::new(lowering),
        value,
        work: Some(OwnedWork { state, causes }),
    }
}

fn observed(effect: &ProjectionEffect, events: &[EventView]) -> Result<Leaf, String> {
    let empty = |state| leaf(OwnedLowering::default(), state, None, BTreeMap::new());
    match effect.status.as_str() {
        "uncertain" => return Ok(empty(WorkState::Uncertain)),
        "queued"
        | "running"
        | "blocked"
        | "blocked_by_admission"
        | "blocked_by_dependency"
        | "blocked_by_capacity"
        | "blocked_by_capability"
        | "blocked_by_profile" => {
            return Ok(empty(if effect.cancel_requested {
                WorkState::CancellationRequested
            } else {
                WorkState::Pending
            }));
        }
        "completed" | "failed" | "timed_out" | "cancelled" => {}
        _ => {
            // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
            return Err("recorded timer has an unknown operation status".into());
        }
    }
    let mut terminal = None;
    for event in events.iter().rev().filter(|event| {
        matches!(
            event.event_type.as_str(),
            "effect.terminal" | "effect.cancelled"
        )
    }) {
        let payload: Value = serde_json::from_str(&event.payload_json)
            .map_err(|_| "unreadable timer terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminal = Some((event, payload));
            break;
        }
    }
    let (event, payload) = terminal.ok_or("settled timer has no terminal evidence")?;
    let status = if event.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        return Err("timer terminal evidence differs from its recorded status".into());
    }
    let uncertain = payload["run_status"] == "uncertain";
    if effect.status == "completed" {
        if uncertain {
            return Ok(empty(WorkState::Uncertain));
        }
        // The declared timer success type is null. No provider output fallback.
        return Ok(leaf(
            OwnedLowering::default(),
            WorkState::Succeeded,
            Some(Value::Null.into()),
            BTreeMap::new(),
        ));
    }
    let kind = match effect.status.as_str() {
        "timed_out" => FailureKind::TimedOut,
        "cancelled" => FailureKind::Cancelled,
        _ => FailureKind::Failed,
    };
    let causes = BTreeMap::from([(
        CauseId(effect.effect_id.clone()),
        ObservedCause {
            cause: Cause {
                kind,
                payload,
                evidence: BTreeSet::from([event.event_id.clone()]),
            },
            recovered: false,
        },
    )]);
    let state = if uncertain {
        WorkState::Uncertain
    } else {
        WorkState::Failed(Disposition::Propagate)
    };
    Ok(leaf(OwnedLowering::default(), state, None, causes))
}

#[cfg(test)]
mod tests;
