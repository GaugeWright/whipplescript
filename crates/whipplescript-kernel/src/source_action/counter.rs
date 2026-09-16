//! Managed counter consumption. Admission captures the evaluated key and
//! amount with freshness evidence; settlement projects the durable `Ok` or
//! `Over` decision as one successful, branchable value.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt};
use whipplescript_parser::{IrCounter, IrProgram};
use whipplescript_store::{projection_prefix::ProjectionEffect, EventView};

use super::arguments::{strict, Argument, State};
use super::journal::Frame;
use super::progression::{Leaf, Statement};
use super::{Cause, CauseId, Disposition, FailureKind, ObservedCause, OwnedWork, WorkState};
use crate::lowering::{OwnedEffect, OwnedLowering};
use crate::rule_lowering::{self as lowering, ParsedEffect};

pub struct Context<'a> {
    pub ir: &'a IrProgram,
    pub frame: &'a Frame,
    pub frontier: i64,
    pub effects: &'a [ProjectionEffect],
    pub events: &'a [EventView],
    pub source_path: Option<&'a Path>,
}

struct Contract<'a> {
    counter: &'a IrCounter,
    key_expr: &'a str,
    amount_expr: &'a str,
}

fn contract<'a>(
    ir: &'a IrProgram,
    effect: &'a whipplescript_parser::body::EffectStmt,
) -> Result<Contract<'a>, String> {
    let BodyEffectKind::CounterConsume {
        counter,
        key_expr,
        amount_expr,
    } = &effect.kind
    else {
        return Err("counter projector requires a consume statement".into());
    };
    effect
        .binding
        .as_deref()
        .ok_or("managed counter consume has no result binding")?;
    let counter = ir
        .counters
        .iter()
        .find(|candidate| candidate.name == *counter)
        .ok_or("managed counter consume has no declared counter")?;
    Ok(Contract {
        counter,
        key_expr,
        amount_expr,
    })
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        return Err("counter projector requires an effect statement".into());
    };
    let contract = contract(context.ir, effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        return Err("managed counter consume requires its pinned root rule".into());
    }
    let owner = if contract.counter.shared {
        "shared"
    } else {
        ""
    };
    let timezone = contract.counter.timezone.as_deref().unwrap_or("UTC");
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "counter.consume"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target.as_deref() != Some(contract.counter.name.as_str())
        {
            return Err("recorded counter consume differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded counter consume input")?;
        let decode = |name: &str| -> Result<Argument, String> {
            let raw = input
                .get(name)
                .ok_or_else(|| format!("recorded counter consume has no {name}"))?;
            if !raw["subjects"].is_object()
                || !raw["sources"].is_array()
                || !raw["validity"].is_array()
            {
                return Err(format!(
                    "recorded counter consume has an incomplete freshness argument `{name}`"
                ));
            }
            let argument: Argument = serde_json::from_value(raw.clone())
                .map_err(|_| format!("recorded counter consume has no valid {name}"))?;
            super::journal::validate_argument(&argument, context.frontier)
                .map_err(|issue| issue.0)?;
            Ok(argument)
        };
        let key = decode("key_argument")?;
        let amount = decode("amount_argument")?;
        let key_string = lowering::coordination_key_string(&key.value);
        let amount_value = amount
            .value
            .as_i64()
            .ok_or("recorded counter amount is not an integer")?;
        if input["counter"] != contract.counter.name
            || input["coordination_owner"] != owner
            || input["key_expr"] != contract.key_expr
            || input["amount_expr"] != contract.amount_expr
            || input["key"] != key_string
            || input["amount"] != amount_value
            || input["cap"] != contract.counter.cap
            || input["reset"] != contract.counter.reset
            || input["timezone"] != timezone
            || input["key_type"] != contract.counter.key_type
            || input["rule"] != context.frame.rule
        {
            return Err("recorded counter consume input differs from its source contract".into());
        }
        return observe(
            context.ir,
            contract.counter,
            &key_string,
            existing,
            context.events,
        );
    }

    let key_expr = whipplescript_parser::parse_expression(contract.key_expr)?;
    let amount_expr = whipplescript_parser::parse_expression(contract.amount_expr)?;
    let mut key = statement.evaluate(&key_expr);
    let mut amount = statement.evaluate(&amount_expr);
    if matches!(key.state, State::Absent) {
        key.state = State::Invalid(Box::new(
            "managed counter key cannot be absent".to_owned().into(),
        ));
    }
    if matches!(amount.state, State::Absent) {
        amount.state = State::Invalid(Box::new(
            "managed counter amount cannot be absent".to_owned().into(),
        ));
    }
    let (State::Ready(key_value), State::Ready(amount_value)) = (&key.state, &amount.state) else {
        return Ok(Leaf::Waiting(strict(vec![key, amount], |values| {
            crate::rule_lowering::EvalValue::Json(Value::Array(values))
        })));
    };
    let key_string = lowering::coordination_key_string(key_value);
    let amount_value = amount_value
        .as_i64()
        .ok_or("managed counter amount must be an integer")?;
    let key_argument = Argument {
        value: key_value.clone(),
        sources: key.sources,
        subjects: key.subjects,
        validity: key.validity,
    };
    let amount_argument = Argument {
        value: json!(amount_value),
        sources: amount.sources,
        subjects: amount.subjects,
        validity: amount.validity,
    };
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed counter timeout exceeds the store range")?;
    let parsed = ParsedEffect {
        kind: "counter.consume".into(),
        target: Some(contract.counter.name.clone()),
        name: None,
        binding: effect.binding.clone(),
        args: vec![contract.key_expr.into(), contract.amount_expr.into()],
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let input = json!({
        "counter": contract.counter.name,
        "coordination_owner": owner,
        "key_expr": contract.key_expr,
        "amount_expr": contract.amount_expr,
        "key": key_string,
        "amount": amount_value,
        "cap": contract.counter.cap,
        "reset": contract.counter.reset,
        "timezone": timezone,
        "key_type": contract.counter.key_type,
        "rule": context.frame.rule,
        "key_argument": key_argument,
        "amount_argument": amount_argument,
    });
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: "counter.consume".into(),
                target: Some(contract.counter.name.clone()),
                input_json: input.to_string(),
                status: "queued".into(),
                idempotency_key: lowering::effect_admission_key(
                    context.ir,
                    &context.frame.rule,
                    &parsed,
                    &statement.identity,
                    "",
                ),
                required_capabilities_json: parsed.required_capabilities_json(),
                profile: None,
                correlation_id: context.frame.identity.clone(),
                source_span_json: Some(lowering::source_span_json(
                    context.source_path,
                    effect.span,
                    "effect",
                )),
                timeout_seconds,
            }],
            ..Default::default()
        },
        WorkState::Pending,
        None,
        BTreeMap::new(),
    ))
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

fn observe(
    ir: &IrProgram,
    counter: &IrCounter,
    key: &str,
    effect: &ProjectionEffect,
    events: &[EventView],
) -> Result<Leaf, String> {
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
        _ => return Err("recorded counter consume has an unknown operation status".into()),
    }
    let mut terminals = Vec::new();
    for event in events.iter().filter(|event| {
        matches!(
            event.event_type.as_str(),
            "effect.terminal" | "effect.cancelled"
        )
    }) {
        let payload: Value = serde_json::from_str(&event.payload_json)
            .map_err(|_| "unreadable counter terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminals.push((event, payload));
        }
    }
    let [(terminal, terminal_payload)] = terminals.as_slice() else {
        return Err("settled counter consume requires exactly one terminal".into());
    };
    let status = if terminal.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        terminal_payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        return Err("counter terminal evidence differs from its recorded status".into());
    }
    let uncertain = terminal_payload["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal.event_id.clone()]);
    let mut cause_payload = terminal_payload.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = terminal_payload["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("counter terminal has no run identity")?;
        let expected = if effect.status == "completed" {
            "counter.consume.completed"
        } else {
            "counter.consume.failed"
        };
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let envelope: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable counter result evidence")?;
            let name = envelope["name"].as_str().unwrap_or_default();
            let value = &envelope["value"];
            if matches!(name, "counter.consume.completed" | "counter.consume.failed")
                && envelope["key"] == effect.effect_id
                && value["effect_id"] == effect.effect_id
                && value["run_id"] == run
            {
                results.push((event, name.to_owned(), value.clone()));
            }
        }
        let [(result_event, result_name, result)] = results.as_slice() else {
            return Err("counter terminal requires exactly one result for its run".into());
        };
        if result_name != expected
            || result_event.sequence <= terminal.sequence
            || result["status"] != effect.status
            || result.get("value").is_none()
        {
            return Err("counter result differs from its terminal".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let value = &result["value"];
            let output = whipplescript_parser::counter_consume_output_type(
                whipplescript_parser::SourceSpan { start: 0, end: 0 },
            );
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(ir, value, &output, "$", &mut errors);
            if !errors.is_empty() || value["counter"] != counter.name || value["key"] != key {
                return Err(format!(
                    "counter result violates its source contract{}",
                    if errors.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", errors.join("; "))
                    }
                ));
            }
            return Ok(leaf(
                OwnedLowering::default(),
                WorkState::Succeeded,
                Some(value.clone().into()),
                BTreeMap::new(),
            ));
        }
        cause_payload = result["value"].clone();
    }
    let kind = match effect.status.as_str() {
        "timed_out" => FailureKind::TimedOut,
        "cancelled" => FailureKind::Cancelled,
        _ => FailureKind::Failed,
    };
    Ok(leaf(
        OwnedLowering::default(),
        if uncertain {
            WorkState::Uncertain
        } else {
            WorkState::Failed(Disposition::Propagate)
        },
        None,
        BTreeMap::from([(
            CauseId(effect.effect_id.clone()),
            ObservedCause {
                cause: Cause {
                    kind,
                    payload: cause_payload,
                    evidence,
                },
                recovered: false,
            },
        )]),
    ))
}

#[cfg(test)]
mod tests;
