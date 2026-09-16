//! Managed directed signals. Admission captures the evaluated target and typed
//! payload with their freshness evidence; both hosts execute the existing
//! `signal.emit` handler and this projector observes its durable receipt.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Map, Value};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt, FieldAssign};
use whipplescript_parser::{Expr, IrEvent, IrProgram, IrType};
use whipplescript_store::{projection_prefix::ProjectionEffect, EventView};

use super::arguments::{strict, Argument, Evaluation, State};
use super::journal::Frame;
use super::progression::{Leaf, Statement};
use super::{Cause, CauseId, Disposition, FailureKind, ObservedCause, OwnedWork, WorkState};
use crate::lowering::{OwnedEffect, OwnedLowering};
use crate::rule_lowering::{self as lowering, EvalValue, ParsedEffect};

pub struct Context<'a> {
    pub ir: &'a IrProgram,
    pub frame: &'a Frame,
    pub frontier: i64,
    pub effects: &'a [ProjectionEffect],
    pub events: &'a [EventView],
    pub source_path: Option<&'a Path>,
}

struct Contract<'a> {
    event: &'a IrEvent,
    target_expr: &'a str,
    from: Option<&'a str>,
    fields: &'a [FieldAssign],
}

fn contract<'a>(
    ir: &'a IrProgram,
    effect: &'a whipplescript_parser::body::EffectStmt,
) -> Result<Contract<'a>, String> {
    let BodyEffectKind::Notify {
        target_expr,
        event,
        from,
        fields,
    } = &effect.kind
    else {
        return Err("signal projector requires an emit statement".into());
    };
    let event = ir
        .events
        .iter()
        .find(|candidate| candidate.name == *event)
        .ok_or("managed signal has no declared event")?;
    effect
        .binding
        .as_deref()
        .ok_or("managed signal has no result binding")?;
    let mut names = BTreeSet::new();
    for field in fields {
        if !names.insert(field.name.as_str()) {
            // MUTATION-SUCCESS-EXPR: Ok(Contract { event, target_expr, from: from.as_deref(), fields })
            return Err(format!("signal field `{}` is duplicated", field.name));
        }
    }
    Ok(Contract {
        event,
        target_expr,
        from: from.as_deref(),
        fields,
    })
}

fn payload(contract: &Contract<'_>, statement: &Statement<'_>) -> Evaluation {
    let written: BTreeSet<_> = contract
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect();
    let copied: Vec<_> = contract
        .event
        .fields
        .iter()
        .filter(|field| contract.from.is_some() && !written.contains(field.name.as_str()))
        .map(|field| field.name.clone())
        .collect();
    let fields = contract
        .fields
        .iter()
        .map(|field| {
            field
                .record_expression(contract.from, &|name| {
                    statement.environment.contains_key(name)
                })
                .map(|expr| (field.name.clone(), expr))
        })
        .collect::<Result<Vec<_>, _>>();
    let fields = match fields {
        Ok(fields) => fields,
        Err(message) => return Evaluation::invalid(&message),
    };
    let mut inputs = Vec::new();
    let copy = contract.from.filter(|_| !copied.is_empty());
    if let Some(from) = copy {
        let base = statement.evaluate(&Expr::Path(vec![from.into()]));
        inputs.push(strict(vec![base], |values| {
            let Some(object) = values[0].as_object() else {
                return EvalValue::error("signal projection source must be a present class object");
            };
            EvalValue::Json(Value::Object(
                copied
                    .iter()
                    .filter_map(|name| object.get(name).map(|value| (name.clone(), value.clone())))
                    .collect(),
            ))
        }));
    }
    for (_, expr) in &fields {
        inputs.push(statement.evaluate(expr));
    }
    strict(inputs, |values| {
        let mut values = values.into_iter();
        let mut object = if copy.is_some() {
            values
                .next()
                .expect("projection value")
                .as_object()
                .expect("checked projection")
                .clone()
        } else {
            Map::new()
        };
        object.extend(fields.into_iter().map(|(name, _)| name).zip(values));
        EvalValue::Json(Value::Object(object))
    })
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        return Err("signal projector requires an effect statement".into());
    };
    let contract = contract(context.ir, effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        return Err("managed signal requires its pinned root rule".into());
    }
    let shape = lowering::ingest_shape_json(
        context.ir,
        &IrType::Object(contract.event.fields.clone()),
        0,
    );
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "signal.emit"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target.is_some()
        {
            return Err("recorded signal differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded signal input")?;
        let decode = |name: &str| -> Result<Argument, String> {
            let raw = input
                .get(name)
                .ok_or_else(|| format!("recorded signal has no {name}"))?;
            if !raw["subjects"].is_object()
                || !raw["sources"].is_array()
                || !raw["validity"].is_array()
            {
                return Err(format!(
                    "recorded signal has an incomplete freshness argument `{name}`"
                ));
            }
            let argument: Argument = serde_json::from_value(raw.clone())
                .map_err(|_| format!("recorded signal has no valid {name}"))?;
            super::journal::validate_argument(&argument, context.frontier)
                .map_err(|issue| issue.0)?;
            Ok(argument)
        };
        let target = decode("target_argument")?;
        let payload = decode("payload_argument")?;
        let target_instance = target
            .value
            .as_str()
            .ok_or("recorded signal target is not a string")?;
        if input["target_expr"] != contract.target_expr
            || input["target_instance"] != target_instance
            || input["event"] != contract.event.name
            || input["from"] != contract.from.map_or(Value::Null, |binding| json!(binding))
            || input["fields"]
                != serde_json::to_value(contract.fields)
                    .expect("signal field contract serialization is infallible")
            || input["payload"] != payload.value
            || input["shape"] != shape
            || input["rule"] != context.frame.rule
        {
            return Err("recorded signal input differs from its source contract".into());
        }
        return observe(
            context.ir,
            &contract,
            target_instance,
            existing,
            context.events,
        );
    }

    let target_expr = whipplescript_parser::parse_expression(contract.target_expr)?;
    let mut target = statement.evaluate(&target_expr);
    let mut payload = payload(&contract, &statement);
    if matches!(target.state, State::Absent) {
        target.state = State::Invalid(Box::new(
            "managed signal target cannot be absent".to_owned().into(),
        ));
    }
    if matches!(payload.state, State::Absent) {
        payload.state = State::Invalid(Box::new(
            "managed signal payload cannot be absent".to_owned().into(),
        ));
    }
    let (State::Ready(target_value), State::Ready(payload_value)) = (&target.state, &payload.state)
    else {
        return Ok(Leaf::Waiting(strict(vec![target, payload], |values| {
            EvalValue::Json(Value::Array(values))
        })));
    };
    let target_instance = target_value
        .as_str()
        .ok_or("managed signal target must be a string")?
        .to_owned();
    let mut errors = Vec::new();
    lowering::validate_json_for_object(
        context.ir,
        payload_value,
        &contract.event.fields,
        &contract.event.name,
        &mut errors,
    );
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let target_argument = Argument {
        value: target_value.clone(),
        sources: target.sources,
        subjects: target.subjects,
        validity: target.validity,
    };
    let payload_argument = Argument {
        value: payload_value.clone(),
        sources: payload.sources,
        subjects: payload.subjects,
        validity: payload.validity,
    };
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed signal timeout exceeds the store range")?;
    let parsed = ParsedEffect {
        kind: "signal.emit".into(),
        target: None,
        name: Some(contract.event.name.clone()),
        binding: effect.binding.clone(),
        args: vec![
            contract.target_expr.into(),
            contract.event.name.clone(),
            String::new(),
            contract.from.unwrap_or_default().into(),
        ],
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let input = json!({
        "target_instance": target_instance,
        "target_expr": contract.target_expr,
        "event": contract.event.name,
        "from": contract.from,
        "fields": contract.fields,
        "payload": payload_value,
        "shape": shape,
        "rule": context.frame.rule,
        "target_argument": target_argument,
        "payload_argument": payload_argument,
    });
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: "signal.emit".into(),
                target: None,
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
    contract: &Contract<'_>,
    target: &str,
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
        _ => return Err("recorded signal has an unknown operation status".into()),
    }
    let mut terminals = Vec::new();
    for event in events.iter().filter(|event| {
        matches!(
            event.event_type.as_str(),
            "effect.terminal" | "effect.cancelled"
        )
    }) {
        let payload: Value = serde_json::from_str(&event.payload_json)
            .map_err(|_| "unreadable signal terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminals.push((event, payload));
        }
    }
    let [(terminal, terminal_payload)] = terminals.as_slice() else {
        return Err("settled signal requires exactly one terminal".into());
    };
    let status = if terminal.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        terminal_payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        return Err("signal terminal evidence differs from its recorded status".into());
    }
    let uncertain = terminal_payload["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal.event_id.clone()]);
    let mut cause_payload = terminal_payload.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = terminal_payload["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("signal terminal has no run identity")?;
        let expected = if effect.status == "completed" {
            "signal.emit.completed"
        } else {
            "signal.emit.failed"
        };
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let envelope: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable signal result evidence")?;
            let name = envelope["name"].as_str().unwrap_or_default();
            let value = &envelope["value"];
            if matches!(name, "signal.emit.completed" | "signal.emit.failed")
                && envelope["key"] == effect.effect_id
                && value["effect_id"] == effect.effect_id
                && value["run_id"] == run
            {
                results.push((event, name.to_owned(), value.clone()));
            }
        }
        let [(result_event, result_name, result)] = results.as_slice() else {
            return Err("signal terminal requires exactly one result for its run".into());
        };
        if result_name != expected
            || result_event.sequence <= terminal.sequence
            || result["status"] != effect.status
            || result.get("value").is_none()
        {
            return Err("signal result differs from its terminal".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let value = &result["value"];
            let output =
                whipplescript_parser::signal_emit_output_type(whipplescript_parser::SourceSpan {
                    start: 0,
                    end: 0,
                });
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(ir, value, &output, "$", &mut errors);
            if !errors.is_empty()
                || value["target"] != target
                || value["event"] != contract.event.name
            {
                return Err(format!(
                    "signal result violates its source contract{}",
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
