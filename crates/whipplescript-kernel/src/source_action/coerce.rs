//! Managed named coerce over the driver's retained prefix and pinned declaration.
//! Admission uses the existing effect door; observation reads the existing run result.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt};
use whipplescript_parser::{IrProgram, IrType};
use whipplescript_store::{projection_prefix::ProjectionEffect, EventView};

use super::arguments::{strict, Argument, State};
use super::journal::Frame;
use super::progression::{Leaf, Statement};
use super::{Cause, CauseId, Disposition, FailureKind, ObservedCause, OwnedWork, WorkState};
use crate::lowering::{OwnedEffect, OwnedLowering};
use crate::rule_lowering::{self as lowering, EvalValue, ParsedEffect};

pub struct Context<'a> {
    pub ir: &'a IrProgram,
    pub frame: &'a Frame,
    pub effects: &'a [ProjectionEffect],
    pub events: &'a [EventView],
    pub coercion_config_fingerprint: &'a str,
    pub source_path: Option<&'a Path>,
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("coerce projector requires an effect statement".into());
    };
    let BodyEffectKind::Coerce { name, args, .. } = &effect.kind else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("coerce projector requires a named coerce statement".into());
    };
    let contract = whipplescript_parser::effect_contract::Contract::from_statement(effect);
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("managed coerce requires its pinned root rule".into());
    }
    let declaration = context
        .ir
        .coerces
        .iter()
        .find(|coerce| coerce.name == *name)
        .ok_or("managed coerce has no pinned declaration")?;
    if args.len() != declaration.params.len() {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("managed coerce argument count differs from its declaration".into());
    }
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "schema.coerce"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded coerce differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded coerce input")?;
        if input["function_name"] != *name
            || input["output_type"] != lowering::ir_type_name(&declaration.output)
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded coerce input differs from its pinned declaration".into());
        }
        return observe(
            context.ir,
            &declaration.name,
            &declaration.output,
            existing,
            context.events,
        );
    }
    let inputs = args
        .iter()
        .map(|source| {
            let expression = whipplescript_parser::parse_expression(source)?;
            Ok(statement.evaluate(&expression))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let evaluation = strict(inputs.clone(), |values| {
        let mut errors = Vec::new();
        for (parameter, value) in declaration.params.iter().zip(&values) {
            lowering::validate_json_for_ir_type(
                context.ir,
                value,
                &parameter.ty,
                &parameter.name,
                &mut errors,
            );
        }
        if errors.is_empty() {
            EvalValue::Json(Value::Array(values))
        } else {
            EvalValue::error(errors.join("; "))
        }
    });
    let State::Ready(Value::Array(values)) = &evaluation.state else {
        return Ok(Leaf::Waiting(evaluation));
    };
    let arguments = inputs
        .iter()
        .zip(values)
        .map(|(input, value)| Argument {
            value: value.clone(),
            sources: input.sources.clone(),
            subjects: input.subjects.clone(),
            validity: input.validity.clone(),
        })
        .collect::<Vec<_>>();
    let timeout_seconds = contract
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed coerce timeout exceeds the store range")?;
    let parsed = ParsedEffect {
        kind: "schema.coerce".into(),
        name: Some(name.clone()),
        target: None,
        binding: effect.binding.clone(),
        args: args.clone(),
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: contract.required_capabilities.clone(),
        after: None,
        timeout_seconds,
    };
    let (provider_arguments, media) = lowering::coerce_arguments_json(context.ir, name, values);
    let output_type = lowering::ir_type_name(&declaration.output);
    let mut input = json!({
        "function_name": name, "arguments": provider_arguments,
        "output_type": output_type, "rule": context.frame.rule, "media": media,
        "action_arguments": arguments,
        "access_grants": lowering::access_grants_json(
            &whipplescript_parser::ir_access_grants_for_body(&effect.kind),
            &context.ir.file_stores, &context.ir.vaults,
        ),
    });
    if let Some(prompt) = lowering::coerce_prompt_from_ir(context.ir, name) {
        input["prompt_template"] = json!(prompt.text);
        if let Some(content_type) = prompt.content_type {
            input["prompt_content_type"] = json!(content_type);
        }
    }
    lowering::coerce_fixture_json(context.ir, &output_type, &mut input);
    let key = lowering::effect_admission_key(
        context.ir,
        &context.frame.rule,
        &parsed,
        &statement.identity,
        context.coercion_config_fingerprint,
    );
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity,
                kind: "schema.coerce".into(),
                target: None,
                input_json: input.to_string(),
                status: "queued".into(),
                idempotency_key: key,
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

pub(super) fn observe(
    ir: &IrProgram,
    function_name: &str,
    output: &IrType,
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
        _ => {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded coerce has an unknown operation status".into());
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
            .map_err(|_| "unreadable coerce terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminal = Some((event, payload));
            break;
        }
    }
    let (terminal, payload) = terminal.ok_or("settled coerce has no terminal evidence")?;
    let status = if terminal.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("coerce terminal evidence differs from its recorded status".into());
    }
    let uncertain = payload["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal.event_id.clone()]);
    let mut cause_payload = payload.clone();
    if !uncertain && effect.status != "cancelled" {
        let run = payload["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("coerce terminal has no run identity")?;
        let expected = match effect.status.as_str() {
            "completed" => "schema.coerce.succeeded",
            "timed_out" => "schema.coerce.timed_out",
            _ => "schema.coerce.failed",
        };
        let mut results = Vec::new();
        for event in events.iter().filter(|event| {
            matches!(
                event.event_type.as_str(),
                "schema.coerce.succeeded" | "schema.coerce.failed" | "schema.coerce.timed_out"
            )
        }) {
            let value: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable coerce result evidence")?;
            if value["effect_id"] == effect.effect_id && value["run_id"] == run {
                results.push((event, value));
            }
        }
        let [(result_event, result)] = results.as_slice() else {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("coerce terminal requires exactly one result for its run".into());
        };
        if result_event.event_type != expected
            || result_event.sequence <= terminal.sequence
            || result["status"] != effect.status
            || result["function_name"] != function_name
            || result["output_type"] != lowering::ir_type_name(output)
            || result.get("value").is_none()
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("coerce result differs from its terminal or declaration".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(ir, &result["value"], output, "$", &mut errors);
            if !errors.is_empty() {
                // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
                return Err(format!(
                    "coerce result violates its output type: {}",
                    errors.join("; ")
                ));
            }
            return Ok(leaf(
                OwnedLowering::default(),
                WorkState::Succeeded,
                Some(result["value"].clone().into()),
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
    let causes = BTreeMap::from([(
        CauseId(effect.effect_id.clone()),
        ObservedCause {
            cause: Cause {
                kind,
                payload: cause_payload,
                evidence,
            },
            recovered: false,
        },
    )]);
    Ok(leaf(
        OwnedLowering::default(),
        if uncertain {
            WorkState::Uncertain
        } else {
            WorkState::Failed(Disposition::Propagate)
        },
        None,
        causes,
    ))
}

#[cfg(test)]
mod tests;
