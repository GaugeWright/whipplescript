//! Managed single-value script execution. The typed source fixes the script
//! capability, stdin binding and parse schema; the durable input retains the
//! admitted argument and the existing `exec.command` host door performs work.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt, ExecTarget};
use whipplescript_parser::{IrProgram, IrType};
use whipplescript_store::{projection_prefix::ProjectionEffect, EventView};

use super::arguments::{Argument, State};
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
    capability: &'a str,
    stdin_binding: &'a str,
    output: IrType,
}

fn source_contract(
    effect: &whipplescript_parser::body::EffectStmt,
) -> Result<Contract<'_>, String> {
    let BodyEffectKind::Exec {
        target: ExecTarget::Capability {
            name,
            stdin_binding,
        },
        parse_target: Some(parse),
        ..
    } = &effect.kind
    else {
        // MUTATION-SUCCESS-EXPR: Ok(Contract { capability: "fixture", stdin_binding: "input", output: IrType::Ref("Json".into()) })
        return Err(
            "managed exec requires a script capability and one-value parse contract".into(),
        );
    };
    if parse.each {
        // MUTATION-SUCCESS-EXPR: Ok(Contract { capability: name, stdin_binding, output: IrType::Ref(parse.schema.clone()) })
        return Err("managed exec streams do not produce an action value".into());
    }
    effect
        .binding
        .as_deref()
        .ok_or("managed single-value exec has no result binding")?;
    Ok(Contract {
        capability: name,
        stdin_binding,
        output: IrType::Ref(parse.schema.clone()),
    })
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("exec projector requires an effect statement".into());
    };
    let contract = source_contract(effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("managed exec requires its pinned root rule".into());
    }
    let shape = lowering::ingest_shape_json(context.ir, &contract.output, 0);
    let access_grants = lowering::access_grants_json(
        &whipplescript_parser::ir_access_grants_for_body(&effect.kind),
        &context.ir.file_stores,
        &context.ir.vaults,
    );
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "exec.command"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target.as_deref() != Some(contract.capability)
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded exec differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded exec input")?;
        let raw_argument = input
            .get("action_argument")
            .ok_or("recorded exec has no action argument")?;
        if !raw_argument["subjects"].is_object()
            || !raw_argument["sources"].is_array()
            || !raw_argument["validity"].is_array()
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded exec has an incomplete freshness argument".into());
        }
        let argument: Argument = serde_json::from_value(raw_argument.clone())
            .map_err(|_| "recorded exec has no valid action argument")?;
        super::journal::validate_argument(&argument, context.frontier).map_err(|issue| issue.0)?;
        if input["mode"] != "capability"
            || input["capability"] != contract.capability
            || input["stdin_binding"] != contract.stdin_binding
            || input["rule"] != context.frame.rule
            || input["stdin"] != argument.value
            || input["parse"]
                != json!({
                    "schema": lowering::ir_type_name(&contract.output),
                    "each": false,
                    "shape": shape,
                })
            || input["access_grants"] != access_grants
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded exec input differs from its source contract".into());
        }
        return observe(context.ir, &contract, existing, context.events);
    }

    let expr = whipplescript_parser::parse_expression(contract.stdin_binding)?;
    let mut evaluated = statement.evaluate(&expr);
    if matches!(evaluated.state, State::Absent) {
        evaluated.state = State::Invalid(Box::new(
            "managed exec stdin cannot be absent".to_owned().into(),
        ));
    }
    let State::Ready(stdin) = &evaluated.state else {
        return Ok(Leaf::Waiting(evaluated));
    };
    let argument = Argument {
        value: stdin.clone(),
        sources: evaluated.sources,
        subjects: evaluated.subjects,
        validity: evaluated.validity,
    };
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed exec timeout exceeds the store range")?;
    let parsed = ParsedEffect {
        kind: "exec.command".into(),
        target: Some(contract.capability.into()),
        name: Some("capability".into()),
        binding: effect.binding.clone(),
        args: vec![
            contract.stdin_binding.into(),
            lowering::ir_type_name(&contract.output),
        ],
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let input = json!({
        "mode": "capability",
        "capability": contract.capability,
        "stdin": stdin,
        "stdin_binding": contract.stdin_binding,
        "rule": context.frame.rule,
        "parse": {
            "schema": lowering::ir_type_name(&contract.output),
            "each": false,
            "shape": shape,
        },
        "access_grants": access_grants,
        "action_argument": argument,
    });
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: "exec.command".into(),
                target: Some(contract.capability.into()),
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
            // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
            return Err("recorded exec has an unknown operation status".into());
        }
    }
    let mut terminals = Vec::new();
    for event in events.iter().filter(|event| {
        matches!(
            event.event_type.as_str(),
            "effect.terminal" | "effect.cancelled"
        )
    }) {
        let payload: Value = serde_json::from_str(&event.payload_json)
            .map_err(|_| "unreadable exec terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminals.push((event, payload));
        }
    }
    let [(terminal, payload)] = terminals.as_slice() else {
        // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
        return Err("settled exec requires exactly one terminal".into());
    };
    let status = if terminal.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
        return Err("exec terminal evidence differs from its recorded status".into());
    }
    let uncertain = payload["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal.event_id.clone()]);
    let mut cause_payload = payload.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = payload["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("exec terminal has no run identity")?;
        let expected = if effect.status == "completed" {
            "exec.command.completed"
        } else {
            "exec.command.failed"
        };
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let envelope: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable exec result evidence")?;
            let name = envelope["name"].as_str().unwrap_or_default();
            let value = &envelope["value"];
            if matches!(name, "exec.command.completed" | "exec.command.failed")
                && envelope["key"] == effect.effect_id
                && value["effect_id"] == effect.effect_id
                && value["run_id"] == run
            {
                results.push((event, name.to_owned(), value.clone()));
            }
        }
        let [(result_event, result_name, result)] = results.as_slice() else {
            // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
            return Err("exec terminal requires exactly one result for its run".into());
        };
        if result_name != expected
            || result_event.sequence <= terminal.sequence
            || result["status"] != effect.status
            || result["mode"] != "capability"
            || result["capability"] != contract.capability
            || result.get("value").is_none()
        {
            // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
            return Err("exec result differs from its terminal or source contract".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(
                ir,
                &result["value"],
                &contract.output,
                "$",
                &mut errors,
            );
            if !errors.is_empty() {
                // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
                return Err(format!(
                    "exec result violates its output type: {}",
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
