//! Managed tells use the ordinary agent execution door and immutable terminal
//! summary. No current result fact or second provider invocation supplies a value.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt};
use whipplescript_parser::managed_template::Segment;
use whipplescript_parser::IrProgram;
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
    pub source_path: Option<&'a Path>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PromptPart {
    Text { text: String },
    Value { argument: usize },
}

/// Render only authored segments. Workers repeat this over their ephemeral
/// opened arguments, never over the previously rendered string or durable row.
pub(crate) fn materialize_prompt(input: &mut Value) -> Result<(), String> {
    let Some(parts) = input.get("managed_prompt") else {
        return Ok(());
    };
    let parts: Vec<PromptPart> =
        serde_json::from_value(parts.clone()).map_err(|_| "invalid managed prompt segments")?;
    let arguments: Vec<Argument> = serde_json::from_value(input["action_arguments"].clone())
        .map_err(|_| "invalid managed prompt arguments")?;
    let mut prompt = String::new();
    for part in parts {
        match part {
            PromptPart::Text { text } => prompt.push_str(&text),
            PromptPart::Value { argument } => {
                let value = arguments
                    .get(argument)
                    .ok_or("managed prompt argument is absent")?;
                prompt.push_str(&lowering::render_interpolation_value(&value.value));
            }
        }
    }
    input["prompt"] = Value::String(prompt);
    Ok(())
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("tell projector requires an effect statement".into());
    };
    let BodyEffectKind::Tell { target, .. } = &effect.kind else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("tell projector requires an agent tell statement".into());
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
        return Err("managed tell requires its pinned root rule".into());
    }
    if let Some(existing) = context
        .effects
        .iter()
        .find(|effect| effect.effect_id == statement.identity)
    {
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded tell input")?;
        let agent = context
            .ir
            .agents
            .iter()
            .find(|agent| Some(agent.name.as_str()) == existing.target.as_deref())
            .ok_or("recorded tell has no pinned agent")?;
        if existing.kind != "agent.tell"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.profile != agent.profile
            || input["agent"] != agent.name
            || input["rule"] != context.frame.rule
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded tell differs from its pinned source operation".into());
        }
        return observed(existing, context.events);
    }
    let target_expr = whipplescript_parser::parse_expression(target)?;
    let mut inputs = vec![statement.evaluate(&target_expr)];
    let mut parts = Vec::new();
    for segment in whipplescript_parser::managed_template::parse(
        effect
            .prompt
            .as_ref()
            .map_or("", |prompt| prompt.text.as_str()),
    )? {
        match segment {
            Segment::Text(text) => parts.push(PromptPart::Text { text: text.into() }),
            Segment::Expression { expr, .. } => {
                parts.push(PromptPart::Value {
                    argument: inputs.len(),
                });
                inputs.push(statement.evaluate(&expr));
            }
        }
    }
    let evaluated = strict(inputs.clone(), |values| {
        EvalValue::Json(Value::Array(values))
    });
    let State::Ready(Value::Array(values)) = &evaluated.state else {
        return Ok(Leaf::Waiting(evaluated));
    };
    let agent = values[0]
        .as_str()
        .and_then(|name| context.ir.agents.iter().find(|agent| agent.name == name))
        .ok_or("managed tell target must be a declared agent")?;
    let arguments: Vec<_> = inputs
        .iter()
        .zip(values)
        .map(|(input, value)| Argument {
            value: value.clone(),
            sources: input.sources.clone(),
            subjects: input.subjects.clone(),
            validity: input.validity.clone(),
        })
        .collect();
    let timeout_seconds = contract
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed tell timeout exceeds the store range")?;
    let parsed = ParsedEffect {
        kind: "agent.tell".into(),
        target: Some(agent.name.clone()),
        name: Some("tell".into()),
        binding: effect.binding.clone(),
        args: Vec::new(),
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: contract.required_capabilities.clone(),
        after: None,
        timeout_seconds,
    };
    let mut input = json!({
        "agent": agent.name, "rule": context.frame.rule, "bindings": {},
        "managed_prompt": parts, "action_arguments": arguments,
        "access_grants": lowering::access_grants_json(
            &contract.access_grants, &context.ir.file_stores, &context.ir.vaults),
        "turn_skills": contract.turn_skills, "on_stream": contract.on_stream,
    });
    if let Some(content_type) = effect
        .prompt
        .as_ref()
        .and_then(|prompt| prompt.content_type.as_ref())
    {
        input["prompt_content_type"] = json!(content_type);
    }
    materialize_prompt(&mut input)?;
    let key = lowering::effect_admission_key(
        context.ir,
        &context.frame.rule,
        &parsed,
        &statement.identity,
        "",
    );
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity,
                kind: "agent.tell".into(),
                target: Some(agent.name.clone()),
                input_json: input.to_string(),
                status: "queued".into(),
                idempotency_key: key,
                required_capabilities_json: parsed.required_capabilities_json(),
                profile: agent.profile.clone(),
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
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded tell has an unknown operation status".into());
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
            .map_err(|_| "unreadable tell terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminal = Some((event, payload));
            break;
        }
    }
    let (event, payload) = terminal.ok_or("settled tell has no terminal evidence")?;
    let status = if event.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("tell terminal evidence differs from its recorded status".into());
    }
    let uncertain = payload["run_status"] == "uncertain";
    if effect.status == "completed" {
        if uncertain {
            return Ok(empty(WorkState::Uncertain));
        }
        if payload["run_id"].as_str().is_none_or(str::is_empty)
            || payload["run_status"] != "completed"
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("successful tell has no completed run evidence".into());
        }
        let summary = payload["summary"]
            .as_str()
            .ok_or("successful tell has no string summary")?;
        return Ok(leaf(
            OwnedLowering::default(),
            WorkState::Succeeded,
            Some(json!(summary).into()),
            BTreeMap::new(),
        ));
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
                    payload,
                    evidence: BTreeSet::from([event.event_id.clone()]),
                },
                recovered: false,
            },
        )]),
    ))
}

#[cfg(test)]
mod tests;
