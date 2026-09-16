//! Managed tracker filing. The authored item is captured once at admission;
//! settlement exposes only the durable tracker address.

pub mod lifecycle;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Map, Value};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt, FieldAssign};
use whipplescript_parser::{IrProgram, IrTracker};
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
    tracker: &'a IrTracker,
    fields: &'a [FieldAssign],
}

fn contract<'a>(
    ir: &'a IrProgram,
    effect: &'a whipplescript_parser::body::EffectStmt,
) -> Result<Contract<'a>, String> {
    let BodyEffectKind::TrackerFile { queue, fields } = &effect.kind else {
        return Err("tracker-file projector requires a file statement".into());
    };
    let tracker = ir
        .trackers
        .iter()
        .find(|candidate| candidate.name == *queue)
        .ok_or("managed tracker filing has no declared tracker")?;
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for field in fields {
        if !matches!(
            field.name.as_str(),
            "title" | "body" | "labels" | "metadata"
        ) {
            return Err("managed tracker item has an unknown field".into());
        }
        if !names.insert(field.name.as_str()) {
            return Err("managed tracker item has duplicate fields".into());
        }
    }
    if !names.contains("title") {
        return Err("managed tracker item has no title".into());
    }
    Ok(Contract { tracker, fields })
}

fn item(fields: &[FieldAssign], statement: &Statement<'_>) -> Evaluation {
    let mut names = Vec::new();
    let mut inputs = Vec::new();
    let mut subjects = super::arguments::FactSubjects::new();
    for field in fields {
        let expression =
            match field.record_expression(None, &|name| statement.environment.contains_key(name)) {
                Ok(expression) => expression,
                Err(issue) => return Evaluation::invalid(&issue),
            };
        names.push(field.name.clone());
        let evaluated = statement.evaluate(&expression);
        subjects.extend(super::arguments::subjects::nested(
            &evaluated.subjects,
            &field.name,
        ));
        inputs.push(evaluated);
    }
    let mut item = strict(inputs, |values| {
        EvalValue::Json(Value::Object(
            names.into_iter().zip(values).collect::<Map<_, _>>(),
        ))
    });
    item.subjects = subjects;
    item
}

fn validate_item(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("managed tracker item is not an object")?;
    if !object.get("title").is_some_and(Value::is_string) {
        return Err("managed tracker item title must be a string".into());
    }
    if object.get("body").is_some_and(|value| !value.is_string()) {
        return Err("managed tracker item body must be a string".into());
    }
    if object.get("labels").is_some_and(|value| {
        value
            .as_array()
            .is_none_or(|labels| labels.iter().any(|label| !label.is_string()))
    }) {
        return Err("managed tracker item labels must be strings".into());
    }
    if object
        .get("metadata")
        .is_some_and(|value| !value.is_object())
    {
        return Err("managed tracker item metadata must be an object".into());
    }
    Ok(())
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        return Err("tracker-file projector requires an effect statement".into());
    };
    let contract = contract(context.ir, effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        return Err("managed tracker filing requires its pinned root rule".into());
    }
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "tracker.file"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target.as_deref() != Some(contract.tracker.name.as_str())
        {
            return Err("recorded tracker filing differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded tracker-file input")?;
        let raw = input
            .get("item_argument")
            .ok_or("recorded tracker filing has no item argument")?;
        if !raw["subjects"].is_object() || !raw["sources"].is_array() || !raw["validity"].is_array()
        {
            return Err(
                "recorded tracker filing has an incomplete freshness argument `item`".into(),
            );
        }
        let item: Argument = serde_json::from_value(raw.clone())
            .map_err(|_| "recorded tracker filing has no valid item argument")?;
        super::journal::validate_argument(&item, context.frontier).map_err(|issue| issue.0)?;
        validate_item(&item.value)?;
        if input["queue"] != contract.tracker.name
            || input["provider"] != contract.tracker.provider
            || input["fields"]
                != serde_json::to_value(contract.fields)
                    .expect("tracker field contract serialization is infallible")
            || input["item"] != item.value
            || input["rule"] != context.frame.rule
        {
            return Err("recorded tracker filing input differs from its source contract".into());
        }
        return observe(
            context.ir,
            contract.tracker,
            &item.value,
            existing,
            context.events,
        );
    }

    let item = item(contract.fields, &statement);
    let State::Ready(item_value) = &item.state else {
        return Ok(Leaf::Waiting(item));
    };
    validate_item(item_value)?;
    let item_argument = Argument {
        value: item_value.clone(),
        sources: item.sources,
        subjects: item.subjects,
        validity: item.validity,
    };
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed tracker-file timeout exceeds the store range")?;
    let fields = serde_json::to_string(contract.fields)
        .expect("tracker field contract serialization is infallible");
    let parsed = ParsedEffect {
        kind: "tracker.file".into(),
        target: Some(contract.tracker.name.clone()),
        name: None,
        binding: effect.binding.clone(),
        args: vec![fields],
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let input = json!({
        "queue": contract.tracker.name,
        "provider": contract.tracker.provider,
        "fields": contract.fields,
        "item": item_value,
        "rule": context.frame.rule,
        "item_argument": item_argument,
    });
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: "tracker.file".into(),
                target: Some(contract.tracker.name.clone()),
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
    tracker: &IrTracker,
    item: &Value,
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
        _ => return Err("recorded tracker filing has an unknown operation status".into()),
    }
    let mut terminals = Vec::new();
    for event in events.iter().filter(|event| {
        matches!(
            event.event_type.as_str(),
            "effect.terminal" | "effect.cancelled"
        )
    }) {
        let payload: Value = serde_json::from_str(&event.payload_json)
            .map_err(|_| "unreadable tracker-file terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminals.push((event, payload));
        }
    }
    let [(terminal, terminal_payload)] = terminals.as_slice() else {
        return Err("settled tracker filing requires exactly one terminal".into());
    };
    let status = if terminal.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        terminal_payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        return Err("tracker-file terminal evidence differs from its recorded status".into());
    }
    let uncertain = terminal_payload["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal.event_id.clone()]);
    let mut cause_payload = terminal_payload.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = terminal_payload["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("tracker-file terminal has no run identity")?;
        let expected = if effect.status == "completed" {
            "tracker.file.completed"
        } else {
            "tracker.file.failed"
        };
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let envelope: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable tracker-file result evidence")?;
            let name = envelope["name"].as_str().unwrap_or_default();
            let value = &envelope["value"];
            if matches!(name, "tracker.file.completed" | "tracker.file.failed")
                && envelope["key"] == effect.effect_id
                && value["effect_id"] == effect.effect_id
                && value["run_id"] == run
            {
                results.push((event, name.to_owned(), value.clone()));
            }
        }
        let [(result_event, result_name, result)] = results.as_slice() else {
            return Err("tracker-file terminal requires exactly one result for its run".into());
        };
        if result_name != expected
            || result_event.sequence <= terminal.sequence
            || result["status"] != effect.status
            || result.get("value").is_none()
        {
            return Err("tracker-file result differs from its terminal".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let value = &result["value"];
            let output =
                whipplescript_parser::tracker_file_output_type(whipplescript_parser::SourceSpan {
                    start: 0,
                    end: 0,
                });
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(ir, value, &output, "$", &mut errors);
            if !errors.is_empty()
                || value["queue"] != tracker.name
                || value["title"] != item["title"]
            {
                return Err("tracker-file result violates its source contract".into());
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
