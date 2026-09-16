//! Managed file reads, writes and exports. Scalar arguments and export
//! membership are captured at admission; both runtime hosts keep using the
//! existing host-agnostic file handlers.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt};
use whipplescript_parser::{IrProgram, IrSchema, IrType};
use whipplescript_store::{
    projection_prefix::{ProjectionEffect, ProjectionFact},
    EventView,
};

use super::arguments::{
    strict, Argument, ObservationKind, ObservationMember, State, Validity, ValueSource,
};
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
    pub facts: &'a [ProjectionFact],
    pub source_path: Option<&'a Path>,
}

struct Contract<'a> {
    format: &'a str,
    store: &'a whipplescript_parser::IrFileStore,
    path: &'a str,
}

fn source_contract<'a>(
    ir: &'a IrProgram,
    statement: &'a whipplescript_parser::body::EffectStmt,
) -> Result<Contract<'a>, String> {
    let BodyEffectKind::FileRead {
        format,
        store,
        path,
    } = &statement.kind
    else {
        // MUTATION-SUCCESS-EXPR: Ok(Contract { format: "text", store: &ir.file_stores[0], path: "path" })
        return Err("file read projector requires a read statement".into());
    };
    if !matches!(format.as_str(), "text" | "markdown") {
        // MUTATION-SUCCESS-EXPR: Ok(Contract { format, store: &ir.file_stores[0], path })
        return Err("managed file read has an unsupported format".into());
    }
    let store = ir
        .file_stores
        .iter()
        .find(|candidate| candidate.name == *store)
        .ok_or("managed file read has no declared store")?;
    statement
        .binding
        .as_deref()
        .ok_or("managed file read has no result binding")?;
    Ok(Contract {
        format,
        store,
        path,
    })
}

pub fn project_read(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("file read projector requires an effect statement".into());
    };
    let contract = source_contract(context.ir, effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("managed file read requires its pinned root rule".into());
    }
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "file.read"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target.as_deref() != Some(contract.store.name.as_str())
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded file read differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded file read input")?;
        let raw_argument = input
            .get("path_argument")
            .ok_or("recorded file read has no path argument")?;
        if !raw_argument["subjects"].is_object()
            || !raw_argument["sources"].is_array()
            || !raw_argument["validity"].is_array()
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded file read has an incomplete freshness argument".into());
        }
        let argument: Argument = serde_json::from_value(raw_argument.clone())
            .map_err(|_| "recorded file read has no valid path argument")?;
        super::journal::validate_argument(&argument, context.frontier).map_err(|issue| issue.0)?;
        let path = argument
            .value
            .as_str()
            .ok_or("recorded file read path is not a string")?;
        if input["format"] != contract.format
            || input["store"] != contract.store.name
            || input["path_expr"] != contract.path
            || input["path"] != path
            || input["root"] != contract.store.root
            || input["allow"] != json!(contract.store.read_globs)
            || input["rule"] != context.frame.rule
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded file read input differs from its source contract".into());
        }
        return observe(context.ir, &contract, path, existing, context.events);
    }

    let expr = whipplescript_parser::parse_expression(contract.path)?;
    let mut evaluated = statement.evaluate(&expr);
    if matches!(evaluated.state, State::Absent) {
        evaluated.state = State::Invalid(Box::new(
            "managed file read path cannot be absent".to_owned().into(),
        ));
    }
    let State::Ready(value) = &evaluated.state else {
        return Ok(Leaf::Waiting(evaluated));
    };
    let path = value
        .as_str()
        .ok_or("managed file read path must be a string")?;
    let argument = Argument {
        value: value.clone(),
        sources: evaluated.sources,
        subjects: evaluated.subjects,
        validity: evaluated.validity,
    };
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed file read timeout exceeds the store range")?;
    let parsed = ParsedEffect {
        kind: "file.read".into(),
        target: Some(contract.store.name.clone()),
        name: Some(contract.format.into()),
        binding: effect.binding.clone(),
        args: vec![
            contract.format.into(),
            contract.store.name.clone(),
            contract.path.into(),
        ],
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let input = json!({
        "format": contract.format,
        "store": contract.store.name,
        "path": path,
        "path_expr": contract.path,
        "root": contract.store.root,
        "allow": contract.store.read_globs,
        "rule": context.frame.rule,
        "path_argument": argument,
    });
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: "file.read".into(),
                target: Some(contract.store.name.clone()),
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
    path: &str,
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
            return Err("recorded file read has an unknown operation status".into());
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
            .map_err(|_| "unreadable file read terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminals.push((event, payload));
        }
    }
    let [(terminal, payload)] = terminals.as_slice() else {
        // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
        return Err("settled file read requires exactly one terminal".into());
    };
    let status = if terminal.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
        return Err("file read terminal evidence differs from its recorded status".into());
    }
    let uncertain = payload["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal.event_id.clone()]);
    let mut cause_payload = payload.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = payload["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("file read terminal has no run identity")?;
        let expected = if effect.status == "completed" {
            "file.read.completed"
        } else {
            "file.read.failed"
        };
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let envelope: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable file read result evidence")?;
            let name = envelope["name"].as_str().unwrap_or_default();
            let value = &envelope["value"];
            if matches!(name, "file.read.completed" | "file.read.failed")
                && envelope["key"] == effect.effect_id
                && value["effect_id"] == effect.effect_id
                && value["run_id"] == run
            {
                results.push((event, name.to_owned(), value.clone()));
            }
        }
        let [(result_event, result_name, result)] = results.as_slice() else {
            // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
            return Err("file read terminal requires exactly one result for its run".into());
        };
        if result_name != expected
            || result_event.sequence <= terminal.sequence
            || result["status"] != effect.status
            || result.get("value").is_none()
        {
            // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
            return Err("file read result differs from its terminal".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let output =
                whipplescript_parser::file_read_output_type(whipplescript_parser::SourceSpan {
                    start: 0,
                    end: 0,
                });
            let value = &result["value"];
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(ir, value, &output, "$", &mut errors);
            if !errors.is_empty()
                || value["store"] != contract.store.name
                || value["path"] != path
                || value["format"] != contract.format
            {
                // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
                return Err(format!(
                    "file read result violates its source contract{}",
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

struct WriteContract<'a> {
    format: &'a str,
    store: &'a whipplescript_parser::IrFileStore,
    path: &'a str,
    body: &'a str,
    mode: &'a str,
}

fn write_contract<'a>(
    ir: &'a IrProgram,
    statement: &'a whipplescript_parser::body::EffectStmt,
) -> Result<WriteContract<'a>, String> {
    let BodyEffectKind::FileWrite {
        format,
        store,
        path,
        body,
        mode,
    } = &statement.kind
    else {
        // MUTATION-SUCCESS-EXPR: Ok(WriteContract { format: "text", store: &ir.file_stores[0], path: "path", body: "body", mode: "replace" })
        return Err("file write projector requires a write statement".into());
    };
    if !matches!(format.as_str(), "text" | "markdown")
        || !matches!(mode.as_str(), "create" | "replace" | "upsert" | "append")
    {
        // MUTATION-SUCCESS-EXPR: Ok(WriteContract { format, store: &ir.file_stores[0], path, body, mode })
        return Err("managed file write has an unsupported format or mode".into());
    }
    let store = ir
        .file_stores
        .iter()
        .find(|candidate| candidate.name == *store)
        .ok_or("managed file write has no declared store")?;
    statement
        .binding
        .as_deref()
        .ok_or("managed file write has no result binding")?;
    Ok(WriteContract {
        format,
        store,
        path,
        body,
        mode,
    })
}

pub fn project_write(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("file write projector requires an effect statement".into());
    };
    let contract = write_contract(context.ir, effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("managed file write requires its pinned root rule".into());
    }
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "file.write"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target.as_deref() != Some(contract.store.name.as_str())
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded file write differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded file write input")?;
        let decode = |name: &str| -> Result<Argument, String> {
            let raw = input
                .get(name)
                .ok_or_else(|| format!("recorded file write has no {name}"))?;
            if !raw["subjects"].is_object()
                || !raw["sources"].is_array()
                || !raw["validity"].is_array()
            {
                // MUTATION-SUCCESS-EXPR: Ok(Value::Null.into())
                return Err(format!(
                    "recorded file write has an incomplete freshness argument `{name}`"
                ));
            }
            let argument: Argument = serde_json::from_value(raw.clone())
                .map_err(|_| format!("recorded file write has no valid {name}"))?;
            super::journal::validate_argument(&argument, context.frontier)
                .map_err(|issue| issue.0)?;
            Ok(argument)
        };
        let path_argument = decode("path_argument")?;
        let body_argument = decode("body_argument")?;
        let path = path_argument
            .value
            .as_str()
            .ok_or("recorded file write path is not a string")?;
        let body = body_argument
            .value
            .as_str()
            .ok_or("recorded file write body is not a string")?;
        if input["format"] != contract.format
            || input["store"] != contract.store.name
            || input["path_expr"] != contract.path
            || input["body_expr"] != contract.body
            || input["path"] != path
            || input["body"] != body
            || input["mode"] != contract.mode
            || input["root"] != contract.store.root
            || input["allow"] != json!(contract.store.write_globs)
            || input["rule"] != context.frame.rule
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded file write input differs from its source contract".into());
        }
        return observe_write(context.ir, &contract, path, existing, context.events);
    }

    let path_expr = whipplescript_parser::parse_expression(contract.path)?;
    let body_expr = whipplescript_parser::parse_expression(contract.body)?;
    let mut path_evaluation = statement.evaluate(&path_expr);
    let mut body_evaluation = statement.evaluate(&body_expr);
    if matches!(path_evaluation.state, State::Absent) {
        path_evaluation.state = State::Invalid(Box::new(
            "managed file write path cannot be absent".to_owned().into(),
        ));
    }
    if matches!(body_evaluation.state, State::Absent) {
        body_evaluation.state = State::Invalid(Box::new(
            "managed file write body cannot be absent".to_owned().into(),
        ));
    }
    let (State::Ready(path), State::Ready(body)) = (&path_evaluation.state, &body_evaluation.state)
    else {
        return Ok(Leaf::Waiting(strict(
            vec![path_evaluation, body_evaluation],
            |values| EvalValue::Json(Value::Array(values)),
        )));
    };
    let path_value = path.clone();
    let body_value = body.clone();
    let path = path_value
        .as_str()
        .ok_or("managed file write path must be a string")?
        .to_owned();
    let body = body_value
        .as_str()
        .ok_or("managed file write body must be a string")?
        .to_owned();
    let path_argument = Argument {
        value: path_value,
        sources: path_evaluation.sources,
        subjects: path_evaluation.subjects,
        validity: path_evaluation.validity,
    };
    let body_argument = Argument {
        value: body_value,
        sources: body_evaluation.sources,
        subjects: body_evaluation.subjects,
        validity: body_evaluation.validity,
    };
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed file write timeout exceeds the store range")?;
    let parsed = ParsedEffect {
        kind: "file.write".into(),
        target: Some(contract.store.name.clone()),
        name: Some(contract.format.into()),
        binding: effect.binding.clone(),
        args: vec![
            contract.format.into(),
            contract.store.name.clone(),
            contract.path.into(),
            contract.body.into(),
            contract.mode.into(),
        ],
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let input = json!({
        "format": contract.format,
        "store": contract.store.name,
        "path": path,
        "path_expr": contract.path,
        "body": body,
        "body_expr": contract.body,
        "mode": contract.mode,
        "root": contract.store.root,
        "allow": contract.store.write_globs,
        "rule": context.frame.rule,
        "path_argument": path_argument,
        "body_argument": body_argument,
    });
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: "file.write".into(),
                target: Some(contract.store.name.clone()),
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

fn observe_write(
    ir: &IrProgram,
    contract: &WriteContract<'_>,
    path: &str,
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
            return Err("recorded file write has an unknown operation status".into());
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
            .map_err(|_| "unreadable file write terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminals.push((event, payload));
        }
    }
    let [(terminal, payload)] = terminals.as_slice() else {
        // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
        return Err("settled file write requires exactly one terminal".into());
    };
    let status = if terminal.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
        return Err("file write terminal evidence differs from its recorded status".into());
    }
    let uncertain = payload["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal.event_id.clone()]);
    let mut cause_payload = payload.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = payload["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("file write terminal has no run identity")?;
        let expected = if effect.status == "completed" {
            "file.write.completed"
        } else {
            "file.write.failed"
        };
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let envelope: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable file write result evidence")?;
            let name = envelope["name"].as_str().unwrap_or_default();
            let value = &envelope["value"];
            if matches!(name, "file.write.completed" | "file.write.failed")
                && envelope["key"] == effect.effect_id
                && value["effect_id"] == effect.effect_id
                && value["run_id"] == run
            {
                results.push((event, name.to_owned(), value.clone()));
            }
        }
        let [(result_event, result_name, result)] = results.as_slice() else {
            // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
            return Err("file write terminal requires exactly one result for its run".into());
        };
        if result_name != expected
            || result_event.sequence <= terminal.sequence
            || result["status"] != effect.status
            || result.get("value").is_none()
        {
            // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
            return Err("file write result differs from its terminal".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let raw = &result["value"];
            if raw["store"] != contract.store.name
                || raw["path"] != path
                || raw["format"] != contract.format
                || raw["mode"] != contract.mode
            {
                // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
                return Err("file write result violates its source contract".into());
            }
            let value = json!({
                "store": raw["store"],
                "path": raw["path"],
                "format": raw["format"],
                "mode": raw["mode"],
                "bytes": raw["bytes"],
                "content_hash": raw["content_hash"],
            });
            let output =
                whipplescript_parser::file_write_output_type(whipplescript_parser::SourceSpan {
                    start: 0,
                    end: 0,
                });
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(ir, &value, &output, "$", &mut errors);
            if !errors.is_empty() {
                // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
                return Err(format!(
                    "file write result violates its output type: {}",
                    errors.join("; ")
                ));
            }
            return Ok(leaf(
                OwnedLowering::default(),
                WorkState::Succeeded,
                Some(value.into()),
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

struct ImportContract<'a> {
    format: &'a str,
    schema: &'a str,
    required_fields: Vec<String>,
    natural_key_field: Option<String>,
    store: &'a whipplescript_parser::IrFileStore,
    path: &'a str,
}

fn import_contract<'a>(
    ir: &'a IrProgram,
    statement: &'a whipplescript_parser::body::EffectStmt,
) -> Result<ImportContract<'a>, String> {
    let BodyEffectKind::FileImport {
        format,
        schema,
        store,
        path,
    } = &statement.kind
    else {
        return Err("file import projector requires an import statement".into());
    };
    if !matches!(format.as_str(), "jsonl" | "json" | "csv") {
        return Err("managed file import has an unsupported format".into());
    }
    let class = ir
        .schemas
        .iter()
        .find_map(|candidate| match candidate {
            IrSchema::Class(class) if class.name == *schema => Some(class),
            _ => None,
        })
        .ok_or("managed file import has no declared row schema")?;
    let required_fields = class
        .fields
        .iter()
        .filter(|field| !matches!(field.ty, IrType::Optional(_) | IrType::LiteralString(_)))
        .map(|field| field.name.clone())
        .collect();
    let natural_key_field = class
        .fields
        .iter()
        .find(|field| field.is_key)
        .map(|field| field.name.clone());
    let store = ir
        .file_stores
        .iter()
        .find(|candidate| candidate.name == *store)
        .ok_or("managed file import has no declared store")?;
    statement
        .binding
        .as_deref()
        .ok_or("managed file import has no result binding")?;
    Ok(ImportContract {
        format,
        schema,
        required_fields,
        natural_key_field,
        store,
        path,
    })
}

pub fn project_import(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        return Err("file import projector requires an effect statement".into());
    };
    let contract = import_contract(context.ir, effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        return Err("managed file import requires its pinned root rule".into());
    }
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "file.import"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target.as_deref() != Some(contract.store.name.as_str())
        {
            return Err("recorded file import differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded file import input")?;
        let raw_argument = input
            .get("path_argument")
            .ok_or("recorded file import has no path argument")?;
        if !raw_argument["subjects"].is_object()
            || !raw_argument["sources"].is_array()
            || !raw_argument["validity"].is_array()
        {
            return Err("recorded file import has an incomplete freshness argument".into());
        }
        let argument: Argument = serde_json::from_value(raw_argument.clone())
            .map_err(|_| "recorded file import has no valid path argument")?;
        super::journal::validate_argument(&argument, context.frontier).map_err(|issue| issue.0)?;
        let path = argument
            .value
            .as_str()
            .ok_or("recorded file import path is not a string")?;
        if input["format"] != contract.format
            || input["schema"] != contract.schema
            || input["store"] != contract.store.name
            || input["path_expr"] != contract.path
            || input["path"] != path
            || input["root"] != contract.store.root
            || input["allow"] != json!(contract.store.read_globs)
            || input["required_fields"] != json!(contract.required_fields)
            || input["natural_key_field"]
                != contract
                    .natural_key_field
                    .as_deref()
                    .map_or(Value::String(String::new()), |field| json!(field))
            || input["rule"] != context.frame.rule
        {
            return Err("recorded file import input differs from its source contract".into());
        }
        return observe_import(context.ir, &contract, path, existing, context.events);
    }

    let expr = whipplescript_parser::parse_expression(contract.path)?;
    let mut evaluated = statement.evaluate(&expr);
    if matches!(evaluated.state, State::Absent) {
        evaluated.state = State::Invalid(Box::new(
            "managed file import path cannot be absent"
                .to_owned()
                .into(),
        ));
    }
    let State::Ready(value) = &evaluated.state else {
        return Ok(Leaf::Waiting(evaluated));
    };
    let path = value
        .as_str()
        .ok_or("managed file import path must be a string")?;
    let path_argument = Argument {
        value: value.clone(),
        sources: evaluated.sources,
        subjects: evaluated.subjects,
        validity: evaluated.validity,
    };
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed file import timeout exceeds the store range")?;
    let parsed = ParsedEffect {
        kind: "file.import".into(),
        target: Some(contract.store.name.clone()),
        name: Some(contract.schema.into()),
        binding: effect.binding.clone(),
        args: vec![
            contract.format.into(),
            contract.schema.into(),
            contract.store.name.clone(),
            contract.path.into(),
        ],
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let input = json!({
        "format": contract.format,
        "schema": contract.schema,
        "store": contract.store.name,
        "path": path,
        "path_expr": contract.path,
        "root": contract.store.root,
        "allow": contract.store.read_globs,
        "required_fields": contract.required_fields,
        "natural_key_field": contract.natural_key_field.as_deref().unwrap_or_default(),
        "rule": context.frame.rule,
        "path_argument": path_argument,
    });
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: "file.import".into(),
                target: Some(contract.store.name.clone()),
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

fn observe_import(
    ir: &IrProgram,
    contract: &ImportContract<'_>,
    path: &str,
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
        _ => return Err("recorded file import has an unknown operation status".into()),
    }
    let mut terminals = Vec::new();
    for event in events.iter().filter(|event| {
        matches!(
            event.event_type.as_str(),
            "effect.terminal" | "effect.cancelled"
        )
    }) {
        let payload: Value = serde_json::from_str(&event.payload_json)
            .map_err(|_| "unreadable file import terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminals.push((event, payload));
        }
    }
    let [(terminal, payload)] = terminals.as_slice() else {
        return Err("settled file import requires exactly one terminal".into());
    };
    let status = if terminal.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        return Err("file import terminal evidence differs from its recorded status".into());
    }
    let uncertain = payload["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal.event_id.clone()]);
    let mut cause_payload = payload.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = payload["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("file import terminal has no run identity")?;
        let expected = if effect.status == "completed" {
            "file.import.completed"
        } else {
            "file.import.failed"
        };
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let envelope: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable file import result evidence")?;
            let name = envelope["name"].as_str().unwrap_or_default();
            let value = &envelope["value"];
            if matches!(name, "file.import.completed" | "file.import.failed")
                && envelope["key"] == effect.effect_id
                && value["effect_id"] == effect.effect_id
                && value["run_id"] == run
            {
                results.push((event, name.to_owned(), value.clone()));
            }
        }
        let [(result_event, result_name, result)] = results.as_slice() else {
            return Err("file import terminal requires exactly one result for its run".into());
        };
        if result_name != expected
            || result_event.sequence <= terminal.sequence
            || result["status"] != effect.status
            || result.get("value").is_none()
        {
            return Err("file import result differs from its terminal".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let value = &result["value"];
            let output =
                whipplescript_parser::file_import_output_type(whipplescript_parser::SourceSpan {
                    start: 0,
                    end: 0,
                });
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(ir, value, &output, "$", &mut errors);
            if !errors.is_empty()
                || value["store"] != contract.store.name
                || value["path"] != path
                || value["format"] != contract.format
                || value["schema"] != contract.schema
            {
                return Err(format!(
                    "file import result violates its source contract{}",
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

struct ExportContract<'a> {
    format: &'a str,
    schema: &'a str,
    fields: Vec<String>,
    store: &'a whipplescript_parser::IrFileStore,
    path: &'a str,
    predicate: Option<&'a str>,
    mode: &'a str,
}

fn export_contract<'a>(
    ir: &'a IrProgram,
    statement: &'a whipplescript_parser::body::EffectStmt,
) -> Result<ExportContract<'a>, String> {
    let BodyEffectKind::FileExport {
        format,
        schema,
        store,
        path,
        predicate,
        mode,
    } = &statement.kind
    else {
        // MUTATION-SUCCESS-EXPR: Ok(ExportContract { format: "json", schema: "Row", fields: vec![], store: &ir.file_stores[0], path: "path", predicate: None, mode: "replace" })
        return Err("file export projector requires an export statement".into());
    };
    if !matches!(format.as_str(), "jsonl" | "json" | "csv")
        || !matches!(mode.as_str(), "create" | "replace" | "upsert" | "append")
    {
        // MUTATION-SUCCESS-EXPR: Ok(ExportContract { format, schema, fields: vec![], store: &ir.file_stores[0], path, predicate: predicate.as_deref(), mode })
        return Err("managed file export has an unsupported format or mode".into());
    }
    let fields = ir
        .schemas
        .iter()
        .find_map(|candidate| match candidate {
            IrSchema::Class(class) if class.name == *schema => Some(
                class
                    .fields
                    .iter()
                    .map(|field| field.name.clone())
                    .collect(),
            ),
            _ => None,
        })
        .ok_or("managed file export has no declared row schema")?;
    let store = ir
        .file_stores
        .iter()
        .find(|candidate| candidate.name == *store)
        .ok_or("managed file export has no declared store")?;
    statement
        .binding
        .as_deref()
        .ok_or("managed file export has no result binding")?;
    Ok(ExportContract {
        format,
        schema,
        fields,
        store,
        path,
        predicate: predicate.as_deref(),
        mode,
    })
}

fn capture_export_rows(
    ir: &IrProgram,
    contract: &ExportContract<'_>,
    facts: &[ProjectionFact],
    frontier: i64,
) -> Result<Argument, String> {
    let guard = contract
        .predicate
        .filter(|predicate| !predicate.trim().is_empty());
    let guard_json = guard
        .map(whipplescript_parser::parse_expression)
        .transpose()?
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| "file export predicate cannot be captured")?;
    let mut candidates = facts
        .iter()
        .filter(|fact| fact.name == contract.schema)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| (&left.key, &left.fact_id).cmp(&(&right.key, &right.fact_id)));

    let mut rows = Vec::new();
    let mut sources = BTreeSet::new();
    let mut members = BTreeSet::new();
    let mut validity = Validity::new();
    let row_type = IrType::Ref(contract.schema.to_owned());
    for fact in candidates {
        if fact.fact_id.is_empty() || fact.source_event_id.is_empty() {
            return Err("managed file export member has no durable identity".into());
        }
        let value: Value = serde_json::from_str(&fact.value_json)
            .map_err(|_| "managed file export member has invalid value JSON")?;
        let mut errors = Vec::new();
        lowering::validate_json_for_ir_type(ir, &value, &row_type, "$", &mut errors);
        if !errors.is_empty() {
            return Err(format!(
                "managed file export member violates `{}`: {}",
                contract.schema,
                errors.join("; ")
            ));
        }
        if let Some(raw) = fact.validity_json.as_deref() {
            validity.extend(
                serde_json::from_str::<Validity>(raw)
                    .map_err(|_| "managed file export member has invalid validity JSON")?,
            );
        }
        let selected = match guard {
            Some(predicate) => crate::effect_handlers::evaluate_proj_predicate(predicate, &value)?,
            None => true,
        };
        if selected {
            rows.push(value);
            let source = ValueSource::Fact {
                fact_id: fact.fact_id.clone(),
                admission_event: fact.source_event_id.clone(),
            };
            sources.insert(source);
            members.insert(ObservationMember::Fact {
                fact_id: fact.fact_id.clone(),
                admission_event: fact.source_event_id.clone(),
            });
        }
    }
    validity.insert(super::arguments::QueryObservation {
        frontier,
        kind: ObservationKind::Fact,
        head: contract.schema.to_owned(),
        guard_json,
        members,
    });
    Ok(Argument {
        value: Value::Array(rows),
        sources,
        subjects: Default::default(),
        validity,
    })
}

fn validate_export_capture(
    contract: &ExportContract<'_>,
    argument: &Argument,
    captured_frontier: i64,
) -> Result<(), String> {
    let guard_json = contract
        .predicate
        .filter(|predicate| !predicate.trim().is_empty())
        .map(whipplescript_parser::parse_expression)
        .transpose()?
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|_| "file export predicate cannot be validated")?;
    let observations = argument
        .validity
        .iter()
        .filter(|observation| {
            observation.frontier == captured_frontier
                && observation.kind == ObservationKind::Fact
                && observation.head == contract.schema
                && observation.guard_json == guard_json
        })
        .collect::<Vec<_>>();
    let [observation] = observations.as_slice() else {
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err("recorded file export lacks its exact collection observation".into());
    };
    if argument
        .sources
        .iter()
        .any(|source| matches!(source, ValueSource::Operation { .. }))
    {
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err("recorded file export collection has a non-fact source".into());
    }
    let members = argument
        .sources
        .iter()
        .filter_map(|source| match source {
            ValueSource::Fact {
                fact_id,
                admission_event,
            } => Some(ObservationMember::Fact {
                fact_id: fact_id.clone(),
                admission_event: admission_event.clone(),
            }),
            ValueSource::Operation { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    let rows = argument
        .value
        .as_array()
        .ok_or("recorded file export rows are not an array")?;
    if observation.members != members || rows.len() != members.len() {
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err("recorded file export rows differ from their captured membership".into());
    }
    Ok(())
}

pub fn project_export(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("file export projector requires an effect statement".into());
    };
    let contract = export_contract(context.ir, effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
        return Err("managed file export requires its pinned root rule".into());
    }
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "file.export"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target.as_deref() != Some(contract.store.name.as_str())
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded file export differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded file export input")?;
        let decode = |name: &str| -> Result<Argument, String> {
            let raw = input
                .get(name)
                .ok_or_else(|| format!("recorded file export has no {name}"))?;
            if !raw["subjects"].is_object()
                || !raw["sources"].is_array()
                || !raw["validity"].is_array()
            {
                // MUTATION-SUCCESS-EXPR: Ok(Value::Null.into())
                return Err(format!(
                    "recorded file export has an incomplete freshness argument `{name}`"
                ));
            }
            let argument: Argument = serde_json::from_value(raw.clone())
                .map_err(|_| format!("recorded file export has no valid {name}"))?;
            super::journal::validate_argument(&argument, context.frontier)
                .map_err(|issue| issue.0)?;
            Ok(argument)
        };
        let path_argument = decode("path_argument")?;
        let rows_argument = decode("rows_argument")?;
        let path = path_argument
            .value
            .as_str()
            .ok_or("recorded file export path is not a string")?;
        let rows = rows_argument
            .value
            .as_array()
            .ok_or("recorded file export rows are not an array")?;
        let captured_frontier = input["captured_frontier"]
            .as_i64()
            .ok_or("recorded file export has no captured frontier")?;
        validate_export_capture(&contract, &rows_argument, captured_frontier)?;
        let row_type = IrType::Ref(contract.schema.to_owned());
        for row in rows {
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(context.ir, row, &row_type, "$", &mut errors);
            if !errors.is_empty() {
                // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
                return Err("recorded file export rows violate their source schema".into());
            }
        }
        if input["format"] != contract.format
            || input["schema"] != contract.schema
            || input["store"] != contract.store.name
            || input["path_expr"] != contract.path
            || input["path"] != path
            || input["predicate"] != contract.predicate.unwrap_or_default()
            || input["mode"] != contract.mode
            || input["root"] != contract.store.root
            || input["allow"] != json!(contract.store.write_globs)
            || input["fields"] != json!(contract.fields)
            || input["rule"] != context.frame.rule
        {
            // MUTATION-SUCCESS-EXPR: Ok(leaf(OwnedLowering::default(), WorkState::Pending, None, BTreeMap::new()))
            return Err("recorded file export input differs from its source contract".into());
        }
        return observe_export(context.ir, &contract, path, existing, context.events);
    }

    let path_expr = whipplescript_parser::parse_expression(contract.path)?;
    let mut path_evaluation = statement.evaluate(&path_expr);
    if matches!(path_evaluation.state, State::Absent) {
        path_evaluation.state = State::Invalid(Box::new(
            "managed file export path cannot be absent"
                .to_owned()
                .into(),
        ));
    }
    let State::Ready(path_value) = &path_evaluation.state else {
        return Ok(Leaf::Waiting(path_evaluation));
    };
    let path = path_value
        .as_str()
        .ok_or("managed file export path must be a string")?
        .to_owned();
    let path_argument = Argument {
        value: path_value.clone(),
        sources: path_evaluation.sources,
        subjects: path_evaluation.subjects,
        validity: path_evaluation.validity,
    };
    let rows_argument =
        capture_export_rows(context.ir, &contract, context.facts, context.frontier)?;
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed file export timeout exceeds the store range")?;
    let parsed = ParsedEffect {
        kind: "file.export".into(),
        target: Some(contract.store.name.clone()),
        name: Some(contract.schema.into()),
        binding: effect.binding.clone(),
        args: vec![
            contract.format.into(),
            contract.schema.into(),
            contract.store.name.clone(),
            contract.path.into(),
            contract.predicate.unwrap_or_default().into(),
            contract.mode.into(),
        ],
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let input = json!({
        "format": contract.format,
        "schema": contract.schema,
        "store": contract.store.name,
        "path": path,
        "path_expr": contract.path,
        "predicate": contract.predicate.unwrap_or_default(),
        "mode": contract.mode,
        "root": contract.store.root,
        "allow": contract.store.write_globs,
        "fields": contract.fields,
        "captured_frontier": context.frontier,
        "rule": context.frame.rule,
        "path_argument": path_argument,
        "rows_argument": rows_argument,
    });
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: "file.export".into(),
                target: Some(contract.store.name.clone()),
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

fn observe_export(
    ir: &IrProgram,
    contract: &ExportContract<'_>,
    path: &str,
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
            return Err("recorded file export has an unknown operation status".into());
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
            .map_err(|_| "unreadable file export terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminals.push((event, payload));
        }
    }
    let [(terminal, payload)] = terminals.as_slice() else {
        // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
        return Err("settled file export requires exactly one terminal".into());
    };
    let status = if terminal.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
        return Err("file export terminal evidence differs from its recorded status".into());
    }
    let uncertain = payload["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal.event_id.clone()]);
    let mut cause_payload = payload.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = payload["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("file export terminal has no run identity")?;
        let expected = if effect.status == "completed" {
            "file.export.completed"
        } else {
            "file.export.failed"
        };
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let envelope: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable file export result evidence")?;
            let name = envelope["name"].as_str().unwrap_or_default();
            let value = &envelope["value"];
            if matches!(name, "file.export.completed" | "file.export.failed")
                && envelope["key"] == effect.effect_id
                && value["effect_id"] == effect.effect_id
                && value["run_id"] == run
            {
                results.push((event, name.to_owned(), value.clone()));
            }
        }
        let [(result_event, result_name, result)] = results.as_slice() else {
            // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
            return Err("file export terminal requires exactly one result for its run".into());
        };
        if result_name != expected
            || result_event.sequence <= terminal.sequence
            || result["status"] != effect.status
            || result.get("value").is_none()
        {
            // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
            return Err("file export result differs from its terminal".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let value = &result["value"];
            if value["store"] != contract.store.name
                || value["path"] != path
                || value["format"] != contract.format
                || value["schema"] != contract.schema
                || value["mode"] != contract.mode
            {
                // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
                return Err("file export result violates its source contract".into());
            }
            let output =
                whipplescript_parser::file_export_output_type(whipplescript_parser::SourceSpan {
                    start: 0,
                    end: 0,
                });
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(ir, value, &output, "$", &mut errors);
            if !errors.is_empty() {
                // MUTATION-SUCCESS-EXPR: Ok(empty(WorkState::Pending))
                return Err(format!(
                    "file export result violates its output type: {}",
                    errors.join("; ")
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
