//! Managed claim, release and finish operations over one captured tracker
//! address. Static resource resolution and the selected address are both pinned.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Map, Value};
use whipplescript_parser::action_plan::resolved::TypedActionPlan;
use whipplescript_parser::body::{BodyEffectKind, BodyStmt, EffectStmt, FieldAssign};
use whipplescript_parser::{Expr, ExprLiteral, IrEffectKind, IrProgram, IrType};
use whipplescript_store::{projection_prefix::ProjectionEffect, EventView};

use super::super::arguments::{strict, Argument, Evaluation, State};
use super::super::journal::Frame;
use super::super::progression::{Leaf, Statement};
use super::super::{Cause, CauseId, Disposition, FailureKind, ObservedCause, OwnedWork, WorkState};
use crate::lowering::{OwnedEffect, OwnedLowering};
use crate::rule_lowering::{self as lowering, EvalValue, ParsedEffect};

pub struct Context<'a> {
    pub ir: &'a IrProgram,
    pub typed: &'a TypedActionPlan,
    pub frame: &'a Frame,
    pub frontier: i64,
    pub effects: &'a [ProjectionEffect],
    pub events: &'a [EventView],
    pub source_path: Option<&'a Path>,
}

#[derive(Clone, Copy)]
enum Operation<'a> {
    Claim {
        ttl_seconds: Option<u64>,
        endorsed: bool,
    },
    Release,
    Finish {
        fields: &'a [FieldAssign],
    },
}

impl Operation<'_> {
    fn kind(self) -> &'static str {
        match self {
            Self::Claim { .. } => "tracker.claim",
            Self::Release => "tracker.release",
            Self::Finish { .. } => "tracker.finish",
        }
    }

    fn ir_kind(self) -> IrEffectKind {
        match self {
            Self::Claim { .. } => IrEffectKind::TrackerClaim,
            Self::Release => IrEffectKind::TrackerRelease,
            Self::Finish { .. } => IrEffectKind::TrackerFinish,
        }
    }

    fn output_type(self, span: whipplescript_parser::SourceSpan) -> IrType {
        match self {
            Self::Claim { .. } => whipplescript_parser::tracker_claim_output_type(span),
            Self::Release => whipplescript_parser::tracker_release_output_type(span),
            Self::Finish { .. } => whipplescript_parser::tracker_finish_output_type(span),
        }
    }
}

struct Contract<'a> {
    operation: Operation<'a>,
    item: &'a str,
}

fn validate_finish_fields(fields: &[FieldAssign]) -> Result<(), String> {
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for field in fields {
        if field.name != "summary" {
            return Err("managed tracker finish has an unknown field".into());
        }
        if !names.insert(field.name.as_str()) {
            return Err("managed tracker finish has duplicate fields".into());
        }
    }
    Ok(())
}

fn contract(effect: &EffectStmt) -> Result<Contract<'_>, String> {
    let (operation, item) = match &effect.kind {
        BodyEffectKind::TrackerClaim {
            item,
            ttl_seconds,
            endorsed,
        } => (
            Operation::Claim {
                ttl_seconds: *ttl_seconds,
                endorsed: *endorsed,
            },
            item.as_str(),
        ),
        BodyEffectKind::TrackerRelease { item } => (Operation::Release, item.as_str()),
        BodyEffectKind::TrackerFinish { item, fields } => {
            validate_finish_fields(fields)?;
            (Operation::Finish { fields }, item.as_str())
        }
        _ => return Err("tracker lifecycle projector requires claim, release or finish".into()),
    };
    Ok(Contract { operation, item })
}

fn address(statement: &Statement<'_>, item: &str) -> Evaluation {
    statement.evaluate(&Expr::Literal(ExprLiteral::Ident(item.into())))
}

fn validate_address(value: &Value) -> Result<(&str, &str, &str), String> {
    let object = value
        .as_object()
        .ok_or("managed tracker operand is not an address object")?;
    let queue = object
        .get("queue")
        .and_then(Value::as_str)
        .ok_or("managed tracker operand has no string queue")?;
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or("managed tracker operand has no string id")?;
    let title = object
        .get("title")
        .and_then(Value::as_str)
        .ok_or("managed tracker operand has no string title")?;
    Ok((queue, id, title))
}

fn payload(fields: &[FieldAssign], statement: &Statement<'_>) -> Evaluation {
    let mut names = Vec::new();
    let mut inputs = Vec::new();
    let mut subjects = super::super::arguments::FactSubjects::new();
    for field in fields {
        let expression =
            match field.record_expression(None, &|name| statement.environment.contains_key(name)) {
                Ok(expression) => expression,
                Err(issue) => return Evaluation::invalid(&issue),
            };
        names.push(field.name.clone());
        let evaluated = statement.evaluate(&expression);
        subjects.extend(super::super::arguments::subjects::nested(
            &evaluated.subjects,
            &field.name,
        ));
        inputs.push(evaluated);
    }
    let mut payload = strict(inputs, |values| {
        EvalValue::Json(Value::Object(
            names.into_iter().zip(values).collect::<Map<_, _>>(),
        ))
    });
    payload.subjects = subjects;
    payload
}

fn validate_payload(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("managed tracker finish payload is not an object")?;
    if object.keys().any(|field| field != "summary") {
        return Err("managed tracker finish payload has an unknown field".into());
    }
    if object
        .get("summary")
        .is_some_and(|summary| !summary.is_string())
    {
        return Err("managed tracker finish summary must be a string".into());
    }
    Ok(())
}

fn checked_resources(
    statement: &Statement<'_>,
    context: &Context<'_>,
    operation: Operation<'_>,
) -> Result<Vec<String>, String> {
    let resolved = whipplescript_parser::action_plan::resources::resolve(context.typed, context.ir)
        .map_err(|diagnostic| {
            format!(
                "managed tracker resource contract is invalid: {}",
                diagnostic.message
            )
        })?;
    let effect = resolved
        .get(&statement.node)
        .ok_or("managed tracker operation has no checked resource contract")?;
    validate_checked_resources(effect, operation)
}

fn validate_checked_resources(
    effect: &whipplescript_parser::action_plan::resources::ResolvedEffect,
    operation: Operation<'_>,
) -> Result<Vec<String>, String> {
    if effect.kind != operation.ir_kind() || effect.resources.is_empty() {
        return Err("managed tracker operation has an incompatible resource contract".into());
    }
    Ok(effect.resources.iter().cloned().collect())
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        return Err("tracker lifecycle projector requires an effect statement".into());
    };
    let contract = contract(effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        return Err("managed tracker operation requires its pinned root rule".into());
    }
    let resources = checked_resources(&statement, &context, contract.operation)?;
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed tracker timeout exceeds the store range")?;

    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != contract.operation.kind()
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || !existing
                .target
                .as_ref()
                .is_some_and(|target| resources.contains(target))
        {
            return Err("recorded tracker operation differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded tracker lifecycle input")?;
        let raw = input
            .get("item_argument")
            .ok_or("recorded tracker operation has no item argument")?;
        if !raw["subjects"].is_object() || !raw["sources"].is_array() || !raw["validity"].is_array()
        {
            return Err(
                "recorded tracker operation has an incomplete freshness argument `item`".into(),
            );
        }
        let item: Argument = serde_json::from_value(raw.clone())
            .map_err(|_| "recorded tracker operation has no valid item argument")?;
        super::super::journal::validate_argument(&item, context.frontier)
            .map_err(|issue| issue.0)?;
        let (queue, id, title) = validate_address(&item.value)?;
        if !resources.iter().any(|resource| resource == queue) {
            return Err("recorded tracker address is outside its checked resource set".into());
        }
        let tracker = context
            .ir
            .trackers
            .iter()
            .find(|tracker| tracker.name == queue)
            .ok_or("recorded tracker address has no declaration")?;
        let payload = if let Operation::Finish { fields } = contract.operation {
            let raw = input
                .get("payload_argument")
                .ok_or("recorded tracker finish has no payload argument")?;
            if !raw["subjects"].is_object()
                || !raw["sources"].is_array()
                || !raw["validity"].is_array()
            {
                return Err("recorded tracker finish has an incomplete payload argument".into());
            }
            let payload: Argument = serde_json::from_value(raw.clone())
                .map_err(|_| "recorded tracker finish has no valid payload argument")?;
            super::super::journal::validate_argument(&payload, context.frontier)
                .map_err(|issue| issue.0)?;
            validate_payload(&payload.value)?;
            if input["payload_fields"]
                != serde_json::to_value(fields)
                    .expect("tracker finish field serialization is infallible")
                || input["payload"] != payload.value
            {
                return Err(
                    "recorded tracker finish payload differs from its source contract".into(),
                );
            }
            Some(payload.value)
        } else {
            None
        };
        let (ttl_seconds, endorsed) = match contract.operation {
            Operation::Claim {
                ttl_seconds,
                endorsed,
            } => (ttl_seconds, endorsed),
            _ => (None, false),
        };
        let payload_fields = match contract.operation {
            Operation::Finish { fields } => Some(fields),
            _ => None,
        };
        if input["operation"] != contract.operation.kind()
            || input["item_binding"] != contract.item
            || input["result_binding"] != json!(effect.binding)
            || input["item"] != item.value
            || input["resources"] != json!(resources)
            || input["queue"] != queue
            || input["id"] != id
            || input["title"] != title
            || input["provider"] != tracker.provider
            || input["ttl_seconds"] != json!(ttl_seconds)
            || input["endorsed"] != endorsed
            || input["required_capabilities"] != json!(effect.requires)
            || input["timeout_seconds"] != json!(timeout_seconds)
            || input["payload_fields"] != json!(payload_fields)
            || input["payload"] != json!(payload)
            || (!matches!(contract.operation, Operation::Finish { .. })
                && !input["payload_argument"].is_null())
            || input["rule"] != context.frame.rule
        {
            return Err("recorded tracker operation input differs from its source contract".into());
        }
        return observe(
            context.ir,
            contract.operation,
            queue,
            id,
            title,
            payload.as_ref(),
            existing,
            context.events,
        );
    }

    let item = address(&statement, contract.item);
    let State::Ready(item_value) = &item.state else {
        return Ok(Leaf::Waiting(item));
    };
    let (queue, id, title) = validate_address(item_value)?;
    if !resources.iter().any(|resource| resource == queue) {
        return Err("managed tracker address is outside its checked resource set".into());
    }
    let tracker = context
        .ir
        .trackers
        .iter()
        .find(|tracker| tracker.name == queue)
        .ok_or("managed tracker address has no declaration")?;
    let item_argument = Argument {
        value: item_value.clone(),
        sources: item.sources,
        subjects: item.subjects,
        validity: item.validity,
    };
    let (payload_value, payload_argument, fields) =
        if let Operation::Finish { fields } = contract.operation {
            let payload = payload(fields, &statement);
            let State::Ready(value) = &payload.state else {
                return Ok(Leaf::Waiting(payload));
            };
            validate_payload(value)?;
            (
                Some(value.clone()),
                Some(Argument {
                    value: value.clone(),
                    sources: payload.sources,
                    subjects: payload.subjects,
                    validity: payload.validity,
                }),
                Some(fields),
            )
        } else {
            (None, None, None)
        };
    let (ttl_seconds, endorsed) = match contract.operation {
        Operation::Claim {
            ttl_seconds,
            endorsed,
        } => (ttl_seconds, endorsed),
        _ => (None, false),
    };
    let args = match contract.operation {
        Operation::Claim { .. } => vec![
            contract.item.into(),
            ttl_seconds.map(|ttl| ttl.to_string()).unwrap_or_default(),
        ],
        Operation::Release => vec![contract.item.into()],
        Operation::Finish { .. } => vec![
            contract.item.into(),
            serde_json::to_string(fields.unwrap_or_default())
                .expect("tracker finish field serialization is infallible"),
        ],
    };
    let parsed = ParsedEffect {
        kind: contract.operation.kind().into(),
        target: Some(queue.into()),
        name: None,
        binding: effect.binding.clone(),
        args,
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let input = json!({
        "operation": contract.operation.kind(),
        "item_binding": contract.item,
        "result_binding": effect.binding,
        "item": item_value,
        "item_argument": item_argument,
        "resources": resources,
        "queue": queue,
        "id": id,
        "title": title,
        "provider": tracker.provider,
        "ttl_seconds": ttl_seconds,
        "endorsed": endorsed,
        "required_capabilities": effect.requires,
        "timeout_seconds": timeout_seconds,
        "payload_fields": fields,
        "payload": payload_value,
        "payload_argument": payload_argument,
        "rule": context.frame.rule,
    });
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: contract.operation.kind().into(),
                target: Some(queue.into()),
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

#[allow(clippy::too_many_arguments)]
fn observe(
    ir: &IrProgram,
    operation: Operation<'_>,
    queue: &str,
    id: &str,
    title: &str,
    payload: Option<&Value>,
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
        _ => return Err("recorded tracker operation has an unknown status".into()),
    }
    let mut terminals = Vec::new();
    for event in events.iter().filter(|event| {
        matches!(
            event.event_type.as_str(),
            "effect.terminal" | "effect.cancelled"
        )
    }) {
        let terminal: Value = serde_json::from_str(&event.payload_json)
            .map_err(|_| "unreadable tracker lifecycle terminal evidence")?;
        if terminal["effect_id"] == effect.effect_id {
            terminals.push((event, terminal));
        }
    }
    let [(terminal_event, terminal)] = terminals.as_slice() else {
        return Err("settled tracker operation requires exactly one terminal".into());
    };
    let status = if terminal_event.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        terminal["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        return Err("tracker terminal evidence differs from its recorded status".into());
    }
    let uncertain = terminal["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal_event.event_id.clone()]);
    let mut cause_payload = terminal.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = terminal["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("tracker terminal has no run identity")?;
        let expected = format!("{}.{}", operation.kind(), effect.status);
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let envelope: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable tracker lifecycle result evidence")?;
            let name = envelope["name"].as_str().unwrap_or_default();
            let value = &envelope["value"];
            if matches!(
                name,
                "tracker.claim.completed"
                    | "tracker.claim.failed"
                    | "tracker.release.completed"
                    | "tracker.release.failed"
                    | "tracker.finish.completed"
                    | "tracker.finish.failed"
            ) && envelope["key"] == effect.effect_id
                && value["effect_id"] == effect.effect_id
                && value["run_id"] == run
            {
                results.push((event, name.to_owned(), value.clone()));
            }
        }
        let [(result_event, result_name, result)] = results.as_slice() else {
            return Err("tracker terminal requires exactly one result for its run".into());
        };
        if result_name != &expected
            || result_event.sequence <= terminal_event.sequence
            || result["status"] != effect.status
            || result.get("value").is_none()
        {
            return Err("tracker result differs from its terminal".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let value = &result["value"];
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(
                ir,
                value,
                &operation.output_type(whipplescript_parser::SourceSpan { start: 0, end: 0 }),
                "$",
                &mut errors,
            );
            let finish_summary_matches = !matches!(operation, Operation::Finish { .. })
                || value["summary"]
                    == payload
                        .and_then(|payload| payload.get("summary"))
                        .cloned()
                        .unwrap_or(Value::Null);
            if !errors.is_empty()
                || value["queue"] != queue
                || value["id"] != id
                || value["title"] != title
                || !finish_summary_matches
            {
                return Err("tracker result violates its source contract".into());
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
