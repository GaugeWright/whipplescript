//! Managed initiative membership and inspection over checked tracker addresses.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};
use whipplescript_parser::action_plan::resolved::TypedActionPlan;
use whipplescript_parser::body::{BodyEffectKind, BodyStmt};
use whipplescript_parser::{Expr, ExprLiteral, IrEffectKind, IrProgram, IrType, SourceSpan};
use whipplescript_store::{projection_prefix::ProjectionEffect, EventView};

use super::super::arguments::{Argument, Evaluation, State};
use super::super::journal::Frame;
use super::super::progression::{Leaf, Statement};
use super::super::{Cause, CauseId, Disposition, FailureKind, ObservedCause, OwnedWork, WorkState};
use crate::lowering::{OwnedEffect, OwnedLowering};
use crate::rule_lowering::{self as lowering, ParsedEffect};

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
    Membership {
        task: &'a str,
        initiative: &'a str,
        change: &'static str,
    },
    Inspect {
        initiative: &'a str,
    },
}

impl Operation<'_> {
    fn kind(self) -> &'static str {
        match self {
            Self::Membership { .. } => "tracker.membership",
            Self::Inspect { .. } => "tracker.inspect",
        }
    }

    fn ir_kind(self) -> IrEffectKind {
        match self {
            Self::Membership { .. } => IrEffectKind::TrackerMembership,
            Self::Inspect { .. } => IrEffectKind::TrackerInspect,
        }
    }

    fn output_type(self) -> IrType {
        let span = SourceSpan { start: 0, end: 0 };
        match self {
            Self::Membership { .. } => whipplescript_parser::tracker_membership_output_type(span),
            Self::Inspect { .. } => whipplescript_parser::tracker_inspection_output_type(span),
        }
    }
}

fn operation(effect: &whipplescript_parser::body::EffectStmt) -> Result<Operation<'_>, String> {
    match &effect.kind {
        BodyEffectKind::TrackerMembership {
            task,
            initiative,
            remove,
        } => Ok(Operation::Membership {
            task,
            initiative,
            change: if *remove { "remove" } else { "add" },
        }),
        BodyEffectKind::TrackerInspect { initiative } => {
            if effect.binding.is_none() {
                return Err("managed initiative inspection requires a result binding".into());
            }
            Ok(Operation::Inspect { initiative })
        }
        _ => Err("initiative projector requires membership or inspection".into()),
    }
}

fn address(statement: &Statement<'_>, binding: &str) -> Evaluation {
    statement.evaluate(&Expr::Literal(ExprLiteral::Ident(binding.into())))
}

fn validate_address(value: &Value) -> Result<(&str, &str, &str), String> {
    let object = value
        .as_object()
        .ok_or("initiative operand is not a tracker address")?;
    let field = |name| {
        object
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| format!("initiative operand has no {name}"))
    };
    Ok((field("queue")?, field("id")?, field("title")?))
}

fn checked_resources(
    statement: &Statement<'_>,
    context: &Context<'_>,
    operation: Operation<'_>,
) -> Result<Vec<String>, String> {
    let resolved = whipplescript_parser::action_plan::resources::resolve(context.typed, context.ir)
        .map_err(|diagnostic| {
            format!(
                "initiative resource contract is invalid: {}",
                diagnostic.message
            )
        })?;
    let effect = resolved
        .get(&statement.node)
        .ok_or("initiative operation has no checked resource contract")?;
    if effect.kind != operation.ir_kind() || effect.resources.is_empty() {
        return Err("initiative operation has an incompatible resource contract".into());
    }
    Ok(effect.resources.iter().cloned().collect())
}

fn operand_names(operation: Operation<'_>) -> Vec<(&'static str, &str)> {
    match operation {
        Operation::Membership {
            task, initiative, ..
        } => {
            vec![("task", task), ("initiative", initiative)]
        }
        Operation::Inspect { initiative } => vec![("initiative", initiative)],
    }
}

fn validate_input(
    input: &Value,
    operation: Operation<'_>,
    effect: &whipplescript_parser::body::EffectStmt,
    context: &Context<'_>,
    resources: &[String],
) -> Result<Vec<Value>, String> {
    if input["operation"] != operation.kind()
        || input["resources"] != json!(resources)
        || input["result_binding"] != json!(effect.binding)
        || input["required_capabilities"] != json!(effect.requires)
        || input["rule"] != context.frame.rule
        || input["timeout_seconds"] != json!(effect.timeout_seconds)
    {
        return Err("recorded initiative input differs from its source contract".into());
    }
    let mut values = Vec::new();
    for (name, binding) in operand_names(operation) {
        if input[format!("{name}_binding")] != binding {
            return Err("recorded initiative operand binding differs from source".into());
        }
        let raw = input
            .get(format!("{name}_argument"))
            .ok_or("recorded initiative operand has no freshness argument")?;
        if !raw["subjects"].is_object() || !raw["sources"].is_array() || !raw["validity"].is_array()
        {
            return Err("recorded initiative operand has an incomplete freshness argument".into());
        }
        let argument: Argument = serde_json::from_value(raw.clone())
            .map_err(|_| "recorded initiative operand has an invalid freshness argument")?;
        super::super::journal::validate_argument(&argument, context.frontier)
            .map_err(|issue| issue.0)?;
        let (queue, _, _) = validate_address(&argument.value)?;
        if !resources.iter().any(|resource| resource == queue) || input[name] != argument.value {
            return Err("recorded initiative operand is outside its checked resources".into());
        }
        values.push(argument.value);
    }
    if input["change"]
        != match operation {
            Operation::Membership { change, .. } => json!(change),
            Operation::Inspect { .. } => Value::Null,
        }
    {
        return Err("recorded initiative operation differs from source".into());
    }
    Ok(values)
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        return Err("initiative projector requires an effect statement".into());
    };
    let operation = operation(effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        return Err("managed initiative operation requires its pinned root rule".into());
    }
    let resources = checked_resources(&statement, &context, operation)?;
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed initiative timeout exceeds the store range")?;

    if let Some(existing) = context
        .effects
        .iter()
        .find(|item| item.effect_id == statement.identity)
    {
        if existing.kind != operation.kind()
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target.is_some()
        {
            return Err("recorded initiative effect differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded initiative input")?;
        let values = validate_input(&input, operation, effect, &context, &resources)?;
        return observe(
            context.ir,
            operation,
            &values,
            &resources,
            existing,
            context.events,
        );
    }

    let mut values = Vec::new();
    let mut arguments = Vec::new();
    for (name, binding) in operand_names(operation) {
        let evaluated = address(&statement, binding);
        let State::Ready(value) = &evaluated.state else {
            return Ok(Leaf::Waiting(evaluated));
        };
        let (queue, _, _) = validate_address(value)?;
        if !resources.iter().any(|resource| resource == queue)
            || !context
                .ir
                .trackers
                .iter()
                .any(|tracker| tracker.name == queue && tracker.provider == "builtin")
        {
            return Err(format!(
                "initiative {name} address is outside its checked builtin trackers"
            ));
        }
        values.push((name, binding, value.clone()));
        arguments.push(Argument {
            value: value.clone(),
            sources: evaluated.sources,
            subjects: evaluated.subjects,
            validity: evaluated.validity,
        });
    }
    let mut input = json!({
        "operation": operation.kind(),
        "result_binding": effect.binding,
        "resources": resources,
        "required_capabilities": effect.requires,
        "rule": context.frame.rule,
        "timeout_seconds": effect.timeout_seconds,
        "change": match operation { Operation::Membership { change, .. } => Some(change), Operation::Inspect { .. } => None },
    });
    for ((name, binding, value), argument) in values.iter().zip(arguments) {
        input[*name] = value.clone();
        input[format!("{name}_binding")] = json!(binding);
        input[format!("{name}_argument")] = json!(argument);
    }
    let parsed = ParsedEffect {
        kind: operation.kind().into(),
        target: None,
        name: None,
        binding: effect.binding.clone(),
        args: operand_names(operation)
            .into_iter()
            .map(|(_, binding)| binding.into())
            .collect(),
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: operation.kind().into(),
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
    operation: Operation<'_>,
    addresses: &[Value],
    resources: &[String],
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
        _ => return Err("recorded initiative effect has an unknown status".into()),
    }
    let mut terminals = Vec::new();
    for event in events.iter().filter(|event| {
        matches!(
            event.event_type.as_str(),
            "effect.terminal" | "effect.cancelled"
        )
    }) {
        let terminal: Value = serde_json::from_str(&event.payload_json)
            .map_err(|_| "unreadable initiative terminal evidence")?;
        if terminal["effect_id"] == effect.effect_id {
            terminals.push((event, terminal));
        }
    }
    let [(terminal_event, terminal)] = terminals.as_slice() else {
        return Err("settled initiative effect requires exactly one terminal".into());
    };
    let status = if terminal_event.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        terminal["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        return Err("initiative terminal differs from its recorded status".into());
    }
    let uncertain = terminal["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal_event.event_id.clone()]);
    let mut cause_payload = terminal.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = terminal["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("initiative terminal has no run identity")?;
        let expected = format!("{}.{}", operation.kind(), effect.status);
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let value: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable initiative result evidence")?;
            if value["key"] == effect.effect_id
                && value["value"]["effect_id"] == effect.effect_id
                && value["value"]["run_id"] == run
                && value["name"].as_str().is_some_and(|name| {
                    name.starts_with("tracker.membership.") || name.starts_with("tracker.inspect.")
                })
            {
                results.push((event, value));
            }
        }
        let [(result_event, envelope)] = results.as_slice() else {
            return Err("initiative terminal requires exactly one result for its run".into());
        };
        if envelope["name"] != expected
            || result_event.sequence <= terminal_event.sequence
            || envelope["value"]["status"] != effect.status
        {
            return Err("initiative result differs from its terminal".into());
        }
        evidence.insert(result_event.event_id.clone());
        let value = &envelope["value"]["value"];
        if effect.status == "completed" {
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(
                ir,
                value,
                &operation.output_type(),
                "$",
                &mut errors,
            );
            let matched = match operation {
                Operation::Membership { .. } => {
                    value["task"] == addresses[0]
                        && value["initiative"] == addresses[1]
                        && matches!(
                            value["outcome"].as_str(),
                            Some("added" | "already_member" | "removed" | "already_absent")
                        )
                }
                Operation::Inspect { .. } => {
                    value["initiative"]["id"] == addresses[0]["id"]
                        && value["initiative"]["queue"] == addresses[0]["queue"]
                        && value["members"].as_array().is_some_and(|members| {
                            members.iter().all(|member| {
                                member["queue"].as_str().is_some_and(|queue| {
                                    resources.iter().any(|resource| resource == queue)
                                })
                            })
                        })
                }
            };
            if !errors.is_empty() || !matched {
                return Err("initiative result violates its source contract".into());
            }
            return Ok(leaf(
                OwnedLowering::default(),
                WorkState::Succeeded,
                Some(value.clone().into()),
                BTreeMap::new(),
            ));
        }
        cause_payload = value.clone();
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
mod tests {
    use super::*;
    use crate::source_action::arguments::{Bindings, Slot};
    use whipplescript_parser::action_plan::{NodeId, NodeKind};

    fn frame() -> Frame {
        Frame {
            version: "v".into(),
            revision: "0".into(),
            rule: "run".into(),
            identity: Some("started".into()),
            trigger_event: Some("admitted".into()),
        }
    }

    fn run(
        statement_source: &str,
        effects: &[ProjectionEffect],
        events: &[EventView],
    ) -> Result<Leaf, String> {
        let source = format!(
            r#"workflow Initiative
tracker jobs
tracker company
output answer Answer
class Answer {{ value string }}
rule run
  when jobs has ready issue as task
=> {{
  file initiative into company {{ title "group" body "outcome" }} as group
  {statement_source}
  after operation succeeds {{ complete answer {{ value "done" }} }}
}}"#
        );
        let compiled =
            whipplescript_parser::execution_semantics::compile_recorded_program_with_root(
                &source,
                None,
                whipplescript_parser::ExecutionSemantics::TypedActionsV1,
            );
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        let ir = compiled.ir.expect("ir");
        let typed = compiled
            .typed_actions
            .expect("typed actions")
            .remove("run")
            .expect("typed root");
        let (node, body, environment) = typed
            .plan
            .nodes
            .iter()
            .enumerate()
            .find_map(|(index, node)| {
                let NodeKind::Statement(body) = &node.kind else {
                    return None;
                };
                let BodyStmt::Effect(effect) = body.as_ref() else {
                    return None;
                };
                matches!(
                    effect.kind,
                    BodyEffectKind::TrackerMembership { .. }
                        | BodyEffectKind::TrackerInspect { .. }
                )
                .then(|| {
                    (
                        NodeId(index),
                        body.as_ref().clone(),
                        typed.plan.blocks[node.block.0].environment.clone(),
                    )
                })
            })
            .expect("initiative operation");
        let task = Argument {
            value: json!({"queue":"jobs","id":"WS-1","title":"task"}),
            sources: BTreeSet::new(),
            subjects: Default::default(),
            validity: BTreeSet::new(),
        };
        let group = Argument {
            value: json!({"queue":"company","id":"WS-2","title":"group"}),
            sources: BTreeSet::new(),
            subjects: Default::default(),
            validity: BTreeSet::new(),
        };
        let bindings = Bindings::from([
            (environment["task"], Slot::Ready(task)),
            (environment["group"], Slot::Ready(group)),
        ]);
        project(
            Statement {
                node,
                root_rule: Some("run"),
                admitted: &bindings,
                identity: "operation-id".into(),
                body: &body,
                environment: &environment,
                bindings: &bindings,
                queries: None,
                outcomes: None,
            },
            Context {
                ir: &ir,
                typed: &typed,
                frame: &frame(),
                frontier: 7,
                effects,
                events,
                source_path: None,
            },
        )
    }

    fn drafted(statement: &str) -> Value {
        let Leaf::Ready {
            lowering,
            work: Some(work),
            ..
        } = run(statement, &[], &[]).expect("project")
        else {
            panic!("ready")
        };
        assert_eq!(work.state, WorkState::Pending);
        let [effect] = lowering.effects.as_slice() else {
            panic!("one effect")
        };
        serde_json::from_str(&effect.input_json).expect("input")
    }

    #[test]
    fn membership_and_inspection_capture_checked_cross_queue_addresses() {
        let membership = drafted("add task to initiative group as operation");
        assert_eq!(membership["task"]["queue"], "jobs");
        assert_eq!(membership["initiative"]["queue"], "company");
        assert_eq!(membership["change"], "add");
        assert_eq!(membership["resources"], json!(["company", "jobs"]));
        let removal = drafted("remove task from initiative group as operation");
        assert_eq!(removal["change"], "remove");
        assert_eq!(removal["resources"], json!(["company", "jobs"]));
        let inspection = drafted("inspect initiative group as operation");
        assert_eq!(inspection["initiative"]["id"], "WS-2");
        assert_eq!(inspection["resources"], json!(["company", "jobs"]));
    }

    fn completed_effect(
        kind: &str,
        input: Value,
        value: Value,
    ) -> (ProjectionEffect, Vec<EventView>) {
        let effect = ProjectionEffect {
            effect_id: "operation-id".into(),
            kind: kind.into(),
            target: None,
            input_json: input.to_string(),
            status: "completed".into(),
            created_by_rule: "run".into(),
            program_version_id: Some("v".into()),
            revision_epoch: 0,
            profile: None,
            cancel_requested: false,
        };
        let event = |sequence, event_type: &str, payload: Value| EventView {
            event_id: format!("event-{sequence}"),
            sequence,
            event_type: event_type.into(),
            payload_json: payload.to_string(),
            source: "kernel".into(),
            occurred_at: "2030-01-01T00:00:00Z".into(),
        };
        let events = vec![
            event(
                1,
                "effect.terminal",
                json!({
                    "effect_id":"operation-id", "run_id":"run", "status":"completed"
                }),
            ),
            event(
                2,
                "fact.derived",
                json!({
                    "name":format!("{kind}.completed"),
                    "key":"operation-id",
                    "value":{
                        "effect_id":"operation-id", "run_id":"run", "status":"completed", "value":value,
                    }
                }),
            ),
        ];
        (effect, events)
    }

    #[test]
    fn settled_membership_and_inspection_replay_original_typed_results() {
        let membership_source = "add task to initiative group as operation";
        let membership = drafted(membership_source);
        let value = json!({
            "task": membership["task"],
            "initiative": membership["initiative"],
            "outcome": "added",
        });
        let (effect, events) = completed_effect("tracker.membership", membership, value.clone());
        let Leaf::Ready {
            value: Some(result),
            work: Some(work),
            ..
        } = run(membership_source, &[effect], &events).expect("replay")
        else {
            panic!("settled result")
        };
        assert_eq!(work.state, WorkState::Succeeded);
        assert_eq!(result.value, value);

        let inspect_source = "inspect initiative group as operation";
        let inspection = drafted(inspect_source);
        let value = json!({
            "initiative":{"queue":"company","id":"WS-2","title":"renamed group","status":"open"},
            "members":[{
                "queue":"jobs","id":"WS-1","title":"task","status":"open",
                "ready":true,"unready_reasons":[]
            }],
            "state_counts":{"open":1},
            "at":"2030-01-01 00:00:00",
        });
        let (effect, events) = completed_effect("tracker.inspect", inspection, value.clone());
        let Leaf::Ready {
            value: Some(result),
            work: Some(work),
            ..
        } = run(inspect_source, &[effect], &events).expect("replay")
        else {
            panic!("settled result")
        };
        assert_eq!(work.state, WorkState::Succeeded);
        assert_eq!(result.value, value);
    }

    #[test]
    fn replay_refuses_a_changed_resource_ceiling_or_unreadable_result() {
        let source = "inspect initiative group as operation";
        let mut input = drafted(source);
        let value = json!({
            "initiative":{"queue":"company","id":"WS-2","title":"group","status":"open"},
            "members":[],"state_counts":{},"at":"2030-01-01 00:00:00"
        });
        let (mut effect, mut events) = completed_effect("tracker.inspect", input.clone(), value);
        input["resources"] = json!(["company"]);
        effect.input_json = input.to_string();
        assert!(run(source, &[effect.clone()], &events).is_err());
        effect.input_json = drafted(source).to_string();
        events[1].payload_json = "{broken".into();
        assert!(run(source, &[effect], &events).is_err());
    }
}
