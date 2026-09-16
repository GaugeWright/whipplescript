//! Managed ledger append. Admission captures the fully checked entry and its
//! freshness evidence; settlement exposes only the durable ledger address.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};
use whipplescript_parser::body::{BodyEffectKind, BodyStmt, FieldAssign, RecordStmt};
use whipplescript_parser::{IrClass, IrLedger, IrProgram, IrSchema, IrType};
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
    ledger: &'a IrLedger,
    class: &'a IrClass,
    schema: &'a str,
    fields: &'a [FieldAssign],
}

fn contract<'a>(
    ir: &'a IrProgram,
    effect: &'a whipplescript_parser::body::EffectStmt,
) -> Result<Contract<'a>, String> {
    let BodyEffectKind::LedgerAppend {
        ledger,
        schema,
        fields,
    } = &effect.kind
    else {
        return Err("ledger projector requires an append statement".into());
    };
    let ledger = ir
        .ledgers
        .iter()
        .find(|candidate| candidate.name == *ledger)
        .ok_or("managed append has no declared ledger")?;
    if ledger.entry_schema != *schema {
        return Err("managed append entry schema differs from its ledger declaration".into());
    }
    let class = ir
        .schemas
        .iter()
        .find_map(|candidate| match candidate {
            IrSchema::Class(class) if class.name == *schema => Some(class),
            _ => None,
        })
        .ok_or("managed append has no declared entry class")?;
    let mut names: BTreeSet<&str> = BTreeSet::new();
    for field in fields {
        if !names.insert(field.name.as_str()) {
            return Err("managed append has duplicate entry fields".into());
        }
    }
    Ok(Contract {
        ledger,
        class,
        schema,
        fields,
    })
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Effect(effect) = statement.body else {
        return Err("ledger projector requires an effect statement".into());
    };
    let contract = contract(context.ir, effect)?;
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        return Err("managed append requires its pinned root rule".into());
    }
    let owner = if contract.ledger.shared { "shared" } else { "" };
    let shape =
        lowering::ingest_shape_json(context.ir, &IrType::Ref(contract.schema.to_owned()), 0);
    if let Some(existing) = context
        .effects
        .iter()
        .find(|existing| existing.effect_id == statement.identity)
    {
        if existing.kind != "ledger.append"
            || existing.created_by_rule != context.frame.rule
            || existing.program_version_id.as_deref() != Some(context.frame.version.as_str())
            || existing.target.as_deref() != Some(contract.ledger.name.as_str())
        {
            return Err("recorded append differs from its source operation".into());
        }
        let input: Value = serde_json::from_str(&existing.input_json)
            .map_err(|_| "unreadable recorded append input")?;
        let raw = input
            .get("entry_argument")
            .ok_or("recorded append has no entry argument")?;
        if !raw["subjects"].is_object() || !raw["sources"].is_array() || !raw["validity"].is_array()
        {
            return Err("recorded append has an incomplete freshness argument `entry`".into());
        }
        let entry: Argument = serde_json::from_value(raw.clone())
            .map_err(|_| "recorded append has no valid entry argument")?;
        super::journal::validate_argument(&entry, context.frontier).map_err(|issue| issue.0)?;
        let partition = partition(contract.ledger, &entry.value)?;
        if input["ledger"] != contract.ledger.name
            || input["coordination_owner"] != owner
            || input["schema"] != contract.schema
            || input["fields"]
                != serde_json::to_value(contract.fields)
                    .expect("ledger field contract serialization is infallible")
            || input["entry"] != entry.value
            || input["entry_shape"] != shape
            || input["partition_field"] != contract.ledger.partition_field
            || input["partition"] != partition
            || input["retain_seconds"] != contract.ledger.retain_seconds
            || input["rule"] != context.frame.rule
        {
            return Err("recorded append input differs from its source contract".into());
        }
        return observe(
            context.ir,
            contract.ledger,
            &partition,
            existing,
            context.events,
        );
    }

    let record = RecordStmt {
        schema: contract.schema.to_owned(),
        from: None,
        fields: contract.fields.to_vec(),
        span: effect.span,
    };
    let mut entry = super::records::payload(&record, contract.class, &statement);
    if matches!(entry.state, State::Absent) {
        entry.state = State::Invalid(Box::new(
            "managed ledger entry cannot be absent".to_owned().into(),
        ));
    }
    let State::Ready(entry_value) = &entry.state else {
        return Ok(Leaf::Waiting(entry));
    };
    let mut errors = Vec::new();
    super::records::validate_construction(context.ir, entry_value, contract.class, &mut errors);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let partition = partition(contract.ledger, entry_value)?;
    let entry_argument = Argument {
        value: entry_value.clone(),
        sources: entry.sources,
        subjects: entry.subjects,
        validity: entry.validity,
    };
    let timeout_seconds = effect
        .timeout_seconds
        .map(i64::try_from)
        .transpose()
        .map_err(|_| "managed append timeout exceeds the store range")?;
    let fields = serde_json::to_string(contract.fields)
        .expect("ledger field contract serialization is infallible");
    let parsed = ParsedEffect {
        kind: "ledger.append".into(),
        target: Some(contract.ledger.name.clone()),
        name: None,
        binding: effect.binding.clone(),
        args: vec![contract.schema.into(), fields],
        prompt: None,
        prompt_content_type: None,
        prompt_template: None,
        required_capabilities: effect.requires.clone(),
        after: None,
        timeout_seconds,
    };
    let input = json!({
        "ledger": contract.ledger.name,
        "coordination_owner": owner,
        "schema": contract.schema,
        "fields": contract.fields,
        "entry": entry_value,
        "entry_shape": shape,
        "partition_field": contract.ledger.partition_field,
        "partition": partition,
        "retain_seconds": contract.ledger.retain_seconds,
        "rule": context.frame.rule,
        "entry_argument": entry_argument,
    });
    Ok(leaf(
        OwnedLowering {
            effects: vec![OwnedEffect {
                effect_id: statement.identity.clone(),
                kind: "ledger.append".into(),
                target: Some(contract.ledger.name.clone()),
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

fn partition(ledger: &IrLedger, entry: &Value) -> Result<String, String> {
    let value = entry
        .get(&ledger.partition_field)
        .ok_or("managed ledger entry has no declared partition field")?;
    Ok(lowering::coordination_key_string(value))
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
    ledger: &IrLedger,
    partition: &str,
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
        _ => return Err("recorded append has an unknown operation status".into()),
    }
    let mut terminals = Vec::new();
    for event in events.iter().filter(|event| {
        matches!(
            event.event_type.as_str(),
            "effect.terminal" | "effect.cancelled"
        )
    }) {
        let payload: Value = serde_json::from_str(&event.payload_json)
            .map_err(|_| "unreadable ledger terminal evidence")?;
        if payload["effect_id"] == effect.effect_id {
            terminals.push((event, payload));
        }
    }
    let [(terminal, terminal_payload)] = terminals.as_slice() else {
        return Err("settled append requires exactly one terminal".into());
    };
    let status = if terminal.event_type == "effect.cancelled" {
        Some("cancelled")
    } else {
        terminal_payload["status"].as_str()
    };
    if status != Some(effect.status.as_str()) {
        return Err("ledger terminal evidence differs from its recorded status".into());
    }
    let uncertain = terminal_payload["run_status"] == "uncertain";
    let mut evidence = BTreeSet::from([terminal.event_id.clone()]);
    let mut cause_payload = terminal_payload.clone();
    if !uncertain && matches!(effect.status.as_str(), "completed" | "failed") {
        let run = terminal_payload["run_id"]
            .as_str()
            .filter(|run| !run.is_empty())
            .ok_or("ledger terminal has no run identity")?;
        let expected = if effect.status == "completed" {
            "ledger.append.completed"
        } else {
            "ledger.append.failed"
        };
        let mut results = Vec::new();
        for event in events
            .iter()
            .filter(|event| event.event_type == "fact.derived")
        {
            let envelope: Value = serde_json::from_str(&event.payload_json)
                .map_err(|_| "unreadable ledger result evidence")?;
            let name = envelope["name"].as_str().unwrap_or_default();
            let value = &envelope["value"];
            if matches!(name, "ledger.append.completed" | "ledger.append.failed")
                && envelope["key"] == effect.effect_id
                && value["effect_id"] == effect.effect_id
                && value["run_id"] == run
            {
                results.push((event, name.to_owned(), value.clone()));
            }
        }
        let [(result_event, result_name, result)] = results.as_slice() else {
            return Err("ledger terminal requires exactly one result for its run".into());
        };
        if result_name != expected
            || result_event.sequence <= terminal.sequence
            || result["status"] != effect.status
            || result.get("value").is_none()
        {
            return Err("ledger result differs from its terminal".into());
        }
        evidence.insert(result_event.event_id.clone());
        if effect.status == "completed" {
            let value = &result["value"];
            let output =
                whipplescript_parser::ledger_append_output_type(whipplescript_parser::SourceSpan {
                    start: 0,
                    end: 0,
                });
            let mut errors = Vec::new();
            lowering::validate_json_for_ir_type(ir, value, &output, "$", &mut errors);
            if !errors.is_empty()
                || value["ledger"] != ledger.name
                || value["partition"] != partition
            {
                return Err(format!(
                    "ledger result violates its source contract{}",
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
