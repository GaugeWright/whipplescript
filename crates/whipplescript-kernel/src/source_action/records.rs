//! Managed authored records through the existing fact/commit door. This is a
//! pure draft at one retained frontier, not a second assertion or status ledger.
use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Map, Value};
use whipplescript_parser::body::{BodyStmt, RecordStmt};
use whipplescript_parser::{Expr, IrClass, IrProgram, IrSchema};
use whipplescript_store::{projection_prefix::ProjectionFact, EventView};

use super::arguments::{strict, Evaluation, State};
use super::journal::Frame;
use super::progression::{Leaf, Statement};
use crate::lowering::{OwnedFact, OwnedLowering};
use crate::rule_lowering::{
    record_fact_key, source_span_json, validate_json_for_ir_type, validate_json_for_object,
    EvalValue,
};

/// All projections come from the driver's same instance-scoped retained prefix,
/// after restore. Commit the resulting lowering with its evaluated-frontier guard.
pub struct Context<'a> {
    pub ir: &'a IrProgram,
    pub instance: &'a str,
    pub frame: &'a Frame,
    pub events: &'a [EventView],
    pub active: &'a [ProjectionFact],
    pub source_path: Option<&'a Path>,
}

/// The single bounded projection used by managed construction and sink analysis.
/// Copied optional fields may be absent at runtime; explicit expressions may not.
pub(crate) struct Projection {
    pub copied: Vec<String>,
    pub fields: Vec<(String, Expr)>,
}

pub(crate) fn projection(
    record: &RecordStmt,
    class: &IrClass,
    is_binding: &impl Fn(&str) -> bool,
) -> Result<Projection, String> {
    let written: BTreeSet<_> = record
        .fields
        .iter()
        .map(|field| field.name.as_str())
        .collect();
    let copied = class
        .fields
        .iter()
        .filter(|field| record.from.is_some() && !written.contains(field.name.as_str()))
        .map(|field| field.name.clone())
        .collect();
    let fields = record
        .fields
        .iter()
        .map(|field| {
            field
                .record_expression(record.from.as_deref(), is_binding)
                .map(|expr| (field.name.clone(), expr))
        })
        .collect::<Result<_, _>>()?;
    Ok(Projection { copied, fields })
}

pub(super) fn payload(
    record: &RecordStmt,
    class: &IrClass,
    statement: &Statement<'_>,
) -> Evaluation {
    let projection = match projection(record, class, &|name| {
        statement.environment.contains_key(name)
    }) {
        Ok(projection) => projection,
        Err(message) => return Evaluation::invalid(&message),
    };
    let mut inputs = Vec::new();
    let copy = record
        .from
        .as_ref()
        .filter(|_| !projection.copied.is_empty());
    if let Some(from) = copy {
        let base = statement.evaluate(&Expr::Path(vec![from.clone()]));
        inputs.push(strict(vec![base], |values| {
            let Some(object) = values[0].as_object() else {
                return EvalValue::error("record projection source must be a present class object");
            };
            EvalValue::Json(Value::Object(
                projection
                    .copied
                    .iter()
                    .filter_map(|name| object.get(name).map(|value| (name.clone(), value.clone())))
                    .collect(),
            ))
        }));
    }
    for (_, expr) in &projection.fields {
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
        object.extend(
            projection
                .fields
                .into_iter()
                .map(|(name, _)| name)
                .zip(values),
        );
        EvalValue::Json(Value::Object(object))
    })
}

/// Authored construction checks even inactive fields that it supplies. Forwarded
/// nominal values retain the ordinary shared nominal contract.
pub(super) fn validate_construction(
    ir: &IrProgram,
    payload: &Value,
    class: &IrClass,
    errors: &mut Vec<String>,
) {
    validate_json_for_object(ir, payload, &class.fields, &class.name, errors);
    // The shared nominal class gate intentionally ignores inactive webhook
    // siblings. A field produced by this record must still meet its contract.
    // Do not impose this stronger rule recursively on forwarded nominal values.
    for field in &class.fields {
        if let Some((disc, lit)) = &field.presence_condition {
            if payload.get(disc).and_then(Value::as_str) != Some(lit.as_str()) {
                if let Some(value) = payload.get(&field.name) {
                    validate_json_for_ir_type(
                        ir,
                        value,
                        &field.ty,
                        &format!("{}.{}", class.name, field.name),
                        errors,
                    );
                }
            }
        }
    }
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let (record, consumed) = match statement.body {
        BodyStmt::Record(record) => (record, None),
        BodyStmt::Done {
            binding,
            replacement: Some(record),
            ..
        } => (record, Some(binding)),
        _ => return Err("record projector requires a record or replacement statement".into()),
    };
    if statement.root_rule != Some(context.frame.rule.as_str()) {
        return Err("record admission requires its actual calling rule root".into());
    }
    let class = context
        .ir
        .schemas
        .iter()
        .find_map(|schema| match schema {
            IrSchema::Class(class) if class.name == record.schema => Some(class),
            _ => None,
        })
        .ok_or("record admission requires a declared class")?;
    let mut fields = BTreeSet::<&str>::new();
    for field in &record.fields {
        if !fields.insert(field.name.as_str()) {
            return Err(format!("record field `{}` is duplicated", field.name));
        }
    }
    let mut value = payload(record, class, &statement);
    let mut lowering = OwnedLowering::default();
    if let Some(binding) = consumed {
        let (subject, consumption) =
            super::facts::consume(&statement, binding, context.frame, context.active)?;
        value = strict(vec![value, subject], |mut values| {
            EvalValue::Json(values.remove(0))
        });
        lowering = consumption;
    }
    let State::Ready(payload) = &value.state else {
        return Ok(Leaf::Waiting(value));
    };
    let mut errors = Vec::new();
    validate_construction(context.ir, payload, class, &mut errors);
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let value_json = payload.to_string();
    let key = record_fact_key(&record.schema, &value_json);
    let fact_id = crate::idempotency_key(&[
        context.instance,
        &context.frame.rule,
        &record.schema,
        &key,
        &value_json,
    ]);
    if !crate::rule_pass::recorded_facts_for_firing(context.events, context.frame)
        .contains(&fact_id)
    {
        lowering.facts.push(OwnedFact {
            fact_id,
            name: record.schema.clone(),
            key,
            value_json,
            schema_id: Some(record.schema.clone()),
            provenance_class: "rule".into(),
            correlation_id: context.frame.identity.clone(),
            source_span_json: Some(source_span_json(context.source_path, record.span, "record")),
            validity_json: Some(
                serde_json::to_string(&value.validity)
                    .expect("managed validity serialization is infallible"),
            ),
        });
    }
    Ok(Leaf::Ready {
        lowering: Box::new(lowering),
        value: None,
        work: None,
    })
}

#[cfg(test)]
mod tests;
