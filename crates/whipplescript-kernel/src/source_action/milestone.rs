//! Managed child milestones through the ordinary fact commit. A milestone is a
//! synchronous projection, not owned work and not an effect.
use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{json, Map, Value};
use whipplescript_parser::body::{BodyStmt, RecordStmt};
use whipplescript_parser::{IrProgram, IrSchema};
use whipplescript_store::EventView;

use super::arguments::{strict, State};
use super::journal::Frame;
use super::progression::{Leaf, Statement};
use crate::lowering::{OwnedFact, OwnedLowering};
use crate::rule_lowering::{source_span_json, EvalValue};

pub struct Context<'a> {
    pub ir: &'a IrProgram,
    pub instance: &'a str,
    pub frame: &'a Frame,
    pub events: &'a [EventView],
    pub source_path: Option<&'a Path>,
}

pub fn project(statement: Statement<'_>, context: Context<'_>) -> Result<Leaf, String> {
    let BodyStmt::Milestone {
        name,
        payload_class,
        fields,
        span,
    } = statement.body
    else {
        return Err("milestone projector requires a milestone statement".into());
    };
    if statement.root_rule != Some(context.frame.rule.as_str())
        || !context
            .ir
            .rules
            .iter()
            .any(|rule| rule.name == context.frame.rule)
    {
        return Err("managed milestone requires its pinned calling rule".into());
    }

    let payload = if let Some(class_name) = payload_class {
        let class = context
            .ir
            .schemas
            .iter()
            .find_map(|schema| match schema {
                IrSchema::Class(class) if &class.name == class_name => Some(class),
                _ => None,
            })
            .ok_or("managed milestone requires a declared payload class")?;
        let mut names = BTreeSet::new();
        if fields.iter().any(|field| !names.insert(&field.name)) {
            // MUTATION-SUCCESS-EXPR: Ok(Leaf::Ready { lowering: Box::new(OwnedLowering::default()), value: None, work: None })
            return Err("managed milestone duplicates a payload field".into());
        }
        let value = super::records::payload(
            &RecordStmt {
                schema: class_name.clone(),
                from: None,
                fields: fields.clone(),
                span: *span,
            },
            class,
            &statement,
        );
        if let State::Ready(value) = &value.state {
            let mut errors = Vec::new();
            super::records::validate_construction(context.ir, value, class, &mut errors);
            if !errors.is_empty() {
                return Err(format!(
                    "managed milestone violates payload contract: {}",
                    errors.join("; ")
                ));
            }
        }
        value
    } else {
        if !fields.is_empty() {
            return Err("payload-less milestone cannot contain fields".into());
        }
        strict(Vec::new(), |_| EvalValue::Json(Value::Object(Map::new())))
    };
    let State::Ready(value) = &payload.state else {
        return Ok(Leaf::Waiting(payload));
    };

    let fact_name = format!("workflow.milestone:{name}");
    let firing_identity = context.frame.identity.as_deref().unwrap_or("started");
    let key = crate::idempotency_key(&[
        context.instance,
        &context.frame.rule,
        &fact_name,
        firing_identity,
    ]);
    let fact_id =
        crate::idempotency_key(&[context.instance, &context.frame.rule, &fact_name, &key]);
    let mut lowering = OwnedLowering::default();
    if !crate::rule_pass::recorded_facts_for_firing(context.events, context.frame)
        .contains(&fact_id)
    {
        let value_json = json!({
            "milestone": name,
            "status": "completed",
            "value": value,
        })
        .to_string();
        lowering.facts.push(OwnedFact {
            fact_id,
            name: fact_name,
            key,
            value_json,
            schema_id: None,
            provenance_class: "rule".into(),
            correlation_id: context.frame.identity.clone(),
            source_span_json: Some(source_span_json(context.source_path, *span, "milestone")),
            validity_json: Some(
                serde_json::to_string(&payload.validity)
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
