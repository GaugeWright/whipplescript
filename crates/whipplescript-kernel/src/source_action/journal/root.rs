//! The admitted root of a typed progression. Stored alongside local call
//! captures, never reconstructed from current facts on a later pass.

use super::{validate_argument, validate_frame, Frame, Journal, JournalError};
use crate::rule_lowering::RuleContext;
use crate::source_action::arguments::{Argument, Bindings, Slot, Validity, ValueSource};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use whipplescript_parser::action_plan::{ActionPlan, BindingId, BindingSource};

const SCHEMA: &str = "whipplescript-action-root/v3";
const PREVIOUS_SCHEMA: &str = "whipplescript-action-root/v2";
const LEGACY_SCHEMA: &str = "whipplescript-action-root/v1";
const FIELD: &str = "action_root";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootInput {
    pub binding: u64,
    pub argument: Argument,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCapture {
    pub inputs: Vec<RootInput>,
    pub frontier: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    schema: String,
    pub frame: Frame,
    pub root: RootCapture,
}

fn validate(root: &RootCapture, frontier: i64) -> Result<(), JournalError> {
    if root.frontier < 0 || root.frontier > frontier {
        return Err(JournalError(
            "action root has an impossible evaluated frontier".into(),
        ));
    }
    if root
        .inputs
        .windows(2)
        .any(|pair| pair[0].binding >= pair[1].binding)
    {
        return Err(JournalError(
            "action root input slots must be unique and ordered".into(),
        ));
    }
    for input in &root.inputs {
        validate_argument(&input.argument, root.frontier)?;
    }
    Ok(())
}

impl Journal {
    pub fn root(&self, frame: &Frame) -> Option<&RootCapture> {
        self.roots.get(frame)
    }

    pub fn check_root(
        &self,
        frame: &Frame,
        root: Option<&RootCapture>,
        frontier: i64,
    ) -> Result<(), JournalError> {
        if let Some(root) = root {
            validate(root, frontier)?;
            self.check_root_replay(frame, root)?;
            if self.root(frame).is_none() && root.frontier != frontier {
                return Err(JournalError(
                    "new action root was not evaluated at the committing frontier".into(),
                ));
            }
        }
        Ok(())
    }

    pub(super) fn check_root_replay(
        &self,
        frame: &Frame,
        root: &RootCapture,
    ) -> Result<(), JournalError> {
        if self.root(frame).is_some_and(|previous| previous != root) {
            return Err(JournalError(
                "action root was captured differently on replay".into(),
            ));
        }
        Ok(())
    }
}

pub(super) fn read(payload: &Value, frontier: i64) -> Result<Option<Envelope>, JournalError> {
    let Some(raw) = payload
        .get("context")
        .and_then(|context| context.get(FIELD))
    else {
        return Ok(None);
    };
    let envelope: Envelope = serde_json::from_value(raw.clone())
        .map_err(|_| JournalError("malformed action root envelope".into()))?;
    if !matches!(
        envelope.schema.as_str(),
        SCHEMA | PREVIOUS_SCHEMA | LEGACY_SCHEMA
    ) {
        return Err(JournalError("unsupported action root schema".into()));
    }
    for input in raw["root"]["inputs"].as_array().into_iter().flatten() {
        super::validate_argument_schema(
            &input["argument"],
            envelope.schema != LEGACY_SCHEMA,
            envelope.schema == SCHEMA,
        )?;
    }
    validate_frame(&envelope.frame, &payload["context"])?;
    if payload.get("rule").and_then(Value::as_str) != Some(envelope.frame.rule.as_str()) {
        return Err(JournalError(
            "action root rule differs from its commit".into(),
        ));
    }
    validate(&envelope.root, frontier)?;
    Ok(Some(envelope))
}

/// No root delta means byte-identical legacy context serialization.
pub fn context_with_root(
    context_json: &str,
    frame: &Frame,
    root: Option<&RootCapture>,
    frontier: i64,
) -> Result<String, JournalError> {
    let Some(root) = root else {
        return Ok(context_json.to_owned());
    };
    validate(root, frontier)?;
    let mut context: Value = serde_json::from_str(context_json).map_err(|_| {
        JournalError("invalid pinned context JSON while recording action root".into())
    })?;
    validate_frame(frame, &context)?;
    let object = context
        .as_object_mut()
        .expect("validated context is an object");
    if object.contains_key(FIELD) {
        return Err(JournalError(
            "action root cannot overwrite an existing commit delta".into(),
        ));
    }
    object.insert(
        FIELD.into(),
        serde_json::json!(Envelope {
            schema: SCHEMA.into(),
            frame: frame.clone(),
            root: root.clone()
        }),
    );
    Ok(context.to_string())
}

pub fn identity(root: &RootCapture) -> String {
    crate::idempotency_key(&[SCHEMA, &serde_json::json!(root).to_string()])
}

/// A saved root wins before consulting today's admission inputs. Capturing
/// the entire root also preserves values first read by later continuations.
pub fn prepare(
    plan: &ActionPlan,
    inputs: &Bindings,
    saved: Option<&RootCapture>,
    frontier: i64,
) -> Result<(Bindings, Option<RootCapture>), JournalError> {
    let expected: BTreeSet<_> = plan
        .root_inputs
        .iter()
        .map(|binding| binding.0 as u64)
        .collect();
    let root = if let Some(saved) = saved {
        saved.clone()
    } else {
        if inputs.values().any(|slot| !matches!(slot, Slot::Ready(_))) {
            return Err(JournalError(
                "action root inputs must be admitted values".into(),
            ));
        }
        RootCapture {
            inputs: inputs
                .iter()
                .map(|(binding, slot)| {
                    let Slot::Ready(argument) = slot else {
                        unreachable!("ready inputs checked")
                    };
                    RootInput {
                        binding: binding.0 as u64,
                        argument: argument.clone(),
                    }
                })
                .collect(),
            frontier,
        }
    };
    validate(&root, frontier)?;
    if root
        .inputs
        .iter()
        .map(|input| input.binding)
        .collect::<BTreeSet<_>>()
        != expected
    {
        return Err(JournalError(
            "action root input slots differ from its source plan".into(),
        ));
    }
    let bindings = root
        .inputs
        .iter()
        .map(|input| {
            (
                BindingId(input.binding as usize),
                Slot::Ready(input.argument.clone()),
            )
        })
        .collect();
    Ok((bindings, saved.is_none().then_some(root)))
}

/// Convert the actual admitted fact context, not a restored legacy context
/// with missing admission references or manufactured facts for operation values.
pub fn admitted_rule_inputs(
    plan: &ActionPlan,
    context: &RuleContext,
    frontier: i64,
) -> Result<Bindings, JournalError> {
    if plan.root_rule.is_none() {
        return Err(JournalError(
            "admitted fact inputs require a calling rule plan".into(),
        ));
    }
    let mut facts = BTreeMap::new();
    for (name, fact) in &context.bindings {
        let duplicate = facts.insert(name.as_str(), fact).is_some();
        if duplicate {
            return Err(JournalError(
                "admitted root has duplicate fact bindings".into(),
            ));
        }
    }
    let mut inputs = Bindings::new();
    for id in &plan.root_inputs {
        let binding = &plan.bindings[id.0];
        let name = binding
            .name
            .as_deref()
            .filter(|_| matches!(binding.source, BindingSource::RuleInput { .. }))
            .ok_or_else(|| JournalError("action root slot is not a named rule input".into()))?;
        let fact = facts.remove(name).ok_or_else(|| {
            JournalError(format!("admitted root is missing fact binding `{name}`"))
        })?;
        let argument = Argument {
            subjects: BTreeMap::from([(
                String::new(),
                crate::source_action::arguments::FactSubject {
                    fact_id: fact.fact_id.clone(),
                    admission_event: fact.source_event_id.clone(),
                },
            )]),
            value: serde_json::from_str(&fact.value_json).map_err(|_| {
                JournalError(format!(
                    "admitted root fact `{name}` has invalid value JSON"
                ))
            })?,
            sources: BTreeSet::from([ValueSource::Fact {
                fact_id: fact.fact_id.clone(),
                admission_event: fact.source_event_id.clone(),
            }]),
            validity: fact
                .validity_json
                .as_deref()
                .map(serde_json::from_str::<Validity>)
                .transpose()
                .map_err(|_| {
                    JournalError(format!(
                        "admitted root fact `{name}` has invalid validity JSON"
                    ))
                })?
                .unwrap_or_default(),
        };
        validate_argument(&argument, frontier)?;
        inputs.insert(*id, Slot::Ready(argument));
    }
    if !facts.is_empty() {
        return Err(JournalError(
            "admitted root has fact bindings absent from its source plan".into(),
        ));
    }
    Ok(inputs)
}

#[cfg(test)]
mod tests;
