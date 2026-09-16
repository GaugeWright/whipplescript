//! Bare `done` over exact, pinned fact subjects. No live-input rebinding or
//! independent consumption ledger.
use whipplescript_parser::body::BodyStmt;
use whipplescript_store::projection_prefix::ProjectionFact;

use super::arguments::{read_binding, Evaluation, Slot, State};
use super::journal::Frame;
use super::progression::{Leaf, Statement};
use crate::lowering::OwnedLowering;

/// `active` is the real instance-scoped fact projection from the driver's retained frontier.
/// The combined lowering must commit with that frontier's atomic guard.
pub fn project(
    statement: Statement<'_>,
    frame: &Frame,
    active: &[ProjectionFact],
) -> Result<Leaf, String> {
    let BodyStmt::Done {
        binding,
        replacement,
        ..
    } = statement.body
    else {
        // MUTATION-SUCCESS-EXPR: Ok(Leaf::Ready { lowering: Box::default(), value: None, work: None })
        return Err("fact consumption projector requires a done statement".into());
    };
    if replacement.is_some() {
        // MUTATION-SUCCESS-EXPR: Ok(Leaf::Ready { lowering: Box::default(), value: None, work: None })
        return Err("replacement record requires the atomic record projector".into());
    }
    let (value, lowering) = consume(&statement, binding, frame, active)?;
    if !matches!(value.state, State::Ready(_)) {
        return Ok(Leaf::Waiting(value));
    }
    Ok(Leaf::Ready {
        lowering: Box::new(lowering),
        value: None,
        work: None,
    })
}

/// The same exact-subject proof is used by bare done and atomic replacement.
/// This only drafts consumption; the caller must wait for its other inputs.
pub(super) fn consume(
    statement: &Statement<'_>,
    binding: &str,
    frame: &Frame,
    active: &[ProjectionFact],
) -> Result<(Evaluation, OwnedLowering), String> {
    if statement.root_rule != Some(frame.rule.as_str()) {
        // MUTATION-SUCCESS-EXPR: Ok((Evaluation::invalid("mutation"), OwnedLowering::default()))
        return Err("fact consumption requires its actual calling rule root".into());
    }
    let binding = statement
        .environment
        .get(binding)
        .ok_or("done names an unknown managed binding")?;
    let value = read_binding(*binding, statement.bindings);
    let State::Ready(payload) = &value.state else {
        return Ok((value, OwnedLowering::default()));
    };
    let subject = value
        .subjects
        .get("")
        .ok_or("done requires an exact whole fact subject, not only fact provenance")?;
    let admitted = statement.admitted.values().any(|slot| match slot {
        Slot::Ready(root) => root.subjects.get("") == Some(subject) && root.value == *payload,
        _ => false,
    });
    if !admitted
        || !frame.trigger_event.as_ref().is_some_and(|events| {
            events
                .split('|')
                .any(|event| event == subject.admission_event)
        })
    {
        // MUTATION-SUCCESS-EXPR: Ok((value, OwnedLowering::default()))
        return Err("done subject is not this firing's captured admitted fact".into());
    }
    let matches: Vec<_> = active
        .iter()
        .filter(|fact| fact.fact_id == subject.fact_id)
        .collect();
    if matches.len() > 1 {
        // MUTATION-SUCCESS-EXPR: Ok((value, OwnedLowering::default()))
        return Err("done sees conflicting active projections for one fact".into());
    }
    let mut lowering = OwnedLowering::default();
    if let Some(fact) = matches.first() {
        if fact.provenance_class == "effect" {
            // MUTATION-SUCCESS-EXPR: Ok((value, OwnedLowering::default()))
            return Err("done cannot consume an effect placeholder fact".into());
        }
        if fact.source_event_id.is_empty() {
            // MUTATION-SUCCESS-EXPR: Ok((value, OwnedLowering::default()))
            return Err("done active fact has no admitting event".into());
        }
        if fact.source_event_id == subject.admission_event {
            let current: serde_json::Value = serde_json::from_str(&fact.value_json)
                .map_err(|_| "done fact projection has invalid JSON")?;
            if current != *payload {
                // MUTATION-SUCCESS-EXPR: Ok((value, OwnedLowering::default()))
                return Err("done fact payload changed under its captured admission".into());
            }
            lowering.consumed_fact_ids.push(subject.fact_id.clone());
        }
        // A different admitting event belongs to a different firing. A replay
        // cannot consume the revived fact merely because its content key agrees.
    }
    Ok((value, lowering))
}

#[cfg(test)]
mod tests;
