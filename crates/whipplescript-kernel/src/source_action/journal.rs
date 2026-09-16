//! Admitted roots and local calls in the existing rule commit journal. This fold owns
//! no effect status and does not evaluate expressions or admit external work.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use whipplescript_store::EventView;

mod prefix;
pub mod regions;
pub mod root;

const SCHEMA: &str = "whipplescript-action-captures/v3";
const PREVIOUS_SCHEMA: &str = "whipplescript-action-captures/v2";
const LEGACY_SCHEMA: &str = "whipplescript-action-captures/v1";
const FIELD: &str = "action_captures";

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frame {
    pub version: String,
    pub revision: String,
    pub rule: String,
    #[serde(deserialize_with = "required_nullable")]
    pub identity: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub trigger_event: Option<String>,
}

fn required_nullable<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Option::deserialize(d)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallCapture {
    /// Structural call node in this version's expanded rule, not a source span.
    pub call: u64,
    pub arguments: Vec<super::arguments::Argument>,
    pub reads: BTreeSet<u64>,
    pub frontier: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: String,
    frame: Frame,
    calls: Vec<CallCapture>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalError(pub String);

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for JournalError {}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Journal {
    frames: BTreeMap<Frame, BTreeMap<u64, CallCapture>>,
    roots: BTreeMap<Frame, root::RootCapture>,
    regions: BTreeMap<Frame, BTreeMap<u64, regions::History>>,
}

impl Journal {
    /// Every firing with a durably admitted managed root, in stable frame
    /// order. Read-only projections use these exact recorded identities rather
    /// than reconstructing frames from current instance state.
    pub fn admitted_frames(&self) -> impl Iterator<Item = &Frame> {
        self.roots.keys()
    }

    pub fn calls(&self, frame: &Frame) -> Option<&BTreeMap<u64, CallCapture>> {
        self.frames.get(frame)
    }

    pub fn check(
        &self,
        frame: &Frame,
        calls: &[CallCapture],
        frontier: i64,
    ) -> Result<(), JournalError> {
        let calls = validate_delta(calls, frontier)?;
        for (call, captured) in &calls {
            if self
                .calls(frame)
                .and_then(|known| known.get(call))
                .is_none()
                && captured.frontier != frontier
            {
                return Err(JournalError(format!(
                    "new action call {call} was not evaluated at the committing frontier"
                )));
            }
        }
        self.check_replay(frame, &calls)
    }

    fn check_replay(
        &self,
        frame: &Frame,
        calls: &BTreeMap<u64, CallCapture>,
    ) -> Result<(), JournalError> {
        if let Some(previous) = self.frames.get(frame) {
            for (call, captured) in calls {
                if previous.get(call).is_some_and(|old| old != captured) {
                    return Err(JournalError(format!(
                        "action call {call} was captured differently on replay"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The caller supplies the same retained events used by its progression
    /// fold after restore. Validate a whole delta before publishing any of it.
    pub fn apply(&mut self, event: &EventView) -> Result<(), JournalError> {
        if event.event_type != "rule.committed" {
            return Ok(());
        }
        let payload: Value = serde_json::from_str(&event.payload_json).map_err(|_| {
            JournalError("invalid rule commit JSON while reading action captures".into())
        })?;
        let root = root::read(&payload, event.sequence.saturating_sub(1))?;
        if let Some(root) = &root {
            self.check_root_replay(&root.frame, &root.root)?;
        }
        let calls = if let Some(raw) = payload
            .get("context")
            .and_then(|context| context.get(FIELD))
        {
            let envelope: Envelope = serde_json::from_value(raw.clone())
                .map_err(|_| JournalError("malformed action capture envelope".into()))?;
            if !matches!(
                envelope.schema.as_str(),
                SCHEMA | PREVIOUS_SCHEMA | LEGACY_SCHEMA
            ) {
                return Err(JournalError(format!(
                    "unsupported action capture schema `{}`",
                    envelope.schema
                )));
            }
            for call in raw["calls"].as_array().into_iter().flatten() {
                for argument in call["arguments"].as_array().into_iter().flatten() {
                    validate_argument_schema(
                        argument,
                        envelope.schema != LEGACY_SCHEMA,
                        envelope.schema == SCHEMA,
                    )?;
                }
            }
            validate_frame(&envelope.frame, &payload["context"])?;
            if payload.get("rule").and_then(Value::as_str) != Some(envelope.frame.rule.as_str()) {
                return Err(JournalError(
                    "action capture rule differs from its commit".into(),
                ));
            }
            let frames_differ = root
                .as_ref()
                .is_some_and(|root| root.frame != envelope.frame);
            if frames_differ {
                return Err(JournalError(
                    "action root and call capture frames differ".into(),
                ));
            }
            let calls = validate_delta(&envelope.calls, event.sequence.saturating_sub(1))?;
            self.check_replay(&envelope.frame, &calls)?;
            Some((envelope.frame, calls))
        } else {
            None
        };
        let regions = regions::read(&payload, event.sequence.saturating_sub(1))?;
        if let Some(regions) = &regions {
            let frame_matches = root.as_ref().is_none_or(|root| root.frame == regions.frame)
                && calls
                    .as_ref()
                    .is_none_or(|(frame, _)| frame == &regions.frame);
            if !frame_matches {
                return Err(JournalError(
                    "action region, root and call frames differ".into(),
                ));
            }
            self.check_region_replay(
                &regions.frame,
                &regions.cuts,
                root.as_ref().map(|root| &root.root),
                event.sequence.saturating_sub(1),
            )?;
        }
        // Publish nothing until every part of the commit has passed validation.
        if let Some(root) = root {
            self.roots.insert(root.frame, root.root);
        }
        if let Some((frame, calls)) = calls {
            self.frames.entry(frame).or_default().extend(calls);
        }
        if let Some(regions) = regions {
            self.publish_regions(regions);
        }
        Ok(())
    }
}

fn validate_frame(frame: &Frame, context: &Value) -> Result<(), JournalError> {
    if frame.version.is_empty() || frame.revision.is_empty() || frame.rule.is_empty() {
        return Err(JournalError(
            "action capture needs a version, revision and rule".into(),
        ));
    }
    // Require the actual nullable fields. Missing, a number, or an empty
    // object must not collapse to the same key as a legitimate absent identity.
    if context.get("identity") != Some(&serde_json::json!(frame.identity))
        || context.get("trigger_event_id") != Some(&serde_json::json!(frame.trigger_event))
    {
        return Err(JournalError(
            "action capture firing differs from its pinned context".into(),
        ));
    }
    if crate::rule_lowering::context_from_record(context).is_none() {
        return Err(JournalError(
            "action capture has no valid pinned trigger context".into(),
        ));
    }
    Ok(())
}

fn validate_argument_schema(
    raw: &Value,
    has_subjects: bool,
    has_validity: bool,
) -> Result<(), JournalError> {
    if raw.get("subjects").is_some_and(Value::is_object) != has_subjects {
        return Err(JournalError(
            "action argument subject map differs from its capture schema".into(),
        ));
    }
    if raw.get("validity").is_some_and(Value::is_array) != has_validity {
        return Err(JournalError(
            "action argument validity set differs from its capture schema".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_argument(
    argument: &super::arguments::Argument,
    frontier: i64,
) -> Result<(), JournalError> {
    if argument.sources.iter().any(|source| match source {
        super::arguments::ValueSource::Fact {
            fact_id,
            admission_event,
        } => fact_id.is_empty() || admission_event.is_empty(),
        super::arguments::ValueSource::Operation { operation_id } => operation_id.is_empty(),
    }) {
        return Err(JournalError(
            "action argument has an incomplete source identity".into(),
        ));
    }
    for observation in &argument.validity {
        if observation.frontier < 0
            || observation.frontier > frontier
            || observation.head.trim().is_empty()
        {
            return Err(JournalError(
                "action argument has an impossible query observation".into(),
            ));
        }
        if observation
            .guard_json
            .as_ref()
            .is_some_and(|guard| serde_json::from_str::<whipplescript_parser::Expr>(guard).is_err())
        {
            return Err(JournalError(
                "action argument has an invalid query predicate identity".into(),
            ));
        }
        let invalid_member = observation.members.iter().any(|member| {
            use super::arguments::{ObservationKind, ObservationMember};
            match (observation.kind, member) {
                (
                    ObservationKind::Fact,
                    ObservationMember::Fact {
                        fact_id,
                        admission_event,
                    },
                ) => fact_id.is_empty() || admission_event.is_empty(),
                (ObservationKind::Effect, ObservationMember::Effect { effect_id }) => {
                    effect_id.is_empty()
                }
                _ => true,
            }
        });
        if invalid_member {
            return Err(JournalError(
                "action argument query membership differs from its observation kind".into(),
            ));
        }
    }
    super::arguments::subjects::validate(argument).map_err(JournalError)
}

fn validate_delta(
    calls: &[CallCapture],
    frontier: i64,
) -> Result<BTreeMap<u64, CallCapture>, JournalError> {
    let mut result = BTreeMap::new();
    for capture in calls {
        for argument in &capture.arguments {
            validate_argument(argument, capture.frontier)?;
        }
        if capture.frontier < 0 || capture.frontier > frontier {
            return Err(JournalError(format!(
                "action call {} has an impossible evaluated frontier",
                capture.call
            )));
        }
        if result.insert(capture.call, capture.clone()).is_some() {
            return Err(JournalError(format!(
                "action call {} occurs twice in one capture delta",
                capture.call
            )));
        }
    }
    Ok(result)
}

/// Extend only the commit's context JSON. The trigger context itself is kept
/// unchanged, and an ordinary legacy commit retains its exact previous bytes.
pub fn context_with_captures(
    context_json: &str,
    frame: &Frame,
    calls: &[CallCapture],
    frontier: i64,
) -> Result<String, JournalError> {
    if calls.is_empty() {
        return Ok(context_json.to_owned());
    }
    let calls = validate_delta(calls, frontier)?.into_values().collect();
    let mut context: Value = serde_json::from_str(context_json).map_err(|_| {
        JournalError("invalid pinned context JSON while recording action captures".into())
    })?;
    if !context.is_object() {
        return Err(JournalError(
            "action capture requires an object pinned context".into(),
        ));
    }
    validate_frame(frame, &context)?;
    let object = context.as_object_mut().expect("context object checked");
    if object.contains_key(FIELD) {
        return Err(JournalError(
            "action capture cannot overwrite an existing commit delta".into(),
        ));
    }
    object.insert(
        FIELD.into(),
        serde_json::json!(Envelope {
            schema: SCHEMA.into(),
            frame: frame.clone(),
            calls,
        }),
    );
    Ok(context.to_string())
}

/// The enclosing commit key separately contains the frame. This contribution
/// distinguishes capture-only lowerings, values, and evaluation frontiers.
pub fn capture_identity(calls: &[CallCapture]) -> String {
    let mut calls = calls.to_vec();
    calls.sort_by_key(|capture| capture.call);
    crate::idempotency_key(&[SCHEMA, &serde_json::json!(calls).to_string()])
}

#[cfg(test)]
mod tests;

#[cfg(all(test, feature = "native"))]
mod native_tests;
