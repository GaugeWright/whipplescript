//! Immutable region cuts in the existing rule commit journal. A cut records
//! an evaluation frontier, not an effect status or permission to run a node.

use super::{root::RootCapture, validate_frame, Frame, Journal, JournalError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

const SCHEMA: &str = "whipplescript-action-regions/v1";
const FIELD: &str = "action_regions";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Holding,
    Exited,
    Lapsed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cut {
    /// Structural region node in this frame's source plan.
    pub region: u64,
    pub frontier: i64,
    pub phase: Phase,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct History {
    cuts: BTreeMap<i64, Cut>,
}

impl History {
    pub(super) fn retain_through(&mut self, frontier: i64) {
        self.cuts.retain(|evaluated, _| *evaluated <= frontier);
    }

    pub fn latest(&self) -> Option<&Cut> {
        self.cuts.last_key_value().map(|(_, cut)| cut)
    }

    pub fn cuts(&self) -> impl Iterator<Item = &Cut> {
        self.cuts.values()
    }

    /// A lapse at entry has no held prefix. Exit includes the final held
    /// evaluation; lapse itself must not introduce another held evaluation.
    pub fn held_frontier(&self) -> Option<i64> {
        self.cuts.values().rev().find_map(|cut| {
            matches!(cut.phase, Phase::Holding | Phase::Exited).then_some(cut.frontier)
        })
    }

    fn check(&self, next: &Cut) -> Result<(), JournalError> {
        if self.cuts.get(&next.frontier) == Some(next) {
            return Ok(());
        }
        let issue = self.latest().and_then(|previous| {
            if next.frontier <= previous.frontier {
                Some("region cut rewrites or precedes its recorded history")
            } else if previous.phase != Phase::Holding {
                Some("region cannot advance after clean exit or lapse")
            } else {
                None
            }
        });
        require(issue.is_none(), issue.unwrap_or("invalid region history"))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    schema: String,
    pub frame: Frame,
    pub cuts: Vec<Cut>,
}

fn require(condition: bool, message: &str) -> Result<(), JournalError> {
    if !condition {
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err(JournalError(message.into()));
    }
    Ok(())
}

fn validate(cuts: &[Cut], frontier: i64) -> Result<(), JournalError> {
    let mut regions = std::collections::BTreeSet::new();
    for cut in cuts {
        require(
            cut.frontier >= 0 && cut.frontier <= frontier,
            "region cut has an impossible evaluated frontier",
        )?;
        require(
            regions.insert(cut.region),
            "region occurs twice in one cut delta",
        )?;
    }
    Ok(())
}

impl Journal {
    pub fn regions(&self, frame: &Frame) -> Option<&BTreeMap<u64, History>> {
        self.regions.get(frame)
    }

    pub fn region(&self, frame: &Frame, region: u64) -> Option<&History> {
        self.regions(frame).and_then(|regions| regions.get(&region))
    }

    pub fn check_regions(
        &self,
        frame: &Frame,
        cuts: &[Cut],
        root: Option<&RootCapture>,
        frontier: i64,
    ) -> Result<(), JournalError> {
        self.check_root(frame, root, frontier)?;
        self.check_region_replay(frame, cuts, root, frontier)?;
        for cut in cuts {
            let recorded = self
                .region(frame, cut.region)
                .is_some_and(|history| history.cuts.get(&cut.frontier) == Some(cut));
            require(
                recorded || cut.frontier == frontier,
                "new region cut was not evaluated at the committing frontier",
            )?;
        }
        Ok(())
    }

    /// Validate and apply a prospective cut to an isolated journal view. The
    /// phase driver can project the newly selected arm at the same evaluated
    /// frontier before one atomic commit; the durable journal is unchanged.
    pub fn preview_regions(
        &self,
        frame: &Frame,
        cuts: &[Cut],
        root: Option<&RootCapture>,
        frontier: i64,
    ) -> Result<Self, JournalError> {
        self.check_regions(frame, cuts, root, frontier)?;
        let mut preview = self.clone();
        preview.publish_regions(Envelope {
            schema: SCHEMA.into(),
            frame: frame.clone(),
            cuts: cuts.to_vec(),
        });
        Ok(preview)
    }

    pub(super) fn check_region_replay(
        &self,
        frame: &Frame,
        cuts: &[Cut],
        root: Option<&RootCapture>,
        frontier: i64,
    ) -> Result<(), JournalError> {
        if cuts.is_empty() {
            return Ok(());
        }
        validate(cuts, frontier)?;
        if let Some(root) = root {
            self.check_root_replay(frame, root)?;
        }
        let root = root.or_else(|| self.root(frame));
        require(
            root.is_some(),
            "region cuts require their admitted action root",
        )?;
        for cut in cuts {
            require(
                root.is_none_or(|root| cut.frontier >= root.frontier),
                "region cut precedes its admitted action root",
            )?;
            if let Some(history) = self.region(frame, cut.region) {
                history.check(cut)?;
            }
        }
        Ok(())
    }

    pub(super) fn publish_regions(&mut self, envelope: Envelope) {
        if envelope.cuts.is_empty() {
            return;
        }
        let regions = self.regions.entry(envelope.frame).or_default();
        for cut in envelope.cuts {
            regions
                .entry(cut.region)
                .or_default()
                .cuts
                .insert(cut.frontier, cut);
        }
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
        .map_err(|_| JournalError("malformed action region envelope".into()))?;
    require(
        envelope.schema == SCHEMA,
        "unsupported action region schema",
    )?;
    validate_frame(&envelope.frame, &payload["context"])?;
    require(
        payload.get("rule").and_then(Value::as_str) == Some(envelope.frame.rule.as_str()),
        "region cut rule differs from its commit",
    )?;
    validate(&envelope.cuts, frontier)?;
    Ok(Some(envelope))
}

/// No cuts preserve the original legacy context bytes exactly.
pub fn context_with_regions(
    context_json: &str,
    frame: &Frame,
    cuts: &[Cut],
    frontier: i64,
) -> Result<String, JournalError> {
    if cuts.is_empty() {
        return Ok(context_json.to_owned());
    }
    validate(cuts, frontier)?;
    let mut context: Value = serde_json::from_str(context_json)
        .map_err(|_| JournalError("invalid pinned context JSON while recording regions".into()))?;
    validate_frame(frame, &context)?;
    let object = context.as_object_mut().expect("validated pinned context");
    require(
        !object.contains_key(FIELD),
        "region cut cannot overwrite an existing commit delta",
    )?;
    let mut cuts = cuts.to_vec();
    cuts.sort_by_key(|cut| cut.region);
    object.insert(
        FIELD.into(),
        serde_json::json!(Envelope {
            schema: SCHEMA.into(),
            frame: frame.clone(),
            cuts,
        }),
    );
    Ok(context.to_string())
}

pub fn identity(cuts: &[Cut]) -> String {
    let mut cuts = cuts.to_vec();
    cuts.sort_by_key(|cut| cut.region);
    crate::idempotency_key(&[SCHEMA, &serde_json::json!(cuts).to_string()])
}

#[cfg(test)]
mod tests;
