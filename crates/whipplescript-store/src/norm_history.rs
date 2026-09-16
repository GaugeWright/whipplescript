//! Historical norm reads anchored in a verified complete current history.
//! A projected old authority is query data, never a replacement restoration pin.
use crate::items::TrackerEvent;
use crate::norm::{replay_norm, NormCheckpoint, NormVerifier, NormView};
use crate::{StoreError, StoreResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormReadAnchor {
    pub checkpoint: NormCheckpoint,
    pub frontier: BTreeSet<String>,
}
#[derive(Clone, Copy, Debug)]
pub struct NormHistoryLimits {
    pub max_events: usize,
}
impl Default for NormHistoryLimits {
    fn default() -> Self {
        Self {
            max_events: 100_000,
        }
    }
}

/// No deserializer: the host must verify the whole stored history before it can
/// project a subset. Public query bodies cannot supply this trusted container.
pub struct CapturedNormHistory {
    current: NormView,
    events: BTreeMap<String, TrackerEvent>,
    limits: NormHistoryLimits,
}
impl CapturedNormHistory {
    /// `current` comes from the host's current verified store read. The second
    /// read must contain exactly that event set, or the caller retries capture.
    /// Reverification also catches altered transport bytes behind a known id.
    pub fn capture(
        current: &NormView,
        events: &[TrackerEvent],
        verifier: &dyn NormVerifier,
        limits: NormHistoryLimits,
    ) -> StoreResult<Self> {
        let count = events
            .iter()
            .filter(|event| event.kind.starts_with("norm."))
            .count();
        if limits.max_events == 0 || count > limits.max_events {
            return Err(StoreError::Conflict(
                "norm history exceeds its event budget".into(),
            ));
        }
        let verified = replay_norm(events, &current.checkpoint(), verifier)?;
        let expected: BTreeSet<_> = current.event_order().iter().collect();
        let observed: BTreeSet<_> = verified.event_order().iter().collect();
        if expected != observed
            || current.checkpoint() != verified.checkpoint()
            || current.frontier != verified.frontier
        {
            return Err(StoreError::Conflict(
                "norm history changed during query capture".into(),
            ));
        }
        let events = events
            .iter()
            .filter(|event| event.kind.starts_with("norm."))
            .map(|event| (event.event_id.clone(), event.clone()))
            .collect();
        Ok(Self {
            current: verified,
            events,
            limits,
        })
    }
    /// Check an unsigned creation against the captured schema/policy. This is
    /// not authentication, admission, or a reservation of current authority.
    pub fn preview_creation(&self, statement: &crate::norm::NormStatement) -> StoreResult<()> {
        self.current.preview_creation(statement)
    }

    /// Reuse exact ledger admission before retaining an outbox candidate. The
    /// final append still rechecks its own current state inside its transaction.
    pub fn preflight(
        &self,
        event: &crate::norm::SignedNormEvent,
        verifier: &dyn NormVerifier,
    ) -> StoreResult<()> {
        crate::norm::admit_norm(
            &self.events.values().cloned().collect::<Vec<_>>(),
            Some(&self.current.checkpoint()),
            &event.tracker_event()?,
            verifier,
        )
        .map(|_| ())
    }

    /// Immutable admitted transport, including causal parents. Consumers must
    /// independently interpret payloads; authentication alone is not exercise.
    pub fn events(&self) -> impl Iterator<Item = &TrackerEvent> {
        self.events.values()
    }

    pub fn anchor(&self) -> NormReadAnchor {
        NormReadAnchor {
            checkpoint: self.current.checkpoint(),
            frontier: self.current.frontier.clone(),
        }
    }
    /// None selects the captured current frontier. An explicit frontier must be
    /// a nonempty unique antichain of events in the verified captured history.
    pub fn project(
        &self,
        frontier: Option<&[String]>,
        verifier: &dyn NormVerifier,
    ) -> StoreResult<NormView> {
        let Some(frontier) = frontier else {
            return Ok(self.current.clone());
        };
        let requested: BTreeSet<_> = frontier.iter().cloned().collect();
        if frontier.is_empty()
            || frontier.len() > self.limits.max_events
            || requested.len() != frontier.len()
        {
            return Err(StoreError::Conflict(
                "norm query frontier must be nonempty, unique, and within its event budget".into(),
            ));
        }
        let mut selected = BTreeSet::new();
        let mut pending = frontier.to_vec();
        while let Some(id) = pending.pop() {
            if !selected.insert(id.clone()) {
                continue;
            }
            let Some(event) = self.events.get(&id) else {
                // MUTATION-SUCCESS-EXPR: Ok(self.current.clone())
                return Err(StoreError::Conflict("unknown norm frontier".into()));
            };
            pending.extend(event.parents.iter().cloned());
        }
        let events: Vec<_> = selected.iter().map(|id| self.events[id].clone()).collect();
        // This genesis checkpoint is safe only inside the already verified
        // current-history container. It never reaches a store's trust pin.
        let view = replay_norm(
            &events,
            &NormCheckpoint::genesis(self.current.ledger.clone()),
            verifier,
        )?;
        if view.frontier != requested {
            return Err(StoreError::Conflict(
                "norm query frontier includes a redundant ancestor".into(),
            ));
        }
        Ok(view)
    }
}
