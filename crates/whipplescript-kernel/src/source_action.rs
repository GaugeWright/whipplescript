//! DR-0100 source-language action boundary, distinct from authenticated host
//! actions. A pure projection over ONE captured progression prefix; this is
//! neither a scheduler nor another status ledger. The expanded graph driver
//! must supply actual owned work and prove continuation closure. It must not
//! infer closure from an empty list of pending effects.
//!
//! This evaluator is the first semantic component. Source lowering and native/
//! hosted progression integration are tracked separately in
//! `spec/reactive-composition-tracker.md`; declaring this module does not enable
//! the new action syntax or change existing program execution.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

pub mod arguments;
pub mod cancellation;
pub mod coerce;
pub mod counter;
pub mod exec;
pub mod explanation;
pub mod facts;
pub mod file;
pub mod inline_coerce;
pub mod journal;
pub mod ledger;
pub mod milestone;
pub mod notify;
pub mod plan_artifact;
pub mod progression;
pub mod records;
pub mod regions;
pub mod rule;
pub mod tell;
pub mod terminal;
pub mod timer;
pub mod tracker;
pub mod transforms;

/// A durable leaf operation/attempt identity, already scoped by program version,
/// revision, rule firing and expanded call path by the owning execution ledger.
/// It is never the author's short binding name or a display label.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CauseId(pub String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureKind {
    Failed,
    TimedOut,
    Cancelled,
    Domain,
}

/// Preserved evidence from the originating terminal, including typed domain or
/// provider payload. References remain references; this projection does not
/// dereference them, redact them, or authorize a reader to see their contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cause {
    pub kind: FailureKind,
    pub payload: Value,
    pub evidence: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// No successful recovery exists. Observation/logging has this disposition.
    Propagate,
    /// A selected recovery continuation still owes its result or owned work.
    Recovering,
    /// Checked recovery has completed. The original cause remains in history.
    Recovered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkState {
    Pending,
    /// Asking to cancel does not acknowledge termination of external work.
    CancellationRequested,
    /// External outcome remains unresolved, even if a local deadline passed.
    Uncertain,
    Succeeded,
    Failed(Disposition),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedWork {
    pub state: WorkState,
    /// Child scopes retain both known causes while draining and recovered
    /// causes after success. Copies through dependents keep the leaf identity.
    pub causes: BTreeMap<CauseId, ObservedCause>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChosenResult<T> {
    Pending,
    Return(T),
    /// An explicit domain failure of this action; never a workflow terminal.
    Fail {
        origin: CauseId,
        cause: Cause,
    },
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum WaitReason {
    Continuations,
    Operation(String),
    CancellationAcknowledgement(String),
    UncertainOutcome(String),
    Recovery(String),
    Return,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Boundary<T> {
    Waiting(BTreeSet<WaitReason>),
    Succeeded(T),
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedCause {
    pub cause: Cause,
    /// False if ANY contributing selected path has not recovered this cause.
    pub recovered: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Projection<T> {
    pub boundary: Boundary<T>,
    /// Includes recovered causes and known causes while siblings drain.
    pub causes: BTreeMap<CauseId, ObservedCause>,
}

impl<T> Projection<T> {
    /// Feed a nested action's boundary into its parent without losing causes.
    /// The caller separately binds the child's successful value when present.
    pub fn into_owned_work(self) -> OwnedWork {
        OwnedWork {
            state: match self.boundary {
                Boundary::Waiting(_) => WorkState::Pending,
                Boundary::Succeeded(_) => WorkState::Succeeded,
                Boundary::Failed => WorkState::Failed(Disposition::Propagate),
            },
            causes: self.causes,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    /// Two views of one original event cannot disagree about its payload.
    ConflictingCause(CauseId),
    /// A failure cannot become successful merely by losing its origin evidence.
    MissingCause(String),
    UnrecoveredSuccess(String),
    NonDomainFailure(CauseId),
}

/// Evaluate an action's boundary without performing any work. `owned` includes
/// every operation actually started on selected paths, including child scopes;
/// unselected nodes are absent. `continuations_closed` must come from the graph
/// at this same captured prefix. This function does not prove those premises.
pub fn project<T: Clone>(
    chosen: &ChosenResult<T>,
    continuations_closed: bool,
    owned: &BTreeMap<String, OwnedWork>,
) -> Result<Projection<T>, ProjectionError> {
    let mut waits = BTreeSet::new();
    let mut causes = BTreeMap::new();
    if !continuations_closed {
        waits.insert(WaitReason::Continuations);
    }
    for (operation, work) in owned {
        match work.state {
            WorkState::Pending => {
                waits.insert(WaitReason::Operation(operation.clone()));
            }
            WorkState::CancellationRequested => {
                waits.insert(WaitReason::CancellationAcknowledgement(operation.clone()));
            }
            WorkState::Uncertain => {
                waits.insert(WaitReason::UncertainOutcome(operation.clone()));
            }
            WorkState::Succeeded => {
                if work.causes.values().any(|cause| !cause.recovered) {
                    return Err(ProjectionError::UnrecoveredSuccess(operation.clone()));
                }
            }
            WorkState::Failed(disposition) => {
                if work.causes.values().all(|cause| cause.recovered) {
                    return Err(ProjectionError::MissingCause(operation.clone()));
                }
                if disposition == Disposition::Recovering {
                    waits.insert(WaitReason::Recovery(operation.clone()));
                }
            }
        }
        for (origin, observed) in &work.causes {
            merge_cause(
                &mut causes,
                origin,
                &observed.cause,
                observed.recovered || work.state == WorkState::Failed(Disposition::Recovered),
            )?;
        }
    }
    if let ChosenResult::Fail { origin, cause } = chosen {
        if cause.kind != FailureKind::Domain {
            return Err(ProjectionError::NonDomainFailure(origin.clone()));
        }
        merge_cause(&mut causes, origin, cause, false)?;
    }

    // Known failures remain visible while work drains. A candidate result does
    // not settle the scope and a selected recovery cannot be skipped here.
    let boundary = if !waits.is_empty() {
        Boundary::Waiting(waits)
    } else if causes.values().any(|cause| !cause.recovered) {
        Boundary::Failed
    } else {
        match chosen {
            ChosenResult::Return(value) => Boundary::Succeeded(value.clone()),
            ChosenResult::Pending => Boundary::Waiting(BTreeSet::from([WaitReason::Return])),
            // Explicit failure always inserted an unrecovered cause above.
            ChosenResult::Fail { .. } => Boundary::Failed,
        }
    };
    Ok(Projection { boundary, causes })
}

fn merge_cause(
    causes: &mut BTreeMap<CauseId, ObservedCause>,
    origin: &CauseId,
    cause: &Cause,
    recovered: bool,
) -> Result<(), ProjectionError> {
    if let Some(existing) = causes.get_mut(origin) {
        if existing.cause != *cause {
            return Err(ProjectionError::ConflictingCause(origin.clone()));
        }
        existing.recovered &= recovered;
    } else {
        causes.insert(
            origin.clone(),
            ObservedCause {
                cause: cause.clone(),
                recovered,
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
