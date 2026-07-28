//! The instance-level sans-IO scheduler (DR-0033 chunk 4).
//!
//! This is the top-level machine the whole lift exists to enable: a workflow
//! instance driven as a resumable [`StepMachine`]. Its control flow is the native
//! `dev`-loop fixpoint, re-expressed so that when a ready effect needs the network
//! it suspends with [`Outcome::NeedsIo`] and the host re-enters `step` with the
//! response — the native host runs it straight through, the durable-object host
//! awaits `fetch` across isolate wakes.
//!
//! The fixpoint (proven in `models/tla/InstanceSchedulerLifecycle.tla`):
//!
//! ```text
//! loop:
//!   advance the rule pass to quiescence
//!     -> terminal?  Settle(Terminal)        (absorbing: no more rules/effects)
//!   next ready effect?
//!     -> none:      Settle(Parked)          (genuine fixpoint: nothing to do)
//!     -> some e:    run e
//!         -> Done:      loop                (store-only effect settled synchronously)
//!         -> NeedsHttp: NeedsIo(Http), remember e; resume it on the next step
//! ```
//!
//! The two host-varying pieces — the rule pass and effect execution — sit behind
//! [`InstanceDriver`]: the native binding wires `advance_rules` to
//! `rule_pass::step_instance_generic` and `run_effect` to the effect handlers; the
//! DO binding wires the same seams over its `DoSqliteStore` + `fetch`. Keeping the
//! scheduler control flow behind that seam is what makes the invariants above
//! unit-testable in the kernel (below) independent of any store or transport.

use whipplescript_store::{ClaimableEffect, StoreError, StoredEvent};

use crate::sansio::{
    HttpRequest, HttpResponse, IoRequest, IoResult, Outcome, StepMachine, TransportError,
};

/// The result of running one ready effect.
#[derive(Debug)]
pub enum EffectStep {
    /// The effect settled synchronously to its terminal (a store-only effect, or
    /// the final round of an HTTP effect).
    Done(StoredEvent),
    /// The effect needs one HTTP round; the host performs it and re-runs the
    /// effect with the response (at-least-once + idempotency key — DR-0033
    /// Decision 3; see `ResumableEffectLifecycle`).
    NeedsHttp(HttpRequest),
    /// The same durable effect remains running while awaiting externally
    /// admitted input (currently a human answer). It is not terminalized or
    /// released; a later host command mutates its durable snapshot and re-drives.
    Parked,
}

/// The host-varying work the instance scheduler drives: the rule pass and effect
/// execution over one held store handle. The native binding implements it with
/// `rule_pass::step_instance_generic` + the effect handlers; the DO binding
/// implements it over `DoSqliteStore` + `fetch`.
pub trait InstanceDriver {
    /// Advance the rule pass to quiescence (commit every ready rule). Returns
    /// `Ok(true)` once the instance has reached a workflow terminal.
    fn advance_rules(&mut self) -> Result<bool, StoreError>;

    /// The next ready (claimable) effect, or `None` at a genuine fixpoint.
    fn next_ready_effect(&mut self) -> Result<Option<ClaimableEffect>, StoreError>;

    /// Run one ready effect. `incoming` is `None` on the first attempt and
    /// `Some(..)` when resuming after the host performed the HTTP round it asked
    /// for.
    fn run_effect(
        &mut self,
        effect: &ClaimableEffect,
        incoming: Option<Result<HttpResponse, TransportError>>,
    ) -> Result<EffectStep, StoreError>;

    /// Run the due-time pass at `now` (ISO-8601 UTC): complete due timers,
    /// expire deadline-passed effects (DR-0033 Phase 6). `now` is injected —
    /// the driver never reads wall time itself. Default: hosts without time
    /// semantics do nothing.
    fn advance_time(&mut self, _now: &str) -> Result<(), StoreError> {
        Ok(())
    }

    /// The earliest future wake-up (unix milliseconds) the instance needs
    /// strictly after `now`, or `None` when nothing is scheduled — pending
    /// timed effects plus the next clock-source occurrence. The DO shell sets
    /// its single alarm from this when the instance parks. Default: no wake-up.
    fn next_due_unix_ms(&mut self, _now: &str) -> Result<Option<i64>, StoreError> {
        Ok(None)
    }
}

/// What a whole instance settles to when the scheduler yields control.
#[derive(Debug)]
pub enum InstanceOutcome {
    /// A workflow terminal was reached — absorbing; the instance is done.
    Terminal,
    /// Quiescent but not terminal: no ready rule, no ready effect, nothing
    /// mid-fetch. The instance parks awaiting external input / an alarm.
    Parked,
    /// A store error aborted the pass (surfaced, not swallowed).
    Failed(StoreError),
}

/// A workflow instance as a resumable sans-IO step machine.
pub struct InstanceStepMachine<D: InstanceDriver> {
    driver: D,
    /// The effect currently suspended on an HTTP round, awaiting its response.
    /// Persisting it in `self` is what lets the DO host be evicted between the
    /// `NeedsIo` and the resuming `step` without losing the in-flight effect.
    in_flight: Option<ClaimableEffect>,
}

impl<D: InstanceDriver> InstanceStepMachine<D> {
    pub fn new(driver: D) -> Self {
        Self {
            driver,
            in_flight: None,
        }
    }

    /// Recover the driver (and thus the store handle it holds) after the machine
    /// settles.
    pub fn into_driver(self) -> D {
        self.driver
    }
}

impl<D: InstanceDriver> StepMachine for InstanceStepMachine<D> {
    type Output = InstanceOutcome;

    fn step(&mut self, incoming: Option<IoResult>) -> Outcome<InstanceOutcome> {
        // Resume an effect suspended on an HTTP round with the host's response.
        if let Some(effect) = self.in_flight.take() {
            let response = incoming.map(|IoResult::Http(result)| result);
            match self.driver.run_effect(&effect, response) {
                Ok(EffectStep::Done(_)) => {} // fall through into the fixpoint
                Ok(EffectStep::NeedsHttp(request)) => {
                    self.in_flight = Some(effect);
                    return Outcome::NeedsIo(IoRequest::Http(request));
                }
                Ok(EffectStep::Parked) => return Outcome::Settle(InstanceOutcome::Parked),
                Err(error) => return Outcome::Settle(InstanceOutcome::Failed(error)),
            }
        }

        // The fixpoint: rule pass -> ready effect -> dispatch -> repeat, until a
        // terminal (absorbing) or a genuine quiescent park.
        loop {
            match self.driver.advance_rules() {
                Ok(true) => return Outcome::Settle(InstanceOutcome::Terminal),
                Ok(false) => {}
                Err(error) => return Outcome::Settle(InstanceOutcome::Failed(error)),
            }
            let ready = match self.driver.next_ready_effect() {
                Ok(Some(effect)) => effect,
                Ok(None) => return Outcome::Settle(InstanceOutcome::Parked),
                Err(error) => return Outcome::Settle(InstanceOutcome::Failed(error)),
            };
            match self.driver.run_effect(&ready, None) {
                Ok(EffectStep::Done(_)) => continue,
                Ok(EffectStep::NeedsHttp(request)) => {
                    self.in_flight = Some(ready);
                    return Outcome::NeedsIo(IoRequest::Http(request));
                }
                Ok(EffectStep::Parked) => return Outcome::Settle(InstanceOutcome::Parked),
                Err(error) => return Outcome::Settle(InstanceOutcome::Failed(error)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sansio::{run_to_completion, HostDriver};
    use serde_json::json;

    fn effect(id: &str, kind: &str) -> ClaimableEffect {
        ClaimableEffect {
            effect_id: id.to_owned(),
            kind: kind.to_owned(),
            target: None,
            profile: None,
            input_json: "{}".to_owned(),
            required_capabilities_json: "[]".to_owned(),
            declared_profiles_json: "[]".to_owned(),
        }
    }

    fn stored_event(id: &str) -> StoredEvent {
        StoredEvent {
            event_id: id.to_owned(),
            sequence: 1,
        }
    }

    /// A scripted driver: each rule pass exposes the next queued effect; once every
    /// effect has settled the instance reaches its terminal (unless `parks`, which
    /// models an instance that goes quiescent without terminating). Effects named
    /// `http` need one HTTP round; all others settle synchronously.
    struct ScriptedDriver {
        ready: Vec<ClaimableEffect>,
        settled: Vec<String>,
        http_rounds: u32,
        parks: bool,
    }

    impl InstanceDriver for ScriptedDriver {
        fn advance_rules(&mut self) -> Result<bool, StoreError> {
            // Terminal once all ready work is drained (unless this instance parks).
            Ok(self.ready.is_empty() && !self.parks)
        }

        fn next_ready_effect(&mut self) -> Result<Option<ClaimableEffect>, StoreError> {
            Ok(self.ready.first().cloned())
        }

        fn run_effect(
            &mut self,
            effect: &ClaimableEffect,
            incoming: Option<Result<HttpResponse, TransportError>>,
        ) -> Result<EffectStep, StoreError> {
            if effect.kind == "http" && incoming.is_none() {
                self.http_rounds += 1;
                return Ok(EffectStep::NeedsHttp(HttpRequest {
                    url: "https://provider/settle".to_owned(),
                    headers: vec![],
                    body: json!({}),
                }));
            }
            // First (or resumed) settle: consume the effect.
            let e = self.ready.remove(0);
            self.settled.push(e.effect_id.clone());
            Ok(EffectStep::Done(stored_event(&e.effect_id)))
        }
    }

    /// A host that answers every HTTP round with a 200.
    struct OkHost;
    impl HostDriver for OkHost {
        fn fulfill(&self, request: &IoRequest) -> IoResult {
            let IoRequest::Http(http) = request;
            IoResult::Http(Ok(HttpResponse {
                status: 200,
                body: json!({ "url": http.url }),
            }))
        }
    }

    #[test]
    fn drives_store_only_effects_to_a_terminal() {
        // Two store-only effects settle synchronously across rule passes, then the
        // instance reaches its terminal (absorbing).
        let mut machine = InstanceStepMachine::new(ScriptedDriver {
            ready: vec![effect("e1", "coordination"), effect("e2", "queue")],
            settled: vec![],
            http_rounds: 0,
            parks: false,
        });
        let outcome = run_to_completion(&mut machine, &OkHost);
        assert!(matches!(outcome, InstanceOutcome::Terminal), "{outcome:?}");
        let driver = machine.into_driver();
        assert_eq!(driver.settled, vec!["e1".to_owned(), "e2".to_owned()]);
        assert_eq!(driver.http_rounds, 0, "store-only effects raise no HTTP");
    }

    #[test]
    fn suspends_on_a_http_effect_and_resumes_to_terminal() {
        // An HTTP effect suspends with NeedsIo(Http); the host answers and the
        // machine resumes the same effect, settles it, and reaches the terminal.
        let mut machine = InstanceStepMachine::new(ScriptedDriver {
            ready: vec![effect("h1", "http")],
            settled: vec![],
            http_rounds: 0,
            parks: false,
        });
        let outcome = run_to_completion(&mut machine, &OkHost);
        assert!(matches!(outcome, InstanceOutcome::Terminal), "{outcome:?}");
        let driver = machine.into_driver();
        assert_eq!(
            driver.http_rounds, 1,
            "the HTTP effect took exactly one round"
        );
        assert_eq!(driver.settled, vec!["h1".to_owned()]);
    }

    #[test]
    fn parks_at_a_non_terminal_fixpoint() {
        // No ready effect and not terminal -> the scheduler parks (sound quiescence,
        // per the model's QuiesceSound invariant).
        let mut machine = InstanceStepMachine::new(ScriptedDriver {
            ready: vec![],
            settled: vec![],
            http_rounds: 0,
            parks: true,
        });
        let outcome = run_to_completion(&mut machine, &OkHost);
        assert!(matches!(outcome, InstanceOutcome::Parked), "{outcome:?}");
    }
}
