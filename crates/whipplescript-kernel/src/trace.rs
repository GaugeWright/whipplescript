//! Trace-conformance checks for abstract runtime lifecycle events.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DependencyPredicate {
    Succeeds,
    Fails,
    Completes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EffectStatus {
    Queued,
    Blocked,
    Claimed,
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

impl EffectStatus {
    fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::TimedOut | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DependencyEdge {
    pub upstream_effect_id: String,
    pub predicate: DependencyPredicate,
    pub downstream_effect_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TraceEvent {
    EffectCreated {
        effect_id: String,
        status: EffectStatus,
    },
    DependencyCreated(DependencyEdge),
    EffectClaimed {
        effect_id: String,
    },
    RunStarted {
        run_id: String,
        effect_id: String,
    },
    LeaseExpired {
        run_id: String,
        effect_id: String,
    },
    EffectTerminal {
        run_id: String,
        effect_id: String,
        status: EffectStatus,
    },
    ProviderDiagnostic {
        run_id: String,
        effect_id: String,
        provider: String,
        status: EffectStatus,
        summary: String,
        diagnostics_json: String,
    },
    EffectBlocked {
        effect_id: String,
        status: Option<String>,
        reason: String,
    },
    /// An operator (`whip retry`) re-queued a terminally-failed effect. Mirrors the
    /// lifecycle models' `retry-failed`/`retry-timeout` rules (kernel.maude) and the
    /// store's `retry_effect` (`status IN ('failed','timed_out') -> 'queued'`).
    EffectRetried {
        effect_id: String,
    },
    EffectCancelled {
        effect_id: String,
    },
    RevisionActivated {
        revision_id: String,
        from_version_id: String,
        to_version_id: String,
        from_epoch: i64,
        to_epoch: i64,
        cancellation_policy: String,
        terminal_cancel_effects: Vec<String>,
        request_cancel_effects: Vec<String>,
    },
    EffectCancellationRequested {
        effect_id: String,
        revision_id: Option<String>,
        reason: Option<String>,
        requested_by: String,
    },
    InstancePaused,
    InstanceResumed,
    InstanceCancelled,
    InstanceFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceRecord {
    pub sequence: u64,
    pub event: TraceEvent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceViolation {
    pub sequence: u64,
    pub message: String,
}

#[derive(Default)]
struct TraceState {
    effects: BTreeMap<String, EffectStatus>,
    run_effects: BTreeMap<String, String>,
    live_runs: BTreeSet<String>,
    stale_runs: BTreeSet<String>,
    terminal_effects: BTreeSet<String>,
    cancel_requested_effects: BTreeSet<String>,
    /// Dependency edges keyed by DOWNSTREAM effect id: every reader wants the
    /// edges of one downstream, and a flat list makes that a scan of the whole
    /// instance's edges on each claim and each block.
    dependencies: BTreeMap<String, Vec<DependencyEdge>>,
    revision_epoch: i64,
    cancelled: bool,
    paused: bool,
}

pub fn check_trace(records: &[TraceRecord]) -> Result<(), TraceViolation> {
    let mut state = TraceState::default();
    for (expected_sequence, record) in (1..).zip(records.iter()) {
        if record.sequence != expected_sequence {
            return Err(TraceViolation {
                sequence: record.sequence,
                message: format!(
                    "event sequence gap: expected {expected_sequence}, got {}",
                    record.sequence
                ),
            });
        }

        check_record(&mut state, record)?;
    }

    Ok(())
}

fn check_record(state: &mut TraceState, record: &TraceRecord) -> Result<(), TraceViolation> {
    match &record.event {
        TraceEvent::EffectCreated { effect_id, status } => {
            if state.effects.contains_key(effect_id) {
                return violation(record, format!("effect {effect_id} was created twice"));
            }
            state.effects.insert(effect_id.clone(), status.clone());
        }
        TraceEvent::DependencyCreated(edge) => {
            if !state.effects.contains_key(&edge.upstream_effect_id) {
                return violation(
                    record,
                    format!(
                        "dependency references unknown upstream {}",
                        edge.upstream_effect_id
                    ),
                );
            }
            if !state.effects.contains_key(&edge.downstream_effect_id) {
                return violation(
                    record,
                    format!(
                        "dependency references unknown downstream {}",
                        edge.downstream_effect_id
                    ),
                );
            }
            state
                .dependencies
                .entry(edge.downstream_effect_id.clone())
                .or_default()
                .push(edge.clone());
        }
        TraceEvent::EffectClaimed { effect_id } => {
            if state.cancelled {
                return violation(record, "effect claimed after instance cancellation");
            }
            if state.paused {
                return violation(record, "effect claimed while instance is paused");
            }
            let Some(status) = state.effects.get(effect_id) else {
                return violation(record, format!("unknown effect {effect_id} claimed"));
            };
            // A claim is legal from `Queued` and also directly from `Blocked`
            // (policy/capacity/dependency block). The store's `start_run` re-checks
            // the block condition and, if it now clears, transitions the effect
            // straight to `running` in one atomic step — there is no separate
            // observable "unblock" event to re-queue first (unlike lease expiry,
            // which does emit one). So the claim absorbs the store's unblock: this
            // is the folded refinement of the lifecycle models' explicit
            // `blocked -> queued -> claimed` (see models/trace-conformance.md,
            // kernel.maude `policy-release`/`capacity-release`, and
            // ControlPlaneLifecycle.tla `UnblockEffect`). The dependency-ordering
            // invariant below is what gives this rule its bite.
            if !matches!(status, EffectStatus::Queued | EffectStatus::Blocked) {
                return violation(
                    record,
                    format!("effect {effect_id} claimed from invalid status {status:?}"),
                );
            }
            if state.cancel_requested_effects.contains(effect_id) {
                return violation(
                    record,
                    format!("effect {effect_id} claimed after cancellation request"),
                );
            }
            if let Some(edge) = first_unsatisfied_dependency(state, effect_id) {
                return violation(
                    record,
                    format!(
                        "effect {effect_id} claimed before dependency on {} was satisfied",
                        edge.upstream_effect_id
                    ),
                );
            }
            state
                .effects
                .insert(effect_id.clone(), EffectStatus::Claimed);
        }
        TraceEvent::RunStarted { run_id, effect_id } => {
            if state.cancelled {
                return violation(record, "run started after instance cancellation");
            }
            if state.run_effects.contains_key(run_id) {
                return violation(record, format!("run {run_id} was started twice"));
            }
            let Some(status) = state.effects.get(effect_id) else {
                return violation(
                    record,
                    format!("run started for unknown effect {effect_id}"),
                );
            };
            if *status != EffectStatus::Claimed {
                return violation(
                    record,
                    format!("run started for effect {effect_id} in status {status:?}"),
                );
            }
            state
                .effects
                .insert(effect_id.clone(), EffectStatus::Running);
            state.run_effects.insert(run_id.clone(), effect_id.clone());
            state.live_runs.insert(run_id.clone());
        }
        TraceEvent::LeaseExpired { run_id, effect_id } => {
            let Some(run_effect_id) = state.run_effects.get(run_id) else {
                return violation(record, format!("lease expired for unknown run {run_id}"));
            };
            if run_effect_id != effect_id {
                return violation(
                    record,
                    format!("lease expired for run {run_id} on wrong effect {effect_id}"),
                );
            }
            if !state.live_runs.remove(run_id) {
                return violation(record, format!("lease expired for non-live run {run_id}"));
            }
            let Some(status) = state.effects.get(effect_id) else {
                return violation(
                    record,
                    format!("lease expired for unknown effect {effect_id}"),
                );
            };
            if *status != EffectStatus::Running {
                return violation(
                    record,
                    format!("lease expired for effect {effect_id} in status {status:?}"),
                );
            }
            state.stale_runs.insert(run_id.clone());
            state
                .effects
                .insert(effect_id.clone(), EffectStatus::Queued);
        }
        TraceEvent::EffectTerminal {
            run_id,
            effect_id,
            status,
        } => {
            if !status.is_terminal() {
                return violation(
                    record,
                    format!("terminal event used non-terminal status {status:?}"),
                );
            }
            if !state.effects.contains_key(effect_id) {
                return violation(
                    record,
                    format!("terminal event for unknown effect {effect_id}"),
                );
            }
            if state.terminal_effects.contains(effect_id) {
                return violation(
                    record,
                    format!("duplicate terminal event for effect {effect_id}"),
                );
            }
            let Some(run_effect_id) = state.run_effects.get(run_id) else {
                return violation(record, format!("terminal event for unknown run {run_id}"));
            };
            if run_effect_id != effect_id {
                return violation(
                    record,
                    format!("terminal event for run {run_id} on wrong effect {effect_id}"),
                );
            }
            if state.stale_runs.contains(run_id) {
                return violation(record, format!("terminal event from stale run {run_id}"));
            }
            if !state.live_runs.remove(run_id) {
                return violation(record, format!("terminal event for non-live run {run_id}"));
            }
            state.terminal_effects.insert(effect_id.clone());
            state.cancel_requested_effects.remove(effect_id);
            state.effects.insert(effect_id.clone(), status.clone());
        }
        TraceEvent::ProviderDiagnostic {
            run_id,
            effect_id,
            status,
            diagnostics_json,
            ..
        } => {
            if !status.is_terminal() {
                return violation(
                    record,
                    format!("provider diagnostic used non-terminal status {status:?}"),
                );
            }
            let Some(run_effect_id) = state.run_effects.get(run_id) else {
                return violation(
                    record,
                    format!("provider diagnostic for unknown run {run_id}"),
                );
            };
            if run_effect_id != effect_id {
                return violation(
                    record,
                    format!("provider diagnostic for run {run_id} on wrong effect {effect_id}"),
                );
            }
            if state.stale_runs.contains(run_id) {
                return violation(
                    record,
                    format!("provider diagnostic from stale run {run_id}"),
                );
            }
            if !state.live_runs.contains(run_id) {
                return violation(
                    record,
                    format!("provider diagnostic for non-live run {run_id}"),
                );
            }
            let Some(effect_status) = state.effects.get(effect_id) else {
                return violation(
                    record,
                    format!("provider diagnostic for unknown effect {effect_id}"),
                );
            };
            if *effect_status != EffectStatus::Running {
                return violation(
                    record,
                    format!(
                        "provider diagnostic for effect {effect_id} in status {effect_status:?}"
                    ),
                );
            }
            if serde_json::from_str::<serde_json::Value>(diagnostics_json).is_err() {
                return violation(record, "provider diagnostic metadata is not valid JSON");
            }
        }
        TraceEvent::EffectBlocked {
            effect_id,
            status: blocked_status,
            ..
        } => {
            let Some(status) = state.effects.get(effect_id) else {
                return violation(record, format!("blocked unknown effect {effect_id}"));
            };
            if status.is_terminal() || *status == EffectStatus::Running {
                return violation(
                    record,
                    format!("effect {effect_id} blocked from invalid status {status:?}"),
                );
            }
            if matches!(blocked_status.as_deref(), Some("blocked_by_dependency"))
                && first_unsatisfied_dependency(state, effect_id).is_none()
            {
                return violation(
                    record,
                    format!(
                        "effect {effect_id} marked blocked_by_dependency without an unsatisfied dependency"
                    ),
                );
            }
            state
                .effects
                .insert(effect_id.clone(), EffectStatus::Blocked);
        }
        TraceEvent::EffectRetried { effect_id } => {
            let Some(status) = state.effects.get(effect_id) else {
                return violation(record, format!("retried unknown effect {effect_id}"));
            };
            // `whip retry` only re-queues a terminally failed/timed-out effect. Any
            // other source status (queued/blocked/claimed/running/completed/cancelled)
            // is illegal — this is the invariant's bite.
            if !matches!(status, EffectStatus::Failed | EffectStatus::TimedOut) {
                return violation(
                    record,
                    format!("effect {effect_id} retried from non-retryable status {status:?}"),
                );
            }
            // Re-queue: clear the terminal mark so a fresh claim/run/terminal is legal.
            state.terminal_effects.remove(effect_id);
            state
                .effects
                .insert(effect_id.clone(), EffectStatus::Queued);
        }
        TraceEvent::EffectCancelled { effect_id } => {
            let Some(status) = state.effects.get(effect_id) else {
                return violation(record, format!("cancelled unknown effect {effect_id}"));
            };
            if status.is_terminal() {
                return violation(
                    record,
                    format!("effect {effect_id} cancelled from terminal status {status:?}"),
                );
            }
            state.terminal_effects.insert(effect_id.clone());
            state.cancel_requested_effects.remove(effect_id);
            state
                .effects
                .insert(effect_id.clone(), EffectStatus::Cancelled);
        }
        TraceEvent::RevisionActivated {
            revision_id,
            from_epoch,
            to_epoch,
            cancellation_policy,
            ..
        } => {
            if revision_id.is_empty() {
                return violation(record, "revision activation has empty revision id");
            }
            if *from_epoch != state.revision_epoch {
                return violation(
                    record,
                    format!(
                        "revision activation from epoch {from_epoch} but trace is at epoch {}",
                        state.revision_epoch
                    ),
                );
            }
            if *to_epoch <= *from_epoch {
                return violation(
                    record,
                    format!("revision activation did not advance epoch {from_epoch}->{to_epoch}"),
                );
            }
            if !matches!(
                cancellation_policy.as_str(),
                "keep" | "cancel_queued" | "request_running"
            ) {
                return violation(
                    record,
                    format!("unknown revision cancellation policy {cancellation_policy}"),
                );
            }
            state.revision_epoch = *to_epoch;
        }
        TraceEvent::EffectCancellationRequested {
            effect_id,
            revision_id,
            requested_by,
            ..
        } => {
            if revision_id.as_deref() == Some("") {
                return violation(record, "cancellation request has empty revision id");
            }
            if requested_by.is_empty() {
                return violation(record, "cancellation request has empty requester");
            }
            let Some(status) = state.effects.get(effect_id) else {
                return violation(
                    record,
                    format!("cancellation requested for unknown effect {effect_id}"),
                );
            };
            if *status != EffectStatus::Running {
                return violation(
                    record,
                    format!("cancellation requested for effect {effect_id} in status {status:?}"),
                );
            }
            if !state.cancel_requested_effects.insert(effect_id.clone()) {
                return violation(
                    record,
                    format!("duplicate cancellation request for effect {effect_id}"),
                );
            }
        }
        TraceEvent::InstancePaused => {
            state.paused = true;
        }
        TraceEvent::InstanceResumed => {
            if state.cancelled {
                return violation(record, "cancelled instance resumed");
            }
            state.paused = false;
        }
        TraceEvent::InstanceCancelled => {
            state.cancelled = true;
            state.paused = true;
        }
        // A generic internal failure is a terminal; replay records it like any
        // other terminal and reprojects identically (no extra trace invariant).
        TraceEvent::InstanceFailed => {}
    }

    Ok(())
}

fn first_unsatisfied_dependency<'a>(
    state: &'a TraceState,
    effect_id: &str,
) -> Option<&'a DependencyEdge> {
    // Insertion order within a downstream is preserved by the per-key vector,
    // so this reports the same edge the flat scan did; a downstream with no
    // edges recorded is the empty case.
    state
        .dependencies
        .get(effect_id)?
        .iter()
        .find(|edge| !dependency_satisfied(state, edge))
}

fn dependency_satisfied(state: &TraceState, edge: &DependencyEdge) -> bool {
    let Some(status) = state.effects.get(&edge.upstream_effect_id) else {
        return false;
    };

    match edge.predicate {
        DependencyPredicate::Succeeds => *status == EffectStatus::Completed,
        DependencyPredicate::Fails => {
            matches!(status, EffectStatus::Failed | EffectStatus::TimedOut)
        }
        DependencyPredicate::Completes => status.is_terminal(),
    }
}

fn violation<T>(record: &TraceRecord, message: impl Into<String>) -> Result<T, TraceViolation> {
    Err(TraceViolation {
        sequence: record.sequence,
        message: message.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn effect_created(sequence: u64, effect_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::EffectCreated {
                effect_id: effect_id.to_owned(),
                status: EffectStatus::Queued,
            },
        }
    }

    fn claim(sequence: u64, effect_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::EffectClaimed {
                effect_id: effect_id.to_owned(),
            },
        }
    }

    fn start(sequence: u64, effect_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::RunStarted {
                run_id: format!("run-{effect_id}"),
                effect_id: effect_id.to_owned(),
            },
        }
    }

    fn expire_lease(sequence: u64, effect_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::LeaseExpired {
                run_id: format!("run-{effect_id}"),
                effect_id: effect_id.to_owned(),
            },
        }
    }

    fn terminal(sequence: u64, effect_id: &str, status: EffectStatus) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::EffectTerminal {
                run_id: format!("run-{effect_id}"),
                effect_id: effect_id.to_owned(),
                status,
            },
        }
    }

    fn cancellation_request(sequence: u64, effect_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::EffectCancellationRequested {
                effect_id: effect_id.to_owned(),
                revision_id: Some("rev-a".to_owned()),
                reason: Some("workflow revision".to_owned()),
                requested_by: "workflow.revision".to_owned(),
            },
        }
    }

    fn revision_activated(sequence: u64, from_epoch: i64, to_epoch: i64) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::RevisionActivated {
                revision_id: format!("rev-{to_epoch}"),
                from_version_id: format!("version-{from_epoch}"),
                to_version_id: format!("version-{to_epoch}"),
                from_epoch,
                to_epoch,
                cancellation_policy: "request_running".to_owned(),
                terminal_cancel_effects: Vec::new(),
                request_cancel_effects: Vec::new(),
            },
        }
    }

    fn diagnostic(sequence: u64, effect_id: &str, status: EffectStatus) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::ProviderDiagnostic {
                run_id: format!("run-{effect_id}"),
                effect_id: effect_id.to_owned(),
                provider: "test".to_owned(),
                status,
                summary: "provider failed".to_owned(),
                diagnostics_json: r#"{"error":"boom"}"#.to_owned(),
            },
        }
    }

    fn dependency_block(sequence: u64, effect_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::EffectBlocked {
                effect_id: effect_id.to_owned(),
                status: Some("blocked_by_dependency".to_owned()),
                reason: "effect dependencies are not satisfied".to_owned(),
            },
        }
    }

    fn capacity_block(sequence: u64, effect_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::EffectBlocked {
                effect_id: effect_id.to_owned(),
                status: Some("blocked_by_capacity".to_owned()),
                reason: "agent capacity exhausted".to_owned(),
            },
        }
    }

    fn policy_block(sequence: u64, effect_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::EffectBlocked {
                effect_id: effect_id.to_owned(),
                status: Some("blocked".to_owned()),
                reason: "provider_health: provider is unhealthy".to_owned(),
            },
        }
    }

    fn retried(sequence: u64, effect_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::EffectRetried {
                effect_id: effect_id.to_owned(),
            },
        }
    }

    #[test]
    fn accepts_claim_after_success_dependency() {
        let trace = vec![
            effect_created(1, "upstream"),
            effect_created(2, "downstream"),
            TraceRecord {
                sequence: 3,
                event: TraceEvent::DependencyCreated(DependencyEdge {
                    upstream_effect_id: "upstream".to_owned(),
                    predicate: DependencyPredicate::Succeeds,
                    downstream_effect_id: "downstream".to_owned(),
                }),
            },
            claim(4, "upstream"),
            start(5, "upstream"),
            terminal(6, "upstream", EffectStatus::Completed),
            claim(7, "downstream"),
            start(8, "downstream"),
        ];

        assert_eq!(check_trace(&trace), Ok(()));
    }

    #[test]
    fn accepts_provider_diagnostic_before_terminal_event() {
        let trace = vec![
            effect_created(1, "a"),
            claim(2, "a"),
            start(3, "a"),
            diagnostic(4, "a", EffectStatus::Failed),
            terminal(5, "a", EffectStatus::Failed),
        ];

        assert_eq!(check_trace(&trace), Ok(()));
    }

    #[test]
    fn accepts_cancellation_request_before_terminal_event() {
        let trace = vec![
            effect_created(1, "a"),
            claim(2, "a"),
            start(3, "a"),
            cancellation_request(4, "a"),
            terminal(5, "a", EffectStatus::Completed),
        ];

        assert_eq!(check_trace(&trace), Ok(()));
    }

    #[test]
    fn accepts_monotonic_revision_activation() {
        let trace = vec![revision_activated(1, 0, 1), revision_activated(2, 1, 2)];

        assert_eq!(check_trace(&trace), Ok(()));
    }

    #[test]
    fn rejects_sequence_gap() {
        let trace = vec![effect_created(1, "a"), claim(3, "a")];

        let violation = check_trace(&trace).expect_err("sequence gap should fail");
        assert!(violation.message.contains("sequence gap"));
    }

    #[test]
    fn rejects_claim_before_dependency_satisfied() {
        let trace = vec![
            effect_created(1, "upstream"),
            effect_created(2, "downstream"),
            TraceRecord {
                sequence: 3,
                event: TraceEvent::DependencyCreated(DependencyEdge {
                    upstream_effect_id: "upstream".to_owned(),
                    predicate: DependencyPredicate::Succeeds,
                    downstream_effect_id: "downstream".to_owned(),
                }),
            },
            claim(4, "downstream"),
        ];

        let violation = check_trace(&trace).expect_err("unsatisfied dependency should fail");
        assert!(violation.message.contains("before dependency"));
    }

    #[test]
    fn accepts_dependency_block_for_unsatisfied_dependency() {
        let trace = vec![
            effect_created(1, "upstream"),
            effect_created(2, "downstream"),
            TraceRecord {
                sequence: 3,
                event: TraceEvent::DependencyCreated(DependencyEdge {
                    upstream_effect_id: "upstream".to_owned(),
                    predicate: DependencyPredicate::Succeeds,
                    downstream_effect_id: "downstream".to_owned(),
                }),
            },
            dependency_block(4, "downstream"),
        ];

        assert_eq!(check_trace(&trace), Ok(()));
    }

    #[test]
    fn rejects_dependency_block_without_unsatisfied_dependency() {
        let trace = vec![
            effect_created(1, "downstream"),
            dependency_block(2, "downstream"),
        ];

        let violation =
            check_trace(&trace).expect_err("dependency block without dependency should fail");
        assert!(violation
            .message
            .contains("without an unsatisfied dependency"));
    }

    #[test]
    fn rejects_dependency_block_for_satisfied_failure_dependency() {
        let trace = vec![
            effect_created(1, "upstream"),
            effect_created(2, "downstream"),
            TraceRecord {
                sequence: 3,
                event: TraceEvent::DependencyCreated(DependencyEdge {
                    upstream_effect_id: "upstream".to_owned(),
                    predicate: DependencyPredicate::Fails,
                    downstream_effect_id: "downstream".to_owned(),
                }),
            },
            claim(4, "upstream"),
            start(5, "upstream"),
            terminal(6, "upstream", EffectStatus::Failed),
            dependency_block(7, "downstream"),
        ];

        let violation =
            check_trace(&trace).expect_err("satisfied failure dependency block should fail");
        assert!(violation
            .message
            .contains("without an unsatisfied dependency"));
    }

    // Recovery-from-block coverage. The store re-checks the block condition on the
    // next `start_run` and, if it clears, claims + starts the effect straight from
    // its blocked status (no separate observable unblock event). These traces are
    // exactly what `whip trace --check` reconstructs for a capacity/policy-contended
    // effect, and they must be accepted. Regression for the tutorial-repro bug where
    // a `capacity 1` agent's second turn tripped "claimed from non-queued status".

    #[test]
    fn accepts_claim_after_capacity_block() {
        let trace = vec![
            effect_created(1, "turn"),
            capacity_block(2, "turn"),
            claim(3, "turn"),
            start(4, "turn"),
            terminal(5, "turn", EffectStatus::Completed),
        ];

        assert_eq!(check_trace(&trace), Ok(()));
    }

    #[test]
    fn accepts_claim_after_policy_block() {
        let trace = vec![
            effect_created(1, "turn"),
            policy_block(2, "turn"),
            claim(3, "turn"),
            start(4, "turn"),
            terminal(5, "turn", EffectStatus::Completed),
        ];

        assert_eq!(check_trace(&trace), Ok(()));
    }

    #[test]
    fn accepts_reblock_then_claim() {
        // An effect can be blocked more than once (capacity frees, is retaken, then
        // frees again) before it finally claims. Every EffectBlocked/claim cycle is legal.
        let trace = vec![
            effect_created(1, "turn"),
            capacity_block(2, "turn"),
            capacity_block(3, "turn"),
            claim(4, "turn"),
            start(5, "turn"),
            terminal(6, "turn", EffectStatus::Completed),
        ];

        assert_eq!(check_trace(&trace), Ok(()));
    }

    // Bite preserved: relaxing the claim guard to `Queued | Blocked` must NOT let
    // through claims from live/terminal statuses or dependency-unsatisfied claims.

    #[test]
    fn rejects_claim_from_running() {
        let trace = vec![
            effect_created(1, "turn"),
            claim(2, "turn"),
            start(3, "turn"),
            claim(4, "turn"),
        ];

        let violation =
            check_trace(&trace).expect_err("double-claim of a running effect must fail");
        assert!(violation.message.contains("claimed from invalid status"));
        assert!(violation.message.contains("Running"));
    }

    #[test]
    fn rejects_claim_after_terminal() {
        let trace = vec![
            effect_created(1, "turn"),
            claim(2, "turn"),
            start(3, "turn"),
            terminal(4, "turn", EffectStatus::Completed),
            claim(5, "turn"),
        ];

        let violation = check_trace(&trace).expect_err("claim of a completed effect must fail");
        assert!(violation.message.contains("claimed from invalid status"));
        assert!(violation.message.contains("Completed"));
    }

    #[test]
    fn rejects_claim_before_dependency_satisfied_even_when_blocked() {
        // A dependency-blocked effect is abstract-`Blocked`; the relaxed guard lets it
        // reach the dependency check, which must still reject the premature claim.
        let trace = vec![
            effect_created(1, "upstream"),
            effect_created(2, "downstream"),
            TraceRecord {
                sequence: 3,
                event: TraceEvent::DependencyCreated(DependencyEdge {
                    upstream_effect_id: "upstream".to_owned(),
                    predicate: DependencyPredicate::Succeeds,
                    downstream_effect_id: "downstream".to_owned(),
                }),
            },
            dependency_block(4, "downstream"),
            claim(5, "downstream"),
        ];

        let violation =
            check_trace(&trace).expect_err("claim before dependency satisfied must fail");
        assert!(violation
            .message
            .contains("before dependency on upstream was satisfied"));
    }

    // Retry recovery coverage. `whip retry` re-queues a terminally-failed effect
    // (effect.retried event), after which it is claimed and run again. Before this
    // was modeled the second claim tripped "claimed from ... status Failed". Mirrors
    // kernel.maude `retry-failed`/`retry-timeout`.

    // The retried effect is re-run under a FRESH run id (a run id can never be
    // reused), so the second run/terminal are built explicitly rather than via the
    // effect-derived `start`/`terminal` helpers.
    fn start_run_id(sequence: u64, effect_id: &str, run_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::RunStarted {
                run_id: run_id.to_owned(),
                effect_id: effect_id.to_owned(),
            },
        }
    }

    fn terminal_run_id(
        sequence: u64,
        effect_id: &str,
        run_id: &str,
        status: EffectStatus,
    ) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::EffectTerminal {
                run_id: run_id.to_owned(),
                effect_id: effect_id.to_owned(),
                status,
            },
        }
    }

    #[test]
    fn accepts_retry_then_reclaim() {
        let trace = vec![
            effect_created(1, "turn"),
            claim(2, "turn"),
            start(3, "turn"),
            terminal(4, "turn", EffectStatus::Failed),
            retried(5, "turn"),
            claim(6, "turn"),
            start_run_id(7, "turn", "run-turn-2"),
            terminal_run_id(8, "turn", "run-turn-2", EffectStatus::Completed),
        ];

        assert_eq!(check_trace(&trace), Ok(()));
    }

    #[test]
    fn accepts_retry_after_timeout() {
        let trace = vec![
            effect_created(1, "turn"),
            claim(2, "turn"),
            start(3, "turn"),
            terminal(4, "turn", EffectStatus::TimedOut),
            retried(5, "turn"),
            claim(6, "turn"),
            start_run_id(7, "turn", "run-turn-2"),
            terminal_run_id(8, "turn", "run-turn-2", EffectStatus::Completed),
        ];

        assert_eq!(check_trace(&trace), Ok(()));
    }

    #[test]
    fn rejects_retry_of_running_effect() {
        let trace = vec![
            effect_created(1, "turn"),
            claim(2, "turn"),
            start(3, "turn"),
            retried(4, "turn"),
        ];

        let violation = check_trace(&trace).expect_err("retry of a running effect must fail");
        assert!(violation
            .message
            .contains("retried from non-retryable status"));
        assert!(violation.message.contains("Running"));
    }

    #[test]
    fn rejects_retry_of_completed_effect() {
        let trace = vec![
            effect_created(1, "turn"),
            claim(2, "turn"),
            start(3, "turn"),
            terminal(4, "turn", EffectStatus::Completed),
            retried(5, "turn"),
        ];

        let violation = check_trace(&trace).expect_err("retry of a completed effect must fail");
        assert!(violation
            .message
            .contains("retried from non-retryable status"));
        assert!(violation.message.contains("Completed"));
    }

    // -- Conformance bridge: check_trace <-> models/effect-lifecycle-transitions.tsv --
    //
    // The `.tsv` is the single source of truth for the effect-lifecycle transition
    // relation, shared with the executable models (the Maude side is generated from
    // the same file; see scripts/check-trace-model-conformance.sh). This test asserts
    // check_trace ACCEPTS exactly the transitions the corpus marks legal and REJECTS
    // every other (from_status, event) cell — the exhaustive negative coverage that
    // makes the "checker silently diverged from the model" bug class impossible to
    // reintroduce (it is what would have caught the blocked->claim / failed->retry
    // regressions).

    fn cancel_record(sequence: u64, effect_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::EffectCancelled {
                effect_id: effect_id.to_owned(),
            },
        }
    }

    fn expire_lease_run(sequence: u64, effect_id: &str, run_id: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::LeaseExpired {
                run_id: run_id.to_owned(),
                effect_id: effect_id.to_owned(),
            },
        }
    }

    /// Minimal legal prefix that leaves effect `e` in `from`, using a stable live run
    /// id `setup-run` where a run is involved.
    fn setup_to_status(from: &str) -> Vec<TraceRecord> {
        let e = "e";
        let mut r = vec![effect_created(1, e)];
        match from {
            "queued" => {}
            "blocked" => r.push(capacity_block(2, e)),
            "claimed" => r.push(claim(2, e)),
            "running" => {
                r.push(claim(2, e));
                r.push(start_run_id(3, e, "setup-run"));
            }
            "completed" => {
                r.push(claim(2, e));
                r.push(start_run_id(3, e, "setup-run"));
                r.push(terminal_run_id(4, e, "setup-run", EffectStatus::Completed));
            }
            "failed" => {
                r.push(claim(2, e));
                r.push(start_run_id(3, e, "setup-run"));
                r.push(terminal_run_id(4, e, "setup-run", EffectStatus::Failed));
            }
            "timed_out" => {
                r.push(claim(2, e));
                r.push(start_run_id(3, e, "setup-run"));
                r.push(terminal_run_id(4, e, "setup-run", EffectStatus::TimedOut));
            }
            "cancelled" => r.push(cancel_record(2, e)),
            other => panic!("unknown from_status {other}"),
        }
        r
    }

    /// The event under test, applied to effect `e` at `sequence`. Terminal/lease
    /// events reference the setup's live run so that, from `running`, the rejection
    /// (or acceptance) is decided by the effect status rather than a run-id artifact;
    /// `start_run` uses a fresh run id for the same reason.
    fn transition_event(sequence: u64, event: &str) -> TraceRecord {
        let e = "e";
        match event {
            "claim" => claim(sequence, e),
            "start_run" => start_run_id(sequence, e, "probe-run"),
            "terminal_completed" => {
                terminal_run_id(sequence, e, "setup-run", EffectStatus::Completed)
            }
            "terminal_failed" => terminal_run_id(sequence, e, "setup-run", EffectStatus::Failed),
            "terminal_timed_out" => {
                terminal_run_id(sequence, e, "setup-run", EffectStatus::TimedOut)
            }
            "block" => capacity_block(sequence, e),
            "retry" => retried(sequence, e),
            "lease_expire" => expire_lease_run(sequence, e, "setup-run"),
            "cancel" => cancel_record(sequence, e),
            "cancel_request" => cancellation_request(sequence, e),
            other => panic!("unknown event {other}"),
        }
    }

    #[test]
    fn checker_matches_transition_corpus() {
        const CORPUS: &str = include_str!("../../../models/effect-lifecycle-transitions.tsv");

        let legal: BTreeSet<(String, String)> = CORPUS
            .lines()
            .map(str::trim_end)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter(|line| !line.starts_with("from_status"))
            .map(|line| {
                let cols: Vec<&str> = line.split('\t').collect();
                assert!(cols.len() >= 3, "malformed corpus row: {line:?}");
                (cols[0].to_owned(), cols[1].to_owned())
            })
            .collect();
        assert!(!legal.is_empty(), "corpus parsed to zero legal transitions");

        let statuses = [
            "queued",
            "blocked",
            "claimed",
            "running",
            "completed",
            "failed",
            "timed_out",
            "cancelled",
        ];
        let events = [
            "claim",
            "start_run",
            "terminal_completed",
            "terminal_failed",
            "terminal_timed_out",
            "block",
            "retry",
            "lease_expire",
            "cancel",
            "cancel_request",
        ];

        // Every listed legal transition must correspond to a real cell we probe.
        for (from, event) in &legal {
            assert!(
                statuses.contains(&from.as_str()) && events.contains(&event.as_str()),
                "corpus lists unknown transition {from} --{event}-->"
            );
        }

        for from in statuses {
            for event in events {
                let mut records = setup_to_status(from);
                let sequence = records.len() as u64 + 1;
                records.push(transition_event(sequence, event));
                let verdict = check_trace(&records);
                let expected_legal = legal.contains(&(from.to_owned(), event.to_owned()));
                assert_eq!(
                    verdict.is_ok(),
                    expected_legal,
                    "transition {from} --{event}--> : check_trace said {}, corpus says {}; verdict = {verdict:?}",
                    if verdict.is_ok() { "ACCEPT" } else { "REJECT" },
                    if expected_legal { "LEGAL" } else { "ILLEGAL" },
                );
            }
        }
    }

    fn paused(sequence: u64) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::InstancePaused,
        }
    }

    fn instance_cancelled(sequence: u64) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::InstanceCancelled,
        }
    }

    fn dep_edge(sequence: u64, upstream: &str, downstream: &str) -> TraceRecord {
        TraceRecord {
            sequence,
            event: TraceEvent::DependencyCreated(DependencyEdge {
                upstream_effect_id: upstream.to_owned(),
                predicate: DependencyPredicate::Succeeds,
                downstream_effect_id: downstream.to_owned(),
            }),
        }
    }

    /// A trace that VIOLATES the richer check_trace invariant named `key` (see
    /// models/trace-invariant-correspondence.tsv). check_trace must reject each.
    fn richer_invariant_violation(key: &str) -> Vec<TraceRecord> {
        match key {
            "dependency_ordering" => vec![
                effect_created(1, "up"),
                effect_created(2, "down"),
                dep_edge(3, "up", "down"),
                claim(4, "down"), // upstream not completed
            ],
            "run_starts_from_claimed" => vec![
                effect_created(1, "e"),
                start_run_id(2, "e", "r1"), // run started for a queued (not claimed) effect
            ],
            "terminal_from_stale_run" => vec![
                effect_created(1, "e"),
                claim(2, "e"),
                start_run_id(3, "e", "r1"),
                expire_lease_run(4, "e", "r1"), // r1 is now stale
                terminal_run_id(5, "e", "r1", EffectStatus::Completed),
            ],
            "terminal_not_duplicated" => vec![
                effect_created(1, "e"),
                claim(2, "e"),
                start_run_id(3, "e", "r1"),
                terminal_run_id(4, "e", "r1", EffectStatus::Completed),
                terminal_run_id(5, "e", "r1", EffectStatus::Completed),
            ],
            "no_claim_while_paused" => vec![effect_created(1, "e"), paused(2), claim(3, "e")],
            "no_claim_after_cancel" => {
                vec![effect_created(1, "e"), instance_cancelled(2), claim(3, "e")]
            }
            "blocked_not_from_terminal" => vec![
                effect_created(1, "e"),
                claim(2, "e"),
                start_run_id(3, "e", "r1"),
                terminal_run_id(4, "e", "r1", EffectStatus::Completed),
                capacity_block(5, "e"), // blocking a terminal effect
            ],
            "revision_epoch_advances" => vec![revision_activated(1, 0, 0)], // 0 -> 0 does not advance
            other => panic!("no violation builder for correspondence key {other}"),
        }
    }

    // -- Bridge to ControlPlaneLifecycle.tla's richer invariants --
    //
    // For each row of models/trace-invariant-correspondence.tsv, build a trace that
    // violates the invariant and assert check_trace rejects it with the recorded
    // message. Removing the invariant from check_trace makes its row's trace conform,
    // failing this test. The paired assertion that the TLA counterpart is present and
    // conjoined into SafetyInvariants lives in scripts/check-trace-model-conformance.sh.
    #[test]
    fn richer_invariants_have_bite() {
        const MAP: &str = include_str!("../../../models/trace-invariant-correspondence.tsv");

        let mut keys_seen = BTreeSet::new();
        for line in MAP.lines() {
            let line = line.trim_end();
            if line.is_empty() || line.starts_with('#') || line.starts_with("key\t") {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            assert!(cols.len() >= 3, "malformed correspondence row: {line:?}");
            let (key, substring, tla_invariant) = (cols[0], cols[1], cols[2]);
            assert!(!tla_invariant.is_empty(), "row {key} has no tla_invariant");
            keys_seen.insert(key.to_owned());

            let trace = richer_invariant_violation(key);
            let violation = check_trace(&trace).expect_err(&format!(
                "richer invariant `{key}` trace should be rejected"
            ));
            assert!(
                violation.message.contains(substring),
                "richer invariant `{key}`: expected message containing {substring:?}, got {:?}",
                violation.message,
            );
        }

        // Every builder arm must correspond to a corpus row (no orphan builders).
        for key in [
            "dependency_ordering",
            "run_starts_from_claimed",
            "terminal_from_stale_run",
            "terminal_not_duplicated",
            "no_claim_while_paused",
            "no_claim_after_cancel",
            "blocked_not_from_terminal",
            "revision_epoch_advances",
        ] {
            assert!(
                keys_seen.contains(key),
                "builder key {key} is not in the correspondence corpus"
            );
        }
    }

    #[test]
    fn rejects_duplicate_terminal_completion() {
        let trace = vec![
            effect_created(1, "a"),
            claim(2, "a"),
            start(3, "a"),
            terminal(4, "a", EffectStatus::Completed),
            terminal(5, "a", EffectStatus::Failed),
        ];

        let violation = check_trace(&trace).expect_err("duplicate terminal should fail");
        assert!(violation.message.contains("duplicate terminal"));
    }

    #[test]
    fn rejects_stale_lease_completion() {
        let trace = vec![
            effect_created(1, "a"),
            claim(2, "a"),
            start(3, "a"),
            expire_lease(4, "a"),
            terminal(5, "a", EffectStatus::Completed),
        ];

        let violation = check_trace(&trace).expect_err("stale lease completion should fail");
        assert!(violation.message.contains("stale run"));
    }

    #[test]
    fn rejects_provider_diagnostic_after_terminal_event() {
        let trace = vec![
            effect_created(1, "a"),
            claim(2, "a"),
            start(3, "a"),
            terminal(4, "a", EffectStatus::Failed),
            diagnostic(5, "a", EffectStatus::Failed),
        ];

        let violation = check_trace(&trace).expect_err("late diagnostic should fail");
        assert!(violation.message.contains("non-live run"));
    }

    #[test]
    fn rejects_provider_diagnostic_with_invalid_json() {
        let trace = vec![
            effect_created(1, "a"),
            claim(2, "a"),
            start(3, "a"),
            TraceRecord {
                sequence: 4,
                event: TraceEvent::ProviderDiagnostic {
                    run_id: "run-a".to_owned(),
                    effect_id: "a".to_owned(),
                    provider: "test".to_owned(),
                    status: EffectStatus::Failed,
                    summary: "provider failed".to_owned(),
                    diagnostics_json: "not json".to_owned(),
                },
            },
        ];

        let violation = check_trace(&trace).expect_err("invalid diagnostic JSON should fail");
        assert!(violation.message.contains("valid JSON"));
    }

    #[test]
    fn rejects_cancellation_request_for_non_running_effect() {
        let trace = vec![effect_created(1, "a"), cancellation_request(2, "a")];

        let violation =
            check_trace(&trace).expect_err("cancellation request before running should fail");
        assert!(violation.message.contains("in status Queued"));
    }

    #[test]
    fn rejects_duplicate_cancellation_request() {
        let trace = vec![
            effect_created(1, "a"),
            claim(2, "a"),
            start(3, "a"),
            cancellation_request(4, "a"),
            cancellation_request(5, "a"),
        ];

        let violation = check_trace(&trace).expect_err("duplicate cancellation request fails");
        assert!(violation.message.contains("duplicate cancellation request"));
    }

    #[test]
    fn rejects_claim_after_cancellation_request_and_lease_expiry() {
        let trace = vec![
            effect_created(1, "a"),
            claim(2, "a"),
            start(3, "a"),
            cancellation_request(4, "a"),
            expire_lease(5, "a"),
            claim(6, "a"),
        ];

        let violation = check_trace(&trace).expect_err("cancel-requested effect claim fails");
        assert!(violation.message.contains("after cancellation request"));
    }

    #[test]
    fn rejects_revision_activation_with_stale_epoch() {
        let trace = vec![revision_activated(1, 1, 2)];

        let violation = check_trace(&trace).expect_err("stale revision epoch should fail");
        assert!(violation.message.contains("trace is at epoch 0"));
    }

    #[test]
    fn rejects_run_started_after_cancel() {
        let trace = vec![
            effect_created(1, "a"),
            claim(2, "a"),
            TraceRecord {
                sequence: 3,
                event: TraceEvent::InstanceCancelled,
            },
            start(4, "a"),
        ];

        let violation = check_trace(&trace).expect_err("start after cancel should fail");
        assert!(violation.message.contains("after instance cancellation"));
    }
}
