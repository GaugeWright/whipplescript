# Trace Conformance

Status: first-pass contract

Runtime traces are the bridge between the executable formal models and the Rust
implementation. Every runtime integration test should be able to emit an
ordered trace and pass it through a conformance checker.

The initial Rust checker lives in:

```text
crates/whipplescript-kernel/src/trace.rs
```

It validates these invariants:

```text
event sequence numbers are contiguous
dependencies reference known effects
effects are not claimed while paused or cancelled
effects are not claimed before dependency predicates are satisfied
effects may be claimed from queued OR from a blocked status (see below)
runs start only for claimed effects
lease expiry marks the active run stale and makes the effect queueable again
a policy/capacity/dependency block does not strand an effect: it can still be claimed
`whip retry` re-queues a failed/timed-out effect (EffectRetried) so it can run again
retry is legal only from a failed/timed-out status
terminal completions must come from the live run for the effect
terminal completions from stale runs are rejected
terminal completions reference known effects
terminal completions are not duplicated
cancelled instances cannot resume or start new runs
```

## Blocked and retried effects (refinement of the lifecycle models)

The executable lifecycle models model a blocked effect returning to the ready set
as an explicit `blocked -> queued` re-queue (`kernel.maude`
`policy-release`/`capacity-release`; `ControlPlaneLifecycle.tla` `UnblockEffect`).
The store, however, folds that unblock into the next claim: `start_run` re-checks
the policy/capacity/dependency condition inside one transaction and, if it now
clears, moves the effect straight from its blocked status to `running`. There is no
separate observable "unblock" event to reconstruct (unlike lease expiry, which does
emit `lease.expired`). The trace checker therefore accepts a claim directly from
`Blocked` — the coarser but faithful observation of the models' two-step recovery.
The dependency-ordering invariant (a claim is illegal while an upstream predicate is
unsatisfied) is what keeps this rule's bite; capacity/policy are re-verified by the
store and are not observable in the trace.

`whip retry`, by contrast, IS an observable event (`effect.retried`), so it is
modeled directly as `TraceEvent::EffectRetried`: a `failed`/`timed_out` effect
returns to `queued` (matching `retry_effect`'s `WHERE status IN ('failed','timed_out')`
and the models' `retry-failed`/`retry-timeout` rules), clearing its terminal mark so
a fresh claim/run/terminal is legal.

This checker is intentionally abstract. It does not know SQL table names,
provider-specific payloads, or source-language syntax. Runtime code should
lower concrete events into these trace records before conformance checking.

The checker should grow alongside the store and kernel. In particular, later
stages should add:

```text
lease renewal checks
retry attempt identity checks
rule commit and projection trace checks
artifact/evidence reference checks
```

Done: blocked-by-policy/capacity traces and the recovery paths out of them (claim
from blocked, and `whip retry`) are now checked — see "Blocked and retried effects"
above and the regression tests in `crates/whipplescript-kernel/src/trace.rs`
(`accepts_claim_after_capacity_block`, `accepts_retry_then_reclaim`, and the paired
negative fixtures) plus the reconstruct-path tests in the CLI crate.
