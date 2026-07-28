# TLA+ Models

TLA+ is for durable control-plane lifecycle validation, not per-program user
checks in v0.

Model:

```text
event log
projection cursor
effect outbox
effect dependencies
leases
workers
runs
crash/recovery
pause/resume/cancel
revision cancellation policy
terminal event records
```

Current model:

```text
ControlPlaneLifecycle.tla
NativeProviderLifecycle.tla
```

It encodes a first-pass runtime lifecycle:

```text
append event
derive projection cursor
claim effect
start run
complete/fail/timeout run
cancellation request acknowledgement
cancel run after acknowledgement
expire lease
retry failed or timed-out effect
start/finish recovery from the durable event log
pause/resume/cancel
workflow complete/fail terminal states
dependency-gated claimability
revision activation policies for old queued/running effects
```

It names safety invariants for:

```text
run/effect references
claimed/running run consistency
claimability and dependency satisfaction
paused instances not producing new claimable work
terminal instances not producing new claimable work
cancelled/completed/failed instance states remaining mutually exclusive
current terminal-effect set matching effect status
run-scoped lease consistency
at most one run executing a given effect at once (concurrent-worker safety)
retry removing current terminal status before a new attempt
projection cursor bounds
recovery preserving event-log order
recovery blocking live-state mutation until finish
explicit terminal event records not duplicating a run/effect outcome
revision cancellation policy and requestability gates
basic type correctness
```

`NativeProviderLifecycle.tla` is a focused native-provider fixture for:

```text
cancellation acknowledgement not fabricating terminal cancellation
provider terminal evidence recovery
required artifact-capture failure preventing successful completion
duplicate terminal outcome prevention
terminal event records matching the terminal set
```

It also names weak-fairness and liveness goals:

```text
FairSpec
LivenessGoals
ClaimableEffectEventuallyRunsOrStops
RunningEffectEventuallyTerminalsOrRecovers
ProjectionEventuallyCatchesUp
RecoveryEventuallyFinishes
```

## Durable-object runtime models (DR-0033)

Two models cover the sans-IO durable-object runtime lifecycle, at two scales:

```text
ResumableEffectLifecycle.tla
InstanceSchedulerLifecycle.tla
```

`ResumableEffectLifecycle.tla` (Phase 0) models ONE external-I/O effect as a
resumable step machine — `claim → [NeedsIo → io_pending → io_done]* → settle` —
and proves exactly-once settle, at-least-once network delivery deduplicated by a
stable idempotency key (the DO host may be evicted mid-`fetch`), no orphaned
`io_pending`, and that the native run-to-completion path is the eviction-free
refinement.

`InstanceSchedulerLifecycle.tla` sits one level up: it models the WHOLE instance
as the native `dev` fixpoint re-expressed as a host-agnostic step machine —
alternate a pure rule pass (commit ready rules; may spawn effects or reach a
workflow terminal) with an effect pass (run each ready effect to a terminal that
becomes a fact), abstracting each effect's fetch rounds to one `inflight/evicted`
slot. It names the NEW instance-level obligations the full-lift refactor must
preserve: a workflow terminal is recorded at most once and is **absorbing** (no
rule commits or effect settles after it); the scheduler **parks only at a genuine
fixpoint** (no ready rule, no ready effect, nothing mid-fetch); an effect is
mid-fetch only while the instance is running; and eviction/resume of a suspended
effect **never loses or double-counts instance progress**. Each safety invariant
carries an inline `Bite:` mutation (five of them, each verified to produce an
Apalache counterexample — e.g. letting `Quiesce` fire with a ready effect
outstanding, or an `EffectResume` that re-settles).

## Information-flow models (temporal layer)

Two models carry the information-flow properties that are about a *sequence* of
steps over time, complementing the single-step Maude bites and the timeless Lean
algebra:

```text
InfoflowReleaseBudget.tla
InfoflowLabelCarriage.tla
```

`InfoflowReleaseBudget.tla` (DR-0030 Direction C) checks, over all traces, that the
checked declassifier never exceeds the public release budget and that no committed
privileged release ever carries a tainted (adaptively-derived) selector — the
no-adaptive-oracle safety surrogate.

`InfoflowLabelCarriage.tla` (I-IFC7, audit-findings W6) checks that a datum's label
is carried across every transport hop — persist, reload, cross-instance handoff,
replay — without being **stripped** (`NoStrip`, confidentiality silently lowered) or
**forged/laundered** (`NoForge`, integrity silently raised). It is the inductive,
all-interleavings complement to `infoflow-carriage.maude`'s single hop. *Bite
(verified to fail):* adding a `LaunderHandoff` transport that rewrites integ to 1
produces an Apalache counterexample at the `NoForge`/`CarriagePreserved` invariant.
Label *crossings* (declassify/endorse) are authorized exceptions modeled in the
crossing models, not here.

## Versioned-workspace models

```text
ReconciliationDaemonLifecycle.tla
```

`ReconciliationDaemonLifecycle.tla` (versioned-workspace research note §7.1,
untie-substrate tracker Phase 1) checks the reconciliation daemon's lifecycle
policies over all interleavings of two branches and a moving mainline: a
slice-DISJOINT mainline delta rebases down silently at any time, an
INTERSECTING delta is applied only at a quiescence point (`NoMidRunIntrusion` —
per-run snapshot isolation), merge-up happens only under the adoption lease
with the staleness bound discharged at merge time (`NoStaleMerge` — the guard
re-checks freshness after the lease was acquired), and the pending-delta
bookkeeping stays consistent. The merge CONTENT semantics (certificates,
confluence, joint escalation) live in the Maude `merge-slice` /
`merge-confluence` models. *Bite (verified to fail):* dropping the quiescence
guard on `RebaseIntersecting` produces an Apalache counterexample at
`NoMidRunIntrusion` within 3 steps.

The default script typechecks these formulas with Apalache and runs a bounded
safety check over `SafetyInvariants` using `ConstInit`, a small finite harness.
It does not treat full temporal liveness proof as a v0 release gate; the
formulas are kept in the model so future TLC/Apalache temporal-checking work
has a stable target.

Current local workspace status:

```text
java: provided by the repo Nix dev shell
apalache: provided by the repo Nix dev shell
```

Run:

```sh
scripts/check-tla-models.sh
```

If `apalache-mc` is not already on `PATH`, the script enters the repo Nix dev
shell and runs the check there.

The bounded safety depth defaults to `6`. Override it when doing deeper local
validation:

```sh
WHIPPLESCRIPT_TLA_LENGTH=10 scripts/check-tla-models.sh
```

CI policy:

```text
run TLA+/Apalache in default CI
keep generated per-program Maude model search opt-in from the CLI
```

This keeps durable control-plane regressions in the normal gate while avoiding a
formal-tool requirement for ordinary local `whip check` usage.
