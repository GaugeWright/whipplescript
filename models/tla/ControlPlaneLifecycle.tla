---- MODULE ControlPlaneLifecycle ----
EXTENDS Naturals, Sequences, FiniteSets

\* This model captures the durable control-plane lifecycle independently of
\* any particular WhippleScript source program. Maude models local rule/effect
\* rewrites; this TLA+ model tracks asynchronous runtime actions, leases,
\* recovery, pause/resume, cancellation, and event-log ordering.

CONSTANTS
  \* @type: Set(Str);
  Effects,
  \* @type: Set(Str);
  Runs,
  \* @type: Set(Str);
  Events,
  \* @type: Set(Str);
  Versions,
  \* @type: Set(Str);
  RequestableEffects,
  \* @type: Set(<<Str, Str, Str>>);
  Dependencies,
  \* Denial/diagnostic domains. Each is DELIBERATELY WIDER than the set the
  \* corresponding guard admits (ConstInit seeds each with one value the guard
  \* must reject), so the evidence invariants below are not true by construction:
  \* drop a guard and Apalache finds the rejected value in the evidence log.
  \* @type: Set(Str);
  DenialReasonDomain,
  \* @type: Set(Str);
  DenialCodeDomain,
  \* @type: Set(Str);
  Assertions,
  \* @type: Set(Str);
  AssertionSubjectDomain,
  \* @type: Set(Str);
  AssertionCodeDomain,
  \* @type: Set(Str);
  TerminalDiagnosticCodeDomain

VARIABLES
  \* @type: Seq(Str);
  eventLog,
  \* @type: Seq(Str);
  recoveryLog,
  \* @type: Str -> Str;
  effects,
  \* @type: Str -> Str;
  runs,
  \* @type: Str -> Str;
  runEffect,
  \* @type: Str -> Str;
  leases,
  \* @type: Set(Str);
  terminalEffects,
  \* @type: Int;
  projectionCursor,
  \* @type: Bool;
  paused,
  \* @type: Bool;
  cancelled,
  \* @type: Bool;
  completed,
  \* @type: Bool;
  failed,
  \* @type: Bool;
  recovering,
  \* @type: Str;
  activeVersion,
  \* @type: Int;
  revisionEpoch,
  \* @type: Str -> Str;
  effectVersion,
  \* @type: Set(Str);
  cancelRequested,
  \* @type: Set(Str);
  cancelAcknowledged,
  \* @type: Str -> Str;
  revisionPolicy,
  \* @type: Seq(Str);
  revisionEvents,
  \* @type: Seq(<<Str, Str, Str>>);
  terminalRunEvents,
  \* @type: Seq(<<Str, Str>>);
  terminalControlEvents,
  \* D12 evidence logs. Each denial the runtime refuses to perform appends the
  \* record that explains it, so "the work did not happen" is joined by "the log
  \* says why". <<effect, reason, code>>.
  \* @type: Seq(<<Str, Str, Str>>);
  denialEvidence,
  \* <<assertion, code>>.
  \* @type: Seq(<<Str, Str>>);
  assertionEvidence,
  \* <<run, effect, code>>.
  \* @type: Seq(<<Str, Str, Str>>);
  terminalDiagnostics,
  \* The set of effects `denialEvidence` carries a record for. A projection of
  \* the sequence, kept as its own variable only because Apalache cannot
  \* evaluate an existential over a sequence index range (`\E i \in 1..Len(s)`).
  \* BindBlock writes both in one step, so they cannot disagree.
  \* @type: Set(Str);
  deniedEffects

vars ==
  << eventLog, recoveryLog, effects, runs, runEffect, leases, terminalEffects,
     projectionCursor, paused, cancelled, completed, failed, recovering,
     activeVersion, revisionEpoch, effectVersion, cancelRequested,
     cancelAcknowledged, revisionPolicy, revisionEvents, terminalRunEvents,
     terminalControlEvents, denialEvidence, assertionEvidence,
     terminalDiagnostics, deniedEffects >>

EvidenceVars ==
  << denialEvidence, assertionEvidence, terminalDiagnostics, deniedEffects >>

RevisionVars ==
  << activeVersion, revisionEpoch, effectVersion, cancelRequested,
     cancelAcknowledged, revisionPolicy, revisionEvents >>

\* `policy_denied` is the admission gate's refusal (blocked_by_capability /
\* blocked_by_profile), kept distinct from the worker-time `blocked` of a
\* provider-binding failure because only the former owes denial evidence -- the
\* same split the Rust checker makes with `NON_DENIAL_BLOCK_STATUSES`.
EffectStatuses ==
  {"queued", "blocked", "policy_denied", "claimed", "running", "completed",
   "failed", "timed_out", "cancelled"}

RunStatuses ==
  {"none", "claimed", "running", "completed", "failed", "timed_out",
   "cancelled", "lease_expired", "uncertain"}

TerminalEffectStatuses ==
  {"completed", "failed", "timed_out", "cancelled"}

TerminalRunStatuses ==
  {"completed", "failed", "timed_out", "cancelled", "lease_expired", "uncertain"}

RevisionPolicies ==
  {"keep", "cancelQueued", "requestRunning"}

LeaseStatuses ==
  {"none", "active", "released", "expired"}

\* -- D12 runtime diagnostic adequacy: what counts as EVIDENCE -----------------
\*
\* A denial reason NAMES the denied subject. The store's admission gate writes
\* "capability `x` is not bound for program p" / "profile `p` is not registered"
\* / "profile `p` does not allow capability `x`"; each backtick-quotes the
\* subject it refused. `unnamedDenial` is the shape that does not, and the
\* Rust checker rejects it for the same reason (trace.rs `EffectBlocked`).
\* `scriptCapabilityNotBound` is the same shape for a `script.*` capability --
\* the denial that IS the script hard-off, singled out because it is the one
\* denial the runtime owes a diagnostic id (see below).
NamedDenialReasons ==
  {"capabilityNotRegistered", "capabilityNotBound", "profileNotRegistered",
   "profileDisallowsCapability", "scriptCapabilityNotBound"}

\* A denial that carries a diagnostic id carries a REGISTERED one. The only id
\* the runtime prefixes onto a block reason today is the script hard-off id
\* (`security.script_disabled:`, spec/std-script.md); an uncoded denial carries
\* the empty code. `unregisteredDenialCode` stands for a misspelt or invented id.
RegisteredDenialCodes ==
  {"", "securityScriptDisabled"}

\* A failing assertion's evidence carries one of the two registered assertion
\* codes (spec/diagnostic-codes-runtime.txt `assertion.failed`,
\* `assertion.errored`).
RegisteredAssertionCodes ==
  {"assertionFailed", "assertionErrored"}

\* A terminal diagnostic carries a CODE -- an identifier, not prose. When a
\* terminal records a diagnostic at all, the runtime passes either the provider's
\* own failure kind (`nonzero_exit`) or a registered runtime code
\* (`schema.coerce.failed`, `runtime.recovery_uncertain`); it never leaves the
\* code empty and never puts the message there. `proseDiagnostic` and the empty
\* string are the two shapes that are not a code.
CodeShapedTerminalDiagnostics ==
  {"nonzeroExit", "schemaCoerceFailed", "schemaCoerceTimedOut",
   "runtimeRecoveryUncertain"}

\* The claim modeled here is CONDITIONAL, because the runtime's is: `fail_run`
\* and `timeout_run` forward `None` as the diagnostic and more than a dozen
\* production call sites use them, so a terminal that records no diagnostic at
\* all is a real state (spec/error-handling.md records it as an open product
\* gap). `noDiagnostic` is that state, and a terminal in it appends nothing --
\* it is never a code that reaches `terminalDiagnostics`. What the model and the
\* checker both say is: IF a terminal diagnostic exists, it carries a code and
\* names its own run's effect.
NoTerminalDiagnostic ==
  "noDiagnostic"

Init ==
  /\ eventLog = << >>
  /\ recoveryLog = << >>
  /\ effects = [e \in Effects |-> "queued"]
  /\ runs = [r \in Runs |-> "none"]
  /\ runEffect = [r \in Runs |-> CHOOSE e \in Effects : TRUE]
  /\ leases = [r \in Runs |-> "none"]
  /\ terminalEffects = {}
  /\ projectionCursor = 0
  /\ paused = FALSE
  /\ cancelled = FALSE
  /\ completed = FALSE
  /\ failed = FALSE
  /\ recovering = FALSE
  /\ activeVersion = "version1"
  /\ revisionEpoch = 0
  /\ effectVersion = [e \in Effects |-> "version1"]
  /\ cancelRequested = {}
  /\ cancelAcknowledged = {}
  /\ revisionPolicy = [v \in Versions |-> "keep"]
  /\ revisionEvents = << >>
  /\ terminalRunEvents = << >>
  /\ terminalControlEvents = << >>
  /\ denialEvidence = << >>
  /\ assertionEvidence = << >>
  /\ terminalDiagnostics = << >>
  /\ deniedEffects = {}

InstanceRunning ==
  /\ ~paused
  /\ ~cancelled
  /\ ~completed
  /\ ~failed

AppendEvent(ev) ==
  /\ ev \in Events
  /\ ~recovering
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, completed, failed,
                  recoveryLog, recovering, RevisionVars, EvidenceVars >>

\* @type: (<<Str, Str, Str>>) => Str;
DepUpstream(d) == d[1]

\* @type: (<<Str, Str, Str>>) => Str;
DepPredicate(d) == d[2]

\* @type: (<<Str, Str, Str>>) => Str;
DepDownstream(d) == d[3]

PredicateSatisfied(d) ==
  \/ /\ DepPredicate(d) = "succeeds"
     /\ effects[DepUpstream(d)] = "completed"
  \/ /\ DepPredicate(d) = "fails"
     /\ effects[DepUpstream(d)] \in {"failed", "timed_out"}
  \/ /\ DepPredicate(d) = "completes"
     /\ effects[DepUpstream(d)] \in {"completed", "failed", "timed_out", "cancelled"}

EffectHasUnsatisfiedDeps(e) ==
  \E d \in Dependencies :
    /\ DepDownstream(d) = e
    /\ ~PredicateSatisfied(d)

Claimable(e) ==
  /\ InstanceRunning
  /\ effects[e] = "queued"
  /\ e \notin cancelRequested
  /\ ~EffectHasUnsatisfiedDeps(e)

ClaimEffect(e, r) ==
  /\ e \in Effects
  /\ r \in Runs
  /\ ~recovering
  /\ Claimable(e)
  /\ runs[r] = "none"
  /\ effects' = [effects EXCEPT ![e] = "claimed"]
  /\ runs' = [runs EXCEPT ![r] = "claimed"]
  /\ runEffect' = [runEffect EXCEPT ![r] = e]
  /\ UNCHANGED << eventLog, recoveryLog, leases, terminalEffects, projectionCursor,
                  terminalRunEvents, terminalControlEvents, paused, cancelled,
                  completed, failed, recovering, RevisionVars, EvidenceVars >>

StartRun(r) ==
  /\ r \in Runs
  /\ ~recovering
  /\ InstanceRunning
  /\ runs[r] = "claimed"
  /\ effects[runEffect[r]] = "claimed"
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "running"]
  /\ runs' = [runs EXCEPT ![r] = "running"]
  /\ leases' = [leases EXCEPT ![r] = "active"]
  /\ UNCHANGED << eventLog, recoveryLog, runEffect, terminalEffects, projectionCursor,
                  terminalRunEvents, terminalControlEvents, paused, cancelled,
                  completed, failed, recovering, RevisionVars, EvidenceVars >>

\* Worker-time provider-binding failure (missing config/credentials/enforcement/
\* healthy binding): a claimed effect parks back to a non-terminal `blocked`
\* state BEFORE provider execution, releasing its run and lease. Recoverable, not
\* terminal (DR-0020). The categorized reason is a runtime field abstracted away
\* here; the lifecycle guarantee is that this never fabricates a terminal outcome.
\*
\* This is NOT the D12 denial. A binding block is a `provider_health:`-style
\* category written by `block_effect_binding` from a run that had already been
\* claimed, and it owes no named subject -- exactly as the Rust checker owes it
\* none (trace.rs lists the bare `blocked` status a binding block writes in
\* `NON_DENIAL_BLOCK_STATUSES`). The admission-gate denial is `PolicyDenyEffect`
\* below.
BindBlock(r) ==
  /\ r \in Runs
  /\ ~recovering
  /\ InstanceRunning
  /\ runs[r] = "claimed"
  /\ effects[runEffect[r]] = "claimed"
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "blocked"]
  /\ runs' = [runs EXCEPT ![r] = "none"]
  /\ leases' = [leases EXCEPT ![r] = "none"]
  /\ UNCHANGED << eventLog, recoveryLog, runEffect, terminalEffects, projectionCursor,
                  terminalRunEvents, terminalControlEvents, paused, cancelled,
                  completed, failed, recovering, RevisionVars, EvidenceVars >>

\* D12 (capability denial -> diagnostic, no provider run; script disabled ->
\* security.script_disabled diagnostic, no exec boundary crossed).
\*
\* THE ADMISSION GATE, and deliberately a different action from BindBlock above.
\* The store's `policy_block_on` refuses a QUEUED effect before any run row
\* exists: no run is claimed, no lease is taken, the effect lands in
\* `blocked_by_capability`/`blocked_by_profile` (abstracted here as the single
\* status `policy_denied`), and the refusal WRITES -- an `effect.blocked` event
\* plus the reason record that explains it. That is the shape the Rust checker
\* reads (trace.rs `EffectBlocked` with any status NOT in
\* `NON_DENIAL_BLOCK_STATUSES`), so the two planes are quantified over the same
\* class of denial and not over two different ones -- and stay so when a new
\* denial status appears, since the Rust side classifies by exclusion.
\*
\* All three guards below are load-bearing -- `DenialReasonDomain` and
\* `DenialCodeDomain` each carry a value the guard rejects, so removing a guard
\* puts that value into `denialEvidence` and Apalache reports the paired
\* invariant violated (scripts/check-tla-models.sh).
PolicyDenyEffect(e, ev, reason, code) ==
  /\ e \in Effects
  /\ ev \in Events
  /\ reason \in DenialReasonDomain
  /\ code \in DenialCodeDomain
  /\ ~recovering
  /\ InstanceRunning
  /\ effects[e] = "queued"
  /\ e \notin terminalEffects
  /\ reason \in NamedDenialReasons  \* THE DENIAL NAMES ITS SUBJECT
  /\ code \in RegisteredDenialCodes  \* THE DENIAL CODE IS REGISTERED
  /\ (reason = "scriptCapabilityNotBound") => (code = "securityScriptDisabled")  \* THE SCRIPT DENIAL CARRIES ITS ID
  /\ effects' = [effects EXCEPT ![e] = "policy_denied"]
  /\ denialEvidence' = Append(denialEvidence, <<e, reason, code>>)
  /\ deniedEffects' = deniedEffects \cup {e}
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, completed, failed, recovering, RevisionVars,
                  assertionEvidence, terminalDiagnostics >>

\* The binding prerequisite becomes available: a blocked effect returns to
\* `queued` and is claimable again, so a fixed config/credential resumes work
\* without a manual re-trigger. This requeue is NECESSARY: `ClaimEffect` can only
\* fire from `queued` (via `Claimable`), so a blocked effect can never go directly
\* to `claimed`. That necessity is given executable teeth -- and the guard proven
\* load-bearing by mutation -- in models/tla/EffectRequeueNecessity.tla (run by
\* scripts/check-tla-models.sh).
UnblockEffect(e) ==
  /\ e \in Effects
  /\ ~recovering
  /\ InstanceRunning
  /\ effects[e] = "blocked"
  /\ effects' = [effects EXCEPT ![e] = "queued"]
  /\ UNCHANGED << eventLog, recoveryLog, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, completed, failed, recovering, RevisionVars, EvidenceVars >>

CompleteRun(r, ev) ==
  /\ r \in Runs
  /\ ev \in Events
  /\ ~recovering
  /\ runs[r] = "running"
  /\ runEffect[r] \notin terminalEffects
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "completed"]
  /\ runs' = [runs EXCEPT ![r] = "completed"]
  /\ leases' = [leases EXCEPT ![r] = "released"]
  /\ terminalEffects' = terminalEffects \cup {runEffect[r]}
  /\ terminalRunEvents' = Append(terminalRunEvents, <<r, runEffect[r], "completed">>)
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, runEffect, projectionCursor, paused, cancelled,
                  completed, failed, recovering, activeVersion, revisionEpoch,
                  effectVersion, cancelRequested, cancelAcknowledged,
                  revisionPolicy, revisionEvents, terminalControlEvents, EvidenceVars >>

\* D12 (provider failure -> terminal failure diagnostic; provider output
\* validation failure -> failed effect and validation diagnostic). IF the
\* terminal records a diagnostic, that diagnostic is CODE-SHAPED and NAMES the
\* effect its run executed. `TerminalDiagnosticCodeDomain` carries a value that
\* is not a code, so the guard is load-bearing; it also carries
\* `NoTerminalDiagnostic`, which is the runtime state where no diagnostic is
\* recorded at all and nothing is appended.
FailRun(r, ev, code) ==
  /\ r \in Runs
  /\ ev \in Events
  /\ code \in TerminalDiagnosticCodeDomain
  /\ ~recovering
  /\ runs[r] = "running"
  /\ runEffect[r] \notin terminalEffects
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "failed"]
  /\ runs' = [runs EXCEPT ![r] = "failed"]
  /\ leases' = [leases EXCEPT ![r] = "released"]
  /\ terminalEffects' = terminalEffects \cup {runEffect[r]}
  /\ terminalRunEvents' = Append(terminalRunEvents, <<r, runEffect[r], "failed">>)
  /\ \/ /\ code = NoTerminalDiagnostic
        /\ terminalDiagnostics' = terminalDiagnostics
     \/ /\ terminalDiagnostics' = Append(terminalDiagnostics, <<r, runEffect[r], code>>)  \* THE DIAGNOSTIC NAMES ITS RUN EFFECT
        /\ code \in CodeShapedTerminalDiagnostics  \* THE TERMINAL DIAGNOSTIC CARRIES A CODE
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, runEffect, projectionCursor, paused, cancelled,
                  completed, failed, recovering, activeVersion, revisionEpoch,
                  effectVersion, cancelRequested, cancelAcknowledged,
                  revisionPolicy, revisionEvents, terminalControlEvents,
                  denialEvidence, assertionEvidence, deniedEffects >>

CancelAcknowledgedRun(r, ev) ==
  /\ r \in Runs
  /\ ev \in Events
  /\ ~recovering
  /\ runs[r] = "running"
  /\ runEffect[r] \in cancelAcknowledged
  /\ runEffect[r] \notin terminalEffects
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "cancelled"]
  /\ runs' = [runs EXCEPT ![r] = "cancelled"]
  /\ leases' = [leases EXCEPT ![r] = "released"]
  /\ terminalEffects' = terminalEffects \cup {runEffect[r]}
  /\ terminalRunEvents' = Append(terminalRunEvents, <<r, runEffect[r], "cancelled">>)
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, runEffect, projectionCursor, paused, cancelled,
                  completed, failed, recovering, activeVersion, revisionEpoch,
                  effectVersion, cancelRequested, cancelAcknowledged,
                  revisionPolicy, revisionEvents, terminalControlEvents, EvidenceVars >>

TimeoutRun(r, ev, code) ==
  /\ r \in Runs
  /\ ev \in Events
  /\ code \in TerminalDiagnosticCodeDomain
  /\ ~recovering
  /\ runs[r] = "running"
  /\ runEffect[r] \notin terminalEffects
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "timed_out"]
  /\ runs' = [runs EXCEPT ![r] = "timed_out"]
  /\ leases' = [leases EXCEPT ![r] = "released"]
  /\ terminalEffects' = terminalEffects \cup {runEffect[r]}
  /\ terminalRunEvents' = Append(terminalRunEvents, <<r, runEffect[r], "timed_out">>)
  /\ \/ /\ code = NoTerminalDiagnostic
        /\ terminalDiagnostics' = terminalDiagnostics
     \/ /\ terminalDiagnostics' = Append(terminalDiagnostics, <<r, runEffect[r], code>>)  \* THE DIAGNOSTIC NAMES ITS RUN EFFECT
        /\ code \in CodeShapedTerminalDiagnostics  \* THE TERMINAL DIAGNOSTIC CARRIES A CODE
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, runEffect, projectionCursor, paused, cancelled,
                  completed, failed, recovering, activeVersion, revisionEpoch,
                  effectVersion, cancelRequested, cancelAcknowledged,
                  revisionPolicy, revisionEvents, terminalControlEvents,
                  denialEvidence, assertionEvidence, deniedEffects >>

ExpireLease(r, ev) ==
  /\ r \in Runs
  /\ ev \in Events
  /\ ~recovering
  /\ runs[r] = "running"
  /\ effects[runEffect[r]] = "running"
  /\ leases[r] = "active"
  /\ runEffect[r] \notin terminalEffects
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "queued"]
  /\ runs' = [runs EXCEPT ![r] = "lease_expired"]
  /\ leases' = [leases EXCEPT ![r] = "expired"]
  /\ terminalRunEvents' = Append(terminalRunEvents, <<r, runEffect[r], "lease_expired">>)
  /\ eventLog' = Append(eventLog, ev)
  /\ cancelAcknowledged' = cancelAcknowledged \ {runEffect[r]}
  /\ UNCHANGED << recoveryLog, runEffect, terminalEffects, projectionCursor,
                  terminalControlEvents, paused, cancelled, completed, failed,
                  recovering, activeVersion, revisionEpoch, effectVersion,
                  cancelRequested, revisionPolicy, revisionEvents, EvidenceVars >>

RetryEffect(e, ev) ==
  /\ e \in Effects
  /\ ev \in Events
  /\ ~recovering
  /\ InstanceRunning
  /\ effects[e] \in {"failed", "timed_out"}
  /\ effects' = [effects EXCEPT ![e] = "queued"]
  /\ terminalEffects' = terminalEffects \ {e}
  /\ cancelRequested' = cancelRequested \ {e}
  /\ cancelAcknowledged' = cancelAcknowledged \ {e}
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, runs, runEffect, leases, projectionCursor,
                  terminalRunEvents, terminalControlEvents, paused, cancelled,
                  completed, failed, recovering, activeVersion, revisionEpoch,
                  effectVersion, revisionPolicy, revisionEvents, EvidenceVars >>

DeriveProjection ==
  /\ ~recovering
  /\ projectionCursor < Len(eventLog)
  /\ projectionCursor' = projectionCursor + 1
  /\ UNCHANGED << eventLog, recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  terminalRunEvents, terminalControlEvents, paused, cancelled,
                  completed, failed, recovering,
                  RevisionVars, EvidenceVars >>

PauseInstance ==
  /\ ~recovering
  /\ InstanceRunning
  /\ ~paused
  /\ paused' = TRUE
  /\ UNCHANGED << eventLog, recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  cancelled, completed, failed, recovering,
                  RevisionVars, EvidenceVars >>

ResumeInstance ==
  /\ ~recovering
  /\ paused
  /\ ~cancelled
  /\ ~completed
  /\ ~failed
  /\ paused' = FALSE
  /\ UNCHANGED << eventLog, recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  cancelled, completed, failed, recovering,
                  RevisionVars, EvidenceVars >>

CancelInstance(ev) ==
  /\ ev \in Events
  /\ ~recovering
  /\ ~completed
  /\ ~failed
  /\ ~cancelled
  /\ cancelled' = TRUE
  /\ paused' = TRUE
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  completed, failed, recovering,
                  RevisionVars, EvidenceVars >>

CompleteWorkflow(ev) ==
  /\ ev \in Events
  /\ ~recovering
  /\ InstanceRunning
  /\ completed' = TRUE
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, failed, recovering,
                  RevisionVars, EvidenceVars >>

FailWorkflow(ev) ==
  /\ ev \in Events
  /\ ~recovering
  /\ InstanceRunning
  /\ failed' = TRUE
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, completed, recovering,
                  RevisionVars, EvidenceVars >>

OldVersionEffect(e) ==
  effectVersion[e] # activeVersion

ActivateRevision(newVersion, policy, ev) ==
  /\ newVersion \in Versions
  /\ policy \in RevisionPolicies
  /\ ev \in Events
  /\ ~recovering
  /\ InstanceRunning
  /\ newVersion # activeVersion
  /\ revisionPolicy' = [revisionPolicy EXCEPT ![activeVersion] = policy]
  /\ activeVersion' = newVersion
  /\ revisionEpoch' = revisionEpoch + 1
  /\ revisionEvents' = Append(revisionEvents, ev)
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, completed, failed, recovering,
                  effectVersion, cancelRequested, cancelAcknowledged, EvidenceVars >>

TerminalCancelQueuedRevisionEffect(e, ev) ==
  /\ e \in Effects
  /\ ev \in Events
  /\ ~recovering
  /\ InstanceRunning
  /\ OldVersionEffect(e)
  /\ revisionPolicy[effectVersion[e]] \in {"cancelQueued", "requestRunning"}
  /\ effects[e] \in {"queued", "blocked"}
  /\ e \notin terminalEffects
  /\ effects' = [effects EXCEPT ![e] = "cancelled"]
  /\ terminalEffects' = terminalEffects \cup {e}
  /\ terminalControlEvents' = Append(terminalControlEvents, <<e, "cancelled">>)
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, runs, runEffect, leases, projectionCursor,
                  terminalRunEvents, paused, cancelled, completed, failed,
                  recovering, activeVersion, revisionEpoch, effectVersion,
                  cancelRequested, cancelAcknowledged, revisionPolicy,
                  revisionEvents, EvidenceVars >>

RequestCancelEffect(e, ev) ==
  /\ e \in Effects
  /\ ev \in Events
  /\ ~recovering
  /\ InstanceRunning
  /\ OldVersionEffect(e)
  /\ revisionPolicy[effectVersion[e]] = "requestRunning"
  /\ e \in RequestableEffects
  /\ effects[e] \in {"claimed", "running"}
  /\ e \notin terminalEffects
  /\ cancelRequested' = cancelRequested \cup {e}
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, completed, failed,
                  recovering, activeVersion, revisionEpoch, effectVersion,
                  cancelAcknowledged, revisionPolicy, revisionEvents, EvidenceVars >>

AcknowledgeCancelRun(r, ev) ==
  /\ r \in Runs
  /\ ev \in Events
  /\ ~recovering
  /\ runs[r] = "running"
  /\ runEffect[r] \in cancelRequested
  /\ runEffect[r] \notin terminalEffects
  /\ cancelAcknowledged' = cancelAcknowledged \cup {runEffect[r]}
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases,
                  terminalEffects, projectionCursor, terminalRunEvents,
                  terminalControlEvents, paused, cancelled, completed, failed,
                  recovering, activeVersion, revisionEpoch, effectVersion,
                  cancelRequested, revisionPolicy, revisionEvents, EvidenceVars >>

IgnoreLateCancelAfterTerminal(e) ==
  /\ e \in Effects
  /\ ~recovering
  /\ e \in terminalEffects
  /\ e \in cancelRequested
  /\ cancelRequested' = cancelRequested \ {e}
  /\ UNCHANGED << eventLog, recoveryLog, effects, runs, runEffect, leases,
                  terminalEffects, projectionCursor, terminalRunEvents,
                  terminalControlEvents, paused, cancelled,
                  completed, failed, recovering, activeVersion, revisionEpoch,
                  effectVersion, cancelAcknowledged, revisionPolicy,
                  revisionEvents, EvidenceVars >>

StartRecovery ==
  /\ ~recovering
  /\ recovering' = TRUE
  /\ recoveryLog' = eventLog
  /\ UNCHANGED << eventLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, completed, failed, RevisionVars, EvidenceVars >>

FinishRecovery ==
  /\ recovering
  /\ eventLog' = recoveryLog
  /\ projectionCursor' = Len(recoveryLog)
  /\ recovering' = FALSE
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  terminalRunEvents, terminalControlEvents, paused, cancelled,
                  completed, failed, RevisionVars, EvidenceVars >>

\* Recovery resolution for a run that started its external side effect but whose
\* worker crashed before the terminal was appended. The provider has no idempotent
\* re-query here, so the effect resolves to a single `uncertain` terminal rather
\* than being silently re-executed (admission-and-idempotency.md exactly-once).
\* The event is appended to both logs so it survives FinishRecovery and the
\* RecoveryDoesNotReorderEventLog invariant (eventLog = recoveryLog) holds.
ResolveUncertainRun(r, ev, code) ==
  /\ r \in Runs
  /\ ev \in Events
  /\ code \in TerminalDiagnosticCodeDomain
  /\ recovering
  /\ runs[r] = "running"
  /\ runEffect[r] \notin terminalEffects
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "failed"]
  /\ runs' = [runs EXCEPT ![r] = "uncertain"]
  /\ leases' = [leases EXCEPT ![r] = "released"]
  /\ terminalEffects' = terminalEffects \cup {runEffect[r]}
  /\ terminalRunEvents' = Append(terminalRunEvents, <<r, runEffect[r], "uncertain">>)
  /\ \/ /\ code = NoTerminalDiagnostic
        /\ terminalDiagnostics' = terminalDiagnostics
     \/ /\ terminalDiagnostics' = Append(terminalDiagnostics, <<r, runEffect[r], code>>)  \* THE DIAGNOSTIC NAMES ITS RUN EFFECT
        /\ code \in CodeShapedTerminalDiagnostics  \* THE TERMINAL DIAGNOSTIC CARRIES A CODE
  /\ eventLog' = Append(eventLog, ev)
  /\ recoveryLog' = Append(recoveryLog, ev)
  /\ UNCHANGED << runEffect, projectionCursor, paused, cancelled, completed,
                  failed, recovering, activeVersion, revisionEpoch, effectVersion,
                  cancelRequested, cancelAcknowledged, revisionPolicy,
                  revisionEvents, terminalControlEvents, denialEvidence,
                  assertionEvidence, deniedEffects >>

\* D12 (assertion failure -> diagnostic/evidence, no user fact/effect mutation).
\* A failing assertion appends the evidence that explains it -- the assertion it
\* names and one of the two REGISTERED assertion codes -- and settles nothing:
\* every effect, run, lease and terminal set is UNCHANGED, so the denial half and
\* the evidence half are one step. `AssertionSubjectDomain` carries a nameless
\* subject and `AssertionCodeDomain` an unregistered code, so both guards below
\* are load-bearing.
FailAssertion(a, code, ev) ==
  /\ a \in AssertionSubjectDomain
  /\ code \in AssertionCodeDomain
  /\ ev \in Events
  /\ ~recovering
  /\ InstanceRunning
  /\ a \in Assertions  \* THE EVIDENCE NAMES ITS ASSERTION
  /\ code \in RegisteredAssertionCodes  \* THE ASSERTION CODE IS REGISTERED
  /\ assertionEvidence' = Append(assertionEvidence, <<a, code>>)
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, completed, failed, recovering, RevisionVars,
                  denialEvidence, terminalDiagnostics, deniedEffects >>

Next ==
  \/ \E ev \in Events : AppendEvent(ev)
  \/ \E e \in Effects, r \in Runs : ClaimEffect(e, r)
  \/ \E r \in Runs : StartRun(r)
  \/ \E r \in Runs : BindBlock(r)
  \/ \E e \in Effects, ev \in Events, reason \in DenialReasonDomain,
       code \in DenialCodeDomain : PolicyDenyEffect(e, ev, reason, code)
  \/ \E e \in Effects : UnblockEffect(e)
  \/ \E r \in Runs, ev \in Events : CompleteRun(r, ev)
  \/ \E r \in Runs, ev \in Events, code \in TerminalDiagnosticCodeDomain :
       FailRun(r, ev, code)
  \/ \E r \in Runs, ev \in Events : CancelAcknowledgedRun(r, ev)
  \/ \E r \in Runs, ev \in Events, code \in TerminalDiagnosticCodeDomain :
       TimeoutRun(r, ev, code)
  \/ \E r \in Runs, ev \in Events : ExpireLease(r, ev)
  \/ \E e \in Effects, ev \in Events : RetryEffect(e, ev)
  \/ DeriveProjection
  \/ PauseInstance
  \/ ResumeInstance
  \/ \E ev \in Events : CancelInstance(ev)
  \/ \E ev \in Events : CompleteWorkflow(ev)
  \/ \E ev \in Events : FailWorkflow(ev)
  \/ \E newVersion \in Versions, policy \in RevisionPolicies, ev \in Events :
       ActivateRevision(newVersion, policy, ev)
  \/ \E e \in Effects, ev \in Events : TerminalCancelQueuedRevisionEffect(e, ev)
  \/ \E e \in Effects, ev \in Events : RequestCancelEffect(e, ev)
  \/ \E r \in Runs, ev \in Events : AcknowledgeCancelRun(r, ev)
  \/ \E e \in Effects : IgnoreLateCancelAfterTerminal(e)
  \/ StartRecovery
  \/ FinishRecovery
  \/ \E r \in Runs, ev \in Events, code \in TerminalDiagnosticCodeDomain :
       ResolveUncertainRun(r, ev, code)
  \/ \E a \in AssertionSubjectDomain, code \in AssertionCodeDomain, ev \in Events :
       FailAssertion(a, code, ev)

Spec ==
  Init /\ [][Next]_vars

ClaimAny(e) ==
  \E r \in Runs : ClaimEffect(e, r)

StartAny(e) ==
  \E r \in Runs :
    /\ runEffect[r] = e
    /\ StartRun(r)

ProviderTerminalOrRecovered(e) ==
  \E r \in Runs, ev \in Events, code \in TerminalDiagnosticCodeDomain :
    /\ runEffect[r] = e
    /\ \/ CompleteRun(r, ev)
       \/ FailRun(r, ev, code)
       \/ CancelAcknowledgedRun(r, ev)
       \/ TimeoutRun(r, ev, code)
       \/ ExpireLease(r, ev)

FairSpec ==
  /\ Spec
  /\ WF_vars(DeriveProjection)
  /\ WF_vars(FinishRecovery)
  /\ \A e \in Effects :
       /\ WF_vars(ClaimAny(e))
       /\ WF_vars(StartAny(e))
       /\ WF_vars(ProviderTerminalOrRecovered(e))

EveryRunReferencesEffect ==
  \A r \in Runs : runEffect[r] \in Effects

NoRunWithoutRunningEffect ==
  \A r \in Runs :
    runs[r] = "running" => effects[runEffect[r]] = "running"

NoClaimedRunWithoutClaimedEffect ==
  \A r \in Runs :
    runs[r] = "claimed" => effects[runEffect[r]] = "claimed"

NoClaimableEffectHasUnsatisfiedDeps ==
  \A e \in Effects :
    Claimable(e) => ~EffectHasUnsatisfiedDeps(e)

NoNewEffectfulWorkWhilePaused ==
  paused => \A e \in Effects : ~Claimable(e)

TerminalEffectSetMatchesCurrentStatus ==
  \A e \in Effects :
    (e \in terminalEffects) <=> effects[e] \in {"completed", "failed", "timed_out", "cancelled"}

ProjectionCursorWithinLog ==
  projectionCursor <= Len(eventLog)

RecoveryDoesNotReorderEventLog ==
  recovering => eventLog = recoveryLog

NoActiveLeaseWithoutRunningRun ==
  \A r \in Runs :
    leases[r] = "active" => /\ runs[r] = "running"
                             /\ effects[runEffect[r]] = "running"

\* A binding-blocked effect is recoverable, never terminal (DR-0020). A
\* misspecified BindBlock that fabricated a terminal outcome would violate this
\* together with TerminalEffectSetMatchesCurrentStatus.
BlockedEffectIsNotTerminal ==
  \A e \in Effects : effects[e] = "blocked" => e \notin terminalEffects

\* A blocked effect holds no live run or active lease: BindBlock released them, so
\* the effect can be re-claimed once UnblockEffect requeues it.
BlockedEffectHasNoLiveRun ==
  \A r \in Runs :
    effects[runEffect[r]] = "blocked" =>
      /\ runs[r] \notin {"claimed", "running"}
      /\ leases[r] # "active"

NoRunningRunWithoutActiveLease ==
  \A r \in Runs :
    runs[r] = "running" => /\ leases[r] = "active"
                            /\ effects[runEffect[r]] = "running"

NoTerminalRunHasActiveLease ==
  \A r \in Runs :
    runs[r] \in {"completed", "failed", "timed_out", "cancelled", "lease_expired", "uncertain"}
      => leases[r] # "active"

NoReleasedLeaseWithoutTerminalRun ==
  \A r \in Runs :
    leases[r] = "released" => runs[r] \in {"completed", "failed", "timed_out", "cancelled", "uncertain"}

\* Concurrent-worker safety: at most one run is executing (claimed/running) a
\* given effect at any instant. A whip worker may execute the ready set of
\* effects concurrently (a bounded thread pool), and several worker processes may
\* run against one instance; this invariant is the guarantee that lets that be
\* safe -- no external effect is ever executed by two runs at once. It holds
\* because `Claimable(e)` requires `effects[e] = "queued"` and `ClaimEffect`
\* flips the effect to "claimed", so a second concurrent claim for the same
\* effect cannot fire. (Bite: drop the `effects[e] = "queued"` guard from
\* Claimable and Apalache reports this invariant violated.)
AtMostOneRunExecutingEffect ==
  \A e \in Effects :
    Cardinality({ r \in Runs : runEffect[r] = e /\ runs[r] \in {"claimed", "running"} }) <= 1

\* Admission/idempotency contract (admission-and-idempotency.md): exactly-once
\* external effect. A run that recorded a terminal -- including an `uncertain`
\* recovery resolution of a started-without-terminal run -- never reverts to an
\* executing status, so its external side effect is never silently re-executed.
\* A retry of the effect is a fresh run (ClaimEffect requires run status "none"),
\* not a re-run of the terminaled one. With NoDuplicateTerminalRunEvents this
\* gives: each started run resolves to exactly one terminal and runs at most once.
TerminaledRunStaysTerminal ==
  \A i \in 1..Len(terminalRunEvents) :
    runs[terminalRunEvents[i][1]] \in TerminalRunStatuses

ActiveLeaseForEffect(e) ==
  \E r \in Runs :
    /\ runEffect[r] = e
    /\ runs[r] = "running"
    /\ leases[r] = "active"

EffectTerminalOrNotRunning(e) ==
  \/ effects[e] \in {"blocked", "policy_denied", "claimed"}
  \/ e \in terminalEffects
  \/ paused
  \/ cancelled
  \/ completed
  \/ failed
  \/ recovering

ClaimableEffectEventuallyRunsOrStops(e) ==
  [](Claimable(e) => <>(effects[e] = "running" \/ EffectTerminalOrNotRunning(e)))

RunningEffectEventuallyTerminalsOrRecovers(e) ==
  [](effects[e] = "running" /\ ActiveLeaseForEffect(e) =>
      <>(e \in terminalEffects \/ effects[e] = "queued" \/ cancelled \/ completed \/ failed \/ recovering))

ProjectionEventuallyCatchesUp ==
  [](~recovering /\ projectionCursor < Len(eventLog) =>
      <>(projectionCursor = Len(eventLog) \/ recovering))

RecoveryEventuallyFinishes ==
  [](recovering => <>~recovering)

LivenessGoals ==
  /\ \A e \in Effects : ClaimableEffectEventuallyRunsOrStops(e)
  /\ \A e \in Effects : RunningEffectEventuallyTerminalsOrRecovers(e)
  /\ ProjectionEventuallyCatchesUp
  /\ RecoveryEventuallyFinishes

EventSeqOk(seq) ==
  \A i \in 1..Len(seq) : seq[i] \in Events

\* @type: (Seq(<<Str, Str, Str>>)) => Bool;
TerminalRunEventSeqOk(seq) ==
  \A i \in 1..Len(seq) :
    /\ seq[i][1] \in Runs
    /\ seq[i][2] \in Effects
    /\ seq[i][3] \in TerminalRunStatuses

\* @type: (Seq(<<Str, Str>>)) => Bool;
TerminalControlEventSeqOk(seq) ==
  \A i \in 1..Len(seq) :
    /\ seq[i][1] \in Effects
    /\ seq[i][2] \in TerminalEffectStatuses

\* @type: (Seq(<<Str, Str, Str>>)) => Bool;
DenialEvidenceSeqOk(seq) ==
  \A i \in 1..Len(seq) :
    /\ seq[i][1] \in Effects
    /\ seq[i][2] \in DenialReasonDomain
    /\ seq[i][3] \in DenialCodeDomain

\* @type: (Seq(<<Str, Str>>)) => Bool;
AssertionEvidenceSeqOk(seq) ==
  \A i \in 1..Len(seq) :
    /\ seq[i][1] \in AssertionSubjectDomain
    /\ seq[i][2] \in AssertionCodeDomain

\* @type: (Seq(<<Str, Str, Str>>)) => Bool;
TerminalDiagnosticSeqOk(seq) ==
  \A i \in 1..Len(seq) :
    /\ seq[i][1] \in Runs
    /\ seq[i][2] \in Effects
    /\ seq[i][3] \in TerminalDiagnosticCodeDomain

TypeOk ==
  /\ EventSeqOk(eventLog)
  /\ EventSeqOk(recoveryLog)
  /\ EventSeqOk(revisionEvents)
  /\ TerminalRunEventSeqOk(terminalRunEvents)
  /\ TerminalControlEventSeqOk(terminalControlEvents)
  /\ DenialEvidenceSeqOk(denialEvidence)
  /\ AssertionEvidenceSeqOk(assertionEvidence)
  /\ TerminalDiagnosticSeqOk(terminalDiagnostics)
  /\ deniedEffects \subseteq Effects
  /\ RequestableEffects \subseteq Effects
  /\ effects \in [Effects -> EffectStatuses]
  /\ runs \in [Runs -> RunStatuses]
  /\ runEffect \in [Runs -> Effects]
  /\ leases \in [Runs -> LeaseStatuses]
  /\ terminalEffects \subseteq Effects
  /\ projectionCursor \in Nat
  /\ paused \in BOOLEAN
  /\ cancelled \in BOOLEAN
  /\ completed \in BOOLEAN
  /\ failed \in BOOLEAN
  /\ recovering \in BOOLEAN
  /\ activeVersion \in Versions
  /\ revisionEpoch \in Nat
  /\ effectVersion \in [Effects -> Versions]
  /\ cancelRequested \subseteq Effects
  /\ cancelAcknowledged \subseteq Effects
  /\ revisionPolicy \in [Versions -> RevisionPolicies]

RevisionEpochMatchesEvents ==
  revisionEpoch = Len(revisionEvents)

CancelRequestIsNotTerminalByItself ==
  \A e \in cancelRequested :
    effects[e] = "cancelled" => e \in terminalEffects

CancellationAcknowledgementDoesNotFabricateTerminal ==
  \A e \in cancelAcknowledged :
    e \notin terminalEffects => effects[e] = "running"

NoDuplicateTerminalRunEvents ==
  \A i, j \in 1..Len(terminalRunEvents) :
    terminalRunEvents[i][1] = terminalRunEvents[j][1] => i = j

NoDuplicateTerminalControlEvents ==
  \A i, j \in 1..Len(terminalControlEvents) :
    terminalControlEvents[i][1] = terminalControlEvents[j][1] => i = j

NoConflictingInstanceTerminalStates ==
  /\ ~(cancelled /\ completed)
  /\ ~(cancelled /\ failed)
  /\ ~(completed /\ failed)

NoNewEffectfulWorkAfterTerminalInstance ==
  (cancelled \/ completed \/ failed) => \A e \in Effects : ~Claimable(e)

\* -- D12 runtime diagnostic adequacy: the EVIDENCE half ------------------------
\*
\* The invariants above say the denied work does not happen. These say the log
\* explains why. Each is paired one-for-one with a richer invariant in the Rust
\* trace checker through models/trace-invariant-correspondence.tsv; the shared
\* claim is stated in the comment on each pair.

\* An effect the ADMISSION GATE denied has a record saying so. The denial is
\* never silent, so "no provider run" is always accompanied by the reason there
\* was none. Scoped to `policy_denied` and not to `blocked`, because a
\* worker-time binding block (`BindBlock`) owes no denial evidence and the Rust
\* checker demands none from it either -- the two planes must forbid the same
\* thing. Supporting invariant only: it has no correspondence row, because it is
\* a claim about the model's own shape (no future action may reach
\* `policy_denied` without writing evidence), not a claim a trace can falsify.
\* Non-vacuity of the rows below is carried by the witness invariants instead.
EveryPolicyDeniedEffectHasDenialEvidence ==
  \A e \in Effects :
    effects[e] = "policy_denied" => e \in deniedEffects

\* SHARED CLAIM (tsv row `capability_denial_names_subject`): a policy denial's
\* record NAMES the subject it refused -- the capability or the profile -- not
\* merely that something was denied. Rust counterpart: trace.rs rejects an
\* `EffectBlocked` whose reason quotes no subject, for every block status it does
\* not recognise as a non-denial (capacity, dependency, binding). That is an
\* exclusion rather than an allowlist so the Rust side keeps quantifying over as
\* much as this invariant does when the store grows a new denial.
DenialEvidenceNamesItsSubject ==
  \A i \in 1..Len(denialEvidence) :
    denialEvidence[i][2] \in NamedDenialReasons

\* SHARED CLAIM (tsv row `denial_diagnostic_code_registered`): when a denial
\* carries a diagnostic id, the id is a REGISTERED runtime diagnostic code --
\* this is what makes script disablement read as `security.script_disabled`
\* rather than as prose. Rust counterpart: trace.rs rejects an `EffectBlocked`
\* whose reason carries a `<domain>.<id>:` prefix that is not a registered code.
DenialEvidenceCodeIsRegistered ==
  \A i \in 1..Len(denialEvidence) :
    denialEvidence[i][3] \in RegisteredDenialCodes

\* SHARED CLAIM (tsv row `script_denial_carries_disabled_code`): the denial of a
\* `script.*` capability IS the "scripts are disabled" state, and it says so --
\* it carries the `security.script_disabled` id and not merely some registered
\* id. This is the claim that pins the spelling; `DenialEvidenceCodeIsRegistered`
\* above admits the empty code and so cannot. Rust counterpart: trace.rs rejects
\* an `EffectBlocked` whose named subject is a `script.*` capability and whose
\* reason does not carry the `security.script_disabled:` prefix.
ScriptDenialCarriesItsDiagnosticId ==
  \A i \in 1..Len(denialEvidence) :
    denialEvidence[i][2] = "scriptCapabilityNotBound" =>
      denialEvidence[i][3] = "securityScriptDisabled"

\* SHARED CLAIM (tsv row `assertion_failure_evidence`): a failing assertion's
\* evidence NAMES a real assertion, so the log says WHICH expectation was not
\* met rather than only that one was not. The Rust counterpart reads the event
\* payload's `assertion_id`, which a store can leave empty.
AssertionFailureNamesItsAssertion ==
  \A i \in 1..Len(assertionEvidence) :
    assertionEvidence[i][1] \in Assertions

\* TLA-ONLY (no correspondence row, deliberately): that same evidence carries one
\* of the two registered assertion diagnostic codes. There is no Rust counterpart
\* because there is nothing in the store log for one to read: the
\* `assertion.failed`/`assertion.errored` event payload carries no code field and
\* its `diagnostic_ids` is hardcoded `[]`, so the registered code lives only in
\* the `diagnostics` side table, which no event points into. A trace checker
\* could only re-derive the code from the event type it just matched -- a check
\* no runtime state could ever fail, which is why `check_record` deliberately
\* ignores the code and the corresponding conjunct was removed rather than kept
\* as a tautology. The runtime behaviour is held instead by store-level tests
\* that assert the persisted diagnostic's code. Carrying the code (or the
\* diagnostic link) in the event payload is the runtime change that would let the
\* trace plane pin it; see spec/error-handling.md for the recorded gap.
AssertionFailureCarriesRegisteredCode ==
  \A i \in 1..Len(assertionEvidence) :
    assertionEvidence[i][2] \in RegisteredAssertionCodes

\* SHARED CLAIM (tsv row `terminal_diagnostic_carries_code`): WHERE a failed or
\* timed-out provider terminal -- including a recovery's `uncertain` resolution
\* -- records a diagnostic, that diagnostic's code is a CODE: an identifier,
\* never empty and never the message. Conditional on both sides: the model's
\* `NoTerminalDiagnostic` branch appends nothing, and the Rust checker only sees
\* a `ProviderDiagnostic` record where one was persisted. That a terminal
\* records a diagnostic AT ALL is not claimed by either plane and is an open
\* product gap (spec/error-handling.md).
TerminalDiagnosticCarriesCode ==
  \A i \in 1..Len(terminalDiagnostics) :
    terminalDiagnostics[i][3] \in CodeShapedTerminalDiagnostics

\* SHARED CLAIM (tsv row `terminal_diagnostic_names_effect`): a terminal
\* diagnostic that exists explains its OWN run's effect -- the subject it names
\* is the effect that run executed, so a failure is never attributed to a
\* bystander. Rust counterpart: trace.rs rejects a `ProviderDiagnostic` whose
\* recorded subject is not the effect the run is executing.
TerminalDiagnosticNamesItsRunEffect ==
  \A i \in 1..Len(terminalDiagnostics) :
    terminalDiagnostics[i][2] = runEffect[terminalDiagnostics[i][1]]

\* -- Vacuity witnesses (scripts/check-tla-models.sh) --------------------------
\*
\* These three are DELIBERATELY FALSE of the model and are never conjoined into
\* SafetyInvariants. Each says an evidence log is never written; the gate checks
\* Apalache VIOLATES each one, which is the proof that the evidence invariants
\* above are satisfied non-trivially rather than over an empty log. An invariant
\* quantified over a sequence the spec never appends to is true and proves
\* nothing -- that is the failure this row exists to end.
NoDenialEvidenceWitness ==
  Len(denialEvidence) = 0

NoAssertionEvidenceWitness ==
  Len(assertionEvidence) = 0

NoTerminalDiagnosticWitness ==
  Len(terminalDiagnostics) = 0

ConstInit ==
  /\ Effects = {"effectA", "effectB"}
  /\ Runs = {"runA", "runB"}
  /\ Events = {"eventA", "eventB"}
  /\ Versions = {"version1", "version2"}
  /\ RequestableEffects = {"effectA"}
  /\ Dependencies = {
       <<"effectA", "succeeds", "effectB">>,
       <<"effectA", "fails", "effectB">>,
       <<"effectA", "completes", "effectB">>
     }
  \* Each domain below is a WITNESS SET: it carries the values the guards admit
  \* PLUS one the guards must reject. Without the rejected value the evidence
  \* invariants would hold no matter what the guards did, and the mutation bites
  \* in scripts/check-tla-models.sh would find nothing to report.
  /\ DenialReasonDomain = {"capabilityNotBound", "profileDisallowsCapability",
                           "scriptCapabilityNotBound", "unnamedDenial"}
  /\ DenialCodeDomain = {"", "securityScriptDisabled", "unregisteredDenialCode"}
  /\ Assertions = {"assertionA"}
  \* `noAssertion` is evidence that some assertion failed without saying which:
  \* the value the naming guard must reject.
  /\ AssertionSubjectDomain = {"assertionA", "noAssertion"}
  /\ AssertionCodeDomain = {"assertionFailed", "assertionErrored",
                            "unregisteredAssertionCode"}
  \* Carries `noDiagnostic` (the terminal that records none -- a real runtime
  \* state, not a rejected value) alongside two codes the guard admits and two
  \* shapes it must reject.
  /\ TerminalDiagnosticCodeDomain = {"nonzeroExit", "schemaCoerceFailed", "",
                                     "proseDiagnostic", "noDiagnostic"}

SafetyInvariants ==
  /\ TypeOk
  /\ EveryRunReferencesEffect
  /\ NoRunWithoutRunningEffect
  /\ NoClaimedRunWithoutClaimedEffect
  /\ NoClaimableEffectHasUnsatisfiedDeps
  /\ NoNewEffectfulWorkWhilePaused
  /\ NoNewEffectfulWorkAfterTerminalInstance
  /\ NoConflictingInstanceTerminalStates
  /\ TerminalEffectSetMatchesCurrentStatus
  /\ ProjectionCursorWithinLog
  /\ RecoveryDoesNotReorderEventLog
  /\ RevisionEpochMatchesEvents
  /\ CancelRequestIsNotTerminalByItself
  /\ CancellationAcknowledgementDoesNotFabricateTerminal
  /\ NoDuplicateTerminalRunEvents
  /\ NoDuplicateTerminalControlEvents
  /\ NoActiveLeaseWithoutRunningRun
  /\ BlockedEffectIsNotTerminal
  /\ BlockedEffectHasNoLiveRun
  /\ NoRunningRunWithoutActiveLease
  /\ NoTerminalRunHasActiveLease
  /\ NoReleasedLeaseWithoutTerminalRun
  /\ AtMostOneRunExecutingEffect
  /\ TerminaledRunStaysTerminal
  /\ EveryPolicyDeniedEffectHasDenialEvidence
  /\ DenialEvidenceNamesItsSubject
  /\ DenialEvidenceCodeIsRegistered
  /\ ScriptDenialCarriesItsDiagnosticId
  /\ AssertionFailureNamesItsAssertion
  /\ AssertionFailureCarriesRegisteredCode
  /\ TerminalDiagnosticCarriesCode
  /\ TerminalDiagnosticNamesItsRunEffect

====
