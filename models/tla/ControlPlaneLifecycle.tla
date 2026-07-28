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
  Dependencies

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
  terminalControlEvents

vars ==
  << eventLog, recoveryLog, effects, runs, runEffect, leases, terminalEffects,
     projectionCursor, paused, cancelled, completed, failed, recovering,
     activeVersion, revisionEpoch, effectVersion, cancelRequested,
     cancelAcknowledged, revisionPolicy, revisionEvents, terminalRunEvents,
     terminalControlEvents >>

RevisionVars ==
  << activeVersion, revisionEpoch, effectVersion, cancelRequested,
     cancelAcknowledged, revisionPolicy, revisionEvents >>

EffectStatuses ==
  {"queued", "blocked", "claimed", "running", "completed",
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
                  recoveryLog, recovering, RevisionVars >>

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
                  completed, failed, recovering, RevisionVars >>

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
                  completed, failed, recovering, RevisionVars >>

\* Worker-time provider-binding failure (missing config/credentials/enforcement/
\* healthy binding): a claimed effect parks back to a non-terminal `blocked`
\* state BEFORE provider execution, releasing its run and lease. Recoverable, not
\* terminal (DR-0020). The categorized reason is a runtime field abstracted away
\* here; the lifecycle guarantee is that this never fabricates a terminal outcome.
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
                  completed, failed, recovering, RevisionVars >>

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
                  paused, cancelled, completed, failed, recovering, RevisionVars >>

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
                  revisionPolicy, revisionEvents, terminalControlEvents >>

FailRun(r, ev) ==
  /\ r \in Runs
  /\ ev \in Events
  /\ ~recovering
  /\ runs[r] = "running"
  /\ runEffect[r] \notin terminalEffects
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "failed"]
  /\ runs' = [runs EXCEPT ![r] = "failed"]
  /\ leases' = [leases EXCEPT ![r] = "released"]
  /\ terminalEffects' = terminalEffects \cup {runEffect[r]}
  /\ terminalRunEvents' = Append(terminalRunEvents, <<r, runEffect[r], "failed">>)
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, runEffect, projectionCursor, paused, cancelled,
                  completed, failed, recovering, activeVersion, revisionEpoch,
                  effectVersion, cancelRequested, cancelAcknowledged,
                  revisionPolicy, revisionEvents, terminalControlEvents >>

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
                  revisionPolicy, revisionEvents, terminalControlEvents >>

TimeoutRun(r, ev) ==
  /\ r \in Runs
  /\ ev \in Events
  /\ ~recovering
  /\ runs[r] = "running"
  /\ runEffect[r] \notin terminalEffects
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "timed_out"]
  /\ runs' = [runs EXCEPT ![r] = "timed_out"]
  /\ leases' = [leases EXCEPT ![r] = "released"]
  /\ terminalEffects' = terminalEffects \cup {runEffect[r]}
  /\ terminalRunEvents' = Append(terminalRunEvents, <<r, runEffect[r], "timed_out">>)
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, runEffect, projectionCursor, paused, cancelled,
                  completed, failed, recovering, activeVersion, revisionEpoch,
                  effectVersion, cancelRequested, cancelAcknowledged,
                  revisionPolicy, revisionEvents, terminalControlEvents >>

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
                  cancelRequested, revisionPolicy, revisionEvents >>

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
                  effectVersion, revisionPolicy, revisionEvents >>

DeriveProjection ==
  /\ ~recovering
  /\ projectionCursor < Len(eventLog)
  /\ projectionCursor' = projectionCursor + 1
  /\ UNCHANGED << eventLog, recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  terminalRunEvents, terminalControlEvents, paused, cancelled,
                  completed, failed, recovering,
                  RevisionVars >>

PauseInstance ==
  /\ ~recovering
  /\ InstanceRunning
  /\ ~paused
  /\ paused' = TRUE
  /\ UNCHANGED << eventLog, recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  cancelled, completed, failed, recovering,
                  RevisionVars >>

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
                  RevisionVars >>

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
                  RevisionVars >>

CompleteWorkflow(ev) ==
  /\ ev \in Events
  /\ ~recovering
  /\ InstanceRunning
  /\ completed' = TRUE
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, failed, recovering,
                  RevisionVars >>

FailWorkflow(ev) ==
  /\ ev \in Events
  /\ ~recovering
  /\ InstanceRunning
  /\ failed' = TRUE
  /\ eventLog' = Append(eventLog, ev)
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, completed, recovering,
                  RevisionVars >>

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
                  effectVersion, cancelRequested, cancelAcknowledged >>

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
                  revisionEvents >>

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
                  cancelAcknowledged, revisionPolicy, revisionEvents >>

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
                  cancelRequested, revisionPolicy, revisionEvents >>

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
                  revisionEvents >>

StartRecovery ==
  /\ ~recovering
  /\ recovering' = TRUE
  /\ recoveryLog' = eventLog
  /\ UNCHANGED << eventLog, effects, runs, runEffect, leases, terminalEffects,
                  projectionCursor, terminalRunEvents, terminalControlEvents,
                  paused, cancelled, completed, failed, RevisionVars >>

FinishRecovery ==
  /\ recovering
  /\ eventLog' = recoveryLog
  /\ projectionCursor' = Len(recoveryLog)
  /\ recovering' = FALSE
  /\ UNCHANGED << recoveryLog, effects, runs, runEffect, leases, terminalEffects,
                  terminalRunEvents, terminalControlEvents, paused, cancelled,
                  completed, failed, RevisionVars >>

\* Recovery resolution for a run that started its external side effect but whose
\* worker crashed before the terminal was appended. The provider has no idempotent
\* re-query here, so the effect resolves to a single `uncertain` terminal rather
\* than being silently re-executed (admission-and-idempotency.md exactly-once).
\* The event is appended to both logs so it survives FinishRecovery and the
\* RecoveryDoesNotReorderEventLog invariant (eventLog = recoveryLog) holds.
ResolveUncertainRun(r, ev) ==
  /\ r \in Runs
  /\ ev \in Events
  /\ recovering
  /\ runs[r] = "running"
  /\ runEffect[r] \notin terminalEffects
  /\ effects' = [effects EXCEPT ![runEffect[r]] = "failed"]
  /\ runs' = [runs EXCEPT ![r] = "uncertain"]
  /\ leases' = [leases EXCEPT ![r] = "released"]
  /\ terminalEffects' = terminalEffects \cup {runEffect[r]}
  /\ terminalRunEvents' = Append(terminalRunEvents, <<r, runEffect[r], "uncertain">>)
  /\ eventLog' = Append(eventLog, ev)
  /\ recoveryLog' = Append(recoveryLog, ev)
  /\ UNCHANGED << runEffect, projectionCursor, paused, cancelled, completed,
                  failed, recovering, activeVersion, revisionEpoch, effectVersion,
                  cancelRequested, cancelAcknowledged, revisionPolicy,
                  revisionEvents, terminalControlEvents >>

Next ==
  \/ \E ev \in Events : AppendEvent(ev)
  \/ \E e \in Effects, r \in Runs : ClaimEffect(e, r)
  \/ \E r \in Runs : StartRun(r)
  \/ \E r \in Runs : BindBlock(r)
  \/ \E e \in Effects : UnblockEffect(e)
  \/ \E r \in Runs, ev \in Events : CompleteRun(r, ev)
  \/ \E r \in Runs, ev \in Events : FailRun(r, ev)
  \/ \E r \in Runs, ev \in Events : CancelAcknowledgedRun(r, ev)
  \/ \E r \in Runs, ev \in Events : TimeoutRun(r, ev)
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
  \/ \E r \in Runs, ev \in Events : ResolveUncertainRun(r, ev)

Spec ==
  Init /\ [][Next]_vars

ClaimAny(e) ==
  \E r \in Runs : ClaimEffect(e, r)

StartAny(e) ==
  \E r \in Runs :
    /\ runEffect[r] = e
    /\ StartRun(r)

ProviderTerminalOrRecovered(e) ==
  \E r \in Runs, ev \in Events :
    /\ runEffect[r] = e
    /\ \/ CompleteRun(r, ev)
       \/ FailRun(r, ev)
       \/ CancelAcknowledgedRun(r, ev)
       \/ TimeoutRun(r, ev)
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
  \/ effects[e] \in {"blocked", "claimed"}
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

TypeOk ==
  /\ EventSeqOk(eventLog)
  /\ EventSeqOk(recoveryLog)
  /\ EventSeqOk(revisionEvents)
  /\ TerminalRunEventSeqOk(terminalRunEvents)
  /\ TerminalControlEventSeqOk(terminalControlEvents)
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

====
