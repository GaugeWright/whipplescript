---- MODULE InstanceSchedulerLifecycle ----
EXTENDS Naturals, Sequences, FiniteSets

\* Instance-level scheduler model for the durable-object runtime (DR-0033, the
\* full-lift of the top-level `dev` fixpoint into a host-agnostic instance step
\* machine). Where `ResumableEffectLifecycle` models ONE external-I/O effect, this
\* models the WHOLE instance: the native `dev` loop is a fixpoint that alternates
\*
\*     rule pass (pure: reads facts/effects, commits ready rules, may spawn
\*                 effects and may reach a workflow terminal)
\*     effect pass (runs each ready effect to a terminal; a terminal becomes a
\*                  fact that can enable more rules)
\*
\* until a full round commits no rule and runs no effect (idle / parked) or the
\* instance reaches a workflow terminal. Re-expressed as a sans-IO step machine,
\* an effect that needs the network suspends with NeedsIo(Http) and the DO host
\* may be evicted mid-fetch (per-effect at-least-once, already proven in
\* ResumableEffectLifecycle). This model abstracts a single effect's fetch rounds
\* to one `effPhase` slot (idle/inflight/evicted) and focuses on the NEW,
\* instance-level obligations the full lift must preserve:
\*
\*   - a workflow terminal is recorded at most once and is ABSORBING (no rule
\*     commits, no effect settles after it);
\*   - the scheduler declares idle (quiesced) ONLY at a genuine fixpoint (no ready
\*     rule, no ready effect, no effect mid-fetch) -- so parking is sound;
\*   - an effect is only ever mid-fetch while the instance is running;
\*   - eviction/resume of a suspended effect never loses or double-counts instance
\*     progress (committed rules / settled effects are bounded by what was
\*     generated -- a resume that re-settled would break the bound).
\*
\* The Maude models cover the local rule/effect rewrites; this TLA+ model covers
\* the asynchronous instance lifecycle (resumable, evictable, terminating).

CONSTANTS
  \* @type: Int;
  MaxRules,
  \* @type: Int;
  MaxEffects,
  \* @type: Int;
  MaxEvicts

VARIABLES
  \* @type: Str;
  instStatus,
  \* @type: Int;
  readyRules,
  \* @type: Int;
  committedRules,
  \* @type: Int;
  readyEffects,
  \* @type: Int;
  settledEffects,
  \* @type: Str;
  effPhase,
  \* @type: Int;
  effEvicts,
  \* @type: Bool;
  quiesced,
  \* @type: Int;
  terminalCount,
  \* @type: Int;
  rulesAtTerminal,
  \* @type: Int;
  ruleGen,
  \* @type: Int;
  effGen,
  \* @type: Str;
  hostMode

vars ==
  << instStatus, readyRules, committedRules, readyEffects, settledEffects,
     effPhase, effEvicts, quiesced, terminalCount, rulesAtTerminal, ruleGen,
     effGen, hostMode >>

InstStatuses == {"running", "terminal"}
EffPhases == {"idle", "inflight", "evicted"}
HostModes == {"native", "do"}

\* Only the durable-object host can lose an in-flight effect (eviction / resume);
\* the native host runs the effect step machine to completion in one pass.
CanEvict == hostMode = "do"

Init ==
  /\ instStatus = "running"
  \* The `external.started` event enables the first ready rule contexts; a
  \* workflow that fires effects before its terminal has ready work of both kinds
  \* outstanding, so seed both pools (a terminal may be reached with an effect
  \* still queued -- the case the absorption invariants must cover).
  /\ readyRules = 2
  /\ committedRules = 0
  /\ readyEffects = 1
  /\ settledEffects = 0
  /\ effPhase = "idle"
  /\ effEvicts = 0
  /\ quiesced = FALSE
  /\ terminalCount = 0
  \* Meaningless until a terminal is reached (read only under instStatus =
  \* "terminal", where ReachTerminal has pinned it to committedRules).
  /\ rulesAtTerminal = 0
  /\ ruleGen = 2
  /\ effGen = 1
  /\ hostMode \in HostModes

\* A pure rule pass commits one ready rule. It may spawn one async effect (bounded
\* by MaxEffects) -- the effect becomes ready for the effect pass. Never fires
\* after a terminal or after the scheduler has parked (both are quiescent).
CommitRule ==
  /\ instStatus = "running"
  /\ ~quiesced
  /\ readyRules > 0
  /\ committedRules < ruleGen        \* cannot commit more than were generated
  /\ committedRules' = committedRules + 1
  /\ readyRules' = readyRules - 1
  /\ \E spawn \in {FALSE, TRUE} :
       IF spawn /\ effGen < MaxEffects
       THEN /\ readyEffects' = readyEffects + 1
            /\ effGen' = effGen + 1
       ELSE /\ readyEffects' = readyEffects
            /\ effGen' = effGen
  /\ UNCHANGED << instStatus, settledEffects, effPhase, effEvicts, quiesced,
                  terminalCount, rulesAtTerminal, ruleGen, hostMode >>

\* A terminal rule commit: the rule pass reaches a workflow terminal. Recorded at
\* most once and only while running with no effect mid-fetch (the rule pass and
\* the effect pass alternate; a terminal is committed in a rule pass). Absorbing:
\* every progress action guards on instStatus = "running".
ReachTerminal ==
  /\ instStatus = "running"
  /\ ~quiesced
  /\ readyRules > 0
  /\ committedRules < ruleGen
  /\ effPhase = "idle"
  /\ committedRules' = committedRules + 1
  /\ readyRules' = readyRules - 1
  /\ instStatus' = "terminal"
  /\ terminalCount' = terminalCount + 1
  /\ rulesAtTerminal' = committedRules + 1
  /\ UNCHANGED << readyEffects, settledEffects, effPhase, effEvicts, quiesced,
                  ruleGen, effGen, hostMode >>

\* The effect pass picks a ready effect that needs the network: it suspends with
\* NeedsIo(Http) (effPhase inflight). Abstracts the per-effect fetch rounds
\* (proven in ResumableEffectLifecycle) to a single slot.
EffectNeedIo ==
  /\ instStatus = "running"
  /\ readyEffects > 0
  /\ effPhase = "idle"
  /\ effPhase' = "inflight"
  /\ effEvicts' = 0
  /\ UNCHANGED << instStatus, readyRules, committedRules, readyEffects,
                  settledEffects, quiesced, terminalCount, rulesAtTerminal,
                  ruleGen, effGen, hostMode >>

\* DO eviction mid-fetch: the in-memory wait is lost; instance progress
\* (committedRules / settledEffects) is UNCHANGED. Bounded by MaxEvicts.
EffectEvict ==
  /\ CanEvict
  /\ effPhase = "inflight"
  /\ effEvicts < MaxEvicts
  /\ effPhase' = "evicted"
  /\ effEvicts' = effEvicts + 1
  /\ UNCHANGED << instStatus, readyRules, committedRules, readyEffects,
                  settledEffects, quiesced, terminalCount, rulesAtTerminal,
                  ruleGen, effGen, hostMode >>

\* Resume after eviction: re-drive the same suspended effect. Still no instance
\* progress until it settles -- the at-least-once retry adds no committed/settled.
EffectResume ==
  /\ CanEvict
  /\ effPhase = "evicted"
  /\ effPhase' = "inflight"
  /\ UNCHANGED << instStatus, readyRules, committedRules, readyEffects,
                  settledEffects, effEvicts, quiesced, terminalCount,
                  rulesAtTerminal, ruleGen, effGen, hostMode >>

\* The effect settles to its terminal. The terminal is projected to a fact that
\* may enable a new ready rule (bounded by MaxRules). Exactly one settle per
\* readied effect -- eviction/resume never reaches this action.
EffectSettle ==
  /\ instStatus = "running"
  /\ effPhase = "inflight"
  /\ settledEffects' = settledEffects + 1
  /\ readyEffects' = readyEffects - 1
  /\ effPhase' = "idle"
  /\ effEvicts' = 0
  /\ \E spawn \in {FALSE, TRUE} :
       IF spawn /\ ruleGen < MaxRules
       THEN /\ readyRules' = readyRules + 1
            /\ ruleGen' = ruleGen + 1
       ELSE /\ readyRules' = readyRules
            /\ ruleGen' = ruleGen
  /\ UNCHANGED << instStatus, committedRules, quiesced, terminalCount,
                  rulesAtTerminal, effGen, hostMode >>

\* The scheduler declares idle (parks) ONLY at a genuine fixpoint: no ready rule,
\* no ready effect, nothing mid-fetch. Parking is absorbing (no further progress).
Quiesce ==
  /\ instStatus = "running"
  /\ ~quiesced
  /\ readyRules = 0
  /\ readyEffects = 0
  /\ effPhase = "idle"
  /\ quiesced' = TRUE
  /\ UNCHANGED << instStatus, readyRules, committedRules, readyEffects,
                  settledEffects, effPhase, effEvicts, terminalCount,
                  rulesAtTerminal, ruleGen, effGen, hostMode >>

Next ==
  \/ CommitRule
  \/ ReachTerminal
  \/ EffectNeedIo
  \/ EffectEvict
  \/ EffectResume
  \/ EffectSettle
  \/ Quiesce

Spec ==
  Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* Fairness + liveness (for completeness, mirroring ResumableEffectLifecycle;
\* the gate checks SafetyInvariants). Bounded evictions + weak fairness on the
\* progress actions drive the fixpoint to a terminal or a park.

FairSpec ==
  /\ Spec
  /\ WF_vars(CommitRule)
  /\ WF_vars(EffectResume)
  /\ WF_vars(EffectSettle)
  /\ WF_vars(Quiesce)

\* An effect that is mid-fetch eventually leaves the inflight/evicted phase (it
\* settles, or on the DO host resumes and settles). No effect strands the
\* instance mid-fetch.
EffectEventuallyResolves ==
  [](effPhase \in {"inflight", "evicted"} => <>(effPhase = "idle"))

\* The instance eventually stops making progress: it reaches a terminal or parks.
SchedulerConverges ==
  <>(instStatus = "terminal" \/ quiesced)

LivenessGoals ==
  /\ EffectEventuallyResolves
  /\ SchedulerConverges

-----------------------------------------------------------------------------
\* Safety invariants.

TypeOk ==
  /\ instStatus \in InstStatuses
  /\ readyRules \in Nat
  /\ committedRules \in Nat
  /\ readyEffects \in Nat
  /\ settledEffects \in Nat
  /\ effPhase \in EffPhases
  /\ effEvicts \in Nat
  /\ quiesced \in BOOLEAN
  /\ terminalCount \in Nat
  /\ rulesAtTerminal \in Nat
  /\ ruleGen \in Nat
  /\ effGen \in Nat
  /\ hostMode \in HostModes

\* A workflow terminal is recorded at most once -- protected by the terminal's
\* absorption (once instStatus flips to "terminal", ReachTerminal is disabled).
\* (Bite: drop the `instStatus = "running"` guard in ReachTerminal so a terminal
\* instance with a ready rule can reach a terminal again -> terminalCount = 2.)
TerminalExactlyOnce ==
  terminalCount <= 1

\* The terminal is absorbing: once reached, no further rule commits. rulesAtTerminal
\* pins committedRules at the terminal, and it never grows afterward.
\* (Bite: drop the `instStatus = "running"` guard on CommitRule so a rule commits
\* after the terminal -> committedRules exceeds rulesAtTerminal.)
TerminalAbsorbing ==
  instStatus = "terminal" =>
    /\ committedRules = rulesAtTerminal
    /\ effPhase = "idle"

\* Parking is sound: the scheduler declares idle only at a genuine fixpoint.
\* (Bite: drop the `readyEffects = 0` guard on Quiesce so it parks with a ready
\* effect outstanding -> this fails.)
QuiesceSound ==
  quiesced =>
    /\ readyRules = 0
    /\ readyEffects = 0
    /\ effPhase = "idle"

\* An effect is only ever mid-fetch while the instance is running.
\* (Bite: drop the `effPhase = "idle"` guard on ReachTerminal so a terminal is
\* committed while an effect is inflight -> effPhase # "idle" with a terminal.)
EffectPhaseImpliesRunning ==
  effPhase # "idle" => instStatus = "running"

\* Progress never exceeds what was generated: eviction/resume adds no committed
\* rule or settled effect, and generation is bounded. This is the heart of the
\* eviction-safety obligation -- a resume that re-settled the effect would push
\* settledEffects past effGen.
\* (Bite: make EffectResume increment settledEffects -> settledEffects > effGen.)
ProgressBounded ==
  /\ committedRules <= ruleGen
  /\ settledEffects <= effGen
  /\ ruleGen <= MaxRules
  /\ effGen <= MaxEffects
  /\ effEvicts <= MaxEvicts

ConstInit ==
  /\ MaxRules = 3
  /\ MaxEffects = 2
  /\ MaxEvicts = 1

SafetyInvariants ==
  /\ TypeOk
  /\ TerminalExactlyOnce
  /\ TerminalAbsorbing
  /\ QuiesceSound
  /\ EffectPhaseImpliesRunning
  /\ ProgressBounded

====
