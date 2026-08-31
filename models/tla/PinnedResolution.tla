---- MODULE PinnedResolution ----
EXTENDS Naturals

\* DR-0068: the runner protocol — resolve the ref ONCE at its authority, pin the
\* cut id, and hold that pin against collection for the run's duration
\* (refining whipplescript-store/src/branches.rs `attach_cut_log_heads`,
\* `list_events_pinned`, and `preflight::preflight_manifest`).
\*
\* The forcing scenario, stated in DR-0068's problem section: a set of runners
\* triggers off a particular version and the content they pull is not the content
\* published for that version. Content addressing does not prevent this on its
\* own — it prevents wrong BYTES for a correct NAME, and every remaining failure
\* is about how the name was obtained and whether its closure survives.
\*
\* Two guards, two failures, and unlike DR-0067's pair these are both plain state
\* properties rather than history variables — the divergence is observable in the
\* state itself, so no instrumentation is needed to give the invariants teeth:
\*
\*   Resolve from the TRIGGER  -- not from the ref. A runner that resolves the
\*                                name itself picks up whatever the ref holds at
\*                                the moment it looks, so two runners fired by
\*                                one event can run different worlds, each
\*                                internally consistent and neither able to tell.
\*   Collect only what is UNPINNED -- a run that started valid must not become
\*                                invalid underneath itself.
\*
\* Cut ids are modeled as naturals, with 0 meaning "none". Their ordering carries
\* no meaning beyond distinctness; what matters is only whether two runners hold
\* the same one.

CONSTANTS
  \* @type: Set(Str);
  Runners,
  \* @type: Int;
  MaxCut

VARIABLES
  \* The mutable name. Advancing it is ordinary mainline movement, not a fault.
  \* @type: Int;
  ref,
  \* The cut id the trigger event carries. Dispatch resolves the ref exactly
  \* once, at its authority, and stamps the result here; 0 before it fires.
  \* @type: Int;
  triggerCut,
  \* What each runner resolved, 0 if it has not yet.
  \* @type: Str -> Int;
  resolved,
  \* Cut ids held against collection by a running runner.
  \* @type: Set(Int);
  pinned,
  \* Cut ids whose closure has been reclaimed.
  \* @type: Set(Int);
  collected,
  \* Cut ids whose pin LAPSED — the lease ran out while the cut was still
  \* named. Recorded rather than merely un-pinned, and that distinction is the
  \* whole repair: see `ExpirePin`.
  \* @type: Set(Int);
  lapsed,
  \* Runners currently executing. A runner enters when it resolves and LEAVES
  \* when its lease lapses — the refusal DR-0068 §5 asks for, modeled as the
  \* thing it actually is: the run stops.
  \* @type: Set(Str);
  running

vars == << ref, triggerCut, resolved, pinned, collected, lapsed, running >>

TypeOK ==
  /\ ref \in 0..MaxCut
  /\ triggerCut \in 0..MaxCut
  /\ resolved \in [Runners -> 0..MaxCut]
  /\ pinned \subseteq 0..MaxCut
  /\ collected \subseteq 0..MaxCut
  /\ lapsed \subseteq 0..MaxCut
  /\ running \subseteq Runners

Init ==
  /\ ref = 1
  /\ triggerCut = 0
  /\ resolved = [r \in Runners |-> 0]
  /\ pinned = {}
  /\ collected = {}
  /\ lapsed = {}
  /\ running = {}

\* Mainline moves. Perfectly legitimate, and precisely what makes late
\* resolution dangerous: nothing about this step is a fault.
AdvanceRef ==
  /\ ref < MaxCut
  /\ ref' = ref + 1
  /\ UNCHANGED << triggerCut, resolved, pinned, collected, lapsed, running >>

\* Dispatch resolves the ref ONCE, stamps the cut id into the trigger, AND takes
\* the pin in the same step. After this the run names an immutable object and
\* nothing about its inputs can drift.
\*
\* Pinning here rather than at Resolve is a correction this model forced, not a
\* modeling convenience. DR-0068 §5 said "a run pins its closure for its
\* duration", which reads as the runner pinning when it starts — and that leaves
\* a window between the trigger naming a cut and the runner picking it up, in
\* which nothing holds the closure. Apalache found it in three steps: collect a
\* cut, then fire a trigger that names it, then resolve. Every runner then
\* agrees, preflight is the only thing standing between them and a reclaimed
\* world, and preflight is a check rather than a hold.
FireTrigger ==
  /\ triggerCut = 0
  /\ triggerCut' = ref
  /\ pinned' = pinned \cup {ref}                       \* PIN AT DISPATCH
  /\ UNCHANGED << ref, resolved, collected, lapsed, running >>

\* A runner takes its cut FROM THE TRIGGER. It does not consult the ref, which
\* is the whole of DR-0068 §1.
Resolve(r) ==
  /\ triggerCut # 0
  /\ triggerCut \notin lapsed                          \* REFUSE A LAPSED CUT
  /\ resolved[r] = 0
  /\ resolved' = [resolved EXCEPT ![r] = triggerCut]   \* RESOLVE FROM THE TRIGGER
  /\ running' = running \cup {r}
  /\ UNCHANGED << ref, triggerCut, pinned, collected, lapsed >>

\* Reclamation. Two guards, because two different things make a cut reachable:
\* a run holding it, and the mutable name still pointing at it. DR-0066's fifth
\* refusal is "no collection without a reachability proof", and the live ref is
\* the most trivial proof there is.
\* `c < ref` carries two conditions at once, and both are real. A cut only
\* EXISTS once the ref has reached it, so `c > ref` names nothing; and the live
\* ref is trivially reachable, so `c = ref` is refused too.
Collect(c) ==
  /\ c \in 1..MaxCut
  /\ c \notin pinned                                   \* COLLECT ONLY UNPINNED
  /\ c < ref                                           \* EXISTS, AND NOT THE LIVE REF
  /\ collected' = collected \cup {c}
  /\ UNCHANGED << ref, triggerCut, resolved, pinned, lapsed, running >>

\* A pin LAPSES. This is not a fault injected to see what breaks: `branches.rs`
\* implements pins with an `expires_at`, and `pinned_cuts(now)` silently drops
\* the expired ones from the collector's root set. The model had no such action,
\* so every invariant below was proved of a mechanism that holds a pin forever
\* while the shipped mechanism holds it for a lease.
\*
\* DR-0068 §5 recorded that divergence on 2026-08-25 and said the resolution is
\* "refusal on resume, not silent re-fetch". This is the model finding out
\* whether that is enough.
ExpirePin(c) ==
  /\ c \in pinned
  /\ pinned' = pinned \ {c}
  /\ lapsed' = lapsed \cup {c}                         \* RECORDED, NOT SILENT
  /\ running' = running \ {r \in Runners : resolved[r] = c}  \* AND THE RUN STOPS
  /\ UNCHANGED << ref, triggerCut, resolved, collected >>

Next ==
  \/ AdvanceRef
  \/ FireTrigger
  \/ \E r \in Runners : Resolve(r)
  \/ \E c \in 1..MaxCut : Collect(c)
  \/ \E c \in 1..MaxCut : ExpirePin(c)

\* Every runner fired by one trigger resolved the SAME cut. This is the whole
\* claim of DR-0068 §1, and it is why a trigger carries a cut id rather than a
\* ref name.
RunnersFiredTogetherAgree ==
  \A r1 \in Runners : \A r2 \in Runners :
    (resolved[r1] # 0 /\ resolved[r2] # 0) => (resolved[r1] = resolved[r2])

\* `NoPinnedCutCollected` and `ResolvedImpliesPinned` stood here until
\* 2026-08-30 and are GONE rather than weakened, because both said "a run that
\* started valid stays valid" — which a lease-based pin does not provide, and
\* which this model could only prove because it had no expiry. Their honest
\* successors are below. Recorded rather than silently dropped: an invariant
\* that disappears from a model is a claim someone may still believe.

\* The honest replacement for `NamedCutIsPinned`, which a lease cannot satisfy.
\*
\* A named cut is held, OR its lease visibly lapsed. What is ruled out is the
\* silent third state — unheld, with nothing recording that it ever was held —
\* because that is the state in which a run cannot be told to stop. A pin that
\* merely disappears at expiry leaves exactly that state.
NamedCutIsHeldOrVisiblyLapsed ==
  (triggerCut # 0) => (triggerCut \in pinned \/ triggerCut \in lapsed)

\* **The load-bearing one.** A RUNNING runner's cut is held, always. Not "was
\* held when it started" — held now.
\*
\* This is what both guards exist for, and it fails without either of them: let
\* `Resolve` take a lapsed cut and a runner starts on a closure nothing holds;
\* let `ExpirePin` drop the pin without stopping the run and a live run
\* continues over one. Weaker than the old `ResolvedImpliesPinned` in exactly
\* the right place — it says nothing about a runner that has already been
\* stopped, which is what a lease permits.
NoRunnerRunsOnAnUnheldCut ==
  \A r \in running : resolved[r] \in pinned

\* And therefore no running runner's inputs were reclaimed under it. Follows
\* from the above and `Collect`'s pinned guard, and is stated because it is the
\* property DR-0068 §5 is about; deriving it silently would leave a reader to
\* work out whether it still holds.
NoRunningRunnerLostItsWorld ==
  \A r \in running : resolved[r] \notin collected

SafetyInvariants ==
  /\ TypeOK
  /\ RunnersFiredTogetherAgree
  /\ NoRunnerRunsOnAnUnheldCut
  /\ NoRunningRunnerLostItsWorld
  /\ NamedCutIsHeldOrVisiblyLapsed

ConstInit ==
  /\ Runners = {"r1", "r2"}
  /\ MaxCut = 3
====
