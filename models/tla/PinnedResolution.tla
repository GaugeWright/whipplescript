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
  collected

vars == << ref, triggerCut, resolved, pinned, collected >>

TypeOK ==
  /\ ref \in 0..MaxCut
  /\ triggerCut \in 0..MaxCut
  /\ resolved \in [Runners -> 0..MaxCut]
  /\ pinned \subseteq 0..MaxCut
  /\ collected \subseteq 0..MaxCut

Init ==
  /\ ref = 1
  /\ triggerCut = 0
  /\ resolved = [r \in Runners |-> 0]
  /\ pinned = {}
  /\ collected = {}

\* Mainline moves. Perfectly legitimate, and precisely what makes late
\* resolution dangerous: nothing about this step is a fault.
AdvanceRef ==
  /\ ref < MaxCut
  /\ ref' = ref + 1
  /\ UNCHANGED << triggerCut, resolved, pinned, collected >>

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
  /\ UNCHANGED << ref, resolved, collected >>

\* A runner takes its cut FROM THE TRIGGER. It does not consult the ref, which
\* is the whole of DR-0068 §1.
Resolve(r) ==
  /\ triggerCut # 0
  /\ resolved[r] = 0
  /\ resolved' = [resolved EXCEPT ![r] = triggerCut]   \* RESOLVE FROM THE TRIGGER
  /\ UNCHANGED << ref, triggerCut, pinned, collected >>

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
  /\ UNCHANGED << ref, triggerCut, resolved, pinned >>

Next ==
  \/ AdvanceRef
  \/ FireTrigger
  \/ \E r \in Runners : Resolve(r)
  \/ \E c \in 1..MaxCut : Collect(c)

\* Every runner fired by one trigger resolved the SAME cut. This is the whole
\* claim of DR-0068 §1, and it is why a trigger carries a cut id rather than a
\* ref name.
RunnersFiredTogetherAgree ==
  \A r1 \in Runners : \A r2 \in Runners :
    (resolved[r1] # 0 /\ resolved[r2] # 0) => (resolved[r1] = resolved[r2])

\* No runner's inputs were reclaimed out from under it. A run that started valid
\* stays valid.
NoPinnedCutCollected ==
  \A r \in Runners : (resolved[r] # 0) => (resolved[r] \notin collected)

\* A resolved runner always holds its pin, so the two guards above compose
\* rather than merely coexisting. With the pin taken at dispatch this is what
\* rules out the window: there is no state in which a cut has been named by a
\* trigger and is not yet held.
ResolvedImpliesPinned ==
  \A r \in Runners : (resolved[r] # 0) => (resolved[r] \in pinned)

\* The stronger form of the same claim, and the one that actually closes the
\* gap: a NAMED cut is held, whether or not any runner has picked it up yet.
NamedCutIsPinned ==
  (triggerCut # 0) => (triggerCut \in pinned)

SafetyInvariants ==
  /\ TypeOK
  /\ RunnersFiredTogetherAgree
  /\ NoPinnedCutCollected
  /\ ResolvedImpliesPinned
  /\ NamedCutIsPinned

ConstInit ==
  /\ Runners = {"r1", "r2"}
  /\ MaxCut = 3
====
