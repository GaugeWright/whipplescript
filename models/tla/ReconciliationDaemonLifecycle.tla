---- MODULE ReconciliationDaemonLifecycle ----
EXTENDS Naturals, FiniteSets

\* Versioned-workspace reconciliation daemon lifecycle, per
\* spec/versioned-workspace-research-note.md 7.1 and the untie-substrate
\* readiness tracker Phase 1. The daemon has two directions with different
\* policies. Rebase-down: a mainline delta DISJOINT from a working branch's
\* slice rebases in silently at any time -- "your nose is your branch's
\* slice"; a delta INTERSECTING the slice waits for a quiescence point
\* (never mid-run; per-run snapshot isolation is absolute) and arrives as
\* notification-and-ask. Merge-up: serialized by the adoption lease, and
\* gated by the staleness bound -- a branch must be fully rebased down to
\* the mainline head before it may merge up. Cross-actor interleavings and
\* crash-shaped races are distributed-systems concerns, so this lives in
\* TLA+; the merge CONTENT semantics (certificates, confluence, joint
\* escalation) live in the Maude merge models.
\*
\* The everMergedStale / everMidRunIntrusion history flags stay FALSE
\* because the action guards enforce the policy; they are regression bites:
\* weakening a guard (merging while stale, applying an intersecting delta
\* mid-run) trips the corresponding invariant under Apalache.

CONSTANTS
  \* @type: Set(Str);
  Branches,
  \* @type: Int;
  MaxHead

VARIABLES
  \* @type: Int;
  mainHead,
  \* @type: Str -> Int;
  branchBase,
  \* @type: Str -> Str;
  phase,
  \* @type: Str -> Set(Int);
  intersecting,
  \* @type: Str;
  lease,
  \* @type: Bool;
  everMergedStale,
  \* @type: Bool;
  everMidRunIntrusion

vars == << mainHead, branchBase, phase, intersecting, lease,
           everMergedStale, everMidRunIntrusion >>

Phases == {"running", "quiescent"}

TypeOK ==
  /\ mainHead \in 0..MaxHead
  /\ branchBase \in [Branches -> 0..MaxHead]
  /\ phase \in [Branches -> Phases]
  /\ intersecting \in [Branches -> SUBSET (1..MaxHead)]
  /\ lease \in ({"none"} \cup Branches)
  /\ everMergedStale \in BOOLEAN
  /\ everMidRunIntrusion \in BOOLEAN

Init ==
  /\ mainHead = 0
  /\ branchBase = [b \in Branches |-> 0]
  /\ phase = [b \in Branches |-> "quiescent"]
  /\ intersecting = [b \in Branches |-> {}]
  /\ lease = "none"
  /\ everMergedStale = FALSE
  /\ everMidRunIntrusion = FALSE

\* Mainline advances by one delta; S is the set of branches whose tracked
\* slice the delta intersects (the slicer's verdict, abstracted).
MainAdvance(S) ==
  /\ mainHead < MaxHead
  /\ mainHead' = mainHead + 1
  /\ intersecting' = [b \in Branches |->
       IF b \in S THEN intersecting[b] \cup {mainHead + 1}
                  ELSE intersecting[b]]
  /\ UNCHANGED << branchBase, phase, lease,
                  everMergedStale, everMidRunIntrusion >>

\* Silent continuous rebase-down of a slice-disjoint delta: allowed in ANY
\* phase, including mid-run -- divergence never accumulates where it does
\* not matter.
RebaseDisjoint(b) ==
  /\ branchBase[b] < mainHead
  /\ (branchBase[b] + 1) \notin intersecting[b]
  /\ branchBase' = [branchBase EXCEPT ![b] = branchBase[b] + 1]
  /\ UNCHANGED << mainHead, phase, intersecting, lease,
                  everMergedStale, everMidRunIntrusion >>

\* An intersecting delta arrives as notification-and-ask at a QUIESCENCE
\* point only. The history flag records any mid-run application; the guard
\* keeps it FALSE.
RebaseIntersecting(b) ==
  /\ branchBase[b] < mainHead
  /\ (branchBase[b] + 1) \in intersecting[b]
  /\ phase[b] = "quiescent"
  /\ branchBase' = [branchBase EXCEPT ![b] = branchBase[b] + 1]
  /\ intersecting' = [intersecting EXCEPT ![b] =
       intersecting[b] \ {branchBase[b] + 1}]
  /\ everMidRunIntrusion' =
       (everMidRunIntrusion \/ (phase[b] /= "quiescent"))
  /\ UNCHANGED << mainHead, phase, lease, everMergedStale >>

StartRun(b) ==
  /\ phase[b] = "quiescent"
  /\ phase' = [phase EXCEPT ![b] = "running"]
  /\ UNCHANGED << mainHead, branchBase, intersecting, lease,
                  everMergedStale, everMidRunIntrusion >>

\* A terminal, a mark, or task completion -- the branch reaches quiescence.
Quiesce(b) ==
  /\ phase[b] = "running"
  /\ phase' = [phase EXCEPT ![b] = "quiescent"]
  /\ UNCHANGED << mainHead, branchBase, intersecting, lease,
                  everMergedStale, everMidRunIntrusion >>

AcquireLease(b) ==
  /\ lease = "none"
  /\ lease' = b
  /\ UNCHANGED << mainHead, branchBase, phase, intersecting,
                  everMergedStale, everMidRunIntrusion >>

ReleaseLease(b) ==
  /\ lease = b
  /\ lease' = "none"
  /\ UNCHANGED << mainHead, branchBase, phase, intersecting,
                  everMergedStale, everMidRunIntrusion >>

\* Merge-up: only the adoption-lease holder, only quiescent, and only with
\* the staleness bound discharged -- the branch base must equal the
\* mainline head AT MERGE TIME (mainline may have advanced since the lease
\* was acquired; the guard re-checks). The merged delta may intersect other
\* branches' slices (S), becoming their pending intersecting delta. The
\* history flag records any stale merge; the guard keeps it FALSE.
MergeUp(b, S) ==
  /\ lease = b
  /\ phase[b] = "quiescent"
  /\ branchBase[b] = mainHead
  /\ mainHead < MaxHead
  /\ mainHead' = mainHead + 1
  /\ branchBase' = [branchBase EXCEPT ![b] = mainHead + 1]
  /\ intersecting' = [x \in Branches |->
       IF x \in (S \ {b}) THEN intersecting[x] \cup {mainHead + 1}
                          ELSE intersecting[x]]
  /\ lease' = "none"
  /\ everMergedStale' =
       (everMergedStale \/ (branchBase[b] /= mainHead))
  /\ UNCHANGED << phase, everMidRunIntrusion >>

Next ==
  \/ \E S \in SUBSET Branches : MainAdvance(S)
  \/ \E b \in Branches : RebaseDisjoint(b)
  \/ \E b \in Branches : RebaseIntersecting(b)
  \/ \E b \in Branches : StartRun(b)
  \/ \E b \in Branches : Quiesce(b)
  \/ \E b \in Branches : AcquireLease(b)
  \/ \E b \in Branches : ReleaseLease(b)
  \/ \E b \in Branches, S \in SUBSET Branches : MergeUp(b, S)

\* Snapshot isolation's daemon half: no intersecting delta is ever applied
\* mid-run.
NoMidRunIntrusion ==
  everMidRunIntrusion = FALSE

\* The staleness bound: no branch merges up without being fully rebased
\* down first.
NoStaleMerge ==
  everMergedStale = FALSE

\* A branch base never runs ahead of mainline.
BaseNeverAhead ==
  \A b \in Branches : branchBase[b] <= mainHead

\* Pending intersecting deltas are exactly bookkept: ahead of the branch
\* base, within mainline history.
PendingIntersectingConsistent ==
  \A b \in Branches : \A v \in intersecting[b] :
    /\ branchBase[b] < v
    /\ v <= mainHead

SafetyInvariants ==
  /\ TypeOK
  /\ NoMidRunIntrusion
  /\ NoStaleMerge
  /\ BaseNeverAhead
  /\ PendingIntersectingConsistent

ConstInit ==
  /\ Branches = {"b1", "b2"}
  /\ MaxHead = 3
====
