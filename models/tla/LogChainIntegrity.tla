---- MODULE LogChainIntegrity ----
EXTENDS Naturals, Sequences

\* DR-0067: an instance's event log, its head compare-and-set, and its writer
\* fence (refining whipplescript-store/src/lib.rs `append_event_chained_on` and
\* whipplescript-host-do/src/do_store.rs `do_append_event_chained`).
\*
\* The defect this models is not a fork. `UNIQUE(instance_id, sequence)` already
\* refuses two entries at one position. The defect is subtler and was live: a
\* previous owner, still running after ownership moved, appends at a FRESH
\* position. Every schema constraint is satisfied and the resulting log
\* describes an execution that never happened.
\*
\* Two guards close two different holes, and neither subsumes the other:
\*
\*   CAS on the head   -- defeats a BLIND zombie, one resuming from stale
\*                        in-memory state. It does NOT defeat a zombie that
\*                        re-reads the head first: that append targets the true
\*                        head and is admitted.
\*   The owner epoch   -- defeats the re-reading zombie, because ownership moved
\*                        whether or not it re-read anything.
\*
\* Both guards are structural (they are conjuncts of Append, so a violating step
\* simply cannot be taken), and Apalache 0.56 has no --trace-inv. So each guard
\* gets a HISTORY VARIABLE that records when a write landed in violation of it,
\* exactly as EffectRequeueNecessity does for the requeue guard. The invariants
\* then have real teeth: dropping either guard makes its flag reachable, which
\* scripts/check-tla-models.sh proves by mutation.
\*
\* The head digest is modeled as the log's LENGTH. That is faithful rather than
\* convenient: the chain's whole purpose is that a digest identifies exactly one
\* prefix, so over a single growing log, "the digest I last saw" and "how far the
\* log went when I saw it" carry the same information.

CONSTANTS
  \* @type: Set(Str);
  Writers,
  \* @type: Int;
  MaxLen

VARIABLES
  \* The committed prefix, as the ownership epoch each entry was written under.
  \* The writer's identity is deliberately not carried: no invariant below needs
  \* it, and the epoch is what makes a stale write visible after the fact.
  \* @type: Seq(Int);
  log,
  \* The instance's current owner epoch: how many times the log has changed
  \* hands. Distinct from program lineage (`revision_epoch` in the store).
  \* @type: Int;
  ownerEpoch,
  \* What each writer BELIEVES it holds. A stale owner's belief is stale.
  \* @type: Str -> Int;
  heldEpoch,
  \* The head each writer last read. Stale until it re-reads.
  \* @type: Str -> Int;
  seenHead,
  \* History: a write landed under an epoch that was not the current one.
  \* @type: Bool;
  staleWrite,
  \* History: a write landed on a head that was no longer the live one.
  \* @type: Bool;
  blindWrite

vars == << log, ownerEpoch, heldEpoch, seenHead, staleWrite, blindWrite >>

TypeOK ==
  /\ ownerEpoch \in Nat
  /\ heldEpoch \in [Writers -> Nat]
  /\ seenHead \in [Writers -> Nat]
  /\ staleWrite \in BOOLEAN
  /\ blindWrite \in BOOLEAN
  /\ Len(log) <= MaxLen

Init ==
  /\ log = << >>
  /\ ownerEpoch = 0
  /\ heldEpoch = [w \in Writers |-> 0]
  /\ seenHead = [w \in Writers |-> 0]
  /\ staleWrite = FALSE
  /\ blindWrite = FALSE

\* Take ownership. The bump ALONE evicts the previous owner: from this moment
\* its held epoch is behind, with no window for it to interleave while the new
\* owner gets around to its first append.
Claim(w) ==
  /\ ownerEpoch' = ownerEpoch + 1
  /\ heldEpoch' = [heldEpoch EXCEPT ![w] = ownerEpoch + 1]
  /\ UNCHANGED << log, seenHead, staleWrite, blindWrite >>

\* Any writer may re-read the head at any time. This is what a zombie does to
\* get past compare-and-set, and why the epoch has to exist.
ReadHead(w) ==
  /\ seenHead' = [seenHead EXCEPT ![w] = Len(log)]
  /\ UNCHANGED << log, ownerEpoch, heldEpoch, staleWrite, blindWrite >>

\* The append. Both guards are conjuncts; the history variables record what a
\* landed write would have violated, so removing a guard is observable.
WriteEntry(w) ==
  /\ Len(log) < MaxLen
  /\ heldEpoch[w] = ownerEpoch   \* THE FENCE (DR-0067 section 3)
  /\ seenHead[w] = Len(log)      \* THE COMPARE-AND-SET (DR-0067 section 2)
  /\ log' = Append(log, heldEpoch[w])
  /\ staleWrite' = (staleWrite \/ (heldEpoch[w] # ownerEpoch))
  /\ blindWrite' = (blindWrite \/ (seenHead[w] # Len(log)))
  /\ UNCHANGED << ownerEpoch, heldEpoch, seenHead >>

Next ==
  \/ \E w \in Writers : Claim(w)
  \/ \E w \in Writers : ReadHead(w)
  \/ \E w \in Writers : WriteEntry(w)

\* No committed entry was written by an owner that had already been superseded.
\* This is the invariant the live schema did NOT have: two writers appending at
\* distinct positions both satisfied every constraint.
NoStaleWrite == ~staleWrite

\* No committed entry was written against a head that had already moved.
NoBlindWrite == ~blindWrite

\* Ownership only ever moves forward along the log, so the committed prefix
\* reads as one succession of owners rather than an interleaving of two.
EpochsNonDecreasing ==
  \A i \in 1..Len(log) : \A j \in 1..Len(log) :
    (i < j) => (log[i] <= log[j])

\* Every entry was written under the ownership that was current when it landed,
\* which is what "this log describes a real execution" means here.
EntriesCarryLiveOwnership ==
  \A i \in 1..Len(log) : log[i] <= ownerEpoch

SafetyInvariants ==
  /\ TypeOK
  /\ NoStaleWrite
  /\ NoBlindWrite
  /\ EpochsNonDecreasing
  /\ EntriesCarryLiveOwnership

ConstInit ==
  /\ Writers = {"w1", "w2"}
  /\ MaxLen = 4
====
