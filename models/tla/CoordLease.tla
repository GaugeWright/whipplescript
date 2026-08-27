---- MODULE CoordLease ----
EXTENDS Naturals, FiniteSets

\* std.coord lease protocol (spec/std-coord.md v1 slice 1, refining the shipped
\* atomic store ops in whipplescript-store/src/coordination.rs): a lease is an
\* N-slot semaphore per key. Acquire is attempt-and-branch (an over-capacity
\* attempt is DENIED, never queued -- the FIFO wait queue is deferred with
\* cause, so NoDeadlock/BoundedWait are explicitly out of this model's scope);
\* release and TTL expiry each free a slot. The first safety property is
\* MutualExclusion: never more than Slots concurrent holders per key.
\*
\* The second safety property is TerminalRelease (DR-0076 P5): a holder that has
\* reached a workflow terminal holds no slot, anywhere. This is the coordination
\* lease's half of the holder-lifetime bound that coordination.md states as
\* architectural principle 3. Terminal release is an action of its own here
\* precisely because it is NOT per-key: it frees every slot the holder holds
\* across all keys in one step, which is why Keys carries more than one element
\* below -- at one key the across-all-keys claim is vacuous.
\*
\* TWO HONEST LIMITS, both found by review on 2026-08-26 and both understated in
\* the first version of this header.
\*
\* 1. ABSORBENCY IS AN ENVIRONMENT ASSUMPTION, NOT A MECHANISM PROPERTY. The
\*    `h \notin terminated` guard on Acquire carries the whole absorbing half --
\*    the gate's mutation of exactly that guard is what violates the invariant.
\*    The coordination store has no terminal predicate and no notion of a
\*    workflow terminal at all: try_acquire_for_owner deletes expired rows,
\*    checks already-held, counts slots, inserts. So what the guard models is the
\*    RULE PASS never scheduling an acquisition for a terminated instance. That
\*    is an assumption about the environment, and DR-0076's own Problem 2 is that
\*    such assumptions are what the discharge site exists to stop relying on.
\* 2. IT IS NOT PARITY WITH tracker-lease.maude I3. That model's terminal is NOT
\*    absorbing -- its [grant] rule has no released-guard, and an actor can
\*    re-acquire after release. I3 proves the release step is total and atomic;
\*    this proves total, atomic, AND absorbing. The asymmetry is narrowed, not
\*    removed, and it now points the other way.
\*
\* Neither model can express a PARTIAL discharge: Terminate here and stripLeases
\* there are each one atomic step, so the crash-between-terminal-and-release
\* hazard -- which is what DR-0076 P2 exists to close -- is unrepresentable in
\* both. This model proves P2's post-condition by assuming P2's atomicity.
\*
\* The gate proves both guards load-bearing by mutation (see
\* scripts/check-tla-models.sh).

CONSTANTS
  \* @type: Set(Str);
  Keys,
  \* @type: Set(Str);
  Holders,
  \* @type: Int;
  Slots

VARIABLES
  \* @type: Str -> Set(Str);
  held,
  \* @type: Set(<<Str, Str>>);
  denied,
  \* @type: Set(Str);
  terminated

vars == << held, denied, terminated >>

TypeOK ==
  /\ held \in [Keys -> SUBSET Holders]
  /\ denied \subseteq (Keys \X Holders)
  /\ terminated \subseteq Holders

Init ==
  /\ held = [k \in Keys |-> {}]
  /\ denied = {}
  /\ terminated = {}

\* The atomic acquire: grants a slot only while capacity remains. A holder
\* holds at most one slot per key (a re-acquire by the same holder is
\* AlreadyHeld at the store, modeled by the h \notin held[k] guard).
Acquire(k, h) ==
  /\ h \notin terminated
  /\ h \notin held[k]
  /\ Cardinality(held[k]) < Slots
  /\ held' = [held EXCEPT ![k] = held[k] \cup {h}]
  /\ UNCHANGED << denied, terminated >>

\* The attempt-and-branch deny: at capacity the attempt records Contended and
\* changes no holder state.
Deny(k, h) ==
  /\ h \notin terminated
  /\ h \notin held[k]
  /\ Cardinality(held[k]) >= Slots
  /\ denied' = denied \cup {<<k, h>>}
  /\ UNCHANGED << held, terminated >>

\* Explicit release by the holder, one key at a time.
Release(k, h) ==
  /\ h \in held[k]
  /\ held' = [held EXCEPT ![k] = held[k] \ {h}]
  /\ UNCHANGED << denied, terminated >>

\* TTL expiry frees the slot exactly like a release; expiry never touches
\* another holder's slot.
Expire(k, h) ==
  /\ h \in held[k]
  /\ held' = [held EXCEPT ![k] = held[k] \ {h}]
  /\ UNCHANGED << denied, terminated >>

\* The holder reaches a workflow terminal. One step frees every slot it holds,
\* across ALL keys -- the discharge is owed by reaching the terminal, not by
\* whoever transitioned it, and not key by key. Terminal is absorbing: a
\* terminated holder never acquires again (the guard on Acquire above), which is
\* what keeps TerminalRelease from being restorable by a later acquire.
Terminate(h) ==
  /\ h \notin terminated
  /\ terminated' = terminated \cup {h}
  /\ held' = [k \in Keys |-> held[k] \ {h}]
  /\ UNCHANGED denied

Next ==
  \/ \E k \in Keys : \E h \in Holders : Acquire(k, h)
  \/ \E k \in Keys : \E h \in Holders : Deny(k, h)
  \/ \E k \in Keys : \E h \in Holders : Release(k, h)
  \/ \E k \in Keys : \E h \in Holders : Expire(k, h)
  \/ \E h \in Holders : Terminate(h)

\* MutualExclusion: never more than Slots concurrent holders per key.
MutualExclusion ==
  \A k \in Keys : Cardinality(held[k]) <= Slots

\* TerminalRelease: a holder that reached a terminal holds no slot on any key.
TerminalRelease ==
  \A k \in Keys : \A h \in terminated : h \notin held[k]

SafetyInvariants ==
  /\ TypeOK
  /\ MutualExclusion
  /\ TerminalRelease

\* Two keys, not one: the claim TerminalRelease makes is that ONE terminal step
\* frees the holder's slots everywhere, and a single-key instance cannot tell
\* that apart from a per-key release.
ConstInit ==
  /\ Keys = {"k1", "k2"}
  /\ Holders = {"h1", "h2", "h3"}
  /\ Slots = 2
====
