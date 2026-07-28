---- MODULE CoordLease ----
EXTENDS Naturals, FiniteSets

\* std.coord lease protocol (spec/std-coord.md v1 slice 1, refining the shipped
\* atomic store ops in whipplescript-store/src/coordination.rs): a lease is an
\* N-slot semaphore per key. Acquire is attempt-and-branch (an over-capacity
\* attempt is DENIED, never queued -- the FIFO wait queue is deferred with
\* cause, so NoDeadlock/BoundedWait are explicitly out of this model's scope);
\* release and TTL expiry each free a slot. The safety property is
\* MutualExclusion: never more than Slots concurrent holders per key. The gate
\* proves the slot guard is load-bearing by mutation (see
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
  denied

vars == << held, denied >>

TypeOK ==
  /\ held \in [Keys -> SUBSET Holders]
  /\ denied \subseteq (Keys \X Holders)

Init ==
  /\ held = [k \in Keys |-> {}]
  /\ denied = {}

\* The atomic acquire: grants a slot only while capacity remains. A holder
\* holds at most one slot per key (a re-acquire by the same holder is
\* AlreadyHeld at the store, modeled by the h \notin held[k] guard).
Acquire(k, h) ==
  /\ h \notin held[k]
  /\ Cardinality(held[k]) < Slots
  /\ held' = [held EXCEPT ![k] = held[k] \cup {h}]
  /\ UNCHANGED denied

\* The attempt-and-branch deny: at capacity the attempt records Contended and
\* changes no holder state.
Deny(k, h) ==
  /\ h \notin held[k]
  /\ Cardinality(held[k]) >= Slots
  /\ denied' = denied \cup {<<k, h>>}
  /\ UNCHANGED held

\* Explicit release by the holder (or the terminal auto-release hook).
Release(k, h) ==
  /\ h \in held[k]
  /\ held' = [held EXCEPT ![k] = held[k] \ {h}]
  /\ UNCHANGED denied

\* TTL expiry frees the slot exactly like a release; expiry never touches
\* another holder's slot.
Expire(k, h) ==
  /\ h \in held[k]
  /\ held' = [held EXCEPT ![k] = held[k] \ {h}]
  /\ UNCHANGED denied

Next ==
  \/ \E k \in Keys : \E h \in Holders : Acquire(k, h)
  \/ \E k \in Keys : \E h \in Holders : Deny(k, h)
  \/ \E k \in Keys : \E h \in Holders : Release(k, h)
  \/ \E k \in Keys : \E h \in Holders : Expire(k, h)

\* MutualExclusion: never more than Slots concurrent holders per key.
MutualExclusion ==
  \A k \in Keys : Cardinality(held[k]) <= Slots

SafetyInvariants ==
  /\ TypeOK
  /\ MutualExclusion

ConstInit ==
  /\ Keys = {"k1"}
  /\ Holders = {"h1", "h2", "h3"}
  /\ Slots = 2
====
