---- MODULE CoordCounter ----
EXTENDS Naturals

\* std.coord counter protocol (spec/std-coord.md v1 slice 1, refining the
\* shipped atomic consume/reset ops in whipplescript-store/src/coordination.rs):
\* a consumable counter with a cap and a periodic reset. Consume is
\* attempt-and-branch: an over-cap consume is DENIED atomically, never
\* partially granted. The safety properties are CapInvariant (consumed <= cap
\* between resets), NoLostConsume (grants serialize -- the counter equals the
\* exact sum of granted amounts this epoch, nothing lost or double-counted),
\* and reset monotonicity (a reset opens a fresh epoch at zero; epochs only
\* advance). The gate proves the cap guard is load-bearing by mutation (see
\* scripts/check-tla-models.sh).

CONSTANTS
  \* @type: Int;
  Cap,
  \* @type: Set(Int);
  Amounts

VARIABLES
  \* @type: Int;
  consumed,
  \* @type: Int;
  grantedSum,
  \* @type: Int;
  epoch,
  \* @type: Int;
  deniedCount

TypeOK ==
  /\ consumed \in Nat
  /\ grantedSum \in Nat
  /\ epoch \in Nat
  /\ deniedCount \in Nat

Init ==
  /\ consumed = 0
  /\ grantedSum = 0
  /\ epoch = 0
  /\ deniedCount = 0

\* The atomic grant: only while the whole amount fits under the cap.
\* grantedSum is the history ledger of granted amounts this epoch -- the
\* NoLostConsume witness.
Consume(a) ==
  /\ consumed + a <= Cap
  /\ consumed' = consumed + a
  /\ grantedSum' = grantedSum + a
  /\ UNCHANGED << epoch, deniedCount >>

\* The attempt-and-branch deny: an over-cap consume changes no counter state.
DenyConsume(a) ==
  /\ consumed + a > Cap
  /\ deniedCount' = deniedCount + 1
  /\ UNCHANGED << consumed, grantedSum, epoch >>

\* The periodic reset (anchor vocabulary shared with std.time): a fresh epoch
\* opens at zero. Epochs only ever advance.
Reset ==
  /\ consumed' = 0
  /\ grantedSum' = 0
  /\ epoch' = epoch + 1
  /\ UNCHANGED deniedCount

Next ==
  \/ \E a \in Amounts : Consume(a)
  \/ \E a \in Amounts : DenyConsume(a)
  \/ Reset

\* CapInvariant: consumed never exceeds the cap between resets.
CapInvariant ==
  consumed <= Cap

\* NoLostConsume: the counter is exactly the sum of granted amounts this
\* epoch -- concurrent consumes serialize through the atomic op, so nothing
\* is lost and nothing double-counts.
NoLostConsume ==
  consumed = grantedSum

SafetyInvariants ==
  /\ TypeOK
  /\ CapInvariant
  /\ NoLostConsume

ConstInit ==
  /\ Cap = 3
  /\ Amounts = {1, 2}
====
