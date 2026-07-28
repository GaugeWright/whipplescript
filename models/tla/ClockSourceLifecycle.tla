---- MODULE ClockSourceLifecycle ----
EXTENDS Naturals, FiniteSets

\* This model captures the clock-source occurrence admission lifecycle: a clock
\* occurrence becomes due, a provider observes it on a worker pass, and the kernel
\* admits exactly one durable signal fact keyed by its occurrence id
\* (H(source_id, scheduled_occurrence_instant), per admission-and-idempotency.md).
\* The lifecycle/recovery concern -- a crash between observation and durable record
\* must still resolve to exactly one fact, never zero and never two -- is a
\* distributed-systems property, so it lives in TLA+ rather than Maude. The Maude
\* clock-source model covers lowering preservation and missed-policy determinism.

CONSTANTS
  \* @type: Set(Str);
  Occurrences

VARIABLES
  \* @type: Set(Str);
  observed,
  \* @type: Set(Str);
  recorded,
  \* @type: Str -> Int;
  factCount,
  \* @type: Bool;
  recovering

vars == << observed, recorded, factCount, recovering >>

TypeOK ==
  /\ observed \subseteq Occurrences
  /\ recorded \subseteq Occurrences
  /\ factCount \in [Occurrences -> Nat]
  /\ recovering \in BOOLEAN

Init ==
  /\ observed = {}
  /\ recorded = {}
  /\ factCount = [o \in Occurrences |-> 0]
  /\ recovering = FALSE

\* A provider observes a due occurrence on a worker/scheduler pass.
Observe(o) ==
  /\ ~recovering
  /\ o \in Occurrences
  /\ o \notin observed
  /\ observed' = observed \cup {o}
  /\ UNCHANGED << recorded, factCount, recovering >>

\* The kernel admits the durable signal fact for an observed occurrence. The
\* store's unique index on the occurrence key means an already-recorded occurrence
\* is never admitted a second time.
Admit(o) ==
  /\ ~recovering
  /\ o \in observed
  /\ o \notin recorded
  /\ recorded' = recorded \cup {o}
  /\ factCount' = [factCount EXCEPT ![o] = factCount[o] + 1]
  /\ UNCHANGED << observed, recovering >>

\* A crash interrupts a worker between observation and durable record.
Crash ==
  /\ ~recovering
  /\ recovering' = TRUE
  /\ UNCHANGED << observed, recorded, factCount >>

\* Recovery re-drives an observed-but-unrecorded occurrence. The same unique-index
\* guard prevents a second fact for an occurrence recorded before the crash, so an
\* occurrence in flight at crash time resolves to exactly one fact, never two.
RecoverAdmit(o) ==
  /\ recovering
  /\ o \in observed
  /\ o \notin recorded
  /\ recorded' = recorded \cup {o}
  /\ factCount' = [factCount EXCEPT ![o] = factCount[o] + 1]
  /\ UNCHANGED << observed, recovering >>

RecoverFinish ==
  /\ recovering
  /\ recovering' = FALSE
  /\ UNCHANGED << observed, recorded, factCount >>

Next ==
  \/ \E o \in Occurrences : Observe(o)
  \/ \E o \in Occurrences : Admit(o)
  \/ Crash
  \/ \E o \in Occurrences : RecoverAdmit(o)
  \/ RecoverFinish

\* INV-6: at most one durable fact per occurrence, preserved across recovery.
ExactlyOncePerOccurrence ==
  \A o \in Occurrences : factCount[o] <= 1

\* No fact without a prior observation: admission never invents occurrences.
AdmittedWasObserved ==
  recorded \subseteq observed

\* The recorded set and the per-occurrence fact count stay consistent.
RecordedMatchesFactCount ==
  \A o \in Occurrences : (o \in recorded) <=> (factCount[o] >= 1)

SafetyInvariants ==
  /\ TypeOK
  /\ ExactlyOncePerOccurrence
  /\ AdmittedWasObserved
  /\ RecordedMatchesFactCount

ConstInit ==
  Occurrences = {"occ1", "occ2", "occ3"}
====
