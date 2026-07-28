---- MODULE CoordLedger ----
EXTENDS Naturals, Sequences, FiniteSets

\* std.coord ledger protocol (spec/std-coord.md v1 slice 1, refining the
\* shipped atomic append op in whipplescript-store/src/coordination.rs): an
\* append-only log partitioned by key. Appends are idempotent per entry id
\* (the store's idempotency key absorbs a re-fired append), each partition's
\* log is a totally ordered sequence (AppendLinearizable -- order is the
\* sequence itself; the checkable residue is exactly-once presence), and a
\* projection over partition P observes exactly P's entries
\* (PartitionIsolation). Retention pruning is deliberately out: it removes a
\* PREFIX and never reorders, and no shipped consumer reads pruned history.
\* The gate proves the idempotency guard is load-bearing by mutation (see
\* scripts/check-tla-models.sh).

CONSTANTS
  \* @type: Set(Str);
  Partitions,
  \* @type: Set(Str);
  Entries

VARIABLES
  \* @type: Str -> Seq(Str);
  log,
  \* @type: Set(<<Str, Str>>);
  appended,
  \* @type: Str -> Seq(Str);
  projView

vars == << log, appended, projView >>

\* Apalache cannot enumerate Seq(_) memberships; element-wise bounds carry the
\* same content (the sequence types themselves are pinned by the annotations).
TypeOK ==
  /\ appended \subseteq (Partitions \X Entries)
  /\ \A p \in Partitions :
       /\ \A i \in DOMAIN log[p] : log[p][i] \in Entries
       /\ \A i \in DOMAIN projView[p] : projView[p][i] \in Entries

Init ==
  /\ log = [p \in Partitions |-> << >>]
  /\ appended = {}
  /\ projView = [p \in Partitions |-> << >>]

\* The atomic append: entry e lands on partition p exactly once (the store's
\* idempotency key absorbs a re-fired append of the same entry).
AppendEntry(p, e) ==
  /\ <<p, e>> \notin appended
  /\ log' = [log EXCEPT ![p] = Append(log[p], e)]
  /\ appended' = appended \cup {<<p, e>>}
  /\ UNCHANGED projView

\* A projection over partition P snapshots P's log -- and only P's.
Project(p) ==
  /\ projView' = [projView EXCEPT ![p] = log[p]]
  /\ UNCHANGED << log, appended >>

Next ==
  \/ \E p \in Partitions : \E e \in Entries : AppendEntry(p, e)
  \/ \E p \in Partitions : Project(p)

\* NoLostEntry + exactly-once (the checkable residue of AppendLinearizable
\* over an inherently ordered sequence): every accepted append is present in
\* its partition's log exactly once.
NoLostEntry ==
  \A p \in Partitions :
    Len(log[p]) = Cardinality({ e \in Entries : <<p, e>> \in appended })

\* PartitionIsolation: a projection for partition P observes only entries
\* appended to P -- never a sibling partition's entries.
PartitionIsolation ==
  \A p \in Partitions :
    \A i \in DOMAIN projView[p] : <<p, projView[p][i]>> \in appended

SafetyInvariants ==
  /\ TypeOK
  /\ NoLostEntry
  /\ PartitionIsolation

ConstInit ==
  /\ Partitions = {"p1", "p2"}
  /\ Entries = {"e1", "e2"}
====
