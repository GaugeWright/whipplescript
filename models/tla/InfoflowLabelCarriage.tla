---- MODULE InfoflowLabelCarriage ----
EXTENDS Naturals, FiniteSets

\* Durable label carriage (I-IFC7), the TEMPORAL layer of the audit-findings W6 work.
\* The Maude model (infoflow-carriage.maude) bites a SINGLE persistence/instance hop and
\* the Lean algebra is timeless. The claim I-IFC7 actually makes is a transition-system
\* SAFETY property over a SEQUENCE of hops: a datum's label is carried across EVERY
\* transport step -- persist to a store, reload from it, hand off across an instance
\* boundary, replay from the log -- without being STRIPPED (confidentiality silently
\* lowered) or FORGED (integrity silently raised, i.e. laundered). That inductive,
\* all-interleavings claim lives in TLA+.
\*
\* Each datum has a ground-truth label set once, at creation: (conf, integ) over a tiny
\* level lattice (0 = public / untrusted, 1 = secret / trusted). Transport steps move a
\* labelled datum to a new location, CARRYING the label it already had. The safety
\* invariant is that every placement of a datum, at every location it has reached, still
\* carries exactly its creation label -- so no transport hop is a downgrade or a launder.
\*
\* HONESTY: a label crossing (declassify lowers conf; endorse raises integ) is NOT a
\* transport hop and is deliberately NOT modeled here -- it is an authorized, audited
\* exception bitten in the Maude/Lean crossing models (infoflow-declassifier.maude,
\* NMIF.lean). This model is exactly the no-silent-change-on-transport surrogate; combined
\* with the crossing models it gives the full I-IFC7 picture. The BITE (verified to fail):
\* a Transport step that copies the source placement but rewrites integ to 1 (a laundering
\* hop) makes NoForge / CarriagePreserved produce an Apalache counterexample.

CONSTANTS
  \* @type: Set(Int);
  Ids               \* the datum identities in scope

VARIABLES
  \* @type: Set(Int);
  created,          \* ids whose ground-truth label has been set
  \* @type: Int -> Int;
  originC,          \* ground-truth confidentiality level per id (0 public .. 1 secret)
  \* @type: Int -> Int;
  originI,          \* ground-truth integrity level per id (0 untrusted .. 1 trusted)
  \* @type: Set({ id: Int, loc: Str, c: Int, i: Int });
  placements        \* every (id at location) reached, with the label it carries there

vars == << created, originC, originI, placements >>

Locs == {"created", "persisted", "reloaded", "handed", "replayed"}
Levels == {0, 1}

\* The transport edges: persistence (created -> persisted -> reloaded), replay
\* (persisted -> replayed), and the cross-instance handoff (reloaded/created -> handed).
\* @type: Set(<<Str, Str>>);
TransportEdges == {
  << "created",   "persisted" >>,
  << "persisted", "reloaded"  >>,
  << "persisted", "replayed"  >>,
  << "reloaded",  "handed"    >>,
  << "created",   "handed"    >>
}

TypeOK ==
  /\ created \subseteq Ids
  /\ originC \in [Ids -> Levels]
  /\ originI \in [Ids -> Levels]
  /\ \A p \in placements :
       /\ p.id \in Ids
       /\ p.loc \in Locs
       /\ p.c \in Levels
       /\ p.i \in Levels

Init ==
  /\ created = {}
  /\ originC = [x \in Ids |-> 0]
  /\ originI = [x \in Ids |-> 0]
  /\ placements = {}

\* A datum is created with its ground-truth label, placed at "created".
Create(id, c, i) ==
  /\ id \in Ids
  /\ id \notin created
  /\ c \in Levels
  /\ i \in Levels
  /\ created' = created \cup {id}
  /\ originC' = [originC EXCEPT ![id] = c]
  /\ originI' = [originI EXCEPT ![id] = i]
  /\ placements' = placements \cup {[id |-> id, loc |-> "created", c |-> c, i |-> i]}

\* A transport hop: the datum is at `from`, so it moves to `to` along a legal edge,
\* CARRYING the very label it had at `from`. No transport hop may rewrite the label.
Transport(id, from, to) ==
  /\ << from, to >> \in TransportEdges
  /\ \E src \in placements :
       /\ src.id = id
       /\ src.loc = from
       /\ placements' = placements \cup
            {[id |-> id, loc |-> to, c |-> src.c, i |-> src.i]}
  /\ UNCHANGED << created, originC, originI >>

Next ==
  \/ \E id \in Ids, c \in Levels, i \in Levels : Create(id, c, i)
  \/ \E id \in Ids, from \in Locs, to \in Locs : Transport(id, from, to)

\* (1) Carriage: every placement of a datum still carries its creation label exactly --
\* no transport hop changed it, at any location, on any trace.
CarriagePreserved ==
  \A p \in placements :
    /\ p.id \in created
    /\ p.c = originC[p.id]
    /\ p.i = originI[p.id]

\* (2) No strip: confidentiality is never silently lowered in transit (carried conf is at
\* least the ground-truth conf -- a secret stays at least as protected after a hop).
NoStrip ==
  \A p \in placements : p.c >= originC[p.id]

\* (3) No forge / no laundering (the W6 principle as a trace property): integrity is never
\* silently raised in transit (carried integ is at most the ground-truth integ -- transport
\* can never make untrusted data look more trusted than it was created).
NoForge ==
  \A p \in placements : p.i <= originI[p.id]

SafetyInvariants ==
  /\ TypeOK
  /\ CarriagePreserved
  /\ NoStrip
  /\ NoForge

ConstInit ==
  Ids = {1, 2}
====
