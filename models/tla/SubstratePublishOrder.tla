---- MODULE SubstratePublishOrder ----
EXTENDS Naturals

\* DR-0066 §4: publish bottom-up, read top-down.
\*
\*   A ref advance is observable only after its entire closure is durable at a
\*   class at least as strong as the ref itself.
\*
\* This is the one cross-plane rule, and it is what replaces the structural
\* coherence the three-plane split spends. Git never needed it: reachability
\* closure was an artifact of possessing the bytes, so `fsck` verified a global
\* property purely locally. Once content, history, and refs live in different
\* systems, closure stops being a fact about the bytes and becomes an obligation
\* someone must discharge — which is exactly the kind of claim that has to be
\* written down and checked rather than assumed.
\*
\* Three guards, one per ordering edge, each with its own invariant:
\*
\*   content before history  -- a history entry naming content nobody can serve
\*                              is a record of something unreadable.
\*   history before ref      -- a ref pointing past its own log is a cut with no
\*                              account of how it came to be.
\*   class at least as strong -- the corollary that is easiest to get wrong: a
\*                              globally-consistent ref over single-region
\*                              content promises a cut the system cannot serve.
\*
\* Durability classes are naturals, higher being stronger. Their absolute values
\* carry no meaning; only the comparison does.

CONSTANTS
  \* @type: Int;
  MaxCut,
  \* The class the ref tier is served at. The content behind a ref must reach at
  \* least this.
  \* @type: Int;
  RefClass,
  \* @type: Int;
  MaxClass

VARIABLES
  \* Durability class reached by each cut's content; 0 means not durable at all.
  \* @type: Int -> Int;
  contentClass,
  \* Cuts whose history entry is durable.
  \* @type: Set(Int);
  logged,
  \* The observable ref. 0 before anything is published.
  \* @type: Int;
  ref

vars == << contentClass, logged, ref >>

TypeOK ==
  /\ contentClass \in [1..MaxCut -> 0..MaxClass]
  /\ logged \subseteq 1..MaxCut
  /\ ref \in 0..MaxCut

Init ==
  /\ contentClass = [c \in 1..MaxCut |-> 0]
  /\ logged = {}
  /\ ref = 0

\* Content is idempotent and order-free, so it may be published at any time and
\* strengthened later. Nothing gates this — it is the bottom of the order.
PublishContent(c, class) ==
  /\ c \in 1..MaxCut
  /\ class \in 1..MaxClass
  /\ class > contentClass[c]
  /\ contentClass' = [contentClass EXCEPT ![c] = class]
  /\ UNCHANGED << logged, ref >>

\* A history entry may only be made durable once the content it names is.
PublishHistory(c) ==
  /\ c \in 1..MaxCut
  /\ c \notin logged
  /\ contentClass[c] > 0                  \* CONTENT BEFORE HISTORY
  /\ logged' = logged \cup {c}
  /\ UNCHANGED << contentClass, ref >>

\* The ref advances last, and only over a closure durable at least as strongly
\* as the ref tier itself is served.
AdvanceRef(c) ==
  /\ c \in 1..MaxCut
  /\ c > ref
  /\ c \in logged                         \* HISTORY BEFORE REF
  /\ contentClass[c] >= RefClass          \* NO REF STRONGER THAN ITS CLOSURE
  /\ ref' = c
  /\ UNCHANGED << contentClass, logged >>

Next ==
  \/ \E c \in 1..MaxCut : \E k \in 1..MaxClass : PublishContent(c, k)
  \/ \E c \in 1..MaxCut : PublishHistory(c)
  \/ \E c \in 1..MaxCut : AdvanceRef(c)

\* A reader that observes the ref can always fetch the content behind it. This
\* is the failure the whole design exists to exclude: a runner triggered on a
\* version pulling content that is not there.
NoRefBeyondItsClosure ==
  (ref # 0) => (contentClass[ref] > 0)

\* ...and can always read how that state came about.
NoRefWithoutItsHistory ==
  (ref # 0) => (ref \in logged)

\* The corollary. A ref served more strongly than its closure promises a cut the
\* system cannot actually serve at that strength.
NoRefStrongerThanItsClosure ==
  (ref # 0) => (contentClass[ref] >= RefClass)

\* The bottom edge of the order, stated on its own so it cannot ride on the two
\* above: no history entry names content nobody can serve.
NoHistoryWithoutContent ==
  \A c \in logged : contentClass[c] > 0

SafetyInvariants ==
  /\ TypeOK
  /\ NoRefBeyondItsClosure
  /\ NoRefWithoutItsHistory
  /\ NoRefStrongerThanItsClosure
  /\ NoHistoryWithoutContent

ConstInit ==
  /\ MaxCut = 3
  /\ MaxClass = 2
  /\ RefClass = 2
====
