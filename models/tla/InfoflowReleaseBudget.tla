---- MODULE InfoflowReleaseBudget ----
EXTENDS Naturals, FiniteSets

\* Semantic checked declassifier, the TEMPORAL layer of DR-0030 Direction C. The Maude
\* model (infoflow-declassifier.maude) bites single steps and the Lean module
\* (Whipple/CheckedDeclassify.lean) proves the timeless per-step algebra. Two properties
\* of C are about a SEQUENCE of releases over time and so live in TLA+:
\*
\*   1. BUDGET over all traces. Maude bit only "an exhausted budget blocks the next
\*      release." The real claim is an inductive safety invariant: across ANY
\*      interleaving of release/refuse steps, the number of releases never exceeds the
\*      fixed budget N, and the remaining budget is monotone non-increasing.
\*
\*   2. NO ADAPTIVE ORACLE, as a trace property. The Lean lemma proves per-step that a
\*      privileged release requires a trusted selector. The operational complement is a
\*      trace invariant: a selector derived from a PREVIOUSLY RELEASED OUTPUT (an
\*      adaptive/attacker-observed selector, modeled as provenance "tainted", which is
\*      only available once some release has occurred) can NEVER drive a privileged
\*      release. So the privileged-release query sequence is observation-independent.
\*
\* HONESTY: full attacker-independence is a 2-safety HYPERPROPERTY (it relates two traces
\* differing in the secret), which single-trace model checking cannot decide directly.
\* What is checked here is the SAFETY SURROGATE -- no privileged release ever carries a
\* tainted (adaptively-derived) selector -- which, combined with the Lean per-step lemma
\* (privileged_release_needs_trusted_selector), yields the operational guarantee. The
\* budget bound is the quantitative BACKSTOP for the self-inflicted (trusted-but-too-many)
\* case; the selector invariant is the PRIMARY structural argument.

CONSTANTS
  \* @type: Int;
  N                 \* the fixed, public release budget

VARIABLES
  \* @type: Int;
  releaseCount,     \* releases committed so far
  \* @type: Set({ seq: Int, aud: Str, prov: Str });
  releaseLog,       \* the committed releases: sequence number, audience, selector provenance
  \* @type: Bool;
  hasPending,       \* a release request is awaiting the checked-declassifier decision
  \* @type: Str;
  pendAud,          \* requested audience: "public" or "privileged"
  \* @type: Str;
  pendProv          \* selector provenance: "trusted" (authored) or "tainted" (adaptive)

vars == << releaseCount, releaseLog, hasPending, pendAud, pendProv >>

Auds == {"public", "privileged"}
Provs == {"trusted", "tainted"}

TypeOK ==
  /\ releaseCount \in Nat
  /\ \A r \in releaseLog : r.seq \in Nat /\ r.aud \in Auds /\ r.prov \in Provs
  /\ hasPending \in BOOLEAN
  /\ pendAud \in (Auds \cup {"none"})
  /\ pendProv \in (Provs \cup {"none"})

Init ==
  /\ releaseCount = 0
  /\ releaseLog = {}
  /\ hasPending = FALSE
  /\ pendAud = "none"
  /\ pendProv = "none"

\* The environment submits a release request. A "tainted" selector -- one derived from a
\* previously released output -- is only available AFTER at least one release: that is
\* exactly what makes an oracle "adaptive". A trusted selector is always available
\* (authored, observation-independent).
Submit(aud, prov) ==
  /\ ~hasPending
  /\ aud \in Auds
  /\ prov \in Provs
  /\ (prov = "tainted") => (releaseCount > 0)
  /\ hasPending' = TRUE
  /\ pendAud' = aud
  /\ pendProv' = prov
  /\ UNCHANGED << releaseCount, releaseLog >>

\* The checked declassifier RELEASES iff budget remains AND the NMIF-on-selector guard
\* holds: a privileged release requires a trusted selector. (Grant and predicate are
\* assumed satisfied here; they are bitten in the Maude model.)
Release ==
  /\ hasPending
  /\ releaseCount < N
  /\ ((pendAud = "privileged") => (pendProv = "trusted"))
  /\ releaseCount' = releaseCount + 1
  /\ releaseLog' = releaseLog \cup {[seq |-> releaseCount, aud |-> pendAud, prov |-> pendProv]}
  /\ hasPending' = FALSE
  /\ pendAud' = "none"
  /\ pendProv' = "none"

\* The declassifier REFUSES a request it cannot serve -- an exhausted budget, or a
\* privileged request with a tainted (adaptive) selector. The refusal decision here
\* depends only on the public budget and the selector's integrity, never on the secret,
\* so the refusal itself is not a leak channel (the refusal-channel result, C).
Refuse ==
  /\ hasPending
  /\ ( (releaseCount >= N) \/ (pendAud = "privileged" /\ pendProv = "tainted") )
  /\ hasPending' = FALSE
  /\ pendAud' = "none"
  /\ pendProv' = "none"
  /\ UNCHANGED << releaseCount, releaseLog >>

Next ==
  \/ \E aud \in Auds, prov \in Provs : Submit(aud, prov)
  \/ Release
  \/ Refuse

\* (1) The budget is never exceeded, on any trace.
BudgetBounded ==
  releaseCount <= N

\* (1') The remaining budget is non-negative -- the monotone-non-increasing budget never
\* underflows (releaseCount only ever grows, and only while releaseCount < N).
BudgetNonNegative ==
  (N - releaseCount) >= 0

\* (1'') The release count matches the log size, so the budget accounts for exactly the
\* committed releases (no uncounted release).
CountMatchesLog ==
  releaseCount = Cardinality(releaseLog)

\* (2) NO ADAPTIVE ORACLE (safety surrogate): no committed privileged release ever
\* carries a tainted (adaptively-derived) selector. With the Lean per-step lemma this is
\* the operational "no adaptive oracle to a privileged reader".
NoPrivilegedTaintedRelease ==
  \A r \in releaseLog : (r.aud = "privileged") => (r.prov = "trusted")

SafetyInvariants ==
  /\ TypeOK
  /\ BudgetBounded
  /\ BudgetNonNegative
  /\ CountMatchesLog
  /\ NoPrivilegedTaintedRelease

ConstInit ==
  N = 2
====
