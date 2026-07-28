---- MODULE EffectRequeueNecessity ----
EXTENDS Naturals

\* Focused bite for the requeue-before-claim necessity that ControlPlaneLifecycle's
\* `UnblockEffect` provides: a blocked effect MUST return to `queued` before it can
\* be claimed; it can never go blocked -> claimed directly. ControlPlaneLifecycle
\* enforces this structurally (ClaimEffect's guard `effects[e] = "queued"`), but no
\* state invariant there is *violated* if that guard is weakened -- claim-from-blocked
\* leaves no bad state, only a bad step. This model gives that necessity real teeth:
\* a history variable records whether any claim ever fired from a non-queued status,
\* and the invariant forbids it. Apalache proves the invariant holds here; the paired
\* mutant (scripts/check-tla-models.sh drops the `status = "queued"` guard from Claim)
\* proves the guard is load-bearing -- Apalache then reports ClaimsOnlyFromQueued
\* violated by a blocked -> claimed step. This is the executable analogue of the Rust
\* checker's `EffectClaimed`-from-{Queued,Blocked} rule + its dependency guard
\* (crates/whipplescript-kernel/src/trace.rs) and the corpus row `blocked claim claimed`.

VARIABLES
  \* @type: Str;
  status,
  \* @type: Bool;
  claimedFromNonQueued

vars == << status, claimedFromNonQueued >>

Statuses == {"queued", "blocked", "claimed"}

Init ==
  /\ status = "queued"
  /\ claimedFromNonQueued = FALSE

\* A queued effect parks (capacity/policy/binding block): queued -> blocked.
Block ==
  /\ status = "queued"
  /\ status' = "blocked"
  /\ UNCHANGED claimedFromNonQueued

\* The block clears: blocked -> queued (this is UnblockEffect / policy-release /
\* capacity-release). This is the ONLY way out of blocked toward a claim.
Unblock ==
  /\ status = "blocked"
  /\ status' = "queued"
  /\ UNCHANGED claimedFromNonQueued

\* Claim. GUARD: only a queued effect is claimable. The history variable records the
\* source status so a claim from anything other than queued is observable forever.
\* (Mutant bite: delete the `status = "queued"` conjunct below and Apalache reports
\* ClaimsOnlyFromQueued violated via a blocked -> claimed step.)
Claim ==
  /\ status = "queued"
  /\ status' = "claimed"
  /\ claimedFromNonQueued' = (claimedFromNonQueued \/ (status # "queued"))

Next ==
  \/ Block
  \/ Unblock
  \/ Claim

Spec == Init /\ [][Next]_vars

TypeOk ==
  /\ status \in Statuses
  /\ claimedFromNonQueued \in BOOLEAN

\* The bite: no claim ever fires from a non-queued status. A blocked effect that
\* reaches `claimed` without first passing through `queued` (via Unblock) sets this
\* flag and violates the invariant.
ClaimsOnlyFromQueued == ~claimedFromNonQueued

Invariants ==
  /\ TypeOk
  /\ ClaimsOnlyFromQueued

====
