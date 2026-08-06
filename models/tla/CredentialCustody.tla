---- MODULE CredentialCustody ----
EXTENDS Naturals, FiniteSets

\* DR-0053 credential custody, lifecycle half. The companion Maude models
\* (credential-no-eliminator.maude, credential-verify-endorse.maude) prove the
\* language-level claims. This model proves the runtime properties a type
\* system cannot reach, because they are about time, leases, and policy rather
\* than about derivability.
\*
\* A use is SPLIT into StartUse/CompleteUse rather than being atomic. That is
\* not decoration: DR-0053 section 1 claims uses are "revocable mid-flight",
\* and an atomic use cannot express a revocation that lands while a request is
\* outstanding -- the exact case the claim is about. The split is also what
\* makes the rung floor's TIMING checkable: with Reseal in the model, a floor
\* checked only at admission would let a credential downgraded mid-flight
\* complete a use below the envelope minimum.
\*
\*   NoPlaintextInWhip       substitution happens in the custodian's principal.
\*                           DR-0042 rejected a direct-fetch fallback when the
\*                           broker is down -- availability uncertainty cannot
\*                           widen credential custody.
\*   RungFloor               no use is admitted at a seal rung below the
\*                           envelope's `require credential <rung>` minimum,
\*                           evaluated at COMPLETION against the rung then.
\*   NoUseAfterRevoke        a revoked credential is not still leased.
\*   NoCompletionAfterRevoke no in-flight use completes after its credential is
\*                           revoked. A history variable, because a state
\*                           invariant cannot catch a bad STEP and Apalache
\*                           0.56 has no --trace-inv (same reason
\*                           EffectRequeueNecessity carries one).
\*   UsesAreRecorded         every use that counted left evidence. Without this
\*                           RungFloor is vacuous: it quantifies over
\*                           `admitted`, so a use that skipped recording would
\*                           satisfy it for free. This is the invariant behind
\*                           the DR's "every use is attributable".
\*   RotationNeverEmpty      the dual-validity overlap never leaves a
\*                           credential with zero valid versions.
\*   BudgetRespected         per-credential use budgets bound the blast radius
\*                           of an escape that can use but not extract.
\*
\* Every one is proven load-bearing by mutation in scripts/check-tla-models.sh.

CONSTANTS
  \* @type: Set(Str);
  Creds,
  \* @type: Int;
  MinRung,
  \* @type: Int;
  Budget,
  \* @type: Int;
  MaxVersion

\* Custody requires the brokered path. Mutating this to "whip" models the
\* direct-fetch fallback DR-0042 rejected, and must break NoPlaintextInWhip.
\* @type: () => Str;
SubstitutionPrincipal == "custodian"

VARIABLES
  \* Seal rung per credential: 0 process, 1 os-keyring, 2 hardware, 3 remote.
  \* Mutable, because rungs are DERIVED FROM EVIDENCE and evidence changes --
  \* a backend fails over, or the migration shim resolves a legacy `env:` ref
  \* at a degraded r0.
  \* @type: Str -> Int;
  sealedAt,
  \* @type: Set(Str);
  leased,
  \* @type: Set(Str);
  revoked,
  \* Uses started but not yet completed.
  \* @type: Set(Str);
  inFlight,
  \* @type: Str -> Int;
  uses,
  \* Valid versions during a rotation overlap.
  \* @type: Str -> Set(Int);
  versions,
  \* @type: Str -> Int;
  nextVersion,
  \* Where plaintext material has come into existence: (credential, principal).
  \* @type: Set(<<Str, Str>>);
  materialAt,
  \* Admitted uses as (credential, rung-it-ran-at), which is what the run
  \* evidence carries.
  \* @type: Set(<<Str, Int>>);
  admitted,
  \* History: did any use ever complete against a revoked credential?
  \* @type: Bool;
  badCompletion

vars ==
  << sealedAt, leased, revoked, inFlight, uses, versions, nextVersion,
     materialAt, admitted, badCompletion >>

Rungs == 0 .. 3

\* uses is typed WIDER than Budget on purpose. Typing it 0..Budget would fold
\* BudgetRespected into TypeOK, and the budget mutation would then be caught by
\* the type invariant rather than by the property it is meant to test.
TypeOK ==
  /\ sealedAt \in [Creds -> Rungs]
  /\ leased \subseteq Creds
  /\ revoked \subseteq Creds
  /\ inFlight \subseteq Creds
  /\ uses \in [Creds -> 0 .. (Budget + 2)]
  /\ versions \in [Creds -> SUBSET (1 .. MaxVersion)]
  /\ nextVersion \in [Creds -> 1 .. (MaxVersion + 1)]
  /\ materialAt \subseteq (Creds \X {"whip", "custodian"})
  /\ admitted \subseteq (Creds \X Rungs)
  /\ badCompletion \in BOOLEAN

\* Seal rungs are environment facts, so Init ranges over every assignment --
\* the rung floor is then a real constraint rather than a fixture accident.
Init ==
  /\ sealedAt \in [Creds -> Rungs]
  /\ leased = {}
  /\ revoked = {}
  /\ inFlight = {}
  /\ uses = [c \in Creds |-> 0]
  /\ versions = [c \in Creds |-> {1}]
  /\ nextVersion = [c \in Creds |-> 2]
  /\ materialAt = {}
  /\ admitted = {}
  /\ badCompletion = FALSE

\* A credential is leased to a run. A revoked credential is never re-leased.
Lease(c) ==
  /\ c \notin leased
  /\ c \notin revoked
  /\ leased' = leased \cup {c}
  /\ UNCHANGED << sealedAt, revoked, inFlight, uses, versions, nextVersion,
                  materialAt, admitted, badCompletion >>

\* Admission. The rung and budget are checked here, as a real system would at
\* request time. A rotation must have something valid to use.
StartUse(c) ==
  /\ c \in leased
  /\ c \notin revoked
  /\ c \notin inFlight
  /\ uses[c] < Budget
  /\ sealedAt[c] >= MinRung
  /\ versions[c] # {}
  /\ inFlight' = inFlight \cup {c}
  /\ UNCHANGED << sealedAt, leased, revoked, uses, versions, nextVersion,
                  materialAt, admitted, badCompletion >>

\* Completion. Both the revocation check and the rung check are RE-EVALUATED
\* here against current state -- that is the whole point of splitting the use.
\* Material comes into existence in the custodian's principal and never
\* crosses back. badCompletion records the pre-state unconditionally, so
\* removing the revocation guard is visible rather than merely unguarded.
CompleteUse(c) ==
  /\ c \in inFlight
  /\ c \notin revoked
  /\ sealedAt[c] >= MinRung
  /\ inFlight' = inFlight \ {c}
  /\ uses' = [uses EXCEPT ![c] = uses[c] + 1]
  /\ admitted' = admitted \cup {<<c, sealedAt[c]>>}
  /\ materialAt' = materialAt \cup {<<c, SubstitutionPrincipal>>}
  /\ badCompletion' = (badCompletion \/ (c \in revoked))
  /\ UNCHANGED << sealedAt, leased, revoked, versions, nextVersion >>

\* Revocation caught an in-flight use: it is dropped, not completed. This is
\* the "revocable mid-flight" behaviour DR-0053 section 1 claims.
AbortUse(c) ==
  /\ c \in inFlight
  /\ c \in revoked
  /\ inFlight' = inFlight \ {c}
  /\ UNCHANGED << sealedAt, leased, revoked, uses, versions, nextVersion,
                  materialAt, admitted, badCompletion >>

\* Revocation is prompt: it drops the lease in the same step that revokes, so
\* no later admission can occur. An already in-flight use is handled above.
Revoke(c) ==
  /\ c \notin revoked
  /\ revoked' = revoked \cup {c}
  /\ leased' = leased \ {c}
  /\ UNCHANGED << sealedAt, inFlight, uses, versions, nextVersion,
                  materialAt, admitted, badCompletion >>

\* Re-sealing at a different rung, in either direction: a backend fails over,
\* hardware becomes available, or the migration shim degrades a legacy ref to
\* r0. Unconstrained on purpose -- the floor is enforced at use, not here.
Reseal(c, r) ==
  /\ sealedAt' = [sealedAt EXCEPT ![c] = r]
  /\ UNCHANGED << leased, revoked, inFlight, uses, versions, nextVersion,
                  materialAt, admitted, badCompletion >>

\* Rotation, phase 1: mint the new version alongside the old. Both are valid.
RotateBegin(c) ==
  /\ nextVersion[c] <= MaxVersion
  /\ versions' = [versions EXCEPT ![c] = versions[c] \cup {nextVersion[c]}]
  /\ nextVersion' = [nextVersion EXCEPT ![c] = nextVersion[c] + 1]
  /\ UNCHANGED << sealedAt, leased, revoked, inFlight, uses, materialAt,
                  admitted, badCompletion >>

\* Rotation, phase 2: retire the oldest version. The cardinality guard is what
\* keeps the overlap non-empty; without it, retiring the only version leaves
\* the credential with nothing valid and StartUse can never fire again.
RotateEnd(c) ==
  /\ Cardinality(versions[c]) > 1
  /\ LET oldest == CHOOSE v \in versions[c] : \A w \in versions[c] : v <= w
     IN versions' = [versions EXCEPT ![c] = versions[c] \ {oldest}]
  /\ UNCHANGED << sealedAt, leased, revoked, inFlight, uses, nextVersion,
                  materialAt, admitted, badCompletion >>

Next ==
  \/ \E c \in Creds : Lease(c)
  \/ \E c \in Creds : StartUse(c)
  \/ \E c \in Creds : CompleteUse(c)
  \/ \E c \in Creds : AbortUse(c)
  \/ \E c \in Creds : Revoke(c)
  \/ \E c \in Creds : \E r \in Rungs : Reseal(c, r)
  \/ \E c \in Creds : RotateBegin(c)
  \/ \E c \in Creds : RotateEnd(c)

\* Plaintext never comes into existence in whip's principal.
NoPlaintextInWhip ==
  \A pair \in materialAt : pair[2] # "whip"

\* Every admitted use ran at or above the envelope's minimum rung.
RungFloor ==
  \A pair \in admitted : pair[2] >= MinRung

\* Revocation is prompt: nothing revoked is still leased.
NoUseAfterRevoke ==
  revoked \cap leased = {}

\* No in-flight use ever completed after its credential was revoked.
NoCompletionAfterRevoke ==
  ~badCompletion

\* Every use that counted left evidence. Without this, RungFloor is vacuous.
UsesAreRecorded ==
  \A c \in Creds : (uses[c] > 0) => (\E r \in Rungs : <<c, r>> \in admitted)

\* The rotation overlap never empties.
RotationNeverEmpty ==
  \A c \in Creds : versions[c] # {}

\* Per-credential use budgets hold.
BudgetRespected ==
  \A c \in Creds : uses[c] <= Budget

SafetyInvariants ==
  /\ TypeOK
  /\ NoPlaintextInWhip
  /\ RungFloor
  /\ NoUseAfterRevoke
  /\ NoCompletionAfterRevoke
  /\ UsesAreRecorded
  /\ RotationNeverEmpty
  /\ BudgetRespected

ConstInit ==
  /\ Creds = {"c1", "c2"}
  /\ MinRung = 2
  /\ Budget = 1
  /\ MaxVersion = 3
====
