---- MODULE IngressDeliveryLifecycle ----
EXTENDS Naturals, FiniteSets

\* std.ingress I4 (spec/std-ingress.md "v1 implementation slices"): the inbound
\* HTTP delivery lifecycle -- deliver -> authenticate -> validate ->
\* admit/duplicate/reject -- with crash-retry reusing the delivery key.
\*
\* Model-first by house discipline: this precedes the listener, and the listener
\* is written to it rather than the other way round.
\*
\* What the model is FOR. A webhook sender retries. It retries after a timeout
\* it chose, after a crash on our side, and after a response it did not like,
\* and it reuses its delivery id when it does. So the question the listener has
\* to answer is not "did this arrive twice" but "has this KEY ever been
\* admitted", and the answer has to survive a crash between admitting the fact
\* and answering the sender. The three safety properties are:
\*
\*   AuthenticatedBeforeAdmitted -- nothing unauthenticated ever reaches the
\*     admission core, so a forged delivery cannot append a fact. Fail-closed:
\*     an auth failure is terminal for that delivery, never a retry-into-open.
\*   AtMostOncePerKey -- a delivery key admits at most one fact, EVER, however
\*     many times it is delivered and whatever crashes in between.
\*   NoFactWithoutValidation -- a fact exists only for a payload that passed
\*     its typed check, so a malformed delivery cannot half-admit.
\*
\* The gate proves the auth guard is load-bearing by mutation (see
\* scripts/check-tla-models.sh), because dropping it leaves a bad STEP rather
\* than a bad state unless the model carries the history to notice.

CONSTANTS
  \* @type: Set(Str);
  Keys,
  \* Deliveries that carry a valid signature/token. Everything else is forged.
  \* @type: Set(Str);
  Authentic,
  \* Deliveries whose payload passes the signal's typed contract.
  \* @type: Set(Str);
  WellFormed

VARIABLES
  \* Keys whose fact is durably appended: the admission core's idempotency
  \* index, which is what survives a crash.
  \* @type: Set(Str);
  admitted,
  \* Keys refused by authentication. Terminal: fail-closed means a forged
  \* delivery does not get another attempt at the open door.
  \* @type: Set(Str);
  rejectedAuth,
  \* Keys refused by payload validation, before any fact.
  \* @type: Set(Str);
  rejectedInvalid,
  \* Keys observed as duplicates -- delivered again after admission, absorbed.
  \* @type: Set(Str);
  absorbed,
  \* HISTORY. Every key that ever reached the admission core, whether or not a
  \* fact resulted. Without this, dropping the auth guard leaves no bad state
  \* to violate: the fact still looks legitimate once appended.
  \* @type: Set(Str);
  reachedAdmission,
  \* HISTORY. How many facts each key has appended. `AtMostOncePerKey` reads
  \* this rather than `admitted`, so double-admission is visible even though
  \* the set would absorb it silently.
  \* @type: Str -> Int;
  factCount

TypeOK ==
  /\ admitted \subseteq Keys
  /\ rejectedAuth \subseteq Keys
  /\ rejectedInvalid \subseteq Keys
  /\ absorbed \subseteq Keys
  /\ reachedAdmission \subseteq Keys
  /\ \A k \in Keys : factCount[k] \in Nat

Init ==
  /\ admitted = {}
  /\ rejectedAuth = {}
  /\ rejectedInvalid = {}
  /\ absorbed = {}
  /\ reachedAdmission = {}
  /\ factCount = [k \in Keys |-> 0]

\* Settled: this delivery key has already reached a terminal answer, so a fresh
\* delivery of it is a RETRY rather than a first attempt.
Settled(k) == k \in admitted \/ k \in rejectedAuth \/ k \in rejectedInvalid

\* AUTHENTICATE. The guard is `k \in Authentic`, and it is the one the gate
\* mutates: without it a forged delivery walks into validation.
Authenticate(k) ==
  /\ ~Settled(k)
  /\ k \in Authentic
  /\ k \in WellFormed
  /\ reachedAdmission' = reachedAdmission \cup {k}
  /\ admitted' = admitted \cup {k}
  /\ factCount' = [factCount EXCEPT ![k] = @ + 1]
  /\ UNCHANGED << rejectedAuth, rejectedInvalid, absorbed >>

\* Fail-closed: an unauthentic delivery is refused BEFORE the admission core,
\* appends nothing, and is terminal for that key.
RejectAuth(k) ==
  /\ ~Settled(k)
  /\ k \notin Authentic
  /\ rejectedAuth' = rejectedAuth \cup {k}
  /\ UNCHANGED << admitted, rejectedInvalid, absorbed, reachedAdmission, factCount >>

\* Validation runs INSIDE the authenticated path and still appends nothing when
\* the payload does not match the signal's contract.
RejectInvalid(k) ==
  /\ ~Settled(k)
  /\ k \in Authentic
  /\ k \notin WellFormed
  /\ reachedAdmission' = reachedAdmission \cup {k}
  /\ rejectedInvalid' = rejectedInvalid \cup {k}
  /\ UNCHANGED << admitted, rejectedAuth, absorbed, factCount >>

\* THE RETRY. The sender re-delivers with the same key, because it crashed, or
\* we did, or it did not like our answer. The key is already admitted, so the
\* delivery is absorbed: no second fact.
RedeliverAdmitted(k) ==
  /\ k \in admitted
  /\ k \in Authentic
  /\ absorbed' = absorbed \cup {k}
  /\ UNCHANGED << admitted, rejectedAuth, rejectedInvalid, reachedAdmission, factCount >>

\* A CRASH between appending the fact and answering the sender. The durable
\* index is what survives, so the retry that follows still finds the key
\* admitted -- this is why idempotency lives in the store rather than in the
\* listener's memory.
CrashAndRetry(k) ==
  /\ k \in admitted
  /\ absorbed' = absorbed \cup {k}
  /\ UNCHANGED << admitted, rejectedAuth, rejectedInvalid, reachedAdmission, factCount >>

\* A forged delivery retried after refusal is refused again. Fail-closed does
\* not soften with repetition.
RedeliverRejected(k) ==
  /\ k \in rejectedAuth
  /\ UNCHANGED << admitted, rejectedAuth, rejectedInvalid, absorbed, reachedAdmission, factCount >>

Next ==
  \/ \E k \in Keys : Authenticate(k)
  \/ \E k \in Keys : RejectAuth(k)
  \/ \E k \in Keys : RejectInvalid(k)
  \/ \E k \in Keys : RedeliverAdmitted(k)
  \/ \E k \in Keys : CrashAndRetry(k)
  \/ \E k \in Keys : RedeliverRejected(k)

\* Nothing unauthenticated ever reaches the admission core. This is the property
\* the mutation targets: it reads the HISTORY, so a forged delivery that got in
\* is visible even after its fact looks like any other.
AuthenticatedBeforeAdmitted ==
  \A k \in reachedAdmission : k \in Authentic

\* A delivery key appends at most one fact, ever -- across retries and across a
\* crash between the append and the answer.
AtMostOncePerKey ==
  \A k \in Keys : factCount[k] <= 1

\* A fact exists only for a payload that passed its typed contract.
\*
\* Stated over factCount rather than over `rejectedInvalid`, which is how it
\* was first written and was circular: asking "did the rejected set append
\* anything" cannot see a malformed payload that was ADMITTED instead, so
\* dropping the validation guard violated nothing. The bite pass caught that --
\* the invariant looked reasonable and proved nothing about the guard.
NoFactWithoutValidation ==
  \A k \in Keys : factCount[k] > 0 => k \in WellFormed

\* An authentication failure is terminal: it never also appears as admitted.
AuthFailureIsTerminal ==
  rejectedAuth \cap admitted = {}

SafetyInvariants ==
  /\ TypeOK
  /\ AuthenticatedBeforeAdmitted
  /\ AtMostOncePerKey
  /\ NoFactWithoutValidation
  /\ AuthFailureIsTerminal

\* Every guard needs a WITNESS in the fixture, or removing it changes nothing
\* and the bite pass reports a guard as load-bearing that never fired. The
\* first version of this had WellFormed covering every key, so the validation
\* guard was decorative and the mutation went uncaught:
\*
\*   d1  authentic and well formed   -- admits, and is the retry/crash subject
\*   d2  authentic and MALFORMED     -- the validation guard's witness
\*   d3  FORGED                      -- the authentication guard's witness
ConstInit ==
  /\ Keys = {"d1", "d2", "d3"}
  /\ Authentic = {"d1", "d2"}
  /\ WellFormed = {"d1", "d3"}
====
