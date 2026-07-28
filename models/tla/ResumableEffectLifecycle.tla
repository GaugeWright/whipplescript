---- MODULE ResumableEffectLifecycle ----
EXTENDS Naturals, Sequences, FiniteSets

\* Phase-0 model for the durable-object runtime (DR-0033, Decisions 1-3).
\*
\* Each external-I/O effect is a pure resumable STEP MACHINE that the host drives:
\*
\*     claim -> [ NeedsIo -> io_pending -> io_done ]* -> settle
\*
\* The Rust `step(state, incoming)` is synchronous on both hosts; only the HOST
\* differs. The NATIVE host runs the machine to completion in one pass (no
\* eviction between issuing an HTTP request and recording its response). The
\* DURABLE-OBJECT host may be evicted mid-`fetch`: the in-memory wait is lost but
\* the durable step state survives, so on resume the request is re-dispatched.
\* That is the at-least-once network semantics of Decision 3. A per-round
\* idempotency key derived ONLY from durable identity (instance/version/epoch/
\* rule/node/identity -- here abstracted as `KeyOf(e)`) lets the provider dedupe
\* the retry, so the provider-visible side effect stays exactly-once per round.
\*
\* This model tracks the asynchronous host/network actions; the Maude models
\* cover the local rule/effect rewrites. It proves: exactly-once settle; provider
\* side effects bounded by rounds despite at-least-once dispatch (idempotency-key
\* stability across suspend/resume); no orphaned io_pending; and that the native
\* run-to-completion path is a refinement where at-least-once collapses back to
\* exactly-once.

CONSTANTS
  \* @type: Set(Str);
  Effects,
  \* @type: Int;
  MaxRounds,
  \* @type: Int;
  MaxEvicts

VARIABLES
  \* @type: Str -> Str;
  status,
  \* @type: Str -> Int;
  roundsLeft,
  \* @type: Str -> Str;
  idemKey,
  \* @type: Str -> Bool;
  inflight,
  \* @type: Str -> Int;
  roundsStarted,
  \* @type: Str -> Int;
  dispatchCount,
  \* @type: Str -> Int;
  providerExecCount,
  \* @type: Str -> Int;
  evictions,
  \* @type: Set(<<Str, Int>>);
  providerExecuted,
  \* @type: Str -> Str;
  terminal,
  \* @type: Seq(<<Str, Str>>);
  settledEvents,
  \* @type: Str;
  hostMode

vars ==
  << status, roundsLeft, idemKey, inflight, roundsStarted, dispatchCount,
     providerExecCount, evictions, providerExecuted, terminal, settledEvents,
     hostMode >>

Statuses == {"queued", "claimed", "io_pending", "settled"}
TerminalOutcomes == {"completed", "failed"}
HostModes == {"native", "do"}

\* The stable idempotency identity of an effect: a pure function of durable
\* identity only (never of the runtime attempt / eviction count). In the runtime
\* this is idempotency_key([instance, version, epoch, rule, node_id, identity]);
\* distinct effect nodes have distinct keys, so modelling it as the effect id is
\* faithful (injective) and, crucially, attempt-independent.
\* @type: (Str) => Str;
KeyOf(e) == e

\* The per-ROUND request key: identity + which round. Stable across suspend /
\* resume within a round because neither component changes while io_pending
\* (roundsLeft is decremented only by IoComplete, which leaves io_pending).
\* @type: (Str) => <<Str, Int>>;
RoundKey(e) == << idemKey[e], roundsLeft[e] >>

\* Only the durable-object host can lose an in-flight request (eviction /
\* resume). The native host runs the step machine to completion in one pass.
CanLoseInflight == hostMode = "do"

Init ==
  /\ status = [e \in Effects |-> "queued"]
  /\ roundsLeft = [e \in Effects |-> 0]
  /\ idemKey = [e \in Effects |-> ""]
  /\ inflight = [e \in Effects |-> FALSE]
  /\ roundsStarted = [e \in Effects |-> 0]
  /\ dispatchCount = [e \in Effects |-> 0]
  /\ providerExecCount = [e \in Effects |-> 0]
  /\ evictions = [e \in Effects |-> 0]
  /\ providerExecuted = {}
  /\ terminal = [e \in Effects |-> "none"]
  /\ settledEvents = << >>
  /\ hostMode \in HostModes

\* Claim a queued effect and fix its durable idempotency identity + how many IO
\* rounds it will take (0 = a pure/no-IO effect that settles immediately).
Claim(e) ==
  /\ e \in Effects
  /\ status[e] = "queued"
  /\ \E n \in 0..MaxRounds :
       roundsLeft' = [roundsLeft EXCEPT ![e] = n]
  /\ status' = [status EXCEPT ![e] = "claimed"]
  /\ idemKey' = [idemKey EXCEPT ![e] = KeyOf(e)]
  /\ UNCHANGED << inflight, roundsStarted, dispatchCount, providerExecCount,
                  evictions, providerExecuted, terminal, settledEvents,
                  hostMode >>

\* The step machine needs IO: enter io_pending and dispatch the request. First
\* dispatch of a fresh round, so the provider executes it (its RoundKey is new).
NeedIo(e) ==
  /\ e \in Effects
  /\ status[e] = "claimed"
  /\ roundsLeft[e] > 0
  /\ status' = [status EXCEPT ![e] = "io_pending"]
  /\ roundsStarted' = [roundsStarted EXCEPT ![e] = roundsStarted[e] + 1]
  /\ inflight' = [inflight EXCEPT ![e] = TRUE]
  /\ dispatchCount' = [dispatchCount EXCEPT ![e] = dispatchCount[e] + 1]
  /\ IF RoundKey(e) \notin providerExecuted
     THEN /\ providerExecuted' = providerExecuted \cup { RoundKey(e) }
          /\ providerExecCount' = [providerExecCount EXCEPT ![e] = providerExecCount[e] + 1]
     ELSE /\ providerExecuted' = providerExecuted
          /\ providerExecCount' = providerExecCount
  /\ UNCHANGED << roundsLeft, idemKey, evictions, terminal, settledEvents,
                  hostMode >>

\* Durable-object eviction: the host forgets the in-flight wait. The durable
\* status stays io_pending; on resume the round is re-dispatched. Bounded by
\* MaxEvicts so the state space is finite (a real deployment evicts finitely).
Evict(e) ==
  /\ e \in Effects
  /\ CanLoseInflight
  /\ status[e] = "io_pending"
  /\ inflight[e] = TRUE
  /\ evictions[e] < MaxEvicts
  /\ inflight' = [inflight EXCEPT ![e] = FALSE]
  /\ evictions' = [evictions EXCEPT ![e] = evictions[e] + 1]
  /\ UNCHANGED << status, roundsLeft, idemKey, roundsStarted, dispatchCount,
                  providerExecCount, providerExecuted, terminal, settledEvents,
                  hostMode >>

\* Resume after eviction: re-dispatch the SAME round with the SAME RoundKey.
\* This is the at-least-once retry (dispatchCount rises); the provider dedupes it
\* (RoundKey already executed), so providerExecCount does NOT rise. Always
\* available while io_pending with no in-flight request -> no orphaned state.
Redispatch(e) ==
  /\ e \in Effects
  /\ CanLoseInflight
  /\ status[e] = "io_pending"
  /\ inflight[e] = FALSE
  /\ inflight' = [inflight EXCEPT ![e] = TRUE]
  /\ dispatchCount' = [dispatchCount EXCEPT ![e] = dispatchCount[e] + 1]
  /\ IF RoundKey(e) \notin providerExecuted
     THEN /\ providerExecuted' = providerExecuted \cup { RoundKey(e) }
          /\ providerExecCount' = [providerExecCount EXCEPT ![e] = providerExecCount[e] + 1]
     ELSE /\ providerExecuted' = providerExecuted
          /\ providerExecCount' = providerExecCount
  /\ UNCHANGED << status, roundsLeft, idemKey, roundsStarted, evictions,
                  terminal, settledEvents, hostMode >>

\* The response arrives (io_done): fold it in, one fewer round remains, return to
\* the synchronous compute state. Clears the in-flight wait.
IoComplete(e) ==
  /\ e \in Effects
  /\ status[e] = "io_pending"
  /\ inflight[e] = TRUE
  /\ status' = [status EXCEPT ![e] = "claimed"]
  /\ roundsLeft' = [roundsLeft EXCEPT ![e] = roundsLeft[e] - 1]
  /\ inflight' = [inflight EXCEPT ![e] = FALSE]
  /\ UNCHANGED << idemKey, roundsStarted, dispatchCount, providerExecCount,
                  evictions, providerExecuted, terminal, settledEvents,
                  hostMode >>

\* No more IO rounds: the machine settles to exactly one terminal.
Settle(e, outcome) ==
  /\ e \in Effects
  /\ outcome \in TerminalOutcomes
  /\ status[e] = "claimed"
  /\ roundsLeft[e] = 0
  /\ status' = [status EXCEPT ![e] = "settled"]
  /\ terminal' = [terminal EXCEPT ![e] = outcome]
  /\ settledEvents' = Append(settledEvents, << e, outcome >>)
  /\ UNCHANGED << roundsLeft, idemKey, inflight, roundsStarted, dispatchCount,
                  providerExecCount, evictions, providerExecuted, hostMode >>

Next ==
  \/ \E e \in Effects : Claim(e)
  \/ \E e \in Effects : NeedIo(e)
  \/ \E e \in Effects : Evict(e)
  \/ \E e \in Effects : Redispatch(e)
  \/ \E e \in Effects : IoComplete(e)
  \/ \E e \in Effects, o \in TerminalOutcomes : Settle(e, o)

Spec ==
  Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* Fairness + liveness (defined for completeness, mirroring
\* ControlPlaneLifecycle; the gate checks SafetyInvariants). Bounded evictions +
\* weak fairness on IoComplete/Redispatch/Settle give progress.

FairSpec ==
  /\ Spec
  /\ \A e \in Effects :
       /\ WF_vars(IoComplete(e))
       /\ WF_vars(Redispatch(e))
       /\ WF_vars(\E o \in TerminalOutcomes : Settle(e, o))

\* Every io_pending effect eventually leaves io_pending (io_done or, after
\* eviction, a resume+complete). No effect strands mid-fetch.
IoPendingEventuallyResolves ==
  \A e \in Effects :
    [](status[e] = "io_pending" => <>(status[e] # "io_pending"))

LivenessGoals ==
  /\ IoPendingEventuallyResolves

-----------------------------------------------------------------------------
\* Safety invariants.

\* @type: (Seq(<<Str, Str>>)) => Bool;
TerminalSeqOk(seq) ==
  \A i \in 1..Len(seq) :
    /\ seq[i][1] \in Effects
    /\ seq[i][2] \in TerminalOutcomes

ProviderKeysOk ==
  \A k \in providerExecuted :
    /\ k[1] \in { KeyOf(e) : e \in Effects }
    /\ k[2] \in Nat

TypeOk ==
  /\ status \in [Effects -> Statuses]
  /\ roundsLeft \in [Effects -> Nat]
  /\ idemKey \in [Effects -> ({""} \cup { KeyOf(e) : e \in Effects })]
  /\ inflight \in [Effects -> BOOLEAN]
  /\ roundsStarted \in [Effects -> Nat]
  /\ dispatchCount \in [Effects -> Nat]
  /\ providerExecCount \in [Effects -> Nat]
  /\ evictions \in [Effects -> Nat]
  /\ ProviderKeysOk
  /\ terminal \in [Effects -> ({"none"} \cup TerminalOutcomes)]
  /\ TerminalSeqOk(settledEvents)
  /\ hostMode \in HostModes

\* Exactly-once settle: an effect appears at most once in the terminal ledger.
\* (Bite: drop the `status[e] = "claimed"` guard in Settle so a settled effect
\* can settle again -- Apalache reports a duplicate entry.)
NoDuplicateSettle ==
  \A i, j \in 1..Len(settledEvents) :
    settledEvents[i][1] = settledEvents[j][1] => i = j

\* The settled status and the recorded terminal agree.
\* (Bite: make Settle set status without setting terminal -> the <=> breaks.)
SettledMatchesTerminal ==
  \A e \in Effects :
    (status[e] = "settled") <=> (terminal[e] # "none")

\* The ledger and the settled set are in bijection: equal size and every entry
\* is a settled effect. With NoDuplicateSettle this forces every settled effect
\* to appear exactly once -- so the terminal ledger is the settled set.
SettledLedgerMatchesSet ==
  /\ Len(settledEvents) = Cardinality({ e \in Effects : status[e] = "settled" })
  /\ \A i \in 1..Len(settledEvents) : status[settledEvents[i][1]] = "settled"

\* No orphaned io_pending state: an in-flight request exists only while waiting,
\* and a waiting effect either has a live request or (on the DO host) will be
\* re-dispatched by resume. (Bite: make IoComplete forget to clear `inflight`,
\* leaving inflight set on a settled/claimed effect -> InflightOnlyWhenIoPending
\* fails.)
InflightOnlyWhenIoPending ==
  \A e \in Effects : inflight[e] => status[e] = "io_pending"

NoOrphanedIoPending ==
  \A e \in Effects :
    status[e] = "io_pending" => (inflight[e] \/ hostMode = "do")

\* An io_pending effect always still owes an IO round (structure of the step
\* machine). (Bite: let NeedIo fire with roundsLeft = 0, or IoComplete not
\* decrement -> an io_pending effect with 0 rounds left is reachable.)
IoPendingHasRoundsLeft ==
  \A e \in Effects : status[e] = "io_pending" => roundsLeft[e] >= 1

\* Idempotency-key stability: once claimed, the key is exactly the durable
\* identity function and never changes across suspend / resume / re-dispatch.
\* (Bite: reassign idemKey from `evictions[e]` in Redispatch -> the key drifts
\* across a resume and this fails.)
IdemKeyStable ==
  \A e \in Effects : status[e] # "queued" => idemKey[e] = KeyOf(e)

\* The heart of Decision 3: the provider executes each round's request AT MOST
\* ONCE even though a round may be dispatched several times (at-least-once). This
\* holds because the retry carries the SAME stable RoundKey and is deduped.
\* (Bite: change RoundKey to << idemKey[e], roundsLeft[e], evictions[e] >> so a
\* post-eviction re-dispatch looks like a new request -> the provider executes it
\* twice in one round and providerExecCount exceeds roundsStarted.)
ProviderExecBoundedByRounds ==
  \A e \in Effects : providerExecCount[e] <= roundsStarted[e]

\* At-least-once is real: every started round is dispatched at least once, and
\* dispatches are never fewer than provider executions. After an eviction+resume
\* dispatchCount strictly exceeds providerExecCount -- the duplicate the
\* idempotency key absorbs.
AtLeastOnceLowerBounds ==
  \A e \in Effects :
    /\ dispatchCount[e] >= roundsStarted[e]
    /\ dispatchCount[e] >= providerExecCount[e]

\* Refinement: the native run-to-completion path is the eviction-free special
\* case, where at-least-once collapses back to exactly-once -- one dispatch and
\* one provider execution per started round. (Bite: redefine
\* `CanLoseInflight == TRUE` so the native host may evict/redispatch -> native
\* dispatchCount exceeds providerExecCount and this fails.)
NativeExactlyOnce ==
  hostMode = "native" =>
    \A e \in Effects :
      /\ dispatchCount[e] = roundsStarted[e]
      /\ providerExecCount[e] = roundsStarted[e]

ConstInit ==
  /\ Effects = {"e1", "e2"}
  /\ MaxRounds = 2
  /\ MaxEvicts = 1

SafetyInvariants ==
  /\ TypeOk
  /\ NoDuplicateSettle
  /\ SettledMatchesTerminal
  /\ SettledLedgerMatchesSet
  /\ InflightOnlyWhenIoPending
  /\ NoOrphanedIoPending
  /\ IoPendingHasRoundsLeft
  /\ IdemKeyStable
  /\ ProviderExecBoundedByRounds
  /\ AtLeastOnceLowerBounds
  /\ NativeExactlyOnce

====
