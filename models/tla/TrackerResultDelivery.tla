---- MODULE TrackerResultDelivery ----
EXTENDS Naturals, Sequences

\* One tracker filing, with separate target and runtime transactions.
\* Authentication and target receipt verification are abstracted as current
\* authority and exact proof. This model concerns result publication, not
\* cryptography or the product's interpretation of resource identities.
\* Delivery never invokes the target. It atomically publishes the ordinary
\* result and supersedes only an UNHANDLED failure; run terminals stay final.
VARIABLES
  \* @type: Str;
  run,
  \* @type: Str;
  effect,
  \* @type: Str;
  instance,
  \* @type: Bool;
  receipt,
  \* @type: Int;
  targetWrites,
  \* @type: Int;
  results,
  \* @type: Bool;
  failureFact,
  \* @type: Bool;
  successFact,
  \* @type: Bool;
  appliedEvidence,
  \* @type: Bool;
  handled,
  \* @type: Bool;
  authority,
  \* @type: Bool;
  hasProof,
  \* @type: Bool;
  proofExact,
  \* @type: Bool;
  proofPresent,
  \* @type: Int;
  owner,
  \* @type: Int;
  seenOwner,
  \* @type: Int;
  head,
  \* @type: Int;
  seenHead,
  \* @type: Seq(Str);
  runTerminals,
  \* @type: Seq(Bool);
  deliveryWitness

vars == << run, effect, instance, receipt, targetWrites, results, appliedEvidence, failureFact, successFact, handled, authority, hasProof, proofExact, proofPresent, owner, seenOwner, head, seenHead, runTerminals, deliveryWitness >>

Init ==
  /\ run = "running"
  /\ effect = "running"
  /\ instance = "running"
  /\ receipt = FALSE
  /\ targetWrites = 0
  /\ results = 0
  /\ failureFact = FALSE
  /\ successFact = FALSE
  /\ appliedEvidence = FALSE
  /\ handled = FALSE
  /\ authority = TRUE
  /\ hasProof = FALSE
  /\ proofExact = FALSE
  /\ proofPresent = FALSE
  /\ owner = 0
  /\ seenOwner = 0
  /\ head = 0
  /\ seenHead = 0
  /\ runTerminals = << >>
  /\ deliveryWitness = << >>

ApplyTarget ==
  /\ run = "running"
  /\ ~receipt
  /\ receipt' = TRUE
  /\ targetWrites' = targetWrites + 1
  /\ UNCHANGED << run, effect, instance, results, appliedEvidence, failureFact, successFact, handled, authority, hasProof, proofExact, proofPresent, owner, seenOwner, head, seenHead, runTerminals, deliveryWitness >>

Expire ==
  /\ run = "running"
  /\ results = 0
  /\ run' = "lease_expired"
  /\ effect' = "failed"
  /\ failureFact' = TRUE
  /\ runTerminals' = Append(runTerminals, "lease_expired")
  /\ head' = head + 1
  /\ UNCHANGED << instance, receipt, targetWrites, results, appliedEvidence, successFact, handled, authority, hasProof, proofExact, proofPresent, owner, seenOwner, seenHead, deliveryWitness >>

RecordFailure ==
  /\ run = "running"
  /\ results = 0
  /\ run' = "failed"
  /\ effect' = "failed"
  /\ failureFact' = TRUE
  /\ runTerminals' = Append(runTerminals, "failed")
  /\ head' = head + 1
  /\ UNCHANGED << instance, receipt, targetWrites, results, appliedEvidence, successFact, handled, authority, hasProof, proofExact, proofPresent, owner, seenOwner, seenHead, deliveryWitness >>

Observe(exact) ==
  /\ authority
  /\ exact \in BOOLEAN
  /\ hasProof' = TRUE
  /\ proofExact' = exact
  /\ proofPresent' = receipt
  /\ seenOwner' = owner
  /\ seenHead' = head
  /\ UNCHANGED << run, effect, instance, receipt, targetWrites, results, appliedEvidence, failureFact, successFact, handled, authority, owner, head, runTerminals, deliveryWitness >>

Revoke ==
  /\ authority
  /\ authority' = FALSE
  /\ UNCHANGED << run, effect, instance, receipt, targetWrites, results, appliedEvidence, failureFact, successFact, handled, hasProof, proofExact, proofPresent, owner, seenOwner, head, seenHead, runTerminals, deliveryWitness >>

Handover ==
  /\ owner = 0
  /\ owner' = 1
  /\ head' = head + 1
  /\ UNCHANGED << run, effect, instance, receipt, targetWrites, results, appliedEvidence, failureFact, successFact, handled, authority, hasProof, proofExact, proofPresent, seenOwner, seenHead, runTerminals, deliveryWitness >>

OtherAppend ==
  /\ head < 10
  /\ head' = head + 1
  /\ UNCHANGED << run, effect, instance, receipt, targetWrites, results, appliedEvidence, failureFact, successFact, handled, authority, hasProof, proofExact, proofPresent, owner, seenOwner, seenHead, runTerminals, deliveryWitness >>

RefreshHead ==
  /\ hasProof
  /\ seenHead' = head
  /\ UNCHANGED << run, effect, instance, receipt, targetWrites, results, appliedEvidence, failureFact, successFact, handled, authority, hasProof, proofExact, proofPresent, owner, seenOwner, head, runTerminals, deliveryWitness >>

HandleFailure ==
  /\ failureFact
  /\ instance = "running"
  /\ handled' = TRUE
  /\ failureFact' = FALSE
  /\ head' = head + 1
  /\ UNCHANGED << run, effect, instance, receipt, targetWrites, results, appliedEvidence, successFact, authority, hasProof, proofExact, proofPresent, owner, seenOwner, seenHead, runTerminals, deliveryWitness >>

Cancel ==
  /\ instance = "running"
  /\ instance' = "cancelled"
  /\ head' = head + 1
  /\ UNCHANGED << run, effect, receipt, targetWrites, results, appliedEvidence, failureFact, successFact, handled, authority, hasProof, proofExact, proofPresent, owner, seenOwner, seenHead, runTerminals, deliveryWitness >>

Finish ==
  /\ instance = "running"
  /\ successFact
  /\ instance' = "completed"
  /\ head' = head + 1
  /\ UNCHANGED << run, effect, receipt, targetWrites, results, appliedEvidence, failureFact, successFact, handled, authority, hasProof, proofExact, proofPresent, owner, seenOwner, seenHead, runTerminals, deliveryWitness >>

Deliver ==
  /\ hasProof
  /\ authority \* GUARD current-authority
  /\ proofExact \* GUARD exact-receipt
  /\ proofPresent \* GUARD committed-receipt
  /\ instance = "running" \* GUARD live-workflow
  /\ ~handled \* GUARD unhandled-failure
  /\ results = 0 \* GUARD one-result
  /\ seenOwner = owner \* GUARD ownership
  /\ seenHead = head \* GUARD head-cas
  /\ run' = IF run = "running" THEN "completed" ELSE run
  /\ runTerminals' = IF run = "running" THEN Append(runTerminals, "completed") ELSE runTerminals
  /\ effect' = "completed"
  /\ results' = results + 1
  /\ successFact' = TRUE
  /\ appliedEvidence' = TRUE
  /\ failureFact' = FALSE
  /\ hasProof' = FALSE
  /\ head' = head + 1
  /\ deliveryWitness' = << authority, proofExact, proofPresent, instance = "running", ~handled, seenOwner = owner, seenHead = head >>
  /\ UNCHANGED << instance, receipt, targetWrites, handled, authority, proofExact, proofPresent, owner, seenOwner, seenHead >>

Next ==
  \/ ApplyTarget \/ Expire \/ RecordFailure
  \/ (\E exact \in BOOLEAN : Observe(exact))
  \/ Revoke \/ Handover \/ OtherAppend \/ RefreshHead
  \/ HandleFailure \/ Cancel \/ Finish \/ Deliver

SafetyInvariants ==
  /\ targetWrites <= 1
  /\ results <= 1
  /\ (results = 1 => receipt /\ successFact /\ effect = "completed")
  /\ (successFact <=> results = 1)
  /\ (appliedEvidence <=> results = 1)
  /\ ~(successFact /\ failureFact)
  /\ (handled => results = 0)
  /\ Len(runTerminals) <= 1
  /\ (Len(runTerminals) = 1 => run = runTerminals[1])
  /\ (results > 0 => \A i \in 1..Len(deliveryWitness) : deliveryWitness[i])

\* A positive witness: committed task, expired original attempt, recovered
\* ordinary success. The original expired terminal remains intact.
NoRecoveredExpired == ~(receipt /\ run = "lease_expired" /\ results = 1)
====
