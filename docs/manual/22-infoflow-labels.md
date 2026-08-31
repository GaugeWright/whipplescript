# Information flow I: labels, clearance & reads

A workflow for support triage touches the three components of the lethal
trifecta: confidential customer data, input that an attacker can control, and
an egress channel to the world. Each chapter to this point limited *the
operations that a workflow can do*. The next three chapters limit *the
destinations of the information of a workflow*. WhippleScript states that
contract as a set of **denials**. A denial is a universal property. The checker
proves the property on each rule. Each denial has exactly one permitted
crossing. This chapter introduces the first two denials and the machinery that
supports them.

## Governed and ungoverned

Without an envelope, a program is **ungoverned**. This is development mode.
There is no claim about information flow. The checker applies no limit.
Governance comes from a signed policy file. The checker finds the file through
the `WHIPPLESCRIPT_IFC_ENVELOPE` variable. The policy puts labels on the **true
resources in the environment**. The policy does not put labels on a variable in
a workflow:

```text
# governance.policy — IT signs this once; authors write whips freely
grant file_store crm -> file:/srv/crm.db readable by Operator from Operator
grant file_store inbox -> maildir:/var/mail/support readable by public from public
grant file_store audit_log -> file:/srv/audit.log readable by public from public
grant channel public_reply -> smtp:out readable by public from public
grant provider fixture -> selfhost:llama readable by Operator from Operator
grant factbase fact:Reviewed -> internal:reviewed readable by Operator from public
grant output result -> result readable by Operator
```

The last two rows put labels on doors that are easy to forget. A **recorded
fact** is a sink. Other rules observe the sink. The stream of session events
also observes the sink. The grant form is `fact:<Schema>`. The **`complete
result`** statement of a `@service` workflow returns a payload to the caller.
The grant uses the name of the output binding. The two doors default to public
and fail closed. The safe workflow below needs exactly these grants to pass.

Each grant puts a label on one resource on two axes. The `readable by <set>`
axis is **confidentiality**. It gives the parties that can read data from this
resource. The `from <set>` axis is **integrity**. It gives the parties whose
vouching is necessary for data that enters the resource. The `public` value is
the bottom of the two axes. A `public` resource is readable by the world and is
untrusted.

## A label is a set of readers

A label for confidentiality is a *set of compartments*. A party can read the
value only when the party has clearance for **each** compartment. Thus a
combination of secrets makes the access more narrow. A combination never makes
the access larger:

```text
grant file_store mixed -> ... readable by Bank, Email   # needs BOTH clearances
```

A flow is permitted when the set of readers of the sink **dominates** the set
of readers of the source. Each compartment that gates the source is also at the
sink. Thus no reader of the sink is without clearance for the source.

A label *derives*. A fact that the program records from `crm` data carries the
readers of `crm`. A value that joins two sources carries the union of their
compartments. The checker computes this derivation across the rules. The
result is the *producer reach* of each fact. The fact-provenance section of the
guarantee report prints the producer reach. Thus a consumed fact gives its
consumers its true upstream sources. Where the content is not accountable, the
checker uses the declared label. Seeds, inputs, and external arrivals are such
content. A machine proves the algebra of the sets. The proof is in
`models/lean/Whipple/ReaderSets.lean`.

## The first two denials

- **Confidentiality.** A value has a label that admits the reader set R. The
  checker **denies** that value to each sink whose audience is not in R. A
  sink is a terminal, a recorded fact, a channel, or a provider. The only
  crossing is a coerce with the `declassified` source mark. The next chapter
  gives this crossing. This denial operates in the two directions at a fact.
  The record operation controls the data that can *enter* a labeled fact. The
  consume operation, which is a `when <Schema>` clause, is a read at the
  *computed producer reach* of the fact. The producer reach is the true
  upstream sources where the chain is attributable. Where the content is not
  accountable, the producer reach is the declared label. Thus the denial also
  governs the data that can *exit*. The label is a durable cut point. The label
  is not a check that occurs one time.
- **The identity ceiling.** An agent serves a user. The checker **denies** each
  read above the clearance of that user. Thus an assistant cannot become a side
  door to data that its principal could not see.

These denials are universal. The checker denies *each* instance. The checker
walks the reads and the sinks of each rule under the envelope. A denial is not
a blocklist.

## The rejection of the trifecta

The `support-triage-unsafe.whip` program reads the CRM and sends the data out
by email. The same program also writes inbound email into the CRM. The program
does these operations in one rule. Without governance, the program checks
clean. Under the envelope, the checker gives these errors:

<!-- render: examples/infoflow/support-triage-unsafe.whip envelope examples/infoflow/governance.policy code security.confidentiality_leak code security.integrity_injection -->
```text
error[security.confidentiality_leak]: denied flow in rule `triage`: `crm` may be read by Operator only — writing it to `public_reply` (readable by public) would expose it to parties outside its readers (the checker denies every flow from a value to a sink whose readers are not all within the value's reader set)
   --> examples/infoflow/support-triage-unsafe.whip:44:3
   |
44 |   read text from crm at "customer.json" as crm_record
   |   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   = help: self-serve (no grant needed): separate the contexts — read `crm` in a distinct turn and pass only a bounded result. escalate (needs governance): route the release through a `coerce … declassified` whose output is the egress's whole payload, under `grant declassify crm to <role cleared for public_reply>` (a grant alone never blesses a raw flow)
error[security.integrity_injection]: denied influence in rule `triage`: `inbox` is untrusted (integrity public) — it can never influence `crm`, which only Operator-vouched data may shape (the checker denies every flow from lower-integrity data into a higher-integrity sink; the sanctioned crossing is a source-marked `endorsed` coerce)
   --> examples/infoflow/support-triage-unsafe.whip:44:3
   |
44 |   read text from crm at "customer.json" as crm_record
   |   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   = help: self-serve (no grant needed): do not let `inbox` influence `crm` — gate the sink on trusted data. escalate (needs governance): route the influence through a `coerce … endorsed` whose output is the sink's whole payload, under `grant endorse inbox to <role>` (a grant alone never vouches a raw influence)
```

Read the structure of the diagnostic. Each message about information flow has
the same structure. The message gives the denied value and its intended
audience first. The message then gives the universal rule in parentheses. The
help line gives **two routes to a repair**. The *self-serve* route needs the
author only: keep the contexts separate, and pass a result with limits. The
*escalate* route needs a governance grant. The vocabulary that permits an
operation is the surface for a repair. That vocabulary is the clearances and
the grants. That vocabulary is not the contract.

## The safe shape

The same job passes the same strict policy with no special grant. The method is
the separation of the contexts. The untrusted content from the inbox flows only
to the audit log, which has public integrity. The read of the confidential CRM
occurs in a rule with no egress sink. The reply carries only public content
with limits. This behavior is the purpose of the design. The checker permits
the *safe* structure that has the fewest limits. The checker does not block
each operation. A change to that structure is always the first route to a
repair.

## The guarantee report

Under an envelope, the `whip check` command also prints a guarantee report. An
operator can read the report:

```text
information-flow guarantee report
  guaranteed invariants (proven by the checker on every rule):
    - file:/srv/crm.db: may not flow to a sink not cleared for Operator
      (unless an audited declassify clears it); may not be influenced by
      data below Operator (unless an audited endorse vouches it)
    - internal:reviewed: may not flow to a sink not cleared for Operator
      (unless an audited declassify clears it)
    - result: may not flow to a sink not cleared for Operator (unless an
      audited declassify clears it)
  violations caught in this program: 0
  flagged risks: none (every touched resource is governed)
  trusted surface (declassify + endorse grants): none
  cleared principals (providers/humans, not protected data):
    - selfhost:llama (cleared for Operator; vouched writer from Operator)
  information-flow surface (every door this workflow opens):
    …one line per door: stores, channels, facts, the result, the provider…
```

Read the line for a principal in the two directions. The *cleared for* text
gives the data that the model can **see**. This is egress through the provider.
The *vouched writer* text gives the data that the outputs of the model can
**shape**. These are the sinks with a `from` label. The line of a provider with
no vouch says `outputs untrusted` instead. When a workflow consumes facts, a
*fact provenance* section also appears here. The section lists the computed
producer reach that each consumed fact gives to its consumers.

The report has one line for each governed resource with the exact property that
the checker proved. Each resource that the workflow touches and that governance
did *not* label is a flagged risk. Such a resource defaults to public and to
low integrity. This behavior is **fail-closed**. The operator confirms that the
resource holds nothing confidential, or the operator adds a grant.

## Where next

Chapter 23 gives the remaining denials. The chapter gives egress through a
provider, flow signatures across the boundary of a workflow, the
`redact … keep` construct with its proven non-interference, and the two
crossings with a source mark.
