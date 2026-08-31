# Tutorial: govern a workflow

In this tutorial you put a workflow in a signed **governance envelope**. The
envelope puts labels on the true data sources. The compiler checks the labels.
The compiler then supplies a report that an operator can read. The report gives
the exact guarantees. In this tutorial you look at the rejection of a dangerous
workflow. You then change the workflow into the safe shape. Last, you authorize
one deliberate crossing with a method that permits an audit.

All the steps use the examples in
[`examples/infoflow/`](https://github.com/GaugeWright/whipplescript/tree/main/examples/infoflow).
The example is an assistant for support triage. The assistant touches the three
components of the *lethal trifecta*: confidential data (a CRM), untrusted input
(an inbox), and an egress channel (the reply to the customer).

## 1. You can see the ungoverned condition

```sh
whip check examples/infoflow/support-triage-unsafe.whip
```

If you set no envelope, the whip is **ungoverned**. This is dev mode. The check
passes and makes no claim about information flow. You select governance for
each environment. Governance is not a cost during development.

## 2. Put labels on the world, not on the code

The envelope puts labels on the *true data sources*. The labels are external to
each whip. Open `examples/infoflow/governance.policy`. These lines are the
important part:

```text
grant file_store crm   -> file:/srv/crm.db          readable by Operator from Operator
grant file_store inbox -> maildir:/var/mail/support readable by public   from public
grant channel public_reply -> smtp:out              readable by public   from public
grant provider fixture -> selfhost:llama            readable by Operator from Operator
```

Each resource has two axes. The `readable by` axis is confidentiality. It gives
the parties that can see the resource. The `from` axis is integrity. It gives
the parties whose vouching can shape the resource. Since DR-0046, the `from`
axis also gives the parties whose *outputs* can shape the resource. The
`from Operator` value on the provider line permits an in-house model to write
into vouched state. The IT group writes this file one time and signs it. An
author never changes this file.

## 3. Look at the rejection of the trifecta

```sh
WHIPPLESCRIPT_IFC_ENVELOPE=examples/infoflow/governance.policy \
  whip check examples/infoflow/support-triage-unsafe.whip
```

<!-- render: examples/infoflow/support-triage-unsafe.whip envelope examples/infoflow/governance.policy -->
```text
information-flow guarantee report
  guaranteed invariants (proven by the checker on every rule):
    - file:/srv/crm.db: may not flow to a sink not cleared for Operator (unless an audited declassify clears it); may not be influenced by data below Operator (unless an audited endorse vouches it)
    - internal:reviewed: may not flow to a sink not cleared for Operator (unless an audited declassify clears it)
    - result: may not flow to a sink not cleared for Operator (unless an audited declassify clears it)
  violations caught in this program: 2
  flagged risks: none (every touched resource is governed)
  trusted surface (declassify + endorse grants): none
  cleared principals (providers/humans, not protected data):
    - selfhost:llama (cleared for Operator; vouched writer from Operator)
  information-flow surface (every door this workflow opens):
    - crm
    - fact:Ticket
    - inbox
    - public_reply
  fact provenance (computed producer reach a consumer inherits, DR-0045):
    - fact:Ticket carries: nothing (clean chain)
  result/milestone flow signature (per field, the reads a consumer inherits, fact-granular):
    - result.ok carries reads: crm, inbox
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

That is the whole of what the command prints: the guarantee report first — its
`violations caught in this program: 2` line counts the denials that follow — and
then the two denials themselves. Section 7 below reads the report line by line.

One rule read the CRM, wrote mail from an attacker into the CRM, and sent the
record out by email. The checker denied the two halves. Each denial gives two
repairs. The first repair is a *self-serve* route: keep the contexts separate.
The second repair is an *escalate* route: add a governance grant.

## 4. The safe shape passes the same policy

```sh
WHIPPLESCRIPT_IFC_ENVELOPE=examples/infoflow/governance.policy \
  whip check examples/infoflow/support-triage-safe.whip
```

```text
  violations caught in this program: 0
```

Read `support-triage-safe.whip` to see the method. The untrusted inbound data
goes only to the audit log, which has public integrity. The read of the
confidential CRM occurs in a rule with no egress sink. The acknowledgement to
the customer uses the *public* chain of facts. Even the statement "the review
completed" is Operator information. Thus the reply must not depend on that
statement. The checker permits the **safe** structure, which is the structure
with the fewest limits. A change to this structure is always the first repair.

## 5. Authorize a crossing with a method that permits an audit

Sometimes the dangerous flow is necessary. For example, the customer has a
right to their own record. A grant alone changes nothing. The
`governance-with-hatches.policy` file also rejects the unsafe whip. A grant
authorizes a **crossing with a source mark**:

<!-- check: skip — an intermediate step of the build; the finished program is checked -->
```whip
coerce sanitize(email.content) as clean endorsed          # untrusted -> CRM
coerce release(customer.content) as summary declassified  # CRM -> customer
```

```sh
WHIPPLESCRIPT_IFC_ENVELOPE=examples/infoflow/governance-with-hatches.policy \
  whip check examples/infoflow/support-triage-hatched.whip
```

```text
  violations caught in this program: 0
```

The coercion with the mark is the crossing. Its *output schema* limits the data
that the crossing releases. The grant supplies the audience. The trusted
surface audits the schema and the audience. The trusted surface also audits the
computed provenance of the data that each crossing carries:

```text
trusted surface (audited declassify/endorse crossings to review):
  - declassified (source) at rule `triage` (summary) carries: crm
  - declassify crm -> public
  - endorse inbox -> Operator
  - endorsed (source) at rule `triage` (clean) carries: inbox
```

Run the same whip under the *strict* policy. The checker rejects the whip. A
marker with no grant is a declaration. A marker with no grant is not authority.

## 6. Sign the policy

An unsigned policy is advice only. A production system needs evidence of
tampering:

```sh
WHIPPLESCRIPT_GOV_ADMIN=1 whip gov sign examples/infoflow/governance.policy \
  > examples/infoflow/governance.signed.json
WHIPPLESCRIPT_IFC_ENVELOPE=examples/infoflow/governance.signed.json \
  whip check examples/infoflow/support-triage-safe.whip
```

A signature operation needs privilege. The system refuses a `gov sign` command
that has no privilege. The `whip check` command verifies the attestation before
it trusts any label. The command rejects a modified envelope fully. It does not
accept part of a modified envelope.

## 7. Read the guarantee report

Each governed check prints the report that the IT group needs:

- **guaranteed invariants** — one line for each governed resource. Each line
  gives the exact property that the checker proved on each rule.
- **violations caught** — the items that this envelope rejected here.
- **flagged risks** — the resources that the workflow touches but that have no
  label. These resources default to public and untrusted. The operator must
  confirm them or govern them.
- **trusted surface** — each crossing, each grant, and each point with a source
  mark, with the computed `carries:` provenance.
- **cleared principals** — the data that each model can see. The
  `vouched writer from …` text gives the data that each model can *write*.
- **fact provenance** — the computed reach of the producer that each consumed
  fact gives to its consumers.
- the full **information-flow surface** — each door that the workflow opens.

## Where next

The governance chapters of the manual are
[labels](../manual/22-infoflow-labels.md),
[egress & redaction](../manual/23-infoflow-egress.md), and
[envelopes](../manual/24-governance.md). These chapters teach the model behind
each denial, the `redact` construct, the labels for each field, and the split of
privilege between two agents. The [Guarantees](../guarantees.md) page connects
the promises to models that a machine checks.
