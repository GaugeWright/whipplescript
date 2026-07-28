# Governance envelopes & attestation

The denials in these three chapters bind only when the person that they limit
cannot quietly edit the policy that states them. This last chapter of the three
gives the envelope itself. It gives the party that writes the envelope, the
party that signs the envelope, the method to find a change to the envelope, and
the method that lets the two roles cooperate without shared privilege. The two
roles are the author and governance.

## The split between two agents

Chapters 22 and 23 assumed a division. That division needs its own statement.
The **author** writes workflows, reads diagnostics, and changes the structure
of the flows. The author cannot make the policy weaker. The author cannot
permit a crossing. The **governance agent** writes and signs the policy. The
governance agent is the IT group, the security group, or a process with
privilege. The governance agent gives clearance to a provider. The governance
agent also grants the hatches that permit an audit. The escape routes in each
denial diagnostic show the same split. A *self-serve* correction is a change of
structure in the power of the author. An *escalate* correction gives the exact
grant to request. The CLI applies the same position:

```sh
whip infoflow
```

```text
whip infoflow (unprivileged): check <file> | escalate <request> | quit
```

A session with no privilege can check a program and can file a request for
escalation. Such a session can never grant a request.

## Signature and attestation

A change to the envelope is evident. A signature operation needs privilege:

```sh
WHIPPLESCRIPT_GOV_ADMIN=1 whip gov sign governance.policy > governance.signed.json
```

The refusal is loud when the privilege is absent:

```text
signing a governance envelope requires admin/governance privilege — run via
the governance agent (sudo)
```

The signed envelope carries a SHA-256 attestation of the content of the policy.
Under the `WHIPPLESCRIPT_IFC_ENVELOPE` variable, the `whip check` command
verifies the attestation. The command rejects an envelope whose content no
longer agrees with its attestation. The property is simple: **the policy that
the checker applied is the policy that governance signed**. A workflow makes
its claim about information flow only against an authentic envelope. A policy
that a person edited in position is no longer authentic.

## Hatches that permit an audit

Sometimes you truly need a denied crossing. In that condition, governance
permits the crossing explicitly, narrowly, and in the open:

```text
grant declassify crm to public      # the data subject may see their own record
grant endorse inbox to Operator     # inbound is sanitized upstream
```

Chapter 23 gave the items that these grants authorize. They authorize the
*coercions with a source mark*: `declassified` and `endorsed`. They never
authorize a raw flow. This chapter adds the location where a grant appears.
Each hatch appears in the **trusted surface** section of the guarantee report.
There is one line for each crossing. Thus a review of the accepted dangerous
flows is a read of one section. Such a review is not an audit of each workflow.
An `endorse` grant lifts the integrity denial that it names. A `declassify`
grant arms the marked path for the release. The dangerous flows still exist.
That is the purpose. But now a person accepted the flows explicitly, and an
audit can find them. The flows are not silently present.

## How to operate a governed workflow

This is the working loop from end to end:

1. Governance puts labels on the true resources of the environment in a policy
   file. Governance then signs the file. An author never edits the file.
2. Authors develop the workflow with no governance, or with the envelope
   through `WHIPPLESCRIPT_IFC_ENVELOPE=…`. An author reads a denial diagnostic
   as feedback on the design. Almost always, the self-serve route gives the
   better program. That route keeps the contexts separate, uses `redact`, and
   limits the result.
3. When a crossing is truly necessary, the author files the escalate request
   that the diagnostic names. The `whip infoflow` command opens the governance
   REPL. The `escalate <request>` command of the REPL files the request for
   review by an administrator. The `WHIPPLESCRIPT_GOV_ESCALATIONS` variable
   points at the queue for escalations. Governance then decides. An accepted
   hatch becomes a grant in the policy. The grant is permanently visible in the
   trusted surface.
4. The guarantee report is the permanent contract. The report gives the proven
   invariants for each resource, the violations that the checker caught, the
   flagged resources that governance did not label and that fail closed, the
   cleared principals, and each door that the workflow opens.

Each denial connects to its formal carrier. The carriers are the `infoflow-*`
Maude suite and the Lean proofs `ReaderSets`, `NMIF`, and `Redaction`. The
[Guarantees](../guarantees.md) page states the full set as promises. If you
observe a governed program that violates one promise, the program has a bug.
Give the applicable text of the report in your report of the bug.

## Where next

Part III is complete. A workflow now coordinates, tracks, reacts, composes,
executes, files, and rewinds. Governance covers the workflow from end to end.
Part IV gives the judgment and the improvement of a workflow. Chapter 25 starts
with tests.
