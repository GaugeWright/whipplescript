# Information flow II: signatures, egress & redaction

Chapter 22 limited the flows between a value and a declared sink. Three doors
that are less obvious stay open. The first door is the model provider that
receives the context of a turn. The second door is the payload that a workflow
gives to its invoker. The third door is the set of fields of a record that you
*almost* want to release. Each door gets a denial. One door also gets a tool
that cuts.

## Egress through a provider

A `tell` statement with no write to a file and no send to a channel still does
an egress operation. The context of the turn goes to the model provider of the
agent. The context includes each item that the turn read. Thus a provider is a
governed principal, as each other principal is:

```text
error: denied egress in rule `summarize`: `crm` may be read by Operator
only — sending this turn's context to provider `fixture` (clearance public)
would disclose it to a model outside its readers (the checker denies every
turn egress to a provider not cleared for everything the turn read)
```

The same denial covers the prompt of a coercion and the results of a tool of an
agent. The repair is deliberately not an operation for the author. Add
`grant provider fixture -> selfhost:llama readable by Operator …` to the
envelope. The in-house model then joins the trust domain, and the same workflow
passes with no change. **Governance decides the data that each model can see.
The author does not decide.** Thus a change of a provider is also a governed
act. Chapter 11 gave the rule that a provider is configuration and not code.

The `from` clause of a grant for a provider is the *other* direction of the
door. The clause gives the data that the model can **write**. An output of an
effect can shape a sink with a `from` label. The output can be the result of a
turn, the output of a coercion, or the result of an `exec` statement. The
checker checks such an output against the `from` clearance of its executor.
This check applies when the output is the payload of the sink. The check also
applies when the output is the discriminant of a `case` statement that selects
the arm that contains the sink. Model output with no vouch into vouched state
is a denied influence. The crossing for each value is the `endorsed` judgment
in the next section. The grant for that crossing endorses the executor.
**Governance also decides the data that each model can shape.**

## Flow signatures: a label crosses the boundary of a workflow

In chapter 18, the output payload of a child becomes the typed input of the
parent. The labels go with the payload. The result of each workflow carries a
**flow signature for each field**. The signature is at the bottom of the
guarantee report:

```text
result/milestone flow signature (per field, the reads a consumer inherits,
fact-granular):
    - result.ok carries reads: crm
```

A consumer of this workflow inherits those reads. If you complete a result
field from data that comes from the CRM, each parent that invokes you holds
data with the CRM label. The checker then checks that parent under *its*
envelope. The terminal of a workflow is also a governed sink. A completion that
gives confidential data to an invoker with no clearance is the same denied flow
as a write to a public channel:

```text
error: denied flow in rule `summarize`: `crm` may be read by Operator only —
writing it to `result` (readable by public) would expose it to parties
outside its readers …
```

## Redaction: the tool that cuts

Frequently the *record* is confidential but the *part that you need* is not.
The `redact` construct does this operation. The construct is a relative of the
explicit narrowing family from chapter 4, which contains
`record X from y { … }`:

```whip
rule publish
  when Customer as c
=> {
  redact c keep [id, status] as safe

  complete result {
    who   safe.id
    state safe.status
  }
}
```

The `redact <binding> keep [fields] as <out>` statement projects a record onto
exactly the fields that you keep. The system applies this projection two times.
**At compile time**: the `safe` value has *only* the fields that you kept. Thus
`safe.ssn` is a type error. The error is not a surprise at run time. **At run
time**: the runtime physically removes the fields that you dropped from the
value. Thus no downstream sink can see those fields. The applicable denial is
total. The checker denies a dropped field to *each* sink, and there is no
crossing. A proof shows the non-interference. The proof is in
`models/lean/Whipple/Redaction.lean`. A refinement of the label for each field
follows. If only the `ssn` field made the record readable by Operator only, the
label of the redacted projection becomes more narrow. The flow that the checker
denied then becomes safe.

## The two crossings and their guard

Each denial in these three chapters names a maximum of one permitted crossing.
The two crossings are **coercions with a source mark**. Such a coercion is
visible in the text, a schema limits the coercion, and an audit can examine the
coercion:

- The `coerce release(c) as out declassified` statement crosses
  confidentiality. The *output schema* of the coercion gives the exact limit of
  the release. The crossing needs a matching
  `grant declassify <resource> to <role>` clause in the envelope. The envelope
  needs such a clause for each resource that *gets to the arguments of the
  coercion*. The guarantee report prints these resources for each crossing, as
  `carries: …`. An input that the checker cannot attribute honestly widens the
  set to the full read set of the rule.
- The `coerce sanitize(msg) as clean endorsed` statement crosses integrity.
  Untrusted data can shape trusted state only through an explicitly endorsed
  judgment. The envelope needs a `grant endorse <resource> to <role>` clause.

A raw flow never crosses. A `grant declassify` clause alone does not permit an
unmarked leak. The clause authorizes the *marked* coercion. The clause then
appears in the **trusted surface** section of the guarantee report for review.

The `redact` construct composes with a crossing. A projection of a marked
output is still the carrier of the crossing. A projection can only make the
release more narrow. The fields that you keep also obey their schema labels for
each field. Thus a release type can carry data of more than one sensitivity and
send only its public projection.

The crossings themselves have a guard. The guard is the least obvious denial in
these three chapters: **robust declassification (NMIF)**. The checker denies
data that an attacker can control the ability to steer its *own* release. A
declassification with a selection that low-integrity input decides is denied.
In that condition, the attacker selects the data for declassification. The
proof is in `models/lean/Whipple/NMIF.lean`. Confidentiality and integrity are
not independent controls. The integrity axis protects the escape hatch of the
confidentiality axis.

## Where next

Chapter 24 completes these three chapters with the envelope itself. The chapter
gives the parties that can sign a policy, the method to detect a change to a
policy, and the operation of the split of privilege between two agents.
