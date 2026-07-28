# Information-flow control — worked examples

These examples exercise the IFC checker (DR-0027 / DR-0028) on a realistic
scenario: a **support-triage assistant** that touches the classic "lethal
trifecta" — confidential data, untrusted input, and an egress channel — and show
both where the system earns its keep and where it currently falls short.

The governance policy labels the **real data sources** in the environment (not
variables in any whip). IT signs it once; authors then write whips freely and the
compiler holds them to it.

```
file store crm          readable by Operator,  from Operator   # confidential PII, trusted
file store inbox         readable by public,    from public     # attacker-controllable email
file store audit_log     readable by public,    from public     # untrusted-OK event log
channel   public_reply   readable by public,    from public     # reply back to the customer
provider  fixture        readable by Operator,  from Operator   # in-house model, in trust domain
```

A label is not limited to one role. `readable by` (and `from`) accept a **set of
compartments**, comma- or space-separated, and a party may read the resource only
if it is cleared for **every** one of them (the intersection — combining secrets
*restricts*, it never widens):

```
file store mixed   readable by Bank, Email   # readable only by a party cleared for BOTH
```

A flow is safe when the sink's reader set **dominates** the source's — every
compartment that gates the source is covered by some compartment of the sink, so
no reader of the sink is un-cleared for the source. A single-compartment label is
just the one-element set, behaving exactly as the role it names. The integrity
axis (`from`) is the dual: a sink requiring `from Sec, Ops` accepts data only from
a source that provides a voucher acting-for each. (DR-0027 E6; the set algebra is
machine-proven in `models/lean/Whipple/ReaderSets.lean` and modeled in
`models/maude/infoflow-reader-sets.maude`.)

`whip check` discovers the policy via `WHIPPLESCRIPT_IFC_ENVELOPE`. With no
envelope set, a whip is **ungoverned** (dev mode) and makes no IFC claim — the
checker imposes nothing.

## Running them

```sh
# Dev mode: no envelope, no IFC constraints.
whip check examples/infoflow/support-triage-unsafe.whip

# Governed: the unsafe whip is REJECTED (2 violations).
WHIPPLESCRIPT_IFC_ENVELOPE=examples/infoflow/governance.policy \
  whip check examples/infoflow/support-triage-unsafe.whip

# The safe whip PASSES the same strict policy (0 violations, no hatches).
WHIPPLESCRIPT_IFC_ENVELOPE=examples/infoflow/governance.policy \
  whip check examples/infoflow/support-triage-safe.whip
```

## What the checker catches (demonstrated)

**1. Confidentiality leak — confidential data to an untrusted recipient.**
`support-triage-unsafe.whip` reads `crm` and emails it out on `public_reply` in
the same rule:

```
denied flow in rule `triage`: `crm` may be read by Operator only — writing it
to `public_reply` (readable by public) would expose it to parties outside its
readers (the checker denies every flow from a value to a sink whose readers
are not all within the value's reader set)
```

**2. Integrity injection — untrusted input into a trusted store.** The same rule
writes attacker-controlled `inbox` content into the `crm`:

```
denied influence in rule `triage`: `inbox` is untrusted (integrity public) —
it can never influence `crm`, which only Operator-vouched data may shape (the
checker denies every flow from lower-integrity data into a higher-integrity
sink; the sanctioned crossing is a source-marked `endorsed` coerce)
```

**3. Provider egress — the agent silently ships data to a model.**
`agent-egress.whip` has no file write and no channel send, only a `tell` that
reads `crm`. When the agent's provider is **not** cleared, the turn's context
egresses to an uncleared model:

```
denied egress in rule `summarize`: `crm` may be read by Operator only —
sending this turn's context to provider `fixture` (clearance public) would
disclose it to a model outside its readers (the checker denies every turn
egress to a provider not cleared for everything the turn read)
```

This whip crosses **two** governed boundaries, and the policy must clear
both: the turn's context egresses to the provider (above), and its
`complete result` egresses to whoever invoked the workflow (DR-0030 X2 —
see limitation 1), cleared by `grant output result -> result readable by
Operator`. With both grants in `governance.policy` the whip passes; remove
either one and it is rejected again. Governance, not the author, decides
which providers — and which invokers — are in the trust domain.

**4. Output integrity — the model as a governed writer (DR-0046).** An
effect output (an agent turn's result, a coercion's output, an `exec`
result) shaping a `from`-labeled sink is checked against its *executor's*
`from` clearance — the provider grant's integrity clause, given its natural
reading. Unvouched, by payload or by `case`-selector influence, it denies:

```
denied influence in rule `write_model_output`: the output of executor
`fixture` (vouched at public) shapes `crm`, which only Operator-vouched
data may shape (the checker denies every effect output flowing into a sink
above its executor's `from` clearance; DR-0046)
```

Vouch the provider (`… from Operator`) and it writes freely — the cleared-
principals report line shows `vouched writer from Operator` so the audit
answers "which models may shape trusted state" at a glance. The per-value
alternative is the promised `endorsed` judgment under
`grant endorse <executor> to <role>`; raw dev `exec` output is vouched by
nobody, always. Executor tokens also travel fact chains (recording model
output into a fact and persisting it two rules later injects the same way),
and they are integrity-only — the axis lock keeps them out of every
confidentiality check.

**5. Tamper-evident policy.** `governance.signed.json` is the policy signed by the
governance agent (privileged):

```sh
WHIPPLESCRIPT_GOV_ADMIN=1 whip gov sign examples/infoflow/governance.policy \
  > examples/infoflow/governance.signed.json     # privileged: succeeds
whip gov sign examples/infoflow/governance.policy # unprivileged: REFUSED
```

`whip check` enforces the signed envelope and **rejects a tampered one** (the
SHA-256 attestation no longer matches the content).

## The audited escape hatches (demonstrated)

When a crossing is genuinely intended, governance blesses it explicitly and it
shows up in the guarantee report's **trusted surface** for review.
`governance-with-hatches.policy` adds:

```
grant declassify crm to public      # the data subject is entitled to their own record
grant endorse inbox to Operator     # inbound is sanitized upstream before we trust it
```

A grant alone changes **nothing** for the unsafe whip: it is still rejected
with the same 2 violations. Grants do not bless raw flows — they *authorize
the source-marked crossings* (DR-0027 I-IFC3: "the only operations that lower
confidentiality are explicit in the source"). The sanctioned shape is
`support-triage-hatched.whip` — the same job with the two dangerous flows
routed through marked coercions:

```whip
coerce sanitize(email.content) as clean endorsed        # inbound -> CRM
coerce release(customer.content) as summary declassified # CRM -> customer
```

```sh
# The marked shape PASSES under the hatches policy (0 violations)...
WHIPPLESCRIPT_IFC_ENVELOPE=examples/infoflow/governance-with-hatches.policy \
  whip check examples/infoflow/support-triage-hatched.whip

# ...and the SAME whip is REJECTED under the strict policy (markers without
# grants are declarations, not authority).
WHIPPLESCRIPT_IFC_ENVELOPE=examples/infoflow/governance.policy \
  whip check examples/infoflow/support-triage-hatched.whip
```

The crossing rule, precisely: an egress arms only when its payload references
**nothing but** the marked coercion's output (a marked output beside raw data
taints the payload and the flow is denied), the coercion's *output schema* is
the bounded type of the release, and the grant supplies the audience —
`declassify <r> to <Role>` covers sinks that Role can read, and `declassify
<r> to public` is the audited release-to-the-world. The axes are locked: a
declassified output is still untrusted; an endorsed output is still secret.
NMIF guards the crossing itself (an attacker-steered marked coercion is
denied). The trusted surface audits both layers — the grants and each
source-marked crossing point:

```text
trusted surface (audited declassify/endorse crossings to review):
  - declassified (source) at rule `triage` (summary) carries: crm
  - declassify crm -> public
  - endorse inbox -> Operator
  - endorsed (source) at rule `triage` (clean) carries: inbox
```

The `carries:` tail is the crossing's computed **input provenance** — the
governed sources actually reaching the coercion's arguments. It also narrows
the check: a marked crossing requires grants only for the sources it carries,
so a rule that additionally read a second confidential store the release
never touches does not need a grant for it. Provenance chains through
intermediate unmarked coercions (a model call mixes all its inputs into its
output), and anything unattributable — an agent turn output feeding the
coercion, say — honestly widens back to the rule's whole read set
(`carries: all rule reads (attribution fallback)`), which is the fail-closed
pre-narrowing behavior. Modeled in
`models/maude/infoflow-input-provenance.maude`.

## The safe shape (demonstrated)

`support-triage-safe.whip` does the same job and passes the **strict** policy with
**no hatches**, by separating contexts:

- untrusted `inbox` → the public-integrity `audit_log` (never the CRM);
- the confidential `crm` read happens in a rule with **no egress sink**, and
  the `Reviewed` fact it records stays Operator-labeled internal state —
  consuming it would taint any reply with everything its label protects,
  *including the review-completion bit itself*;
- the reply carries only public, bounded content (the ticket id), driven by
  the **public** fact chain (`Logged`), not the confidential one.

This is the point: the system permits the maximally-permissive *safe* structure —
it is not just blocking everything.

## The guarantee report (`whip check` under an envelope)

Running `whip check` under a governed envelope prints an IT-legible **guarantee
report** (DR-0028). It states, in order:

- **guaranteed invariants** — one line *per governed resource* with the exact
  property proven on every rule, e.g. `crm: may not flow to a sink not cleared for
  Operator (unless an audited declassify clears it)`. Not a generic blanket line.
- **violations caught** — how many dangerous flows the envelope rejects in this whip.
- **flagged risks** — resources the whip touches that governance has *not* labelled;
  each defaults to public + low-integrity (fail-closed), so the operator must confirm
  it holds nothing confidential and feeds no trusted sink, or add a `grant`.
- **trusted surface** — every audited `declassify` / `endorse` crossing to review.
- **fact provenance** (DR-0045) — per consumed fact schema, the *computed
  producer reach* a consumer inherits: real sources where the chain is
  attributable, `its declared label` wherever content is unaccountable (a
  table seed, a workflow input, an `@external` arrival, an unattributable
  producer root). Consumption enforcement substitutes this reach for the
  declared label — a clean chain escapes an over-conservative label, a
  confidential read travels the chain, and untrusted content can no longer
  launder through an unlabeled intermediate fact.
- **cleared principals** and the full **information-flow surface** (every door).

Each violation diagnostic names **two routes to fix**: a **self-serve** route the
whip author can take alone (separate the contexts / gate the sink on trusted data)
and an **escalate** route that needs a governance grant (`grant declassify …` /
`grant endorse …`) — mirroring the two-agent privilege split.

---

## Limitations found hands-on

These are real gaps observed while building the examples, not hypotheticals.

1. **The workflow's own output is a governed sink.** *`record` is governed (H2):* a
   recorded fact is a sink `fact:<schema>` (the DR-0026 stream and other rules observe
   it), defaulting to public/fail-closed — so reading `crm` and `record`ing a derived
   fact is flagged unless governance clears `fact:<schema>` (see `fact:Reviewed` in
   `governance.policy`). *And consumption is governed too (2026-07-22):* a `when
   <Schema>` trigger of a GOVERNED fact is a read at the fact's declared label —
   the record sink gates what may enter the fact, consumption gates where it may
   exit, and a `from`-vouched fact vouches its consumers' writes. (Table seeds and
   workflow inputs never pass a record gate, so consumption labeling is what
   governs them at all.) An unlabeled fact contributes nothing: its record sink is
   fail-closed public, so nothing confidential can legally have entered it. *`complete result` is now governed too (DR-0030 X2,
   top-level):* for a `@service` workflow it is an egress sink at the invoker boundary
   named by the output binding (e.g. `result`), default public/fail-closed — so a rule
   that reads `crm` and `complete`s a result is flagged unless governance clears the
   invoker (`grant … -> result readable by <role>`) or the contexts are separated (the
   safe shape). Whole-result v1: the result conservatively carries the join of the
   completing rule's reads (no per-field value-flow). *The cross-package `@tool` result
   is governed too (DR-0030 X2):* a turn whose agent may call an imported tool folds the
   tool's result reads into the turn — so a tool that reads confidential data the
   consumer never touched, whose result then egresses, is caught. The **Direction A
   reach refinement** keeps only the tool reads that reach a completing rule (inputs the
   result is `independent_of` are dropped); it is computed consumer-side from the pinned
   tool source. *The **per-field flow signature** (DR-0030 X2 v2) refines this further,
   producer-side:* the guarantee report surfaces, for each `complete <binding>` result
   field, the reads reaching that field — at **fact granularity** (a field root that is a
   direct `when <Fact> as b` binding carries only that fact's producer reach; the
   completing rule's own reads reach every field, preserving the rule-level opaque box;
   any within-rule *derived* root falls back to the whole-result reach, so a field reach
   is always a subset of the whole reach and never under-reports — proven in
   `models/maude/infoflow-field-signature.maude`). This is producer-side **audit
   transparency**: a consumer of `result.<field>` inherits only that field's reads.
   **Consumer-side per-field *enforcement* remains a documented boundary:** the only
   cross-package consumer path — an agent turn that may call the tool — folds the result
   into an *opaque* turn, so the turn still conservatively inherits the whole-result
   reach. Relaxing it needs a non-opaque consumer (turn field-access grants, or
   IFC-tracked `invoke` result-field access), not yet built.

2. **Coarse, rule-level join box (no value tracking).** Any read in a rule is
   assumed to potentially reach any sink in the same rule. The safe refactor must
   physically split rules even when a human can see the value does not actually
   flow. This is the intentional conservative-join-box design (we do not trust the
   agent to be value-precise), but it is a real authoring cost.

3. **Diagnostic span is the whole rule.** Violations point at the rule's `=> {`,
   not the specific read/write lines, because the join box is rule-wide. With many
   effects in a rule, the author must hunt for the offending pair.

4. **Per-resource labels, not per-field/path.** You cannot say "the order-status
   field of the CRM is public but the SSN is confidential" — a label attaches to a
   whole `file store` / `channel`, not a path within it. Mixed-sensitivity stores
   must be physically split for *whole-resource* labels. *Addressed by `redact`
   (DR-0027) for typed values:* the `redact <r> keep [..] as <out>` construct
   projects a record to a kept subset, enforced statically (a dropped field is a
   type error on `out`), at runtime (dropped fields are physically removed before
   they can reach any sink), and **in the flow checker**. Per-field labels are
   envelope resources keyed `<Schema>.<field>` (e.g.
   `grant field cust_ssn -> Customer.ssn readable by Operator`); a field with no
   label is public. A fully-redacted egress (`complete result`, `record <Schema>`,
   or `send via <channel>` referencing only redacted projections) is *additionally*
   checked against the kept fields' label join — keeping a field the sink cannot
   read is flagged. This is **additive**: it does not exempt the egress from the
   ordinary read→sink checks, so releasing data derived from a confidential
   *resource read* at a lower label still needs a `grant declassify` (dropping a
   field narrows the per-field schema label, not a confidential source's
   provenance). Redaction projects confidentiality only — integrity still applies.
   *(A prior version wrongly exempted redacted egresses from the read checks, an
   under-taint; fixed. Full per-field provenance — so a kept field derived from a
   public source needs no grant while one derived from a secret does — is the
   value-flow engine, in progress.)*
   The non-interference of the dropped fields is proven in
   `models/lean/Whipple/Redaction.lean` (`canRead_redact`). A pure `from`
   projection (`record T from src { … }`, all shorthand) is auto-governed the same
   way without an explicit `redact` — the bounded-type reading of auto-redaction,
   with the target type as the explicit bound. **Still deferred:** field-level
   precision *within* a non-redacted binding.

5. ~~**Inbound message triggers are not integrity sources.**~~ *Fixed (H3):* a rule
   triggered by `when message from <channel>` now treats the channel as a
   low-integrity read source, so attacker-controlled inbound content driving a
   more-trusted sink is caught as an injection — not only file reads.

6. ~~**`endorse` crossings are absent from the trusted-surface report.**~~ *Fixed
   (H4):* the trusted surface now audits BOTH axes — `declassify <r> -> <role>` and
   `endorse <r> -> <role>` — each tagged by axis.

7. ~~**Clearing a provider marks it "confidential".**~~ *Fixed (H5):* `provider`
   (and `human`) grants are tracked as **principals**; the report lists them under
   "cleared principals (providers/humans, not protected data)", not "protected
   resources".

8. ~~**The guarantee report does not verify the attestation.**~~ *Fixed while
   writing these examples:* the report now verifies a signed envelope first and
   prints `REFUSED: ...` for a tampered policy instead of rendering a guarantee
   computed from tampered labels.

9. ~~**Signal triggers are invisible sources (fail-OPEN).**~~ *Fixed (H8):* a rule
   triggered by `when <Signal> as e` now reads the governed resource
   `signal:<name>` — integrity envelope-declared, default `public`/low (fail-closed)
   — so an externally-injected signal driving a more-trusted sink is caught as an
   injection, just like an inbound channel message. Vouch a trusted signal with
   `grant signal <name> -> signal:<name> from <Role>`. Source recognition is now
   *uniform* (channels, human answers, and signals all governed alike); the signal
   also appears in the workflow's information-flow surface.

10. ~~**Internal signals must be hand-vouched.**~~ *Fixed (H8 stage b — emitter-carried
    integrity):* mark a signal an internal channel with
    `grant signal <name> -> signal:<name> internal`, and its integrity is **derived
    from its emitters** instead of defaulting low — an `emit signal X` carries the
    intersection of its emitting rule's read-source vouchers, and `when X` reads that.
    So you only hand-classify the *external entry points*; internal flows propagate
    the emitter's trust automatically (the labeling burden stays `O(external entry)`).
    Carriage spans packages: an imported `@tool`'s `emit signal X` contributes its
    carried integrity to a consumer's `signal:X`, computed under the consumer's own
    envelope from the pinned source. Soundness is preserved two ways — carriage never
    *fabricates* trust (an untrusted emitter yields an untrusted receiver), and
    `whip signal` **refuses** to externally inject an internal signal (no laundering
    untrusted data in under a trusted signal name).

11. ~~**Source-marked crossings do not yet arm; grants arm resource-level.**~~
    *Fixed (2026-07-22):* the checker now implements DR-0027 I-IFC3 as written.
    A `grant declassify`/`grant endorse` arms **only** an egress carried
    entirely by a source-marked coercion's output (`coerce … declassified` /
    `coerce … endorsed`); raw, unmarked flows are always denied regardless of
    grants. `declassify … to public` is the audited release-to-the-world (it
    previously armed nothing, by accident of the empty-reader-set
    representation). Remaining conservatisms: the payload-purity test is
    rule-local and root-based (a marked output mixed with anything else denies),
    and per-field provenance through a marked output is still the value-flow
    engine's territory (its cross-rule half shipped as DR-0045 — whole-fact
    producer reach with the label-token fallback; per-FIELD fact reach is the
    remaining notch). *Input-side* provenance landed the same day: the
    crossing's grant requirement covers only the sources reaching the
    coercion's arguments (see the hatches section), with a per-sink
    fail-closed fallback on any unattributable root. *`redact` now composes
    with the crossing* (also same day): a projection of a marked output is
    still the crossing's carrier — release types may mix sensitivities, keep
    the per-field labels honest, and ship only the public projection.
