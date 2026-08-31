# Maude Models

Maude is the primary executable-spec target for the WhippleScript kernel and
for the package/library lowering pipeline.

Use it to model:

```text
rule commits
guard/readiness evaluation
workflow assertions
effect nodes
effect dependency edges
tracker-claim gated agent turns
completion/failure outcomes
library declaration acceptance
construct graph composition
lowering-class lifecycle contracts
lowering preservation into core IR
runtime handoff boundaries
bounded searches for bad rule cycles
```

The reusable kernel model lives at:

```sh
models/maude/kernel.maude
```

Hand-written executable checks live under:

```sh
models/maude/tests/
```

Run all Maude checks:

```sh
scripts/check-formal-models.sh
```

## Never begin a `---` comment line with `(`

Maude reads `---(` as the opening of a *bracketed* comment that runs to the
matching `)`, not as a line comment. A wrapped prose comment can form it by
accident:

```text
--- CHECK ERROR 1: a narrowable operation named bare. The list is required
--- (deliberately not prejudging the wildcard spelling deferred in vnext).
```

The bracketed comment swallows the text that follows, and the statement
*before* it loses its terminator. Maude reports only `no parse for statement`
— a warning, not an error — then drops that statement and carries on, so the
file still loads and the gate still exits 0.

This is silent and expensive. In `credential-scope-narrowing.maude` the
dropped statement was `eq checkError checkError = checkError`, the equation
keeping the soup finite. Without it the `check-*` rules re-fired without
bound; one search grew past 18.7 GB before it was killed. The rules were never
the problem, and parenthesizing the equation does **not** fix it — the comment
is still malformed, so a statement is still dropped. Rewrapping the prose so
no line starts with `(` is the fix.

When a search diverges, grep the model for `no parse` first:

```sh
maude -no-banner models/maude/<model>.maude < /dev/null 2>&1 | grep "no parse"
```

The newer package/lowering models layer on top of the reusable kernel:

```text
kernel.maude                   core runtime/event/effect/fact semantics
package-contract.maude         locked package/library contract registry and
                                typed provider-output boundary
construct-grammar.maude         controlled construct vocabulary, fixed
                                package construct grammar, and runtime provider
                                authorization boundary
construct-graph.maude           resource-qualified interface graph acceptance
construct-lowering.maude        accepted graph to ordinary core IR preservation
lowering-runtime-handoff.maude  lowered core IR entry into runtime shapes
lowering-class-lifecycle.maude  platform-owned lowering-class profiles
```

Current test suites:

```text
coerce-branches.maude            schema-coercion success/failure branches
package-contract.maude           locked package/library registry and
                                 typed-output boundary
construct-grammar.maude          construct acceptance, resource-qualified
                                 interface composition, capability_call
                                 lowering, event-source discipline, provider
                                 authorization boundary
construct-graph.maude            normalized construct graph acceptance
                                 invariants: edge compatibility, capability
                                 closure, port cardinality, unique-resolution
                                 witnesses, deterministic lowering output,
                                 compositionality,
                                 produced-port constraints, fact consistency,
                                 accepted-program adequacy
construct-interop-examples.maude abstract package-interop scenarios for the
                                 seven workflows in
                                 spec/construct-interop-examples.md
construct-lowering.maude         accepted-program to core-IR preservation:
                                 platform lowering, edge relation preservation,
                                 lowering-class lifecycle acceptance,
                                 deterministic reports, exactly-one core object
                                 ownership across node/edge entries, no extra
                                 capabilities, runtime inputs, package
                                 schedulers, or package lifecycle semantics
lowering-runtime-handoff.maude   lowered core IR entry into existing runtime
                                 lifecycle shapes: effect graph templates,
                                 dependency blocking, event/projection
                                 records, event-source/schedule templates, and
                                 rejection of lowered run, claim, terminal,
                                 cancellation, retry/lease, or provider-run
                                 state
lowering-class-lifecycle.maude   platform lowering-class lifecycle profiles:
                                 metadata, capability/typed/resource effects,
                                 event emit/source, projection view, schedule
                                 emitter, template vs event-record output,
                                 allowed object-entrypoint pairs, and forbidden
                                 hidden lifecycle authority
effect-dependencies.maude        success/failure/completes dependency release
guard-commit-bite.maude          bite proof: the generated no-commit search shape
                                 stays sound on the correct kernel yet catches an
                                 unsafe guard/assertion commit rewrite
expression-kernel.maude          guards, assertions, optional reads,
                                 AgentRef targets
native-provider-lifecycle.maude  cancellation ack, terminal evidence recovery,
                                 artifact failure, and duplicate-terminal
                                 safety
policy-capacity-retry.maude      policy/capacity blocks, lease expiry, retry
tracker-claim-turn.maude         tracker-claim gated coding-agent turn lifecycle
external-event-loop.maude        external-event-bounded agent loop
workflow-composition.maude       pattern elaboration, workflow completion,
                                 invocation
pattern-recursion.maude          pattern-application reachability: recursive
                                 apply rejection (graph.unbounded_pattern_recursion)
                                 with non-recursive nesting not flagged
effect-cycle-pacing.maude        effect-bearing rule cycles: a same-commit ring
                                 is refused (graph.unbounded_effect_recursion),
                                 including the one-rule form; a ring that waits
                                 on an effect terminal is legal with no
                                 declaration; @bounded and @tool refuse even the
                                 paced ring (graph.bounded_workflow_effect_cycle);
                                 a preserved self-trigger stays with the per-rule
                                 refusal so one defect earns one diagnostic
termination-measure.maude        DR-0081 §2: a ring that advances in one
                                 direction, is bounded somewhere, and consumes
                                 its token is admitted; unbounded, preserving,
                                 carry-through-only, and direction-disagreeing
                                 rings are never admitted
view-derivation.maude            views vs one-shot rules: a `rule` evaluates its
                                 body once and closes, a `view` re-derives when
                                 the set it queries moves, and its derived fact
                                 SUPERSEDES keyed by firing identity while the
                                 commit log appends; today's semantics reaches
                                 both states that ruling forbids, and a view
                                 that could enqueue an effect keeps its first
                                 input for good, which is why it may not
view-retraction.maude            a view whose trigger is retracted ends and
                                 withdraws its derivation; a cascade therefore
                                 holds ONE downstream value, where pinning the
                                 downstream firing accumulates two
settled-firing-closure.maude     closure by completion (DR-0043 Decision 2's
                                 missing case): a firing may close once its
                                 effects have settled AND it has committed
                                 since, and closing on settlement alone strands
                                 the continuation
rule-autofail.maude              rule-level unhandled-failure auto-fail (R1): in a
                                 self-terminating workflow an unhandled effect
                                 failure auto-fails the instance; handled failures,
                                 cancelled effects, and @service workflows never
                                 auto-fail (a service records a durable diagnostic)
std-construct-authorization.maude  std-library construct lock exemption (1929 opt A):
                                 a built-in std construct use compiles without a
                                 package lock; third-party/unknown construct uses
                                 still require an authorizing lock
turn-access-grant.maude          turn-access grant authority narrowing (Proposal A):
                                 effective authority = profile intersect grant; a
                                 grant never widens beyond the profile
workflow-authority-attenuation.maude  workflow-encapsulation D1 invoke-seam
                                 authority narrowing: child authority is bounded
                                 by declared(child) intersect effective(parent),
                                 and an explicit start grant can only narrow
                                 that automatic cap
workflow-runtime-marker-reresolution.maude  workflow-encapsulation E2-DYN
                                 runtime delivery door: re-resolve instance
                                 handle identity before consulting private
                                 workflow markers; unresolved handles fail closed
infoflow-field-signature.maude   DR-0030 X2 per-field result signatures plus
                                 workflow-encapsulation D3' milestone payload
                                 egress and milestone-reached occurrence
                                 read-source checks
infoflow-signal-carriage.maude   signal label carriage, no-laundering, and
                                 workflow-encapsulation D2b invoke-selector NMIF:
                                 invoke inbound payload integrity cannot select
                                 a higher-integrity branch
infoflow-coord-carriage.maude    workflow-encapsulation E-COORD partition fork:
                                 coordination writes are integrity-gated,
                                 outcomes are read sources, `shared` carries
                                 remaining/holders across workflows, and
                                 partition prevents that carriage
envelope-composition.maude       DR-0063 multi-party governance: a run is
                                 governed by a SET of signed envelopes and the
                                 effective policy is their meet, defined by
                                 refusal -- the composed policy never admits
                                 what a constituent refuses. Teeth for source
                                 vouchers composed by union, compartments by
                                 intersection, unqualified roles aliasing across
                                 authorities, a declassify grant from a
                                 non-labelling authority, an owner's grant
                                 applied to the composed label rather than to
                                 its own contribution, and a composition record
                                 consulted as a defaulting map rather than
                                 checked as the set that was checked; plus
                                 omission widening the meet, `require
                                 authority`, the P-256-only trust root, and
                                 order-independence
actsfor-unanimity.maude          DR-0063 O4: what acts-for ORDERING means
                                 across a meet. Closure over the unanimous edge
                                 set stays inside the intersection of the
                                 constituents' closures, so a composed relation
                                 reaches less and can only refuse more. Tooth:
                                 edges pooled instead, where the closure walks
                                 one authority's half-chain into another's and
                                 derives a delegation neither granted
envelope-minting.maude           DR-0063 section 8 `ONE_MINTER`: the KEY the
                                 composed label is about. A key is
                                 (authority, address) so minting is owning; a
                                 second authority attaches by reference to an
                                 opaque exposure, pinning a digest, and can
                                 neither mint nor downgrade; an unresolved
                                 reference is a named error. Teeth for a global
                                 exposure-id space (an impersonation instead of
                                 a dangling reference), a dangling reference
                                 dropped rather than refused, and an ignored
                                 digest. Discharges the modelling assumption
                                 envelope-composition.maude states
action-expansion.maude           action-call inlining (DR-0023): hygienic
                                 binding per call site, acyclic gate, and that
                                 inlining runs no provider work
workflow-revision.maude          active revision, old-effect attribution, and
                                 cancellation policy behavior
workflow-scoping.maude           workflow-local name scoping: a reference resolves
                                 against globals + its own workflow's locals, a
                                 sibling-only local name leaks, and a headerless
                                 program (no explicit workflow) is rejected
terminal-payload-shape.maude     workflow terminal payload shape: a class contract
                                 takes a field block, a scalar contract takes a
                                 matching scalar value; shape/type mismatches are
                                 rejected, correct shapes never wrongly rejected
invoke-result-typing.maude       typed invoke results: `after child succeeds as r`
                                 binds r to the child's OUTPUT contract (field
                                 access checked against it), `after child fails as
                                 f` to the child's FAILURE contract when resolvable
                                 else the base — predicate discrimination
pattern-body-surface.maude       pattern-body allow-list: a pattern body may hold
                                 rules/effects/records/local schemas etc. but not
                                 workflow contracts, nested pattern/apply, or a rule
                                 reaching a workflow terminal; allowed never rejected
merge-slice.maude                versioned-workspace certified merge: disjoint-slice
                                 composition over manifests vs the text-proxy engine;
                                 cross-file write/read and consume/read anti-dependence
                                 conflicts refuse the certificate and escalate honestly
merge-confluence.maude           certified-merge confluence: pairwise-disjoint edits
                                 fold order-independently; overlap-graph components
                                 escalate jointly, never first-come partial folds
workstream.maude                 workstream tier invariants: membership-gates-autosync
                                 with certificate-gated auto-admit, single-valued
                                 membership, archive-rehomes-members to mainline
workstream-boundary.maude        DR-0078 joint workstream/ref boundary: exact-cut
                                 reservation, topology/contribution freeze, one-way
                                 post-CAS close, sparse/fork separation, receipt
                                 non-authority, and an explicit bite for every rule
branch-effect-key.maude          branch-distinct effect idempotency keys: the naive
                                 branch-blind key dedupes counterfactual vs real
                                 effects (both directions demonstrated); the branch
                                 id in the key rejects it, idempotency retained
selective-undo.maude             selective-undo stranding: a naive by-path filter
                                 accepts an undo that strands a retained reader; the
                                 dependency-closure check refuses it and accepts a
                                 selection containing its own reader
stat-cache.maude                 import-back stat-cache soundness: a naive size+mtime
                                 fingerprint drops a racy-granule content change; the
                                 sound importer re-hashes inside the racy window only
improve-acceptance.maude         campaign acceptance invariant: never surface a
                                 dominated candidate -- guarded regressions beyond
                                 band, violated bars, and focus regressions are
                                 refused; sacrifice releases a guard; the naive
                                 focus-only judge demonstrates the hazard
improve-holdout.maude            holdout sealing: the proposer never reads sealed
                                 scenarios; kmax promotion gates wear a seal out with
                                 ambient refresh; anchor asks retire seals honestly;
                                 below the floor the gate passes tagged unheld-out
improve-precedent.maude          tradeoff precedent authority: auto-resolution only by
                                 monotone dominance over an applicable un-revoked
                                 answered precedent (accept and reject duals); the
                                 naive interpolating resolver demonstrates the hazard
prefix-replay.maude              mark-pinned scenario seeding: a replayed pre-cut
                                 effect never fires again, post-cut recorded outcomes
                                 are dropped (the suffix re-executes live), suffix
                                 sites become claimable only after the seed completes
```

The shell script runs every Maude test file and checks the expected number of
`No solution.` and `Solution 1` results for each suite. It also generates the
current `whip package catalog`, converts each catalog lowering into bounded
lifecycle obligations, and verifies the platform lowering classes satisfy
`lowering-class-lifecycle.maude` static-safety and authority-profile rules. That
catalog check does not prove emitted core-object outputs; output compatibility
is checked later from concrete lowered IR inventory. The script then generates a
package check report for `std/manifests/memory.json`, converts the emitted
`package_contract` artifact into bounded Maude obligations, and verifies package
effect-contract acceptance plus executable capability-call declaration lowering
against `package-contract.maude`. It also converts the same package contract's
construct registry into bounded construct-grammar obligations, proving the
package-declared capability-call construct is accepted by
`construct-grammar.maude` and lowers to an ordinary core effect template.

The script then generates a package lock and check report for
`examples/package-memory.whip`, converts the emitted `construct_graph` artifact
into bounded Maude obligations, and verifies node acceptance, edge acceptance,
and graph aggregation against `construct-graph.maude`. The same check report's
`lowered_ir_report` is converted into bounded lowering obligations that verify
edge preservation, node lowering preservation, core-object coverage, graph
lowering boundary evidence, generated graph aggregation, and runtime lifecycle
handoff against `construct-lowering.maude` and
`lowering-runtime-handoff.maude`. The generated handoff check uses concrete
`runtime_entrypoint` values from the emitted report and validator-owned
graph-boundary facts for deterministic lowering, report completeness,
no-runtime-inputs, and individual no-lowered-runtime-state facts rather than
any aggregate runtime-lifecycle evidence shortcut. The
bridge mirrors the Rust lowered-IR validator's current supported object-kind
and runtime-entrypoint slice: schema-reserved future objects such as diagnostic
records must become explicitly supported before generated Maude handoff checks
accept them. This is intentionally simple: generated checks can later emit a
richer manifest, but the
current script already fails CI when an expected safety search starts finding a
path, a real emitted construct graph falls outside the modeled acceptance rules,
the emitted lowered report falls outside the modeled lowering-preservation
rules, or the emitted runtime entrypoints fail the modeled handoff rules.

## Expression Kernel Model

The Maude kernel includes the finite expression-kernel abstraction from
`spec/expression-kernel.md`. It adds guard and assertion semantics without
turning Maude into a JSON/string interpreter.

Target checks:

```text
false guard cannot fire a rule
error guard cannot commit facts/effects
true guard preserves existing effect dependency searches
assertion failure cannot mutate workflow state
optional missing path cannot be read without a presence proof
enum/literal guards cannot match values outside their domain
dynamic tell cannot target an undeclared agent
```

Recommended shape:

```text
fact(F) + guard(R, F, true)  -> ruleReady(R, F, G)
fact(F) + guard(R, F, false) -> no rewrite
fact(F) + guard(R, F, error) -> diagnostic, no graph
```
