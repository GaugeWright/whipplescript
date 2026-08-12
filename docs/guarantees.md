# Guarantees

The value of WhippleScript is not its syntax. The value is the set of
invariants that the compiler and the runtime **promise** and check. This page
collects the invariants in one location. This page states each invariant as a
promise. This page also gives the formal model or the mechanism that carries
each promise. When a guarantee has an executable model, CI runs the model with
the `scripts/check-formal-models.sh` script. Thus a guarantee is not prose.

Each model also carries its own negative test. The test shows the property fail
when you remove the mechanism. A model that cannot fail proves nothing.

If you must approve WhippleScript for your organization, read
[For IT and data owners](for-it.md) first. That page states each promise below
as an answer to a question that you must ask, in a table. If you want the
design that produces these promises, read
[How WhippleScript works](for-developers.md).

## Execution

**Each instance has one writer. Each rule firing commits atomically.**
Each instance is an isolated durable store. A rule firing commits its facts,
its consumed facts, its effects, and its terminal in one transaction. An
instance never observes half of a firing. Two firings never interleave their
writes.
*Carried by:* the transactional `commit_rule` operation of the store and the
single-threaded rule pass for each instance. The kernel semantics are in
`models/maude/kernel.maude`.

**The events have a causal sequence.**
The event log permits append only. Each event carries a causation identifier
and a correlation identifier. Thus a query gives the cause of each event. You
do not reconstruct the cause. A replay follows the same sequence.
*Carried by:* the append-only event store and the `trace --check` conformance
checker of the kernel. The file `models/tla/ControlPlaneLifecycle.tla` pins the
lifecycle invariants of the checker.

**Each effect occurs exactly one time.**
Each effect derives a stable idempotency key from the identity of its firing.
The identity has the program version, the revision epoch, the rule, the path of
the binding, and the identity of the trigger. A re-evaluation, a recovery after
a crash, and a replay each deduplicate against the key. Thus the system
requests an effect one time. This is true for each quantity of lowering
operations on its rule. A branched timeline and a restored timeline get
*different* keys. Thus a counterfactual run never deduplicates against a true
run.
*Carried by:* `models/maude/effect-key.maude`,
`models/maude/branch-effect-key.maude`, and `models/maude/prefix-replay.maude`.

**A firing that commits completes (pinned progressions).**
After a rule firing commits, the firing owns its trigger bindings as immutable
values. Its continuations run from the recorded context of the firing. Thus a
trigger cannot strand the progression. An adjacent rule can consume the
trigger. A projection can also retract the trigger, as when a `finish`
operation closes the ready issue that admitted the rule. In each condition, the
progression completes. The match operation controls the admission only. A query
stays a live read.
*Carried by:* `models/maude/pinned-progressions.maude`. The model proves the
fate at the commit: no step commits after the break of its condition in the
sequence of the log, and no final state strands an open region. The reactive
module reproduces the stall before the pin operation as the negative test.

**There is no silent stall (automatic failure).**
An effect gets to a terminal failure, and no `after` block observes the effect.
This condition cannot leave the instance in the running and idle state for an
unlimited time. The kernel fails the instance with a generic reason. A
cancellation is an exception, because a cancellation is deliberate. An
`@service` workflow records a durable diagnostic and does not fail.
*Carried by:* `models/maude/rule-autofail.maude`. At compile time, the
prominent warning of the unhandled-failure check gives this condition.

## Termination

**Each workflow has a path to an end.**
This is a reachability check, not a proof of general termination. The compiler
does not claim the second one.
A minimum of one rule must be able to get to `complete` or to `fail`. Each
matched class must have a producer: a table, a different rule, or an input of
the workflow. The compiler applies both checks before the run. A workflow that
runs continuously by design carries the `@service` tag. A rule whose facts come
from outside the workflow carries the `@external` tag. Each tag is explicit in
the source. Thus a program that does not stop is a declaration, not an accident.
*Carried by:* the static liveness checks of the compiler. Refer to
[liveness checks](language-reference.md#liveness-checks).

**A tree of recursive agent tools converges.**
An agent can invoke a curated set of `@tool` workflows synchronously. The whole
invoke tree must converge. Thus a turn never blocks for an unlimited time. Two
static checks give this property. The invoke-tool graph must be acyclic, because
a cycle gives an unbounded depth of recursion. Each `@tool` workflow must also be
locally convergent: a `@tool` node that reads external signals, and a `@tool`
node with the `@service` tag, cannot be shown to terminate. The same property on
a node that is not a tool is permitted. Non-termination is a privilege of the
root only.
*Carried by:* `models/maude/subworkflow-convergence.maude`. The model records
each reason that the system is not provably convergent. A valid system never
gets to that marker.

**A spend cap parks work. A spend cap never truncates work.**
A campaign that gets to its cap parks. Its state, its candidates, and its
evidence stay intact. The `whip improve --resume <campaign-id>` command
continues the campaign later with a new allowance. Thus a boundary of the budget
is a pause. It is never a silently smaller evaluation.
*Carried by:* the cap accounting of the campaign. Refer to
[Precedents, spend & estimators](manual/29-precedents.md).

## Typing

**Each outcome settles.**
A `case` statement on a closed domain must be exhaustive. The domains are an
enum, a literal union, and the terminal union of an effect. A branch handles
each outcome of an effect, or the automatic failure catches the outcome. No
outcome passes through silently.
*Carried by:* `models/maude/case-family.maude` and
`models/lean/Whipple/Narrowing.lean`, which proves that exhaustive implies
total. These compose with `models/maude/rule-autofail.maude`.

**A conditional field is unreadable where it may not exist.**
A field declared `when <discriminant> is "<literal>"` is required at admission
exactly when its discriminant holds that literal. A read of it is accepted only
where the discriminant is pinned to that literal, which is the matching arm of a
`case` on it. A `_` arm pins nothing and grants no read. This holds in each read
position of a rule body, including an effect operand and a `from` projection
that copies the field implicitly, so the value cannot leave the instance under a
state in which it may be absent.
*Carried by:* `models/maude/discriminant-schema.maude`.

**Typed effect failures are additive by construction.**
Each effect failure carries the same base. The base has `reason`, `summary`,
`effect_id`, `run_id`, and `kind`. Each kind adds its own extras. The
`exit_code` field of an `exec` effect and the `error_class` field of a coercion
are examples. Such a field is reachable only under the applicable static
narrowing of the effect kind. Thus a new variant can never change a read of the
base that exists.
*Carried by:* `models/maude/effect-error.maude` and
`models/lean/Whipple/EffectError.lean`, which proves that the base is a subset
of each variant and proves the additivity.

## Authority

**There is no ambient authority. Authority only becomes more narrow.**
Capability enters a program explicitly. A `use` statement imports a package
that carries authority. An operator grant gives the machine. Capability then
only becomes more narrow. The access grants of a turn, the authority at the
invoke seam of a child workflow, and the fields that a redaction keeps are each
a subset of the authority of the granter. Nothing becomes larger downstream.
*Carried by:* `models/maude/workflow-authority-attenuation.maude`,
`models/maude/turn-access-grant.maude`, and
`models/maude/script-hard-off.maude`. The last model shows that an `exec`
statement fails closed without the allowlist of the operator. A file store has
the same position. A store is read-only by default. A write operation fails
closed unless the store declares `allow write`.

**Information flow is a set of denials.**
Under a governance envelope, the checker applies universal deny properties.
Each property has exactly one permitted crossing, and the source marks that
crossing:

- The checker **denies** a value to each audience outside its set of readers.
  The crossing is a `declassified` coerce statement. The output schema limits
  the crossing.
- The checker **denies** the context of a turn to each provider that has no
  clearance for the data that the turn read.
- The checker **denies** untrusted data influence over a sink with more trust.
  The crossing is an `endorsed` coerce statement.
- The checker **denies** data that an attacker can control the ability to steer
  its own release. This property is NMIF.
- The checker **denies** a field that a `redact … keep` statement dropped to
  each sink. The runtime physically removes the field. A proof shows the
  non-interference.
- The checker **denies** an agent each read above the clearance of its user.
- A consumed fact gives its consumers its *computed producer reach*. Thus the
  checker gates labeled content on its exit as on its entry. Untrusted content
  cannot pass through an intermediate fact with no label.
- The checker **denies** an output of an effect influence over a sink with a
  `from` label above the vouched clearance of the executor. The output can be
  the result of a turn, the output of a coercion, or the result of an `exec`
  statement. Thus a model writes only where governance vouched for the model.

*Carried by:* the `models/maude/infoflow-*.maude` suite and the proofs in
`models/lean/Whipple/`. The proofs are `ReaderSets.lean`, `NMIF.lean`, and
`Redaction.lean`.

## Data

**A fact is immutable, and the content keys the fact.**
A recorded fact never changes. Identical content becomes one fact. These are
set semantics. To express a change, record a new fact or consume an old fact.
Thus the match operation is deterministic and the history is honest.
*Carried by:* the fact identity of the store, which the content keys, and the
idempotent insert operation.

**A replay is honest.**
The `whip checkpoint` command and the `whip restore` command rewind to a
coherent cut. A suffix that executes again never deduplicates against the
abandoned timeline, because the generation of the restore is part of the
identity of an effect. The `whip trace --check` command verifies the stream of
events of a run against the model of the lifecycle.
*Carried by:* `models/maude/restore-replay.maude` and the `trace --check`
conformance checker of the kernel
(`models/tla/ControlPlaneLifecycle.tla`).

---

If you observe a violation of a promise on this page, the system has a bug.
Report the bug with the `whip log` output of the instance. A guarantee has a
value only when you can falsify it.
