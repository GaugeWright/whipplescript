# Diagnostics Guide

Use this page when the `whip check`, `whip run`, or `whip revise` command
reports an error. Also use this page when a command for inspection at run time
reports an error. This page groups the diagnostics by the location that supplies
them and by the path to the repair. For the syntax of a command and for the
shapes of the JSON, refer to the [CLI reference](api-reference.md) and to the
[JSON reference](json-reference.md).

## Parse And Source Shape

### Expected a WhippleScript declaration

The cause is a file that starts with free text or with Gherkin syntax or
Cucumber syntax that a person pasted into the file.

This source is incorrect:

```text
Feature: Triage tickets
Scenario: high severity ticket
Given an open ticket
```

This source is the correction:

```whip
workflow TicketTriage

output result TriageDecision

class TriageDecision {
  ok bool
}

rule start
  when started
=> {
  complete result { ok true }
}
```

A `when` clause of WhippleScript is a typed readiness pattern. A `when` clause
is not a step in prose.

### Multiple workflow declarations require an explicit root

The cause is a bundle of source with more than one workflow in braces.

This is the correction:

```sh
whip check examples/revision-parent-child.whip --root ParentRevisionExample
whip run examples/revision-parent-child.whip --root ParentRevisionExample
```

The same correction applies to the `check`, `run`, `start`, `step`, and
`revise` commands.

### Binding after a multiline prompt

The cause is a binding of an effect after the closing triple quotation marks.

This source is incorrect:

<!-- check: skip — demonstrates a diagnostic that depends on the surrounding program; the synthetic wrapper errors first -->
```whip
tell worker """markdown
Do the work.
""" as turn
```

This source is the correction:

<!-- check: skip — the correction; `worker` is the surrounding program's agent -->
```whip
tell worker as turn """markdown
Do the work.
"""
```

## Type And Schema Checks

### Unknown schema or field

The cause is a reference to a class or a field with no declaration. The
reference is in a rule, an assertion, a payload, or a template.

This source is incorrect:

<!-- check: skip — demonstrates a diagnostic that depends on the surrounding program; the synthetic wrapper errors first -->
```whip
rule bad
  when MissingTask as task
=> { ... }
```

These are the corrections. Declare the class. As an alternative, include the
file that declares the class. As a second alternative, change the rule to match
a class that exists. For an error about a field, use the exact name of the field
from the body of the class. Usually the checker gives a suggestion when a
similar name is present.

These are the invalid fixtures:

- `examples/invalid/unknown-schema.whip`
- `examples/invalid/bad-record.whip`
- `examples/invalid/bad-effect-payload.whip`

### Object literal without an expected type

The cause is an object literal in a position where the checker cannot find a
class or the shape of a map.

The correction is to put the literal in a typed context. The contexts are
`record Class { ... }`, `complete output { ... }`, `coerce fn(...)`, and a
hosted `exec capability with <record> -> Type` statement.

### Incompatible expression types

The cause is a guard or an assertion that compares values from different
domains. An enum against a string is an example. A number against a boolean is a
second example.

This source is incorrect:

<!-- check: skip — a readiness clause, not a rule body -->
```whip
when Task as task where task.priority == "high"
```

The correction is to use the declared domain:

<!-- check: skip — a readiness clause, not a rule body -->
```whip
when Task as task where task.priority == High
```

These are the invalid fixtures:

- `examples/invalid/bad-expression-functions.whip`
- `examples/invalid/bad-finite-domain.whip`

## Liveness Checks

### Workflow has no terminal rule

This is the diagnostic:

```text
error: workflow `X` has no rule that reaches `complete` or `fail`
```

The correction is to add a rule that runs `complete <output> { ... }` or
`fail <failure> { ... }`.

For a service that runs for a long time by design, add a tag to the workflow:

```whip
@service
workflow WorkerDaemon
```

### Rule can never fire

This is the diagnostic:

```text
error: rule `X` can never fire: nothing produces `Y`
```

The correction is to make `Y` producible. The sources are an `input` of a
workflow, a `table` declaration, a `record` statement in a different rule, and a
declared external event. If external infrastructure truly injects the fact, add
a tag to the rule:

<!-- check: skip — a rule tag shown without the rule it annotates -->
```whip
@external
rule import_ticket
  when Ticket as ticket
=> { ... }
```

## Effect Graph Checks

### Unknown effect binding in `after`

The cause is an `after` block that references a binding. No effect in the body
of the rule introduced that binding.

This source is incorrect:

<!-- check: skip — demonstrates a diagnostic that depends on the surrounding program; the synthetic wrapper errors first -->
```whip
after review succeeds as result {
  record Done { summary result.summary }
}
```

The correction is to bind the effect first:

<!-- check: skip — the correction; `item` is the surrounding program's fact -->
```whip
coerce reviewWork(item.title) as review

after review succeeds as result {
  record Done { summary result.summary }
}
```

The invalid fixture is `examples/invalid/bad-effect-graph.whip`.

### Effect output is out of scope

The cause is a rule that reads the terminal payload of an effect outside the
`after` branch that proved that terminal status.

The correction is to move the read into an `after x succeeds` block, an
`after x fails` block, or an `after x completes` block.

The invalid fixture is `examples/invalid/effect-output-scope.whip`.

## Coordination Checks

### More than one lease in one progression

The cause is a rule that tries to hold more than one lease at the same time. The
default safety model permits one held lease for each progression. This limit
prevents a deadlock.

The correction is to divide the work across rules. As an alternative, design the
resource as one key of a lease.

### Missing lease/counter branch

The cause is an incomplete set of branches. An `acquire` statement and a
`consume` statement are effects that you branch on. The checker needs a handler
for each outcome.

This is the correction:

<!-- check: skip — the correction; `task` is the surrounding program's fact -->
```whip
acquire deploy_slot for task.env as slot

after slot held {
  release slot
}

after slot contended {
  tell worker "Deployment slot is busy."
}
```

## Recursion And Namespace Checks

### Recursive pattern application

This is the diagnostic:

```text
error: recursive pattern application is not allowed (graph.unbounded_pattern_recursion): expansion cycle Loop -> Loop
```

The cause is an `apply` statement of a pattern that expands into itself. The
expansion can be direct or through a cycle. The expansion of a pattern must
give a program with a finite size.

The correction is to break the cycle. The expansion must then terminate.

The invalid fixture is `examples/invalid/recursive-pattern.whip`.

### Recursive workflow invocation

This is the diagnostic:

```text
error: recursive workflow invocation is not allowed (graph.unbounded_workflow_invocation_recursion): invocation cycle Ping -> Pong -> Ping
```

The cause is a cycle of `invoke` statements between workflows. Such a cycle has
no proof of convergence at compile time.

The correction is to route the recurrence through an external event, a clock, or
a durable boundary. Do not use a direct cycle of `invoke` statements.

The invalid fixture is `examples/invalid/recursive-workflow-invocation.whip`.

### Effectful rule cycle

This is the diagnostic:

```text
error: effectful rule cycle is not allowed (graph.unbounded_effect_recursion): rule cycle ping_step -> pong_step -> ping_step turns inside one commit, and rule `ping_step` runs effects on every turn of it
```

The cause is a cycle in the rule dependency graph in which one rule or more runs
an effect, and in which each `record` lands in the same commit as the fact that
the rule matched. Nothing paces such a cycle. It turns as fast as the store
commits, and each turn requests fresh external effects under a new idempotency
key, so the exactly-once guarantee never stops it.

A cycle that waits on the world is a different thing, and the compiler permits
it. When the `record` of a rule sits inside an `after` block, the fact of the
next turn does not exist until the terminal of an effect arrives. Such a loop
turns at the pace of the agent or the service that it talks to. That loop is the
long-running agent loop of the language, and it needs no tag. The rules of
liveness still govern it: the workflow needs a rule that reaches `complete` or
`fail`, or the `@service` tag.

A cycle of ONE rule gets this same diagnostic, because a loop in one rule is the
loop of two rules with fewer names. The retry pattern of
[Agent patterns](manual/13-agent-patterns.md) keeps compiling: it records inside
an `after` block, so it waits on the world each turn. A rule that preserves its
own trigger, rather than advancing it, has a diagnostic of its own and keeps
it.

The correction is to move the `record` of the recurrence into an `after` block,
so each turn of the cycle waits for the terminal of an effect. As an
alternative, break the cycle. A rule whose facts genuinely arrive from outside
the workflow carries the `@external` tag, and a cycle through such a rule is not
internal recursion.

The invalid fixture is `examples/invalid/effectful-rule-cycle.whip`.

### Effect cycle in a bounded workflow

This is the diagnostic:

```text
error: effect cycle in a bounded workflow is not allowed (graph.bounded_workflow_effect_cycle): workflow `BoundedWorkflowEffectCycle` is `@bounded`, and rule cycle ping_step -> pong_step -> ping_step runs the effects of rule `ping_step` on every turn
```

The cause is an effect-bearing cycle in a workflow that declares that it
settles. The `@bounded` tag is the opposite of the `@service` tag. The
`@service` tag declares that a workflow runs for as long as the world gives it
work. The `@bounded` tag declares that the workflow reaches a terminal after a
number of steps that the program fixes, not the data. A loop with the world
breaks that promise, so a `@bounded` workflow may not carry a cycle of rules
that runs an effect, even one that waits on a terminal.

A `@tool` workflow carries the same promise with no tag. An agent invokes a tool
inside a turn, and DR-0025 requires the turn to end, so the check reads a `@tool`
workflow as a bounded one. The message names DR-0025 in that case.

The correction is to break the cycle. As an alternative, remove the `@bounded`
tag when the workflow is meant to keep turning. A `@tool` workflow has no such
alternative.

The invalid fixture is `examples/invalid/bounded-workflow-effect-cycle.whip`.

### Recursive agent tool grant

This is the diagnostic:

```text
error: recursive agent tool grant is not allowed (graph.unbounded_tool_grant_recursion): invoke-tool cycle Alpha -> Beta -> Alpha
```

The cause is a cycle in the invoke-tool graph. An agent may call a granted
`@tool` workflow synchronously inside a turn, and that workflow's own agents may
call further tools. A cycle in the grant graph therefore has an unbounded depth
of recursion and no proof of convergence at compile time. A grant of a workflow
to its own agent is a cycle of length one.

The check reads the grants of the bundle. A grant of a name that no workflow of
the bundle declares gives no edge: such a name is a package export, and the
manifest checks the convergence of a package export when it attests it.

The correction is to break the cycle.

The invalid fixture is `examples/invalid/tool-grant-cycle.whip`.

### Invocation of a `@service` workflow

This is the diagnostic:

```text
error: rule `relay` invokes `Forever`, which is tagged `@service` (graph.invoke_awaits_service_workflow): `@service` declares that a workflow need not terminate, and an invocation awaits its terminal output
```

The cause is an `invoke` statement whose target carries the `@service` tag. The
parent of an invocation observes the typed terminal output of the child. The
`@service` tag is the declaration that a workflow is not required to terminate:
it is the escape from the check that otherwise demands a rule that reaches
`complete` or `fail`.

Note what the tag does not mean. It is not a proof that the workflow runs
forever. A `@service` workflow that carries a completing rule reaches a terminal
at run time in the usual way. The refusal rests on the missing PROMISE. A caller
that blocks on a terminal has nothing to hold the callee to, and if no terminal
comes, the instance stays in the running state with no terminal. The automatic
failure does not catch that condition, because that mechanism observes an effect
that FAILED, and here nothing fails.

This is the same rule that the agent-tool seam applies. A granted `@tool`
workflow that also carries `@service` is refused on the tag alone, with the same
reasoning and whether or not it carries a completing rule.

The tag itself stays legitimate. This diagnostic refuses the AWAIT of a
`@service` workflow, never the declaration of one. Non-termination is a
privilege of the root.

The correction is to remove `@service` from the target when the target does
terminate, or to hand the work to a genuinely long-running service through a
signal or an event that it observes.

The invalid fixture is `examples/invalid/invoke-service-workflow.whip`.

### Evidence-only fact matched as a fact

This is the diagnostic:

```text
error: rule `X` matches evidence-only fact `agent.turn.streamed`: in-turn observations are evidence, not rule-matchable facts
```

The cause is a `when` clause of a rule that matches an observation in a turn.
An example is `agent.turn.streamed`. The system records such an observation as
evidence. The system does not record such an observation as a lifecycle fact
that a rule can match.

The correction is to match a lifecycle fact. The facts are
`agent.turn.completed`, `agent.turn.failed`, `agent.turn.timed_out`, and
`agent.turn.cancelled`. Read the detail from the turn in the evidence of that
fact.

The invalid fixture is `examples/invalid/evidence-fact-match.whip`.

## Runtime And Provider Diagnostics

A failure of a provider does not fail the workflow automatically. Such a failure
appears as the state of an effect and a run, as a durable diagnostic, as
evidence, and as a record in a trace.

Examine the run in this sequence:

```sh
whip status <instance>
whip effects <instance>
whip runs <instance>
whip diagnostics <instance>
whip evidence instance <instance-id>
whip trace <instance> --check
```

These are the usual repairs:

| Symptom | Probable cause | Repair |
| --- | --- | --- |
| `blocked_by_capacity` | The capacity of the agent is full. | Wait, decrease the concurrency, or examine the effects that run. |
| `blocked_by_capability` | The agent or the provider does not expose the necessary capability. | Correct the `capabilities` field or the configuration of the provider. |
| `blocked_by_profile` | The policy of the profile denied the effect. | Use an effect with less authority, or bind a profile that permits the effect. |
| A run of a provider has the `failed` status. | The adapter, the model, the script, or a boundary failed. | Read the `diagnostics` output and the `evidence` output. Then write a rule for the policy: a retry, an escalation, or a `fail` statement. |
| A run of a provider has the `timed_out` status. | The timeout ended. | Add an `after x times out` branch or an `after x fails` branch. As an alternative, add a policy for a retry. |

## Revision Diagnostics

The `whip revise --dry-run` command reports the compatibility and does not
change the store. A revision that the command rejects does not change the active
version of the program.

These are the usual failures:

| Diagnostic family | Meaning | Repair |
| --- | --- | --- |
| The root workflow changed. | The candidate source changes the root of the instance. | Use the same root in v0. As an alternative, start a new instance. |
| The contract changed and the change is not compatible. | The contract of the input, the output, or the failure no longer agrees with the state in operation. | Keep the contract. As an alternative, wait until the instance is terminal. |
| A removed agent still has old work. | Work of the old version still targets an agent that the candidate removes. | Keep the agent. As an alternative, cancel the old work, or complete the instance first. |

## Assertion And Fixture Diagnostics

An assertion runs after the `run` command gets to the idle state. An assertion
that fails records a durable diagnostic. The system links the diagnostic to the
event of the assertion. Use the `--include-tag` flag and the `--exclude-tag`
flag to make the group of the assertions more narrow during a debug operation.

An acceptance fixture validates its own shape before it runs. The system rejects
an expectation with an incorrect type, a `setup.effects` field, a
`setup.artifacts` field, and an absent selector for a read of an assertion. The
system rejects each of these as an error of the fixture. The system does not
ignore them.

## Invalid Fixture Index

The `examples/invalid/` directory is the corpus for the regression tests of the
usual diagnostics:

| Fixture | Covers |
| --- | --- |
| `broken.whip` | Errors in the parse operation and in the shape of the source. |
| `headerless-library.whip` | A source with no `workflow` declaration, which is a fragment of a library. |
| `unknown-schema.whip` | A declaration that no part of the program declares. |
| `bad-record.whip` | The validation of the payload of a record. |
| `bad-agent.whip` | The capacity of an agent, duplicate skills, unknown fields, and an absent profile. |
| `bad-effect-graph.whip` | An unknown binding in an `after` block, and a predicate of a dependency that the system does not support. |
| `bad-effect-payload.whip` | Errors in the type of the payload of an effect. |
| `bad-terminal-payload.whip` | A terminal `complete` payload or `fail` payload with no declared output of the workflow. |
| `bad-expression-functions.whip` | Errors in the arity and the types of a function or a query in an expression. |
| `bad-finite-domain.whip` | An incorrect use of an enum or of a domain of literals. |
| `effect-output-scope.whip` | Errors in the visibility of the output of an effect. |
| `effectful-self-loop.whip` | The limits on the liveness and on a self loop of an effectful rule. |
| `evidence-fact-match.whip` | A match of a fact that is evidence only, as a fact that a rule can match. |
| `recursive-pattern.whip` | A recursive application of a pattern, which is a cycle in the expansion. |
| `recursive-workflow-invocation.whip` | A cycle of `invoke` statements between workflows. |
| `effectful-rule-cycle.whip` | A cycle of two rules or more that turns inside one commit, in which a rule runs an effect. |
| `bounded-workflow-effect-cycle.whip` | A cycle of rules that waits on the world, in a workflow that declares that it settles. |
| `tool-grant-cycle.whip` | A cycle in the invoke-tool graph of the agent `tools` grants. |
| `invoke-service-workflow.whip` | An `invoke` statement whose target is a `@service` workflow and therefore reaches no terminal. |
