# Diagnostics Guide

Use this page when the `whip check`, `whip run`, or `whip revise` command
reports an error. Also use this page when a command for inspection at run time
reports an error. For the syntax of a command and for the shapes of the JSON,
refer to the [CLI reference](api-reference.md) and to the
[JSON reference](json-reference.md).

Read the diagnostic first. A message names what it rejected, points at it, and
carries the repair, so most faults need nothing from this page. This page is for
the *categories* — the design rule behind a refusal — and for the cases a
message cannot fully explain on one screen.

## How to read a diagnostic

<!-- render: examples/invalid/bad-record.whip code type.unknown_enum_variant -->
```text
error[type.unknown_enum_variant]: enum `ReviewStatus` has no variant `Maybe`
   --> examples/invalid/bad-record.whip:25:12
   |
25 |     status Maybe
   |            ^^^^^
   = note: `status` is declared `ReviewStatus` here (examples/invalid/bad-record.whip:15:10)
   = help: use one of: Accept, Blocked, Revise
```

Four parts, and each one has a job:

- **The head** gives a severity, a code in brackets, and what the compiler
  rejected.
- **The location** gives the file, the line and the column, with a caret under
  the token the fault is about — not under the rule that contains it.
- **A `= note:` line** appears when some *other* place in the source explains
  the error. Here it is the declaration the value had to satisfy.
- **A `= help:` line** gives the repair. Where the compiler can tell which name
  you meant, or which values are legal, the help line says so.

An `error` refuses the program. A `warning` does not: it reports a hazard that
the runtime resolves by a documented default. Read a warning before you decide
to keep it.

## Diagnostic codes

The bracketed code — `type.unknown_enum_variant` above — names the *fault*, not
the stage of the compiler that caught it. Two places that reject the same
mistake carry the same code, and a code is never reused for a different mistake.

A code is stable. Once any program in the WhippleScript source tree is known to
make the compiler emit a given code, that code is frozen, so it is safe to grep
for in a log, to pin an acceptance fixture on, and to search this page by. The
source tree carries the register of every code the compiler can emit, in
`spec/diagnostic-codes.txt`; a code no program has yet produced is marked there
as provisional and may still be corrected before it freezes.

`whip check --json` puts the code in a `code` field beside the severity, the
span and the help text, and the language server carries the same. Match on the
code rather than on the wording: the wording is written for a person, and is
rewritten whenever it can be made clearer.

## Parse And Source Shape

### A file that is not WhippleScript

The parser knows the Gherkin and Cucumber keywords by name and rejects each one
where it stands, because pasting a feature file into a `.whip` file is the
common way to arrive here. The repair is not a translation of the steps. A
`when` clause is a typed readiness pattern over facts, not a step in prose; the
[build-a-workflow tutorial](tutorials/build-a-workflow.md) writes that intent as
a workflow.

### More than one workflow in one bundle

The diagnostic lists the workflows it found and asks for `--root`. The flag
means the same thing on `check`, `run`, `start`, `step`, and `revise`.

## Type And Schema Checks

### Object literal without an expected type

An object literal has no type of its own. The checker takes its type from the
position the literal sits in, and the typed positions are `record Class { ... }`,
`complete output { ... }`, a `coerce fn(...)` argument, and a hosted
`exec capability with <record> -> Type` statement. A literal anywhere else — in
a guard, say — is refused because there is nothing to check it against.

## Liveness

Two refusals share one rule: a workflow must be able to end, and a rule must be
able to fire.

<!-- render: examples/diagnostics/no-terminal-rule.whip code graph.unreachable_terminal -->
```text
error[graph.unreachable_terminal]: workflow `AlertWatch` has no rule that reaches `complete` or `fail`
  --> examples/diagnostics/no-terminal-rule.whip:1:1
  |
1 | workflow AlertWatch
  | ^
  = help: add a rule that runs `complete <output> { ... }` or `fail <failure> { ... }`, or tag the workflow `@service` if it intentionally runs forever
```

<!-- render: examples/invalid/rule-never-fires.whip code graph.rule_never_fires -->
```text
error[graph.rule_never_fires]: rule `escalate` can never fire: nothing produces `Escalation`
   --> examples/invalid/rule-never-fires.whip:36:8
   |
36 |   when Escalation as escalation
   |        ^^^^^^^^^^^^^^^^^^^^^^^^
   = help: seed `Escalation` from a table, record it in another rule, declare it as a workflow input, or tag the rule `@external` if it arrives from an external system
```

The tags in those help lines are declarations, not silencers. `@service` on a
workflow says the workflow need not terminate — which is why an `invoke` of a
`@service` workflow is itself refused further down this page. `@external` on a
rule says the fact it matches arrives from outside the program, so the checker
stops requiring the program to produce it. Neither tag is the answer to a
workflow you meant to end, or to a rule whose trigger you forgot to record.

## Effect Graph Checks

### An effect output is out of scope

The output of an effect exists only inside the branch that proved the effect
settled. A read of `x` outside `after x succeeds` — or `fails`, or `completes` —
is refused because at that point the effect has no terminal status and so no
payload. This is the same property that makes an inline "await" impossible: the
branch is how the program observes that the world answered.

## Coordination Checks

### More than one lease in one progression

A progression may hold at most one lease. The limit is structural rather than a
setting: two held leases is hold-and-wait, which is the deadlock condition.
Divide the work across rules, or model the resource as one lease under a key
wide enough to cover both.

### Coordination outcomes are exhaustive

An `acquire` settles as `held` or `contended`, and a `consume` settles as `ok`
or `over`. Both are branches rather than failures, and the checker requires a
handler for each, exactly as it requires a `case` to cover its domain. A missing
handler is not a fallthrough — it is a path the program has no plan for.

## Recursion And Namespace Checks

### Recursive pattern application

<!-- render: examples/invalid/recursive-pattern.whip code graph.unbounded_pattern_recursion -->
```text
error[graph.unbounded_pattern_recursion]: recursive pattern application is not allowed: expansion cycle Loop -> Loop
   --> examples/invalid/recursive-pattern.whip:10:3
   |
10 |   apply Loop<T> as inner {
   |   ^^^^^^^^^^^^^^^^^^^^^^^^
   = help: break the cycle: pattern expansion must elaborate into a finite program
```

The cause is an `apply` statement of a pattern that expands into itself. The
expansion can be direct or through a cycle. The expansion of a pattern must
give a program with a finite size.

### Recursive workflow invocation

<!-- render: examples/invalid/recursive-workflow-invocation.whip code graph.unbounded_workflow_invocation_recursion -->
```text
error[graph.unbounded_workflow_invocation_recursion]: recursive workflow invocation is not allowed: invocation cycle Ping -> Pong -> Ping
   --> examples/invalid/recursive-workflow-invocation.whip:12:6
   |
12 |   => {
   |      ^
   = help: break the cycle: a runtime `invoke` cycle has no compile-time convergence proof; route the recurrence through an external event, clock, or durable boundary instead
```

The cause is a cycle of `invoke` statements between workflows. Such a cycle has
no proof of convergence at compile time.

### Effectful rule cycle

<!-- render: examples/invalid/effectful-rule-cycle.whip code graph.unbounded_effect_recursion -->
```text
error[graph.unbounded_effect_recursion]: effectful rule cycle is not allowed: rule cycle ping_step -> pong_step -> ping_step turns inside one commit, and rule `ping_step` runs effects on every turn of it
   --> examples/invalid/effectful-rule-cycle.whip:31:3
   |
31 |   tell worker "ping {{ p.n }}"
   |   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   = help: field `n` rises by 1 on every hop, but no rule on the cycle bounds it, so nothing stops the turn; every edge of this cycle records its fact in the same commit that read one, so nothing paces it and each turn enqueues fresh effects at commit speed — put the recurrence behind an effect terminal (`after <effect> succeeds { record ... }`) so each turn waits on the world, give the cycle a measure that bounds it, or tag a rule `@external` when its facts genuinely arrive from outside the workflow
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

### Effect cycle in a bounded workflow

<!-- render: examples/invalid/bounded-workflow-effect-cycle.whip code graph.bounded_workflow_effect_cycle -->
```text
error[graph.bounded_workflow_effect_cycle]: effect cycle in a bounded workflow is not allowed: workflow `BoundedWorkflowEffectCycle` is `@bounded`, and rule cycle ping_step -> pong_step -> ping_step runs the effects of rule `ping_step` on every turn
   --> examples/invalid/bounded-workflow-effect-cycle.whip:30:3
   |
30 |   tell worker "ping {{ p.n }}" as t
   |   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   = help: field `n` rises by 1 on every hop, but no rule on the cycle bounds it, so nothing stops the turn; a bounded workflow settles instead of turning, so it may not loop with the world without a proof: give the cycle a measure — an `int` field every hop advances by a literal step, with a rule on the cycle bounding it — or break the cycle, or drop `@bounded` if this workflow is meant to keep going
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

### Recursive agent tool grant

<!-- render: examples/invalid/tool-grant-cycle.whip code graph.unbounded_tool_grant_recursion -->
```text
error[graph.unbounded_tool_grant_recursion]: recursive agent tool grant is not allowed: invoke-tool cycle Alpha -> Beta -> Alpha
   --> examples/invalid/tool-grant-cycle.whip:34:11
   |
34 |     tools [Beta]
   |           ^^^^^^
   = help: break the cycle: an agent may call a granted `@tool` workflow synchronously, so a cycle in the grant graph has unbounded recursion depth and no compile-time convergence proof
```

The cause is a cycle in the invoke-tool graph. An agent may call a granted
`@tool` workflow synchronously inside a turn, and that workflow's own agents may
call further tools. A cycle in the grant graph therefore has an unbounded depth
of recursion and no proof of convergence at compile time. A grant of a workflow
to its own agent is a cycle of length one.

The check reads the grants of the bundle. A grant of a name that no workflow of
the bundle declares gives no edge: such a name is a package export, and the
manifest checks the convergence of a package export when it attests it.

### Invocation of a `@service` workflow

<!-- render: examples/invalid/invoke-service-workflow.whip code graph.invoke_awaits_service_workflow -->
```text
error[graph.invoke_awaits_service_workflow]: rule `relay` invokes `Forever`, which is tagged `@service`: `@service` declares that a workflow need not terminate, and an invocation awaits its terminal output
   --> examples/invalid/invoke-service-workflow.whip:22:5
   |
22 |     invoke Forever { ask { id ticket.id  n 0 } } as sub
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   = help: remove `@service` from the target if it does terminate — non-termination is a root-only privilege, not for an awaited sub-workflow; to hand work to a genuinely long-running service, emit a signal or event it observes instead of awaiting it
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

### Evidence-only fact matched as a fact

<!-- render: examples/invalid/evidence-fact-match.whip code graph.unmatchable_fact -->
```text
error[graph.unmatchable_fact]: rule `react_to_stream` matches evidence-only fact `agent.turn.streamed`: in-turn observations are evidence, not rule-matchable facts
  --> examples/invalid/evidence-fact-match.whip:9:8
  |
9 |   when fact agent.turn.streamed as ev
  |        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  = help: match a lifecycle fact (`agent.turn.completed`/`failed`/`timed_out`/`cancelled`) and read in-turn detail from its evidence
```

The cause is a `when` clause of a rule that matches an observation in a turn.
An example is `agent.turn.streamed`. The system records such an observation as
evidence. The system does not record such an observation as a lifecycle fact
that a rule can match.

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
