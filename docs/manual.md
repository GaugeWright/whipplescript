# Manual

This is the WhippleScript manual. It has one chapter for each feature of the
language. Each chapter starts with the most simple form of its feature that
operates. The chapter then adds more detail. Thus each chapter introduces the
important behavior at the point where the behavior first becomes applicable. If
you are a new user, start with the [quickstart](quickstart.md) and the
[tutorials](tutorials/index.md). The
[language reference](language-reference.md) is the short and complete
specification. The chapters contain links into the language reference.

One premise applies to all of this manual. Rules hold the policy and stay
deterministic. Each external operation is a durable effect. The runtime
controls delivery, retries, idempotency, and inspection.

## Chapters

**Part I — Build workflows**

| # | Chapter | Subject |
| --- | --- | --- |
| 1 | [The smallest workflow](manual/01-smallest-workflow.md) | the skeleton of a program; the check, run, and examine sequence |
| 2 | [Facts and types](manual/02-facts-and-types.md) | classes, enums, literal unions, optionals, tables, the identity of a fact |
| 3 | [Expressions and assertions](manual/03-expressions.md) | conditions on facts; `assert`; queries |
| 4 | [Rules](manual/04-rules.md) | matches, guards, rewrites of facts, joins, the commit |
| 5 | [Effects and durability](manual/05-effects.md) | requests for external work; timers; the ledger; `cancel` |
| 6 | [Error handling](manual/06-error-handling.md) | deliberate failure; the failure of an effect; the automatic fail net |
| 7 | [Branching with `case`](manual/07-case.md) | branches on a closed set of data or outcomes |
| 8 | [Prompts, coerce, and decide](manual/08-coerce.md) | prompt templates; typed model decisions; branches on a decision |
| 9 | [`then`](manual/09-then.md) | the sugar for a chain of steps; the desugar; the automatic fail contract |
| 10 | [Time](manual/10-time.md) | timeouts, absolute deadlines, clock sources, `@service` |

**Part II — Direct agents**

| # | Chapter | Subject |
| --- | --- | --- |
| 11 | [Agents](manual/11-agents.md) | `agent`, `tell`, turns, the three controls |
| 12 | [Readiness patterns](manual/12-readiness.md) | the full vocabulary of `when`; the difference between `after` and `when` |
| 13 | [Agent patterns](manual/13-agent-patterns.md) | watchdogs, pipelines with a set rate, retries as facts |

**Part III — Govern workflows**

| # | Chapter | Subject |
| --- | --- | --- |
| 14 | [Coordination](manual/14-coordination.md) | leases, counters, ledgers; state that a workspace shares; contention as a branch |
| 15 | [Trackers](manual/15-trackers.md) | backlogs, `claim` and `finish`, the `whip issue` commands, a person in the loop |
| 16 | [Progressions](manual/16-progressions.md) | bindings as values; the `during` and `until` regions; lapse arms; `whip progressions` |
| 17 | [Messaging & ingress](manual/17-messaging.md) | channels and `send`; the `Message` envelope; signals, peer signals, sources |
| 18 | [Composition](manual/18-composition.md) | bundles and `input`; `invoke` and milestones; `include`, `pattern`, and `action` |
| 19 | [Exec: validation & hosted scripts](manual/19-exec.md) | `exec -> Schema`; the hosted profile; manifests and pinned hashes |
| 20 | [Files & file stores](manual/20-files.md) | stores with a root scope; the read-only default; read, write, import, and export |
| 21 | [Checkpoints, restore & forking](manual/21-checkpoints.md) | cuts, restore that is honest about replay, forks of a conversation, the VCS substrate |
| 22 | [Information flow I](manual/22-infoflow-labels.md) | envelopes and labels; sets of readers; the first denials; the guarantee report |
| 23 | [Information flow II](manual/23-infoflow-egress.md) | egress through a provider; flow signatures; `redact … keep`; crossings with a mark |
| 24 | [Governance envelopes & attestation](manual/24-governance.md) | the split between two agents; signatures and attestation; hatches that permit an audit |

**Part IV — Evaluate and optimize**

| # | Chapter | Subject |
| --- | --- | --- |
| 25 | [Testing workflows](manual/25-testing.md) | `test` blocks; `given`, `stub`, `run`, and `expect`; the virtual clock; the invalid-not-skipped rule |
| 26 | [Gauges & evidence](manual/26-gauges.md) | dimensions of quality; the granularity of a judge; bars; ambient scores |
| 27 | [Marks: pin, suppose & settle](manual/27-marks.md) | cut points; retroactive pins; regeneration in pairs; certification |
| 28 | [Campaigns & improve](manual/28-campaigns.md) | declared trade partitions; the optimizer loop; the holdout set; adoption |
| 29 | [Precedents, spend & estimators](manual/29-precedents.md) | durable decisions; caps that park work; the estimators; the reopener |
| 30 | [Observability & tracing](manual/30-observability.md) | the instrument panel; `trace --check`; lint; export to OTLP |

**Part V — Extend WhippleScript**

| # | Chapter | Subject |
| --- | --- | --- |
| 31 | [Authoring packages](manual/31-packages.md) | the `call` effect; manifests, `package check`, and `package lock`; the permitted content of a package |
| 32 | [Providers & harness configuration](manual/32-providers.md) | the families of provider; configuration files; credentials as references; the seam |
| 33 | [Script capabilities & the bash tool](manual/33-script-capabilities.md) | grants for a script; the governed virtual bash tool; the design of a tool surface |
| 34 | [Runtimes: native & the edge](manual/34-runtimes.md) | the four loops; the native store; the placement of the Durable Object; `deploy` |
| 35 | [Memory: recall, learn & curate](manual/35-memory.md) | durable pools of memory in a workspace; the three verbs; `whip memory`; memory under governance |

---

# Quick pattern guide

This section is the original single-page guidance for authors. It stays as a
short reference. Each subject below also has a full chapter above.

## Model data with classes and enums

Facts are typed. Use an enum for a closed set of decisions. Use a literal field
for a small state machine:

<!-- check: fragment -->
```whip
enum ReviewStatus {
  Accept
  Revise
  Blocked
}

class WorkItem {
  id string
  title string
  status "queued" | "reviewed"
}

class WorkReview {
  status ReviewStatus
  reason string
  confidence float
}
```

A status field with a literal type keeps the guards deterministic. It also
makes an illegal state impossible: a rule that matches
`where item.status == "queued"` cannot also see an item that has the reviewed
status.

Do not change a status in its position. Consume the fact and record a new fact
instead. The statement `done item -> record WorkItem { ... status "reviewed" }`
makes the change of state atomic with the other operations that the rule
commits.

## Request agent work

<!-- check: fragment -->
```whip
agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
  capabilities ["agent.tell"]
}

rule implement
  when WorkItem as item where item.status == "queued"
  when worker is available
=> {
  tell worker requires ["agent.tell"] as turn """markdown
  Implement this item:

  {{ item.title }}
  """

  after turn succeeds as completed {
    done item -> record WorkItem {
      id item.id
      title item.title
      status "reviewed"
    }
  }
}
```

The `tell` statement records an effect. The provider runs the effect later.
Learn these three results:

- The sequence of the statements in a rule body does not set the sequence of
  the effects. Use an `after` block to make a dependency edge.
- The output of an effect (`completed` in the example) is visible only in the
  `after` block that proves the terminal status. This condition makes the
  causality auditable.
- The `when worker is available` clause is the gate on capacity. Without this
  clause, the rule still fires. But the effect can then stop because of
  capacity.

## Make typed model decisions with `coerce`

Sometimes a judgment must supply structured data and not prose. In this
condition, declare a coerce function and branch on its completion:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
coerce reviewWork(title string, summary string) -> WorkReview {
  prompt """markdown
  Review the completed work.

  Title: {{ title }}
  Summary: {{ summary }}

  {{ ctx.output_format }}
  """
}

rule review
  when ...
=> {
  tell worker as turn "..."

  after turn succeeds as completed {
    coerce reviewWork(item.title, completed.summary) as review
  }

  after review succeeds as result {
    record ReviewedWork {
      item item
      review result
    }
  }

  after review fails as failure {
    tell worker "Review failed: {{ failure.reason }}"
  }
}
```

A `coerce` statement is an effect. It is not a call to a function. It is
durable, it can fail, and its typed output is available only in the `after`
branch.

## Branch deterministically

A guard does the filter operation. A `case` statement covers a finite domain.
An `after ... completes` block does the exhaustive handling of the terminal
status:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule accept
  when ReviewedWork as reviewed where reviewed.review.status == Accept
=> { ... }
```

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
case review.status {
  Accept => {
    record AcceptedWork { id item.id }
  }
  Revise => {
    tell worker as revision "Revise {{ item.title }}."
  }
  Blocked => {
    tell worker "Blocked: {{ review.reason }}"
  }
}
```

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
after turn completes {
  case turn.output {
    Completed as result => { record TurnSucceeded { summary result.summary } }
    Failed as failure   => { record TurnFailed { reason failure.reason } }
    TimedOut as timeout => { record TurnTimedOut { reason timeout.reason } }
    Cancelled as c      => { record TurnCancelled { reason c.reason } }
  }
}
```

Branch on typed values. Never parse the text of a prompt to select a route or a
status. If a decision needs the judgment of a model, make the decision a
`coerce` statement and branch on the typed result.

## Sequential chains with `then`

Independent rules are the best form for the largest part of orchestration. Each
rule reacts to the facts that apply to it. The runtime puts the rules in
sequence through `after` edges. But some work is truly a script: do this
operation, then this operation, then complete. Nested `after` blocks hide the
sequence of such work. The statement `then <binding> <- <effect>` writes the
sequence from the top to the bottom. The statement desugars to the same nested
`after` blocks:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule triage
  when Ticket as ticket
=> {
  then plan <- tell triager "Plan {{ ticket.title }}."
  then verdict <- coerce reviewPlan(ticket.title, plan.summary)

  case verdict.choice {
    "approve" => { complete result { plan plan.summary } }
    "reject"  => { fail error { reason "rejected" } }
  }
}
```

Each `then` binding is the success payload of its step. The binding is in scope
for each subsequent statement. A `then` chain chains success only. If a step
fails or times out, the instance fails automatically. The generic reason gives
the name of the binding. This behavior is the explicit contract of the sugar.
If the failure of a step needs a typed reason or a recovery, write the step in
the traditional `as` and `after` form. The two forms compose.

Use this table to select between a `then` chain and plain rules:

| Situation | Use |
| --- | --- |
| Steps that always run in a set sequence, with shared bindings | a `then` chain |
| A step whose failure needs a typed reason or a recovery | `as` and `after` |
| Independent reactions that come together from different facts | separate `rule` declarations |
| Policy with many branches, where the data and not the position sets the sequence | `rule` declarations and guards |

The `then` statement is not a new mode of the runtime. It desugars to the
nested `after` form before the analysis. You can see the result in the
`whip check` output. Each property of a rule is still applicable: atomic
commits, durable effects, and the semantics of `after`.

## Work queues

Sometimes work comes as a backlog and not as facts that you seed at the start.
In this condition, declare a `tracker`. The rules then claim from the tracker:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
tracker backlog {
  provider builtin
}

rule pick_up
  when backlog has ready issue as issue
  when worker is available
=> {
  claim issue as work
  tell worker as turn "Resolve {{ work.title }}."

  after work fails as taken {
    # another claimant won the race; wait for the next ready issue
  }
}
```

The verbs are `file issue into <tracker> { ... }`, `claim`, `release`, and
`finish`. A `claim` statement that loses is a usual failure that you can
branch on. It is not an error. Thus a tracker with contention stays correct and
the source needs no lock.

Operate the backlog from the CLI with the `whip issue new`, `whip issue list`,
and `whip issue show` commands. The lifecycle verbs are `ready`, `claim`,
`renew`, `release`, and `finish`. The `dep add` command is also available. The
scope of the builtin tracker is the workspace. It gives identifiers in the
`WS-1` format. An item that an agent files during a turn carries the provenance
of the run identity. The [language reference](language-reference.md#trackers)
gives the full syntax.

## Coordinate shared resources

Sometimes concurrent workflows contend for a resource that is limited. Examples
are a deploy slot, a budget of requests, and an audit trail. In this condition,
add `use std.coord` and declare one of the three coordination resources. Branch
on the atomic verbs. Do not build a lock from facts:

| Resource | Declaration | Verb | Outcomes |
|---|---|---|---|
| Lease (a mutex or semaphore with a limit) | `lease name { key Type slots N ttl 10m }` | `acquire <lease> for <key> [until ttl] as x` / `release x` / `renew x [until <dur>] as r` | `held` / `contended` |
| Ledger (a log that permits append only) | `ledger name { entry Schema partition by <field> retain 30d }` | `append <Schema> { ... } to <ledger> as x` | `appended` |
| Counter (a budget with a cap) | `counter name { key Type cap N reset hourly\|daily\|weekly\|monthly [timezone "<IANA zone>"] }` | `consume <counter> for <key> amount <n> as x` | `ok` / `over` |

Each attempt is atomic. Each outcome is a branch and never an error. Handle the
two sides. If you do not, the checker flags the rule:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
use std.coord

lease deploy_slot {
  key Ticket
  slots 1
  ttl 10m
}

rule ship
  when Ticket as t
=> {
  acquire deploy_slot for t.id until ttl as slot

  after slot held {
    release slot
    complete result { note "shipped" }
  }

  after slot contended {
    fail error { reason "another deploy holds the slot" }
  }
}
```

The safety limits are structural. Each lease has a TTL limit. Each ledger has a
retention limit. Each counter has a cap and a periodic reset. Declare the
`timezone` value. If you do not, the boundary uses UTC and the checker gives a
warning. You must release a held lease on the `held` branch or get to a
terminal. If the progression ends in a different manner, the runtime releases
the lease automatically. A cancel operation is one such manner. Thus a holder
that stops cannot block the slot. A hold with `until ttl` expires without help.
The `release` verb operates on two resources. A release of an `acquire` binding
frees the lease. A release of a claimed work item returns the item to the
tracker.

By default, a resource is private to the program that declares it. Add `shared`
to the declaration block to coordinate across the workflows in the same
workspace. The scope of the coordination state is the workspace. The
coordination state continues after a run store is deleted. The coordination
state is in `.whipplescript/coordination.sqlite`, or in the path that
`WHIPPLESCRIPT_COORDINATION_STORE` gives. Examine the state from the CLI:

```bash
whip [--json] leases [<resource>]
whip [--json] ledger [<ledger>] [--partition <value>]
whip [--json] counters [<counter>]
```

Admission is real. The effects run with the `lease.acquire`, `lease.release`,
`ledger.append`, and `counter.consume` capabilities. The embedded `std.coord`
package registers these capabilities when the store initializes. Thus an
operator does no setup. But an operator profile can make these capabilities
smaller, as with any other capability. The
[language reference](language-reference.md) gives the full syntax. The
[API reference](api-reference.md) gives the CLI detail.

## Time and deadlines

Keep time out of a guard. A guard must stay pure. Write a deadline as an
effect:

- The `timeout <dur>` clause on an effect limits the permitted duration of the
  effect. An `after ... times out` branch or an `on timeout` branch reacts when
  the limit expires.
- The `timer <dur> as deadline` statement is a delay that is independent. You
  branch on the delay with `after deadline succeeds`.
- The `cancel <binding>` statement stops an effect that is pending or in
  operation. You must bind the effect before you cancel it.

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
tell worker as turn timeout 10m "Do the work."

after turn times out as t {
  tell worker "Worker exceeded 10m — escalate?"
}
```

A duration has the form `<n><unit>`. The units are `s`, `m`, `h`, and `d`. In
the native worker on your machine, a timer or a timeout fires on a worker pass.
There is no daemon. Thus the `whip run --until idle` command holds a pending
timer to be idle. The `whip status` command lists the time effects that an
instance waits for. The Durable Object runtime in the cloud is different. It
fires a timer without help, through a DO alarm. Refer to
[Runtime & operations](runtime-operations.md).

## Express retries as facts

The language has no built-in retry policy. A retry is a usual fact and a usual
rule. Thus a retry stays visible and auditable:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
rule attempt_job
  when Job as job where job.status == "pending" and job.attempts < 3
  when worker is available
=> {
  tell worker as turn "Do job {{ job.id }}"

  after turn succeeds as ok {
    done job -> record JobDone { id job.id }
  }

  after turn fails as failed {
    done job -> record Job {
      id job.id
      attempts job.attempts + 1
      status "pending"
    }
  }
}

rule give_up
  when Job as job where job.attempts >= 3
=> {
  done job -> record JobAbandoned { id job.id }
}
```

## Gate on humans

A review by a person uses the tracker. File an issue with
`file issue into <queue>`. A person then works the issue with the `whip issue`
command. The person can list, claim, comment, and finish. A rule reacts to the
finish of the issue. The rule can use a `when <queue> has ready issue as x`
clause, or the rule can match the finish. Thus the work of a person is in the
same durable record as the other work. You can examine the record. You do not
operate a separate inbox for questions.

## Run a local command (an escape hatch)

The `exec` statement has a dev form and a hosted form.

The `exec "<command>" as result` statement runs a local command as an effect.
The statement makes `result.exit_code` and `result.stdout` available. This
statement is an escape hatch for the dev profile. It has deliberate limits:

- The program must import `std.script`. The source syntax cannot grant a
  command. The operator makes an allow-list of commands through the
  `WHIPPLESCRIPT_EXEC_ALLOW` variable. The value is a list of glob prefixes
  such as `scripts/*`, with a colon between each prefix. If the import is
  absent, or if there is no allow-list, admission blocks the effect. The block
  reasons are `blocked_by_capability` and `security.script_disabled`. The
  effect then never runs. If the list is not empty and a command is not in the
  list, the effect fails and goes to the `after x fails` branch.
- A raw dev `exec` statement has no sandbox. A grant is a decision to trust,
  and the record shows the decision. Keep the allow-list as small as the
  workflow needs. If an agent, a package capability, or a child workflow is
  applicable, use it in place of `exec`.

In a hosted deployment, use a named script capability instead:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
exec backup_repo with request -> Report as backup
```

The operator supplies `--exec-profile hosted --script-manifest <path>`. The
manifest maps `backup_repo` to an argv list, a pinned SHA-256 digest, and
optional references to secrets:

```json
{
  "backup_repo": {
    "argv": ["bash", "scripts/backup.sh"],
    "sha256": "9f2c...",
    "env": { "BACKUP_TOKEN": "env:BACKUP_TOKEN" }
  }
}
```

A hosted `exec` statement rejects a raw command string. It verifies the bytes
of the script before it starts the process. It runs the argv list directly with
typed JSON on stdin. It records the hash of the script that ran.

Use `exec` for a deterministic local step that belongs in the workflow. A test
script and a linter are examples. Do not use `exec` to move orchestration into
the shell.

## Compose the source

| Need | Use |
| --- | --- |
| Divide the declarations across files | `include "schemas/common.whip"` |
| Bring in coerce classes and functions | `include "review.coerce"` |
| Import the surface of a package or a library | `use std.memory` |
| Reuse a fragment of a rule or an effect at compile time | `pattern` and `apply` |
| Put fixed steps in sequence with shared bindings | a `then` chain |
| Take work from a durable backlog | `tracker` and `claim` |
| Run work with its own lifecycle and terminal contract | `workflow` and `invoke` |

A pattern is a template at compile time. The `apply` statement expands the
pattern into usual declarations before the type check. The `invoke` statement
is composition at run time. The child is a true instance. The parent sees only
the declared output payload or the declared failure payload of the child:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
invoke ReviewPhase {
  phase PhaseReviewRequest {
    id phase.id
    title phase.title
  }
} as child

after child succeeds as result {
  record ReviewComplete { phaseId phase.id result result }
}

after child fails as failure {
  record ReviewBlocked { phaseId phase.id reason failure.reason }
}
```

## End the workflow

Declare the data that the workflow supplies. Then make sure that one rule
supplies that data:

<!-- check: skip — excerpt; the surrounding program's declarations are not shown -->
```whip
output result PhaseReviewResult
failure error ReviewPhaseFailure
```

The `complete result { ... }` statement and the `fail error { ... }` statement
are atomic with the commit of the rule. The runtime validates the payload
against the declared contract. The `whip check` command rejects a workflow that
has no path to a terminal. If a workflow runs continuously by design, add the
`@service` tag. If a rule gets its data from an external source, add the
`@external` tag. Refer to
[liveness checks](language-reference.md#liveness-checks).

Remember the division between two types of failure. A provider failure is state
of an effect or a run. A rule reacts to that state. A `fail` statement is the
workflow itself that stops. Do not mix the two types. The source must express
the policy that decides which provider failures are fatal.

## Debug a run

Use these views in sequence:

```sh
whip status <instance>        # lifecycle, counts, recent events
whip log <instance>           # the event sequence
whip facts <instance>         # current fact state
whip effects <instance>       # effect status + policy_block_reason
whip runs <instance>          # provider attempts
whip diagnostics <instance>   # recorded errors
whip evidence instance <id>   # provider payloads and artifacts
whip evidence [<gauge>]       # gauge evidence view (estimates + contradiction flags)
whip trace <instance> --check # lifecycle conformance
```

The tightest authoring loop is the command
`whip --json run <file> --provider fixture --until idle` together with
assertions. An assertion changes "the workflow appears to operate" into a
checked statement about the final state.

## Checklist before you supply a workflow to other persons

- The `whip check` command passes. The `@service` tag and the `@external` tag
  are present only where you intend them.
- The `after` blocks and not the sequence of the source set the sequence of the
  effects.
- Each routing decision uses typed data in the source: an `AgentRef` value, an
  enum, or a literal. No routing decision uses the output of a model.
- Each failure branch does a retry, an escalation, or a deliberate no-operation.
  No failure branch is silent.
- Each agent profile is as small as the work permits. Each package call is an
  explicit `call` effect. You attach a skill to an agent or to a turn. You do
  not import a skill.
- The `whip --json run --until idle` command passes its assertions with the
  fixture provider. The `whip trace --check` command reports conformance.

## Usual mistakes

| Mistake | Correction |
| --- | --- |
| You use the sequence of the source to sequence the effects. | Use `after effect succeeds`, `after effect fails`, or `after effect completes`. |
| You read the output of an effect outside its `after` branch. | Bind the output in the branch that proves the status. |
| You use `coerce` as a call to a local function. | Branch on the completion of the effect. |
| You let a model select the provider or the route. | Use `AgentRef<...>`, an enum, or a literal field. |
| You treat a provider failure as a workflow failure. | Write a rule that decides when to use `fail`. |
| You import a skill with `use`. | Attach a skill to an agent or to a turn. The `use` statement imports the surface of a package or a library. |
| You hide orchestration in a shell script around the CLI. | Write the orchestration as rules, facts, and effects. |
| You read the clock in a guard. | Use a `timeout`, a `timer`, or a recorded fact. |
| You treat a lost `claim` as an error. | Branch on the failure of the claim and wait for the next ready item. |
| You use a bare `emit <name>` statement to log an event. | The bare `emit` statement is removed. The `emit signal` and `emit milestone` statements stay. Derive a fact from the completion of an effect. |
| You grant a raw dev `exec` statement broadly. | Keep `WHIPPLESCRIPT_EXEC_ALLOW` as small as the workflow needs. For authoring that you do not trust, use a hosted script capability. |
| You put credentials in the `.whip` source. | Use a reference to the provider configuration. |
