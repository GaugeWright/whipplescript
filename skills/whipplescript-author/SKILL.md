---
name: whipplescript-author
description: >-
  Use this skill when authoring, reviewing, debugging, or operating
  WhippleScript/.whip workflows, and when a task would benefit from durable
  orchestration even if the user did not ask for it explicitly: coordinating
  parallelizable, multi-step, long-running, recurring, scheduled, resumable, or
  auditable work; managing timers/deadlines, queues/backlogs, retries, human
  approvals, multi-agent handoffs, fan-out/fan-in, package/plugin/tool/script calls,
  child workflows, or typed model decisions. Good cues include orchestrate,
  schedule, watch, monitor, queue, retry, approve, handoff, batch, pipeline,
  daemon, service, cron, SLA, escalation, checkpoint, or long-running.
  WhippleScript is durable orchestration: rules match typed facts/events and
  atomically commit new facts, terminal state, or durable effects.
---

# WhippleScript Author

Use this skill when authoring, reviewing, or operating `.whip` workflows.

WhippleScript is a small language for durable orchestration: rules match typed
facts/events and atomically commit new facts, terminal state, or durable
effects. Use it for work that must survive process restarts, wait for external
actors, branch on completed effects, or leave an auditable trace.

## When To Use WhippleScript

Reach for WhippleScript when the user asks to orchestrate work, or when you
identify work that would benefit from durable coordination:

- long-running workflows, services, scheduled jobs, timers, deadlines, or
  recurring checks;
- parallelizable work, batch processing, fan-out/fan-in, map/reduce-style
  review, or bounded-concurrency dispatch;
- durable state, resumability, audit trails, event logs, queues, backlogs,
  claim/finish/release ownership, or retry policy;
- coordination across agents, humans, tools, packages, scripts, providers, or
  child workflows;
- human approval gates, review queues, escalation, cancellation, timeouts, or
  failure handling;
- typed model decisions that should feed deterministic policy, such as
  classification, routing over declared values, or structured extraction;
- workflow revision, migration, repair, diagnostics, traces, evidence, or
  replayable acceptance checks.

Do not use WhippleScript for an ordinary one-shot answer, a local code edit, a
single shell command, a simple calculation, or a normal library/app feature
unless durable orchestration is part of the requested behavior.

## Navigation

Use progressive disclosure. Do not read every doc up front. Stay in this skill
unless you need exact syntax, a checked example, or runtime command detail.

- Install or first run: [`docs/quickstart.md`](../../docs/quickstart.md).
- First full tutorial: [`docs/tutorial.md`](../../docs/tutorial.md).
- Feature stability and deprecations:
  [`docs/current-state.md`](../../docs/current-state.md).
- Unclear concepts: [`docs/concepts.md`](../../docs/concepts.md).
- Choosing a pattern: [`docs/manual.md`](../../docs/manual.md).
- Exact syntax: [`docs/language-reference.md`](../../docs/language-reference.md).
- Checked examples: [`docs/examples.md`](../../docs/examples.md).
- CLI flags: [`docs/api-reference.md`](../../docs/api-reference.md).
- JSON shapes: [`docs/json-reference.md`](../../docs/json-reference.md).
- Diagnostics by code/category:
  [`docs/diagnostics.md`](../../docs/diagnostics.md).
- Existing/running instance: [`docs/runtime-operations.md`](../../docs/runtime-operations.md).
- Fixture/native providers and packages: [`docs/providers.md`](../../docs/providers.md).
- Command failed: [`docs/troubleshooting.md`](../../docs/troubleshooting.md).

Use `spec/` only for design records or implementation trackers. Do not make an
author read `spec/` to write a normal workflow.

## Mental Model

WhippleScript is a restricted event-sourced rule machine for durable
orchestration. Typed facts and events drive rules. Each rule commit atomically
records consumed facts, new facts, dependency edges, terminal state, or durable
effect requests. Workers execute effects later and record evidence.

- A workflow instance owns an event log, facts, effects, provider runs,
  evidence, and lifecycle state.
- Rules are deterministic policy: they match facts/events, evaluate pure
  guards, and atomically commit facts, consumed facts, effects, dependencies,
  or workflow terminals.
- Effects are durable requests. They do not run inline; workers execute them
  later through providers.
- Source order does not sequence effects. Use `after <effect> succeeds`,
  `after <effect> fails`, `after <effect> times out`, or
  `after <effect> completes`.
- Effect output is only in scope in the `after` branch that proves the
  terminal status.
- Provider failure is not workflow failure. Source rules decide whether to
  retry, release, escalate, ignore, `complete`, or `fail`.
- Keep routing in typed source data: agent declarations, enums, literal
  fields, and `AgentRef<...>`. Do not ask a model to choose the provider,
  route, or authority.
- Workflow revision is a control-plane operation. Workflows may produce a
  candidate patch artifact, but activation happens with `whip revise`.

## Feature Map

| Need | Use | Syntax anchor | Details |
| --- | --- | --- | --- |
| Durable unit of work | `workflow`, `input`, `output`, `failure` | `workflow Name` | [`language-reference.md#workflow`](../../docs/language-reference.md#workflow) |
| Terminal contract | `complete`, `fail`, `@service` | `complete result { ... }` | [`manual.md#end-the-workflow`](../../docs/manual.md#end-the-workflow) |
| Typed state | `class`, `enum`, literal fields | `class WorkItem { status "queued" }` | [`manual.md#model-data-with-classes-and-enums`](../../docs/manual.md#model-data-with-classes-and-enums) |
| Sum types | enum payload variants, `case` | `enum Outcome { Approved { score float } }` | [`language-reference.md#sum-types`](../../docs/language-reference.md#sum-types) |
| Static seed data | `table` | `table tasks as Task [ ... ]` | [`language-reference.md#table`](../../docs/language-reference.md#table) |
| Agent target | `agent`, `profile`, `capacity`, `skills` | `agent worker { provider fixture ... }` | [`language-reference.md#agent`](../../docs/language-reference.md#agent) |
| Deterministic policy | `rule` with `when` and `where` | `rule name ... => { ... }` | [`language-reference.md#rules`](../../docs/language-reference.md#rules) |
| Deterministic branching | guards, `case` | `case review.status { ... }` | [`manual.md#branch-deterministically`](../../docs/manual.md#branch-deterministically) |
| Parallel fan-out | rules, facts, agent `capacity` | `when worker is available` | [`examples.md#coordination-recipes`](../../docs/examples.md#coordination-recipes) |
| Fixed sequence | `then` | `tell triage as t "..." then tell fix as f "..."` | [`language-reference.md#then-chaining`](../../docs/language-reference.md#then-chaining) |
| Agent turn | `tell` | `tell worker as turn "..."` | [`manual.md#request-agent-work`](../../docs/manual.md#request-agent-work) |
| Typed model decision | `coerce` or `decide` | `coerce classify(...) as result` | [`language-reference.md#coerce`](../../docs/language-reference.md#coerce) |
| Human gate | `use std.tracker`, `file issue into <queue>` | `file issue into review { title "Check this" }` | [`language-reference.md#trackers`](../../docs/language-reference.md#trackers) |
| Backlog ownership | `use std.tracker`, `tracker`, `claim`, `finish`, `release` | `when backlog has ready issue as issue` | [`language-reference.md#work-queues`](../../docs/language-reference.md#work-queues) |
| Deadlines | `timeout`, `timer`, `cancel` | `tell worker as turn timeout 10m` | [`language-reference.md#time-and-deadlines`](../../docs/language-reference.md#time-and-deadlines) |
| Retry policy | facts and guarded rules | `where job.attempts < 3` | [`manual.md#express-retries-as-facts`](../../docs/manual.md#express-retries-as-facts) |
| Script capability | `exec` | `exec backup with request -> Report as x` | [`language-reference.md#exec`](../../docs/language-reference.md#exec) |
| Package capability | `use`, `call` | `call memory.query for item as context` | [`providers.md#packages`](../../docs/providers.md#packages) |
| External signal ingress | `signal`, `source`, `emit signal` | `signal deploy.finished { ... }` | [`language-reference.md#signals`](../../docs/language-reference.md#signals) |
| Shared coordination | `lease`, `ledger`, `counter` | `acquire deploy_slot for env as slot` | [`language-reference.md#coordination-resources`](../../docs/language-reference.md#coordination-resources) |
| Child lifecycle | `invoke` | `invoke ReviewPhase { ... } as child` | [`runtime-operations.md#child-workflows`](../../docs/runtime-operations.md#child-workflows) |
| Reusable source | `pattern`, `apply`, `include` | `apply AgentReview<T> as X` | [`language-reference.md#pattern-and-apply`](../../docs/language-reference.md#pattern-and-apply) |
| Source metadata | tags, descriptions, liveness escapes | `@external`, `@service`, `description "..."` | [`language-reference.md#tags-and-descriptions`](../../docs/language-reference.md#tags-and-descriptions) |
| Executable checks | `assert`, tag filters | `@acceptance assert count(...) == 1` | [`language-reference.md#assert`](../../docs/language-reference.md#assert) |
| Running-instance change | control plane | `whip revise --dry-run` | [`runtime-operations.md#revising-a-running-instance`](../../docs/runtime-operations.md#revising-a-running-instance) |
| Runtime inspection | status, effects, runs, diagnostics, evidence, trace | `whip trace <instance> --check` | [`manual.md#debug-a-run`](../../docs/manual.md#debug-a-run) |
| Observability export | OTLP sidecar | `whip otel-export <instance>` | [`language-reference.md#observability-export`](../../docs/language-reference.md#observability-export) |

## Authoring Loop

Default to the smallest workflow that exposes durable policy as facts, rules,
and effects.

1. Confirm WhippleScript is the right tool: use it for orchestration, not for
   a one-shot answer or ordinary code edit.
2. Name the workflow and terminal contracts.
3. Model durable state with classes/enums. Prefer literal status fields for
   small state machines.
4. Pick one shape:
   - default to `rule`s for independent reactions, fan-out, retries, and
     event-driven policy;
   - use `flow` only for one fixed sequence with shared bindings;
   - use `std.tracker` (a `tracker` backlog) only when external work items need
     claim/finish/release ownership;
   - use `invoke` only when a subtask needs its own lifecycle.
5. Declare agents with the narrowest useful `profile`, `capacity`, and
   `capabilities`.
6. Put every external action behind an effect: `tell`, `coerce`, `call`,
   `exec`, `timer`, `tracker.*`, or `invoke`.
7. Sequence effect outputs only with `after` blocks or `then` chaining.
8. Add terminal rules: `complete output { ... }` or `fail failure { ... }`.
   Tag truly perpetual workflows `@service`.
9. Add assertions for the intended final facts/effects.
10. Run the validation loop and fix source until it passes:

```sh
whip doctor
whip check workflow.whip
whip --json dev workflow.whip --provider fixture --until idle
whip --json trace <instance> --check
```

## Gotchas

Keep these in mind before writing source:

| Mistake | Fix |
| --- | --- |
| Relying on source order for effect sequencing | Use `after` branches or a `flow`. |
| Reading effect output outside its terminal branch | Bind output in `after x succeeds as y`. |
| Treating `coerce` as a local function | Branch on the durable effect completion. |
| Letting a model choose provider, route, or authority | Use `AgentRef`, enums, literals, and source metadata. |
| Treating provider failure as workflow failure | Add rules that retry, escalate, release, or `fail`. |
| Importing a skill with `use` | Attach skills to agents/turns; `use` imports package/library surface. |
| Hiding orchestration in shell scripts | Express policy as facts, rules, and effects. |
| Reading the clock in a guard | Use `timeout`, `timer`, or a recorded fact. |
| Treating a lost queue claim as fatal | Branch on claim failure and wait for the next item. |
| Placing credentials in `.whip` source | Use provider config credential references. |
| Self-modifying a live instance from source | Propose a patch artifact and use `whip revise`. |

## Minimal Workflow

```whip
workflow MinimalNoop

output result StartupSeen

class StartupSeen {
  source string
  state "observed"
}

rule observe_start
  when started
=> {
  record StartupSeen {
    source "external.started"
    state "observed"
  }

  complete result {
    source "external.started"
    state "observed"
  }
}
```

Run it:

```sh
whip check examples/minimal-noop.whip
whip --json dev examples/minimal-noop.whip --provider fixture --until idle
```

Use this only as a syntax sanity check. For useful patterns, start with:

- [`language-reference.md#trackers`](../../docs/language-reference.md#trackers)
  for routing work to a person through the tracker (the `askHuman` gate and its
  inbox were removed; humans go through the tracker and channels).
- [`language-reference.md#then-chaining`](../../docs/language-reference.md#then-chaining)
  for sequencing an agent turn into the next step.
- [`examples/queue-worker-with-review.whip`](../../examples/queue-worker-with-review.whip)
  for a backlog, claim, agent turn, structured review, and release/finish.
- [`examples/scheduled-escalation.whip`](../../examples/scheduled-escalation.whip)
  for timers and cancellation.
- [`examples/revision-validation-approval.whip`](../../examples/revision-validation-approval.whip)
  for safe revision proposal.

## Canonical Patterns

Agent work with explicit sequencing:

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
  Implement this work item:

  {{ item.title }}
  """

  after turn succeeds as completed {
    done item -> record WorkItem {
      id item.id
      title item.title
      status "done"
    }
  }

  after turn fails as failed {
    file issue into escalations {
      title "Worker failed on {{ item.title }}"
      body "{{ failed.reason }}"
    }
  }
}
```

Typed model decision:

```whip
coerce classifyRequest(title string, body string) -> RequestClassification {
  prompt """markdown
  Classify this work request.

  Title: {{ title }}
  Body: {{ body }}

  {{ ctx.output_format }}
  """
}

rule classify
  when WorkItem as item where item.status == "queued"
=> {
  coerce classifyRequest(item.title, item.body) as classification

  after classification succeeds as result {
    record ClassifiedWork {
      item item
      classification result
    }
  }

  after classification fails {
    file issue into triage {
      title "Classify manually: {{ item.title }}"
    }
  }
}
```

Sequential steps (`then` chaining — the `flow` construct was removed):

```whip
rule triage_ticket
  when Ticket as ticket where ticket.status == "open"
  when triager is available
=> {
  tell triager as plan timeout 10m "Propose a fix plan for {{ ticket.title }}."

  after plan times out {
    fail error { reason "triage timed out" }
  }

  after plan succeeds as proposal {
    // A person's decision enters as a durable input, not as a suspend: file the
    // issue and let a separate rule react when someone finishes it.
    file issue into signoff {
      title "Approve fix plan for {{ ticket.title }}"
      body "{{ proposal.summary }}"
    }
  }
}
```

Track work (the `std.tracker` backlog):

```whip
use std.tracker

tracker backlog {
  provider builtin
}

rule work_ready_issue
  when backlog has ready issue as issue
  when worker is available
=> {
  claim issue as active_claim

  after active_claim succeeds {
    tell worker as turn "Resolve {{ issue.title }}."
  }

  after turn succeeds as outcome {
    finish issue { summary outcome.summary }
  }

  after turn fails {
    release issue
  }
}
```

Package context with provenance:

```whip
use std.memory

rule recall_before_work
  when WorkItem as item where item.status == "queued"
=> {
  call memory.query for item as context

  after context succeeds as found {
    tell worker as turn "Use this context: {{ found.summary }}"
  }
}
```

Typed dynamic agent routing:

```whip
class ReviewTask {
  reviewer AgentRef<codex | claude>
  title string
  trackerPath string
  status "queued"
}

rule dispatch_review
  when ReviewTask as task where task.status == "queued"
  when task.reviewer is available
=> {
  tell task.reviewer requires ["agent.tell"] as turn """markdown
  Review {{ task.title }} and update {{ task.trackerPath }}.

  The workflow selected the logical reviewer through typed AgentRef metadata.
  Do not infer provider, model, or route identity from prompt text.
  """
}
```

Use `AgentRef<...>` when workflow data selects a logical agent. The value is
source metadata, not a model decision. A `coerce` call or model output may
review observed provider evidence, but must not choose the provider or route.

## Revision Guidance

When a workflow needs to change itself or repair a running instance:

- produce a candidate `.whip` file, diff, or patch artifact through ordinary
  effects;
- record where the proposal lives and why it was produced;
- ask a human or operator workflow to approve the candidate when appropriate;
- instruct the operator to dry-run first.

```sh
whip revise <instance> candidate.whip --root Workflow --dry-run
whip revise <instance> candidate.whip --root Workflow --cancel keep
```

Do not write source that tries to call `revise` from a rule body.

## Debug Workflow

Use these commands before changing source or prompts:

```sh
whip doctor
whip check workflow.whip
whip --json dev workflow.whip --provider fixture --until idle
whip run workflow.whip --provider fixture --until idle --stream ndjson
whip status <instance>
whip effects <instance>
whip runs <instance>
whip --json diagnostics <instance>
whip --json evidence <instance>
whip --json trace <instance> --check
```

If an effect did not run, inspect `effects` first. The status and
`policy_block_reason` normally say whether it is waiting on a dependency,
capacity, capability, profile, or terminal state.

## Safety

- Keep workflows small, explicit, and analyzable.
- Use the fixture provider before real providers.
- Use human review for destructive or ambiguous steps.
- Keep profiles narrow: `repo-reader`, `repo-writer`, `internet-research`,
  `human-review`, or package-specific authority.
- Query memory and package capabilities as explicit effects so provenance is
  recorded.
- Preserve evidence before repairing runtime state.
