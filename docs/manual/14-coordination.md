# Coordination

Each operation to this point occurred in one instance. The instance has its
facts, its effects, and its rules. But instances share a world: one deploy
pipeline, one budget for an API, one audit trail. Part III starts with the
machinery for that shared world. The answer of WhippleScript is deliberately
narrow. There is a closed family of three **coordination resources**: the
`lease`, the `counter`, and the `ledger`. You declare each resource in the
source with mandatory limits. Each resource is durable state of the workspace,
*outside* each instance. You touch each resource only through an atomic effect.
The outcome of each effect is a branch. There is no lock in the source and no
primitive that blocks. Contention is an outcome that a rule handles. This is
the same behavior as the failure of an effect in chapter 6.

## Leases: mutual exclusion with a limit

A lease guards a resource. A maximum of N holders can use the resource at the
same time:

```whip
use std.coord

workflow Ship

output result Done

class Deploy {
  service string
  env string
}

class Done {
  note string
}

lease deploy_slot {
  key Deploy
  slots 1
  ttl 10m
}

table deploys as Deploy [
  {
    service "api"
    env "prod"
  }
]

rule ship
  when Deploy as d
=> {
  acquire deploy_slot for d.env as slot

  after slot held {
    timer 5s as deploying

    after deploying completes {
      release slot
      done d
      complete result {
        note "deployed"
      }
    }
  }

  after slot contended {
    done d
    complete result {
      note "skipped: deploy slot busy"
    }
  }
}
```

The declaration carries mandatory limits. The `key` clause gives a type. A
lease applies to each key. Here there is one pool of slots for each `env`
value. The `slots` clause gives a count. The `ttl` clause gives a backstop. The
`acquire … for d.env as slot` statement is an atomic attempt. The attempt is an
effect with two outcomes: `held` and `contended`. The held branch holds the
slot *during* the work that the slot protects. Here the work is a timer that
replaces true work. The branch releases the slot at the end of the work.

Run the program two times quickly. The two instances show the behavior:

```sh
whip run deploys.whip     # instance A: acquires, holding through its work
whip leases
```

```text
local/Ship::deploy_slot/prod held by ins_efa1a8… (expires 2026-07-21 19:46:34)
```

```sh
whip run deploys.whip     # instance B, while A still holds
```

```text
status completed          # B: "skipped: deploy slot busy"
```

The acquire operation of instance B returned `contended`. The branch of
instance B ran, and instance B completed. There is no block, no error, and no
retry loop. When the work of instance A completes and instance A releases the
slot, the `whip leases` command reports `no leases held`.

Three semantics are important:

- **The instance is the holder.** The exclusion is *between instances*. If the
  same instance acquires the same key again from a different rule, the instance
  is already the holder and gets `held`. This is re-entry. This is not a
  deadlock.
- **The TTL is the net for a crash. The TTL is not the lifetime.** The lifetime
  of the holder limits each lease. Each of these events frees the held slots of
  an instance automatically: a release, a terminal, and a cancel operation by
  an operator. The `ttl` value exists for a machine that stops during a hold.
  After the TTL expires, the slot becomes free, even when no component released
  the slot.
- **By default, the scope of a lease is its workflow.** The instances of `Ship`
  contend with each other. A different workflow that declares `deploy_slot`
  gets its own partition. A bare `shared` field in the declaration puts the
  resource in one pool across workflows. The field also makes the resource a
  governed channel for communication. Under a governance envelope, a read or a
  write of a shared coordination resource is a governed flow, as each other
  flow is. The information-flow section of the language reference gives the
  rules for a shared resource.

### The compiler holds the discipline

The compiler checks the safety rules for a lease. The rules are not advice.
Ignore the contended outcome, and the `whip check` command refuses the program:

<!-- render: examples/diagnostics/lease-outcomes.whip code effect.unhandled_outcome -->
```text
error[effect.unhandled_outcome]: rule `ship` does not handle the `contended` outcome of lease `slot`
   --> examples/diagnostics/lease-outcomes.whip:38:3
   |
38 |   acquire deploy_slot for d.env as slot
   |   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   = help: coordination outcomes are exhaustive: add `after slot contended { ... }`
```

Hold a lease, and do not release the lease or get to a terminal on some branch.
The command then gives this error:

<!-- render: examples/diagnostics/lease-outcomes.whip code graph.unreleased_lease -->
```text
error[graph.unreleased_lease]: rule `ship` can hold lease `slot` forever: the `held` branch neither releases it nor reaches a workflow terminal
   --> examples/diagnostics/lease-outcomes.whip:38:3
   |
38 |   acquire deploy_slot for d.env as slot
   |   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   = help: add `release slot` on every non-terminal path, or use `acquire ... until ttl` for fire-and-forget
```

A progression can hold a maximum of one lease at a time. The compiler rejects a
nested acquire operation. Thus the construction removes the usual deadlock of
two locks.

### How to wait instead of to skip

Sometimes the correct response to contention is a wait and not a stop. The
`wait <duration>` clause changes the atomic attempt into an attempt with a
limit:

<!-- check: skip — one statement of a rule that binds `d` above it -->
```whip
acquire deploy_slot for d.env wait 30s as slot
```

While the slot is busy, the acquire operation tries again on each worker pass.
The `held` outcome fires when a slot becomes free. The `contended` outcome
fires only when the wait period ends first. With this one clause, the second
deploy above no longer skips. The two deploys become sequential: instance B
waits, instance A releases, and instance B holds the slot and ships. For work
with a long duration, you can extend a held lease and keep the hold. The
`renew slot until 300s as renewed` statement moves the TTL later while the
holder still holds the lease.

## Counters: a budget with a reset

A counter caps the consumption of a quantity for each key and for each period:

```whip
use std.coord

workflow Budget

output result Done

class Job {
  id string
  team string
  cost int
}

class Ran {
  id string
}

class Deferred {
  id string
}

class Done {
  note string
}

counter tokens {
  key Job
  cap 100
  reset daily
  timezone "America/New_York"
}

table jobs as Job [
  {
    id "j1"
    team "core"
    cost 60
  }
  {
    id "j2"
    team "core"
    cost 60
  }
]

rule admit
  when Job as j
=> {
  consume tokens for j.team amount j.cost as spend

  after spend ok {
    done j -> record Ran {
      id j.id
    }
  }

  after spend over {
    done j -> record Deferred {
      id j.id
    }
  }
}

rule finish
  when Ran as r where empty(Job)
=> {
  complete result {
    note "budget applied"
  }
}

rule all_deferred
  when Deferred as d where empty(Job) && empty(Ran)
=> {
  complete result {
    note "nothing fit today's budget"
  }
}
```

The `consume … for j.team amount j.cost` statement atomically checks the
remaining budget of the key and spends from the budget. The first job fits and
gets the `ok` outcome. The second job would take the `core` team to 120 of 100.
Thus the second job settles as `over` and the workflow defers the job. This
outcome is a branch and not a failure. The view of the workspace confirms that
only the admitted spend counts:

```text
$ whip counters
local/Budget::tokens/core consumed=60 period=2026-07-21
```

The three fields are mandatory, as the limits of a lease are. Each counter has
a cap, and each cap resets. The reset value is `hourly`, `daily`, `weekly`, or
`monthly`. The runtime evaluates the reset at the boundary of the consume
operation and not before. Each outcome records the period that the runtime
used. Thus a replay reads the same boundary. The timezone is necessary, as the
schedules in chapter 10 need a timezone. The timezone is not an option:

<!-- render: examples/diagnostics/counter-missing-timezone.whip code construct.missing_timezone -->
```text
warning[construct.missing_timezone]: counter `tokens` declares no `timezone`; its `daily` reset boundary anchors to UTC
   --> examples/diagnostics/counter-missing-timezone.whip:31:1
   |
31 | counter tokens {
   | ^^^^^^^^^^^^^^^^
   = help: declare `timezone "<IANA zone>"` (e.g. `timezone "America/New_York"`) to anchor the period locally
```

A daily budget that resets at midnight in a *different location* is incorrect
for some person. Give the midnight that you intend.

Run the program a second time on the same day. The workflow defers the two
jobs and reports `nothing fit today's budget`. This result shows the purpose of
a counter. The counter is state of the *workspace* and not of the run. The
counter is adjacent to your instances, in the `.whipplescript/` directory of
the workspace. Thus each instance and each run draws from the same daily
quantity of 100 until the period changes. This behavior is also the reason for
the `all_deferred` rule in the example. A workflow that completes only after
success stays in the running state for an unlimited time on the day when the
budget is empty.

## Ledgers: the shared record that permits append only

The third resource keeps a durable record in sequence across instances:

```whip
use std.coord

workflow Decisions

output result Done

class Decision {
  area string
  choice string
}

class Done {
  note string
}

ledger decisions {
  entry Decision
  partition by area
  retain 90d
}

rule decide
  when started
=> {
  append Decision {
    area "deploys"
    choice "ship api first"
  } to decisions as entry

  after entry completes {
    complete result {
      note "decision recorded"
    }
  }
}
```

An `append` operation is in sequence and is never lost. The entries have a
total sequence in each partition. The declared `partition by` field gives the
partition. The ledger keeps the entries for the declared period. Each entry
carries the identity of the instance that appended the entry:

```text
$ whip ledger decisions
local/Decisions::decisions#1 [deploys] by ins_cef0b1…: {"area":"deploys","choice":"ship api first"}
```

Note the operation that is *absent*. A rule does not read a ledger. A ledger is
the record of the events. An operator examines the ledger. A tool exports the
ledger. An auditor audits the ledger. A ledger is not a substrate for a match
operation. A fact is for a match operation. A workflow that must react to its
own history records facts. The read side stays out of the rules. Thus a ledger
can be shared and cannot become a hidden channel for coordination.

## How to select from the three resources

Each of the three resources is a declared limit on shared durable state. Thus
you select by the question that the workflow asks. For **can I continue
alone?** use a lease. For **can I spend this quantity?** use a counter. For
**record this event** use a ledger. No resource here gives the distribution of
work. A queue of items that agents claim, work, and finish is a different
subject. In WhippleScript, a queue is deliberately not a lease pattern. A queue
has its own construct, and the next chapter gives that construct.

## Where next

Chapter 15 gives trackers. A tracker holds durable work items. The chapter
gives the `file issue`, `claim`, and `finish` verbs. The chapter also gives the
readiness sugar that lets a workflow or a group of agents empty a backlog
safely.
