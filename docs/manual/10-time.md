# Time

Chapter 4 gave the rule that a guard never reads a clock. Chapter 5 introduced
the `timer` statement as the first effect. This chapter completes the model.
Time enters a workflow **only as an effect**. A duration passes. An instant
occurs. A schedule fires. Time never enters as an ambient value that a rule can
branch on. This limit keeps the match operation deterministic and keeps the
replay honest.

## Durations

Write a duration in the form `<n><unit>`. The units are `s`, `m`, `h`, and `d`.
Examples are `30s`, `10m`, `24h`, and `7d`. The `timer <duration> as x`
statement from chapter 5 is the basic delay. The effect completes when its
duration is due.

## How to limit an effect: the `timeout` clause

A `timeout` clause limits each type of effect. If the effect does not settle
when the duration is complete, the effect ends with the `timed_out` status:

```whip
rule check
  when started
=> {
  exec "true" as x timeout 5s

  after x succeeds {
    complete result { note "ok" }
  }

  after x times out {
    fail error { reason "too slow" }
  }
}
```

The `after x times out` predicate is the third `after` predicate. The other two
are `succeeds` and `fails`. A timeout is its own outcome. A timeout is not a
type of failure.

The clock starts when the program *creates* the effect. Thus an effect that
waits behind a capacity gate uses its timeout while it waits. Usually this
behavior is correct. The deadline applies to the completion of the work. The
deadline does not apply to the start of the work by a worker. Include this
behavior in your calculation when you use a `timeout` clause with an
`is available` gate.

Each statement in chapter 6 applies here. A timeout with no handler causes the
same automatic failure as a failure with no handler. An `after x completes`
block with a `case` statement handles each outcome exhaustively. The outcomes
include `TimedOut`.

The watchdog in chapter 5 is the manual version of the same idea. In the
watchdog, a `timer` races against the true work, and the program cancels the
effect that loses. Use a `timeout` clause when one effect limits itself. Use
the race between timers when the deadline covers more than one step.

## Absolute deadlines: the `timer until` statement

The `timer <duration>` statement counts from the present time. The
`timer until <time>` statement fires at an instant:

```whip
class Deadline {
  at time
}

rule remind
  when Deadline as d
=> {
  timer until d.at as due

  after due completes {
    record Overdue { at d.at }
  }
}
```

The `time` type is a scalar type. A value is an ISO-8601 instant. Write the
value as a literal in quotation marks, such as `"2027-01-01T00:00:00Z"`. As an
alternative, put the value in a field with the `time` type, such as `d.at`
above. The timer fires on the first worker pass at the instant or after the
instant. If the instant is in the past, the timer completes immediately. A
deadline that occurred before the rule ran is still a deadline.

The difference in the spelling is deliberate and important. A **duration** is a
token with no quotation marks, such as `30s` or `10m`. A duration is a quantity
of time. A **time** is an ISO-8601 string in quotation marks, such as
`"2027-01-01T00:00:00Z"`. A time is a point on the calendar. The `timer 30s`
statement waits. The `timer until "2027-01-01T00:00:00Z"` statement fires at
the instant. A duration in quotation marks is a check error. An instant with no
quotation marks is also a check error. The compiler does not guess.

## There is no daemon in the background

Chapter 5 showed this behavior but did not give it a name. A timer and a
timeout fire on a **worker pass**. They do not fire from a thread of a
scheduler. The `whip run` command holds a pending timer to be idle. The command
does not block on the wall clock. The `whip status` command lists the pending
time effects. Thus an instance that stopped always shows the item that it waits
for. In production, the worker loop runs continuously and a due timer fires
without delay. The semantics are identical in each environment: a time effect
is durable, and the component that drives the instance settles the effect.

## How to run on a schedule: a clock source

Each construct above waits *in* an instance that runs. A **clock source** does
the opposite. A clock source starts work on a recurrent schedule. Use a clock
source for a workflow on a calendar. A daily digest, a weekly report, and an
hourly poll are examples.

```whip
use std.ingress

@service
workflow Daily

class Digest {
  note string
}

signal daily.tick {
  scheduled_at time
  occurrence_id string
}

source clock as morning {
  every weekday at 09:00
  timezone "America/New_York"
  missed coalesce

  observe as tick
  emit daily.tick from tick
}

rule digest
  when daily.tick as tick
=> {
  record Digest { note tick.occurrence_id }
}
```

Three declarations occur here for the first time:

- The `@service` tag marks a workflow that runs continuously by design. Chapter
  1 gave the rule that each workflow must be able to complete. The `@service`
  tag is the one exception. A service has no terminal. Its function is to
  continue to react.
- The `signal <dotted.name> { fields }` declaration declares a typed fact.
  *An external source admits* this fact. A rule does not record this fact. A
  rule matches the fact by its dotted name, as in `when daily.tick as tick`.
  Chapter 12 gives the general form of readiness. A signal is the entry point
  for each external item. Part III gives signals in detail.
- The `source clock as <name>` declaration is the schedule. The
  `every weekday at 09:00` clause is the recurrence. Use `every <dur>` for an
  interval. Use `at <hh:mm>` for one scheduled occurrence. Use
  `every <day|weekday> at <hh:mm>` for a calendar schedule. The `observe`
  clause and the `emit` clause map each firing into the declared signal. The
  `emit daily.tick from tick` clause copies the fields of the observation with
  the same names into the signal. This is the same `from` projection that the
  `record` statement uses. An explicit `{ … }` block can override a field or
  add a field.

Two clauses are necessary. They are not options. They make the schedule honest.

First, a calendar schedule must declare its `timezone` value. The runtime
evaluates a schedule with knowledge of the timezone and with correct behavior
for daylight saving time. If you omit the `timezone` value, the `whip check`
command gives an error. A schedule with a day boundary that silently moved to
UTC is incorrect for some person.

Second, a recurrent source must declare a `missed` policy. This policy gives
the behavior when the runtime was not in operation at a scheduled instant. The
`skip` policy ignores the occurrence. The `coalesce` policy makes the missed
window one tick with a `missed_count` value. The `catch_up limit <N>` policy
fires each missed occurrence, up to a limit. There is no silent default,
because each answer is incorrect for some person.

The runtime admits each occurrence a maximum of one time. The key is the
scheduled instant. Thus a replay or a recovery after a crash never admits a
tick two times.

## Where next

Part I is complete. It gave workflows, facts, expressions, rules, effects,
errors, branches, calls to a model, `then` chains, and time. This is the full
deterministic core and the typed decisions of a model. Part II adds the other
type of model worker: the agent. Part II starts at chapter 11.
