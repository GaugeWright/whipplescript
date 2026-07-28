# Effects and durability

A rule is pure and instantaneous. A rule matches facts and commits rewrites.
Chapter 4 kept each other operation out of a rule. But a true workflow needs
those other operations. It must wait for a time to pass. It must ask an agent.
It must call a language model. It must run a command. Each of these operations
uses one mechanism: the **effect**. A rule *requests* the work. The runtime
*executes* the work durably and records the outcome. This chapter introduces
the mechanism with the most simple effect. The chapter then shows the value of
durability.

## A first effect: the `timer` statement

A timer is an effect that needs nothing outside the workflow. It needs no
credentials and no configuration. A rule requests the timer. The timer fires
when its duration is complete:

```whip
workflow Reminder

output result Done

class Done {
  note string
}

rule begin
  when started
=> {
  timer 1s as t

  after t completes {
    complete result {
      note "time passed"
    }
  }
}
```

Two parts are new. The `timer 1s as t` statement puts the effect in the queue
and binds the effect as `t`. The `after t completes { … }` block declares the
operations for the time when the effect gets an outcome. The contents of the
block run at that time. The contents do not run when the rule fires.

## Durability: the instance continues after the command

Run the program. The result shows an important behavior:

```sh
whip run reminder.whip
```

```text
run ins_0da8f3…
workflow Reminder
iterations 2
status running (idle, not terminal — run `whip status ins_0da8f3…` for
blocked effects or failures)
```

The command returned, and the instance is still in the `running` state. The
`whip run` command drives the instance until no work is ready *at that moment*.
A timer that is not yet complete is not ready. The instance is not lost.
Nothing waits in memory. The pending timer is durable state in the store. Wait
for a short time. Then drive the instance manually:

```sh
whip worker ins_0da8f3… --program reminder.whip   # execute due effects
whip step   ins_0da8f3… --program reminder.whip   # let rules react
whip status ins_0da8f3…
```

```text
instance ins_0da8f3… completed
```

This is the shape of each operation in the execution model of WhippleScript.
The shape is important. The `whip run` command is not a special interpreter.
The command is a loop of exactly these two commands. The `step` command
evaluates the rules and commits the operations that are ready. The `worker`
command executes the pending effects and records their outcomes. Between two
iterations, the process can exit and the machine can restart. The instance then
continues from its durable state. This is possible because *each* part of the
state is in the store. A workflow is not a program that runs. A workflow is a
durable record that a program advances.

## Effects have a ledger

The store records each request for an effect and each attempt to execute an
effect. Two commands for inspection join the `status`, `facts`, and `log`
commands:

```sh
whip effects ins_0da8f3…   # each requested effect and its status
whip runs    ins_0da8f3…   # each execution attempt
```

An effect moves through a small lifecycle. A rule commit requests the effect. A
worker then executes the effect. The effect then settles with an outcome. The
`effects` command shows the condition of each request. The `runs` command shows
the attempts. When an item appears to stop, use these two commands. A
subsequent chapter on error handling uses these two commands frequently.

## Sequence: `after` is the only sequencer

The body of a rule can request more than one effect. A sequence of statements
does **not** run the effects in that sequence. The statements request the
effects concurrently:

```whip
rule begin
  when started
=> {
  timer 1s as first
  timer 1s as second
}
```

The only method to put effects in sequence is to nest them. The program does
not request an effect in an `after` block until the external effect settles.

```whip
rule begin
  when started
=> {
  timer 1s as first

  after first completes {
    timer 1s as second

    after second completes {
      complete result { note "two seconds, sequentially" }
    }
  }
}
```

The same nesting controls *visibility*. The binding of an effect has a meaning
only in the `after` block that observes its outcome. There is no result of
`second` outside the `after second completes` block. Before that block runs, no
result exists.

## How to cancel an effect

A later part of the progression can cancel a pending effect. The usual shape is
a deadline that the success path retires:

```whip
workflow Watchdog

output result Done

class Done {
  note string
}

rule begin
  when started
=> {
  timer 10m as deadline
  timer 1s as quick

  after quick completes {
    cancel deadline
    complete result { note "beat the deadline" }
  }
}
```

The rule requests the two timers together. When `quick` fires, the progression
cancels `deadline`. The timer of ten minutes retires and never fires. In this
example, the terminal also retires the timer, because a complete instance runs
no more operations. The `cancel` statement is important when the workflow
continues after the point where the effect stops being necessary.

Subsequent chapters give agents and models. With an agent or a model, the
deadline pattern becomes practical. Request the work and a timer together. The
effect that settles first then selects the branch.

## The subject that this chapter did not give

An effect can fail. A command can exit with a code that is not zero. A provider
can give an error. A deadline can expire. Each example above handled only the
success path. The next chapter gives failure. That chapter also gives the other
predicates of the `after` block.

## Where next

Chapter 6 gives error handling. The chapter shows how to fail a workflow
deliberately. The chapter also shows the behavior when an effect fails.
