# Error handling

Chapter 1 told you that a workflow ends with the `complete` statement. Chapter
1 also told you that the `complete` statement has an equivalent for failure.
This chapter gives the failure half of the language. It shows how to end a
workflow deliberately without success, how to react when an effect fails, and
the behavior when no part of the program reacts.

## How to fail deliberately

A workflow declares the data that a run without success supplies. The
declaration is adjacent to the output declaration:

```whip
workflow Intake

output result Accepted
failure error Rejected

class Accepted {
  title string
}

class Rejected {
  reason string
}

class Submission {
  title string
  body string
}

table submissions as Submission [
  {
    title "please review"
    body ""
  }
]

rule accept
  when Submission as s where s.body != ""
=> {
  complete result { title s.title }
}

rule reject
  when Submission as s where s.body == ""
=> {
  fail error { reason "empty submission body" }
}
```

The `failure error Rejected` line is the contract. The `fail error { … }`
statement is the terminal that satisfies the contract. Each statement in
chapter 4 about a terminal applies here. The runtime validates the payload
against its class. The terminal commits atomically with the other operations of
the firing. The terminal absorbs the instance. An instance that failed runs no
more operations. Run the program above. The `status` command reports the
failure and its payload:

```text
instance ins_3eb320… failed
workflow terminal: failed error
```

A failure is not an exception mechanism. A failure is a first-class result. The
rule that decides that a run cannot succeed states this with a typed reason.
The observer of the instance then gets structure and not a stack trace. The
observer can be an operator, a parent workflow, or a tool from a subsequent
chapter. Write a failure payload in the form that you want to read at 2 a.m.:
the intended operation, and the reason that the operation could not continue.

## An effect that can fail

A timer rarely fails. Thus this chapter uses the most simple effect that can
fail. The effect is `exec`. The `exec` statement runs a command on the machine.
Two setup items make the statement available. The two items are deliberate
safety gates:

<!-- check: fragment -->
```whip
use std.script
```

The `use` line imports a standard package. This is the first package that this
manual needs. A package holds capabilities that not each workflow must have.
The capability to run commands is such a capability. Thus the source must ask
for the capability. The `use` statement occurs again with agents and models in
subsequent chapters. Packages have their own chapter.

The operator controls the second gate. The source does not control it. Whip
refuses to run a command that is not on the allowlist in the
`WHIPPLESCRIPT_EXEC_ALLOW` environment variable. The source *declares* the
command that it wants to run. The person who runs the workflow *grants* the
command. A program cannot grant the machine to itself.

```whip
use std.script

workflow Fragile

output result Done
failure error Broken

class Done {
  note string
}

class Broken {
  reason string
}

rule begin
  when started
=> {
  exec "false" as attempt

  after attempt succeeds {
    complete result { note "command passed" }
  }

  after attempt fails as f {
    fail error { reason f.reason }
  }
}
```

```sh
WHIPPLESCRIPT_EXEC_ALLOW="false" whip run fragile.whip
```

```text
status failed
```

The `false` shell command always exits with a code that is not zero. Thus the
effect fails, the `after attempt fails` branch fires, and the workflow fails
with a typed reason. Change `"false"` to `"true"` and permit the new command.
The other branch then runs.

## The content of a failure binding

The `after attempt fails as f` clause binds the failure. The binding `f` has
the same shape for *each* kind of effect:

| Field | Meaning |
| --- | --- |
| `f.reason` | The text of the failure. Here it is `exec command exited with status 1`. |
| `f.summary` | A short summary. Frequently the summary is the same as the reason. |
| `f.effect_id`, `f.run_id` | The identifiers that find the failed attempt in the ledger. |
| `f.kind` | The kind of the effect that failed, such as `"exec.command"`. |

This uniformity is deliberate. A failure branch that uses `f.reason` operates
for each type of failure. Each kind of effect also adds its own typed detail on
the base. Here the `attempt` binding is an `exec` effect. Thus `f.exit_code` is
also legal and carries the exit status of the command. The failure binding of a
coercion adds `f.error_class` instead. The binding also adds `f.http_status`
when a provider returned an HTTP error. The failure binding of an agent turn
adds `f.error_class`. The compiler knows the effect of each binding. Thus a
read of a field that does not belong to that kind is a check error. A read of
raw detail such as `stderr` is also a check error. The language deliberately
does not make `stderr` available.

## The three outcomes of a wait

With failure in the model, an `after` block has three predicates:

- `after x succeeds` — success only.
- `after x fails as f` — failure only.
- `after x completes` — *each* settled outcome. The outcomes are success,
  failure, timeout, and cancellation. This predicate also observes a
  cancellation that an arm of a different rule caused.

Use the `succeeds` predicate and the `fails` predicate for the branches that
you handle differently. Use the `completes` predicate for a reaction that
applies to each outcome. With the `case` statement from the next chapter, the
`completes` predicate also handles each outcome exhaustively in one location.

## Automatic failure when no branch handles the failure

Delete the `after attempt fails` branch from the `Fragile` program. First, the
`whip check` command tells you the result of your change:

```text
warning: effect `attempt`'s failure is unhandled in rule `begin`; if it
fails or times out, the instance will auto-fail with a generic reason
```

Run the program:

```text
status failed
```

```sh
whip status ins_50d2c0…
```

```text
instance ins_50d2c0… failed
facts=1 queued_effects=0 blocked_effects=0 active_runs=0 failures=1 …
```

The instance failed **automatically**. The effect got to a terminal failure. No
`after` block on `attempt` could react to the failure, because `succeeds` was
the only observer. A rule that can never continue leaves the instance in the
running state and idle for an unlimited time. Whip refuses this state. The
instance fails with a generic reason. The reason is "unhandled failure of
\`attempt\` in rule \`begin\`". The instance has no typed payload, because you
declared none.

The net has two deliberate limits:

- **A cancellation is an exception.** A cancelled effect never causes an
  automatic failure. A rule cancels an effect *deliberately*. The watchdog in
  chapter 5 cancels the slower effect as its usual operation. Thus a
  cancellation is not an outcome without a handler.
- **A service records the failure instead.** An `@service` workflow runs
  continuously by design. Chapter 10 gives services. Thus a service cannot fail
  automatically. The runtime records each failure without a handler one time as
  a durable diagnostic. The `whip diagnostics` command shows the diagnostic.
  The service continues to run.

The automatic failure makes an unhandled failure *safe*. The workflow still
ends honestly at a terminal. But a generic reason is a poor message at 2 a.m.
Thus the warning at check time is prominent and not hidden. Handle each failure
that needs a typed reason or a recovery. Use `after x fails` for the failure
branch. As an alternative, use `completes` to observe each outcome in one
location.

## Where next

Chapter 7 gives the `case` statement. The statement branches on a closed set.
The statement also handles each outcome of an effect exhaustively.
