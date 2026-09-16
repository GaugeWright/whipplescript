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

The same typed binding is available inside a typed action when the observed
operation is a direct effect. `after attempt times out as elapsed` binds a
`TerminalTimedOut`; `after attempt cancelled as stopped` binds a
`TerminalCancelled`. These values keep the original operation identity and are
rebuilt from its recorded terminal during replay. They are lexical diagnostic
values: returning from the selected handler can recover the action, while
merely reading or recording one does not.

A failed child action may contain several leaf failures and a domain failure.
Its alias is therefore an aggregate rather than one provider payload. The
`failure.causes` array retains every cause in stable origin order, and
`failure.domain` contains the child's optional declared domain failure. The
child section below gives the complete shape.

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

Inside a typed action, observe the operation's terminal union and match it
directly:

<!-- check: fragment -->
```whip
action awaitPause() -> string {
  timer 1s as pause

  case outcome(pause) {
    Completed as value => { return "done" }
    Failed as problem => { return problem.reason }
    TimedOut as problem => { return problem.summary }
    Cancelled as problem => { return problem.summary }
  }
}
```

The four tags form a closed set. Omitting one without a fallback is a local
compile error. Each branch binding has its precise payload type: `Completed`
carries the effect's success value, and the other three carry the same typed
payloads as their individual `after` predicates. The envelope and its payload
keep the original operation's provenance when reconstructed during replay.
Pending work selects no arm, and reading `outcome(pause)` alone does not recover
a failure. A successful return from the selected non-success arm performs the
recovery after that arm's work joins.

The longer `after pause completes as outcome { case outcome { ... } }` form has
the same terminal types and runtime behavior. Use it when the lexical
continuation itself is useful; use `case outcome(pause)` when the extra nesting
adds no meaning.

A child action has a smaller terminal boundary. It either completes with its
declared result or fails with an aggregate:

<!-- check: fragment -->
```whip
class Problem { reason string }

action child() -> string ! Problem {
  fail { reason "unavailable" }
}

action parent() -> string {
  child() as result

  case outcome(result) {
    Completed as value => { return value }
    Failed as failure => {
      case failure.domain {
        Problem as problem => { return problem.reason }
        None => { return failure.summary }
      }
    }
  }
}
```

`failure.causes` retains every cause in stable origin order. Each entry has
`origin`, `kind`, `summary`, `recovered`, and `evidence`. A leaf timeout or
cancellation appears as its cause kind; it is not a `TimedOut` or `Cancelled`
terminal for the child itself. When the child declares a domain failure type,
`failure.domain` is an optional value of exactly that type. Use `after result
fails as failure` when only the failed continuation is relevant; it binds the
same aggregate.

## One handler for an action scope

Use `on failure` when the same recovery applies to any operation in a larger
lexical block. This keeps the successful path direct and avoids repeating a
failure continuation for every step:

<!-- check: fragment -->
```whip
action resilientPause() -> string {
  timer 1s as pause

  after pause succeeds { return "done" }

  on failure as problem {
    return problem.summary
  }
}
```

An action has at most one lexical failure handler. The handler covers
unrecovered operation failures and an explicit typed `fail` selected in its
enclosing block. A more local `after ... fails` or `case outcome(...)` recovery
runs first; the broader handler stays dormant when that recovery succeeds.

The runtime waits for already admitted sibling work before it enters the
handler, so the aggregate cannot depend on which failure arrived first. The
binding has the same `summary`, `operation_id`, `domain`, and `causes` fields as
a child failure. A successful `return` from the handler recovers its causes only
after work started inside the handler settles. A `fail` or failed operation in
the handler propagates outward and does not re-enter the same handler. Merely
reading, recording, or forwarding `problem` does not recover it.

The same spelling gives a rule one recovery boundary for a firing:

```whip
use std.script

workflow Guarded
output result Done
class Done { note string }

rule run when started => {
  exec "false" as attempt

  after attempt succeeds {
    complete result { note "command passed" }
  }

  on failure as problem {
    complete result { note problem.summary }
  }
}
```

The runtime resolves a more local `after` or `case outcome(...)` recovery before
the rule handler. It also waits for admitted sibling work. A rule handler has no
result to return: when its selected body and the work it starts close
successfully, it recovers that firing. Its `domain` field is always `null`.
A failure inside the handler escapes once and cannot select the same handler
again.

## Automatic failure when no branch handles the failure

Delete the `after attempt fails` branch from the `Fragile` program. First, the
`whip check` command tells you the result of your change:

<!-- render: examples/diagnostics/unhandled-failure-warning.whip code effect.unhandled_failure -->
```text
warning[effect.unhandled_failure]: effect `attempt`'s failure is unhandled in rule `begin`; if it fails or times out, the instance will auto-fail with a generic reason
   --> examples/diagnostics/unhandled-failure-warning.whip:28:3
   |
28 |   exec "false" as attempt
   |   ^^^^^^^^^^^^^^^^^^^^^^^
   = help: handle it with `after attempt fails { … }` (typed failure or recovery), observe every outcome with `after attempt completes`, or add one `on failure as problem { … }` handler to the rule
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
  cancellation does not enter the outer failure net.
- **A service records the failure instead.** An `@service` workflow runs
  continuously by design. Chapter 10 gives services. Thus a service cannot fail
  automatically. The runtime records each failure without a handler one time as
  a durable diagnostic. The `whip diagnostics` command shows the diagnostic.
  The service continues to run. A rule-level `on failure` that recovers the
  firing prevents this diagnostic.

The automatic failure makes an unhandled failure *safe*. The workflow still
ends honestly at a terminal. But a generic reason is a poor message at 2 a.m.
Thus the warning at check time is prominent and not hidden. Handle each failure
that needs a typed reason or a recovery. Use `after x fails` for the failure
branch. As an alternative, use `completes` to observe each outcome in one
location.

An effect inside an `action` follows the same rule across the composition
boundary. You may handle its binding inside the action, let the failure
propagate and handle `fails` on the enclosing action call, or put one
`on failure` handler on the rule for any remaining failure in that firing.
`whip check` follows the checked action scopes when it decides whether a failure
is unhandled. When the same action is called more than once, one warning points
back to all unhandled call sites instead of repeating the definition
diagnostic.

## Where next

Chapter 7 gives the `case` statement. The statement branches on a closed set.
The statement also handles each outcome of an effect exhaustively.
