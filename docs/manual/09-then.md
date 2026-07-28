# `then`: how to chain a pipeline

Rules compose a progression from `after` blocks. Chapter 12 tells you to divide
a large rule into small rules that react. But some work is truly a script: do
this operation, then this operation, then complete. Nested `after` blocks hide
a straight pipeline in the indentation. The **`then`** statement writes the
pipeline from the top to the bottom. Below the surface, the statement desugars
to the same nested `after` blocks.

## A pipeline as one sequence

```whip
use std.script
use std.coercion

workflow Pipeline

output result Done
failure error Broken

class Done {
  priority string
}

class Broken {
  reason string
}

class Ticket {
  title string
}

table tickets as Ticket [
  {
    title "checkout is down"
  }
]

coerce judge(title string) -> Verdict """markdown
Classify: {{ title }}

{{ ctx.output_format }}
"""

class Verdict {
  priority "urgent" | "routine"
}

rule triage
  when Ticket as t
=> {
  then precheck <- exec "true"
  then verdict <- coerce judge(t.title)
  complete result { priority verdict.priority }
}
```

The `then <binding> <- <effect>` statement chains the **success** of the effect
into the remainder of the block. Thus the `exec` statement runs first. The
program requests the coercion only after the `exec` statement succeeds. The
program gets to the terminal only after the coercion succeeds. Each `then`
binding is the success payload of its step. The binding is in scope for each
subsequent statement. Thus `verdict.priority` reads the typed result of the
coercion two lines below the request. There is no nested `after` block.

## The desugared form of a `then` statement

A `then` statement has no new semantics. It is only a different spelling. The
rule above compiles to exactly the nested form that you can write manually:

```whip
rule triage
  when Ticket as t
=> {
  exec "true" as __then_precheck

  after __then_precheck succeeds as precheck {
    coerce judge(t.title) as __then_verdict

    after __then_verdict succeeds as verdict {
      complete result { priority verdict.priority }
    }
  }
}
```

The `whip check` command shows the desugared rule. Thus you can always examine
the sequence. The `__then_*` names are the synthetic handles of the effects.
The compiler reserves these names. If you write such a name, the result is a
check error. The compiler hides these names deliberately. The `then` binding is
the *success payload*. The binding is not the handle of the effect. If a step
needs the handle, write the step in the traditional `as` and `after` form. A
step that a `cancel` statement stops is an example.

## Failure: the net and not a branch

A `then` statement chains success **only**. If a chained step fails or times
out, the automatic failure net from chapter 6 catches the failure. The instance
fails with the generic reason that gives the name of your binding. The reason
is "unhandled failure of \`verdict\` in rule \`triage\`". This behavior is the
deliberate contract of the sugar. A `then` chain states this: the failure of
any step fails the run, and the generic reason is sufficient. This selection is
explicit. Thus the `whip check` command gives no warning about an unhandled
failure on a `then` step. The command gives such a warning for a bare effect
that only a `succeeds` predicate handles.

When the failure of a step needs a typed reason or a recovery, write that step
in the traditional form:

```whip
rule triage
  when Ticket as t
=> {
  coerce judge(t.title) as verdict

  after verdict succeeds as v {
    complete result { priority v.priority }
  }

  after verdict fails as f {
    fail error { reason f.reason }
  }
}
```

The two forms compose. A rule can chain its success path with `then`
statements. The same rule can handle one sensitive step explicitly.

## A `then` statement operates in each block

A `then` statement in an `after` block or in a `case` arm chains the remainder
of *that* block:

```whip
after upload succeeds {
  then scanned <- exec "scan incoming.bin"
  record Clean { note scanned.stdout }
}
```

## How to select between `then` and rules

| Situation | Use |
| --- | --- |
| Steps that always run in a set sequence and share bindings | a `then` chain |
| A step whose failure needs a typed reason or a recovery | `as` and `after` |
| Independent reactions to different facts | separate `rule` declarations |
| One decision with more than one outcome | a rule with a `case` statement |
| Many producers and one collector | rules that facts connect |

The boundary is clear. The `then` statement is for a *pipeline*. When the arms
diverge, when the reactions become independent, or when different facts drive
different responses, you describe rules. There is no `flow` construct. A chain
deliberately has no branch. This is the statement of identity from chapter 1:
`case` and pattern matching only.

## Where next

Chapter 10 completes Part I with time. The chapter shows how to limit an effect
with a timeout, how to use an absolute deadline, and how to run a workflow on a
schedule.
