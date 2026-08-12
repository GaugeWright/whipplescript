# Composition

To this point, the manual used one workflow in each file. A true system uses
*parts*. A parent gives a phase to a child workflow. A library holds shared
classes. One rule shape covers five different types. WhippleScript composes on
two axes. The largest part of this chapter keeps the two axes separate. The
first axis is **composition at run time**. The `invoke` statement starts a true
child instance with its own log and its own lifecycle. The second axis is
**reuse at compile time**. The `include`, `pattern`, and `action` constructs
give text and templates. The compiler expands each of these constructs fully
before any operation runs.

## Bundles, the `input` contract, and roots

Composition needs more than one workflow in scope. Thus the declaration surface
gets a form with braces:

```whip
workflow Parent {
  input task Task
  output result ParentDone
  ...
}

workflow Child {
  input task ChildTask
  ...
}
```

A workflow with braces owns its declarations. The declarations are the classes,
the rules, and the agents. Such a workflow does not share the flat namespace of
the file. A file of workflows with braces is a **bundle**. Two new items come
with a bundle.

First, an `input <name> <Class>` contract declares the typed payload that
*starts* an instance. The runtime validates the payload at the boundary. The
runtime then seeds the payload as a fact that the rules match. The behavior is
the same as a table with one row that the caller supplies.

Second, a bundle holds more than one workflow. Thus the CLI takes a root:

```sh
whip run pipeline.whip --root Parent --input '{"task":{"title":"ship the fix"}}'
```

## The `invoke` statement: durable children

The `invoke` statement starts a child instance and reacts to its outcome. The
four terminal arms are the same as the arms of each other family of effect:

<!-- check: root Parent -->
```whip
workflow Parent {
  input task Task
  output result ParentDone
  failure error ParentFailed

  class Task {
    title string
  }

  class ParentDone {
    note string
  }

  class ParentFailed {
    reason string
  }

  rule dispatch
    when Task as task
  => {
    invoke Child { task { title task.title } } as child

    after child succeeds as ok {
      complete result {
        note ok.summary
      }
    }

    after child fails as bad {
      fail error {
        reason bad.reason
      }
    }

    after child times out {
      fail error {
        reason "child workflow timed out"
      }
    }

    after child cancelled {
      fail error {
        reason "child workflow was cancelled"
      }
    }
  }
}

workflow Child {
  input task ChildTask
  output result ChildResult
  failure error ChildFailed

  class ChildTask {
    title string
  }

  class ChildResult {
    summary string
  }

  class ChildFailed {
    reason string
  }

  rule work
    when ChildTask as t
  => {
    complete result {
      summary t.title
    }
  }
}
```

The boundary is deliberately opaque, as the boundary of an agent turn is. The
parent sees the declared `output` payload or the declared `failure` payload of
the child. The parent sees nothing else. The parent cannot read a fact of the
child. The two instances share no state. A provider failure *in* the child does
not go to the parent. The `fails` arm of the parent runs only when the child
itself executes a `fail` statement.

The child is a full instance. The child has its own event log, its own ledger
of effects, its own `whip status` output, and its own workflow principal. An
invocation can carry start grants in a `with access to <resource> { … }` block.
Such a grant *makes more narrow* the items that the child can touch. This is
the same attenuation-only rule as the grants of a turn in chapter 11. The
subsequent chapters give the resources.

Note one limit of the runtime today. An invocation **drives its child toward a
terminal in the execution of the invoke effect**. A child that completes its
work settles the invocation. The child can have more than one step, and the
child can use agent turns. But a child that is designed to *park* does not
settle the invocation. Such a child waits for the answer of a person for many
days, or the child is a long recurrent service. In that condition, the
invocation times out. A peer with a long life must be an instance that starts
independently. Coordinate such a peer through signals and trackers. Chapter 15
and chapter 17 give the two mechanisms. Use the `invoke` statement for
delegated work that has an end.

## Milestones: how to observe a child during its run

A terminal is all or nothing. Sometimes the parent needs evidence of progress
*during* the run of the child. In that condition, the child projects a
**milestone**. A milestone is named, typed, and deliberately declared:

<!-- check: root Parent -->
```whip
workflow Parent {
  input task Task
  output result ParentDone

  class Task {
    title string
  }

  class ParentDone {
    note string
  }

  class SawStart {
    detail string
  }

  rule orchestrate
    when Task as task
  => {
    invoke Child { task { title task.title } } as child

    after child reaches "work_started" as m {
      record SawStart {
        detail m.detail
      }
    }

    after child succeeds as ok {
      complete result {
        note ok.summary
      }
    }

    after child fails as bad {
      complete result {
        note bad.reason
      }
    }
  }
}

workflow Child {
  input task ChildTask
  output result ChildResult

  class ChildTask {
    title string
  }

  class Progress {
    detail string
  }

  class ChildResult {
    summary string
  }

  rule work
    when ChildTask as t
  => {
    emit milestone "work_started" of Progress {
      detail t.title
    }
    complete result {
      summary t.title
    }
  }
}
```

The `emit milestone "<name>" of <Class> { … }` statement is *not* an effect.
The statement is a synchronous durable projection. The runtime commits the
projection with the rule, as it commits a `record` statement. The
`after child reaches "<name>" as m` arm of the parent observes the milestone.
The declared payload class of the child gives the type. The arm does not
replace the terminal arms. The compiler checks the invariant of the observation
statically. A `reaches` arm for a milestone that the child never declares is a
compile error. Thus a parent can observe only the states that the child
projects explicitly.

## Reuse at compile time

The second axis never makes an instance. This axis shapes the source before the
compiler lowers the source.

**The `include "<path>"` statement** puts the declarations of a library file
into the bundle. The compiler resolves the path relative to the file that
contains the `include` statement. Thus a shared class or a shared coerce
contract exists one time:

```whip
include "includes/support-lib.whip"

workflow TriageTickets

input ticket SupportTicket
...
```

**The `pattern` construct and the `apply` construct** make a template of a full
*declaration*. One rule shape then applies to each type:

```whip
pattern AgentReview<Input, Output> {
  rule review
    when Input as item
    when reviewer is available
  => {
    tell reviewer as turn """markdown
    Review {{ item.title }}.
    """

    after turn succeeds as reviewed {
      done item -> record Output {
        id item.id
        summary reviewed.summary
        status "reviewed"
      }
    }

    after turn fails as f {
      record ReviewFailure {
        reason f.reason
      }
    }
  }
}

apply AgentReview<ChangeRequest, ReviewedChange> as changeReview {
}
```

**The `action` construct** makes a template of a *chain of effects in one
rule*. This unit is smaller than a rule:

```whip
action review_change(who AgentRef<reviewer>, item ChangeRequest) {
  tell who as turn """markdown
  Review {{ item.title }}.
  """

  after turn succeeds as reviewed {
    done item -> record ReviewedChange {
      id item.id
      summary reviewed.summary
      status "reviewed"
    }
  }

  after turn fails as f {
    record ReviewFailure {
      reason f.reason
    }
  }
}

rule review
  when ChangeRequest as item
  when reviewer is available
=> {
  review_change(reviewer, item)
}
```

The three constructs expand at compile time. The result is the same explicit
lowered graph that you can write manually. The compiler makes each internal
binding unique for each call site. The compiler substitutes a parameter by its
name. The `whip check` command reports on the expanded result. These constructs
are reuse. They are not subroutines at run time. There is no call stack and no
dynamic dispatch. At run time, you can observe only the items that the
expansion lowered. When the item that you reuse needs its *own* lifecycle, use
the `invoke` statement. Such an item needs its own log, its own retries, and
its own outcome. When more than one program needs the same *shape*, an
expansion has a lower cost and stays fully open to inspection.

## Where next

Chapter 19 returns to the `exec` statement. Chapter 6 introduced the escape
hatch. Chapter 19 adds deterministic validation with the `-> Schema` clause and
the hosted execution profiles. These constructs are the bridge between a shell
command and a typed fact.
