# Rules

A rule is the method that a workflow uses to act. A rule waits for facts. It
can also filter the facts. It then commits changes. The changes are new facts,
consumed facts, or the end of the workflow. Chapter 1 used one rule as an idiom
to copy. This chapter gives the true operation of a rule, one part at a time.

## How to match a fact

The rule in chapter 1 reacted to `started`. A rule can react to a fact instead.
The rule gives the class of the fact:

```whip
class Ticket {
  title string
  impact "high" | "low"
  status "queued" | "routed"
}

rule notice
  when Ticket as t
=> {
  record Seen {
    title t.title
  }
}
```

The `when Ticket as t` clause matches one `Ticket` fact and binds the fact as
`t`. Thus the body can read the fields of the fact. The rule fires one time for
**each** matched fact. If a table seeds three tickets, the `notice` rule fires
three times and records three `Seen` facts. A rule is not a procedure that runs
one time. A rule is a permanent reaction. It applies to each fact that matches
it.

A rule matches only the facts that the instance holds now. If the program
records a fact later in the run, the rule matches the fact at that time. The
rule does not need to exist before the fact.

## How to filter with `where`

A `where` clause makes the match more narrow. The clause uses the expression
language from chapter 3 on the bound fact:

```whip
rule escalate
  when Ticket as t where t.impact == "high" and t.status == "queued"
=> {
  record Escalation {
    title t.title
  }
}
```

A guard is a pure condition. A guard reads the bound facts and no other data. A
guard deliberately cannot call a model, read a file, or read a clock. Thus the
*match* operation of a workflow stays deterministic and you can replay it. Work
that needs the external world is a request from the body of a rule. Such a
request is an effect. Chapter 5 gives effects. The recorded outcome of an
effect then matches in the same manner as any other fact.

Sometimes a guard cannot evaluate. A type mismatch that the checker did not
find is one cause. A comparison with no meaning at run time is a different
cause. In this condition, the rule does not fire. A guard fails closed.

## How to rewrite facts

To this point, a rule only adds facts. The `done` operation consumes a fact.
The operation retires the matched fact. No rule matches that fact again. A
consume operation and a record operation together change the state of a fact:

```whip
rule route
  when Ticket as t where t.status == "queued"
=> {
  done t -> record Ticket from t {
    status "routed"
  }
}
```

Two items are new here. The `done t -> record …` statement consumes the matched
ticket and records the replacement ticket as one operation. The
`record Ticket from t { … }` statement copies the fields of `t` into the new
fact. The statement then overrides only the fields in the list. Thus the
replacement keeps its `title` value and its `impact` value. The `status` value
becomes `"routed"`.

This consume-and-replace step is the primary change of state in WhippleScript.
The step answers a question from the first example: what prevents the `route`
rule from firing on the same ticket continuously? Without this step, nothing
prevents it. A matched fact that no rule consumes continues to match while its
guard passes. The `done` operation is one answer. The queued ticket no longer
exists. Thus the rule is complete with that ticket. The guard is the second
half of the answer. The `status` value of the replacement is `"routed"`. Thus
the replacement does not match `status == "queued"`. Consume a fact when you
are complete with it. As an alternative, change a state field that your guard
selects on. The largest part of the rules do the two operations together, as
the `route` rule does.

The `from` keyword also operates across classes. The statement
`record Audit from t { … }` copies the fields that `t` and `Audit` have
together. The statement discards the other fields. The result is a projection
onto the target class. The `done` statement also operates alone. The statement
`done t` with no arrow retires a fact that needs no replacement.

A consumed fact is absent from the match operation. The fact is not absent from
the history. The `whip facts` command shows the facts that the instance holds
now. The `whip log` command shows each fact that existed and the rule commits
that consumed the facts.

## How to match more than one fact together

A rule can state more than one `when` clause. Each clause must be true at the
same time. If not, the rule does not fire:

```whip
class Responder {
  name string
  free bool
}

class Assignment {
  ticket string
  owner string
}

rule pair
  when Ticket as t where t.status == "queued"
  when Responder as r where r.free == true
=> {
  record Assignment {
    ticket t.title
    owner r.name
  }
}
```

More than one clause makes a join. The behavior for each fact also applies
here. The rule fires one time for each **combination** of facts that satisfies
each clause and each guard. Two queued tickets and two free responders give
four combinations. The result is four `Assignment` facts. Sometimes this
behavior is your intent: you want each ticket with each responder. A join
states that intent in one rule. Sometimes this behavior is not your intent. In
that condition, use the tools that this chapter gave you. Consume a fact so
that the fact leaves the pool. As an alternative, guard on a state field that
the body changes. The `pair` rule above records assignments but consumes
nothing. Add `done t -> record Ticket from t { status "routed" }` to the body.
Each ticket then pairs exactly one time.

## The commit

Each operation of one firing lands as one atomic commit. The commit contains
the consumed facts, the recorded facts, and the terminal. The commit contains
the terminal only when the body ends the workflow. If one part is invalid,
nothing lands. A payload that does not agree with its class is one such
condition. A terminal payload that does not agree with the workflow contract is
a different such condition. There is no rule that applies in part. The
`done … -> record …` change is indivisible. No other rule can see the moment
between the old fact and its replacement.

A terminal absorbs the instance. When a commit gets to `complete`, the instance
is complete. The `fail` statement is the equivalent for error handling. Chapter
6 gives the `fail` statement. After a terminal, nothing fires. This is true
even when other rules still have matched facts.

The material of this chapter follows as one complete program. The program is a
triage pipeline. It routes each queued ticket. It completes when the queue is
empty:

```whip
workflow Triage

output result Report

class Report {
  routed int
}

class Ticket {
  title string
  impact "high" | "low"
  status "queued" | "routed"
}

table tickets as Ticket [
  {
    title "checkout is down"
    impact "high"
    status "queued"
  }
  {
    title "typo on the pricing page"
    impact "low"
    status "queued"
  }
]

rule route
  when Ticket as t where t.status == "queued"
=> {
  done t -> record Ticket from t {
    status "routed"
  }
}

rule finish
  when Ticket as t where t.status == "routed" and empty(Ticket where status == "queued")
=> {
  complete result {
    routed count(Ticket where status == "routed")
  }
}

assert count(Ticket where status == "routed") == 2
```

The `route` rule fires one time for each queued ticket. The `finish` rule uses
a query in its guard. Thus the rule can fire only when no queued ticket stays.
Run the program with the `whip run` command. The instance completes. The
assertion records that the workflow routed the two tickets.

For a statement that a query drives, use a guard or an `assert` declaration. A
query in a *payload* position is not reliable now. This is a known gap, and a
repair is in progress.

## Usual problems

- A rule fires one time for each matched fact. When a rule has more than one
  `when` clause, the rule fires one time for each matched *combination*. If a
  rule must handle each fact one time, consume the fact or change a state field
  that a guard tests.
- The content identifies a fact. Chapter 2 gives this rule. If a replacement
  fact becomes identical to a fact that is present, the two facts are the same
  fact.
- The `done` statement controls **admission only**. After a firing commits, its
  `after` continuations run to completion on the bindings that the firing
  pinned. If an adjacent rule consumes the trigger during this time, the
  continuations do not cancel. If a continuation must react to the removal of
  the trigger, put a live query in the guard of the `after` arm. As an
  alternative, use an `until` region. Chapter 16 gives `until` regions. The
  "Handling cross-rule retraction" section of the language reference gives the
  two remedies.
- Sometimes a rule consumes its trigger and also joins the trigger against a
  `when` clause that has more than one value. In this condition, the sequence
  of arrival selects the combination that wins. This choice is not
  deterministic. If the pairing is important, make the pairing explicit state.
  Do not let the join race.
- A guard reads the bound facts and no other data. If a guard cannot evaluate,
  the rule does not fire.
- After a terminal, nothing fires. If two rules can each end the run, the rule
  that commits first wins.
- The name of a binding cannot be an operation keyword. The keywords include
  `done`, `record`, `complete`, and `fail`.

## Where next

Chapter 5 introduces effects. An effect is the method that a rule uses to
request work from outside the workflow. Agents, models, and timers are
examples. Chapter 5 also shows how a rule reacts to the outcome. In chapter 5,
the body of a rule becomes larger than facts. Almost each operation of a true
workflow between its first fact and its terminal is an effect.
