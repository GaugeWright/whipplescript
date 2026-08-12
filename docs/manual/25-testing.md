# Testing workflows

Part IV gives the judgment of a workflow. Judgment starts with the oldest
instrument. The test harness of WhippleScript is *in the source file*. A `test`
block is adjacent to the workflow that the block exercises. The `whip test`
command runs the block. The block drives the true kernel. The match operation
is true, the commits are true, and the lifecycle of an effect is true. A
declared deterministic replacement covers each edge that is not deterministic.

## A workflow with tests

<!-- check: skip — `Ticket` is seeded by the scenarios' `given fact`, so `whip check` reports rule `work` as unreachable -->
```whip
use std.agent
use std.coercion

workflow Triage

output result Done
failure error Escalated

class Ticket {
  title string
  sev string
}

class Verdict {
  action "reply" | "escalate"
  note string
}

class Done {
  note string
}

class Escalated {
  reason string
}

agent triager

coerce judge(title string) -> Verdict {
  prompt "Route this ticket: {{ title }}"
}

rule work
  when Ticket as t
=> {
  then summary <- tell triager "Summarize: {{ t.title }}"
  then verdict <- coerce judge(t.title)
  case verdict.action {
    "reply" => {
      complete result {
        note verdict.note
      }
    }
    "escalate" => {
      fail error {
        reason verdict.note
      }
    }
  }
}

test "reply verdict completes" {
  workflow Triage

  given fact Ticket {
    title "printer on fire"
    sev "low"
  }

  stub agent triager succeeds
  stub coerce judge returns {
    action "reply"
    note "sent the standard fix"
  }

  run until idle

  expect rule work fired
  expect effect agent.tell completed
  expect workflow completed
}

test "escalate verdict fails with the reason" {
  workflow Triage

  given fact Ticket {
    title "data loss"
    sev "high"
  }

  stub agent triager succeeds
  stub coerce judge returns {
    action "escalate"
    note "needs a human"
  }

  run until idle

  expect workflow failed
}

test "a failed turn never reaches the coercion" {
  workflow Triage

  given fact Ticket {
    title "flaky"
    sev "low"
  }

  stub agent triager fails

  run until idle

  expect effect agent.tell failed
  expect no schema.coerce
  expect workflow failed
}
```

```sh
whip test triage.whip
```

```text
ok   Triage::reply verdict completes
ok   Triage::escalate verdict fails with the reason
ok   Triage::a failed turn never reaches the coercion
3 passed, 0 failed, 0 invalid
```

A scenario has three parts.

The **`given`** clause seeds the world. The `given fact` clause makes a fact
that exists before the run. The `given input` clause supplies an input, and the
runtime validates the input against the input contract. The `given signal`
clause supplies a signal. The `given tracker <name> issue { … }` clause uses
the true ready projection, and each scenario is separate. The
`given file <store> at "<path>" "<content>"` clause makes a fixture file. The
runtime redirects the root of the store for the test.

The **`stub`** clause pins each edge that is not deterministic. The
`stub agent <name> succeeds|fails` clause selects the outcome of the fixture
turn. The clause applies to each agent separately. Thus `alpha succeeds` and
`beta fails` can be adjacent. The `stub coerce <fn> returns { … }` clause
injects the exact typed decision that a branch needs. This clause exercises the
two `case` arms above with no model.

The **`run`** clause drives the rounds of the true engine. The `until idle`
clause and the `until workflow completed|failed` clause drive the engine to a
fixed point. The `for N steps` clause drives the engine to an intermediate
state that you can examine.

Then the **`expect`** clause reads the record. The clause can read the terminal
state of the workflow. The clause can read the firings of a rule with `fired`,
`did not fire`, or `fired N times`. The clause can read the outcome of an
effect by its kind, such as `expect effect agent.tell completed` or
`expect no schema.coerce`. The third scenario uses the second form. The
scenario proves that the automatic failure path from chapter 6 stops the
pipeline *before* the coercion. The clause can also read a projection of the
facts, such as `expect Ticket count where sev == "high" is 1`. This form
includes a runtime fact with a dotted name, such as `agent.turn.completed`. The
clause can also read a recorded diagnostic by its code.

## How to test time

The rule from chapter 10 gives its value here: there is no ambient clock. Time
enters only as an effect. Thus a test can *inject* the clock:

<!-- check: skip — a `test` block, not a `whip check` input -->
```whip
test "a due order fires the deadline" {
  workflow Deadline

  given fact Order {
    id "O-1"
    due "2027-01-01T00:00:00Z"
  }
  given clock at "2027-01-02T00:00:00Z"

  run until idle

  expect effect timer.wait completed
  expect workflow failed
}

test "an order before its deadline stays pending" {
  workflow Deadline

  given fact Order {
    id "O-1"
    due "2027-01-01T00:00:00Z"
  }
  given clock at "2026-06-01T00:00:00Z"

  run until idle

  expect no workflow.failed
  expect rule watch fired
}
```

The `given clock at` clause sets a virtual clock for the evaluation. Thus a
`timer until` deadline and a `timeout` deadline fire deterministically, or stay
pending deterministically. There is no true wait, and there is no unreliable
result from the wall clock. The two sides of a deadline are one clock line
apart.

## Honest by construction

The contract of the harness is the same as the contract of the language. A
scenario that the driver cannot run *faithfully* reports **invalid** with the
reason. Such a scenario never passes silently. An unsupported stub outcome is
one such scenario. The harness rejects `stub agent x times_out`, because the
fixture harness cannot simulate a timeout truthfully. A `given input` clause
that violates the contract is a second such scenario. The harness evaluates
each `expect` target. The harness never skips a target. The exit codes have the
same honesty. Code `0` means that the tests passed. Code `1` means that an
expectation failed. Code `2` means that the setup itself is invalid. Code `4`
means that the command selected nothing.

For a large project, use the `whip test <dir>` command. The command finds each
`.whip` file recursively and gives one report. The address of a scenario is
`<workflow>::<name>`. Select a scenario with the `-i` pattern and the `-x`
pattern. Use `Triage::` for a workflow. Use `::*verdict*` across workflows. Use
`--list` to see the selection first.

An `assert` statement from chapter 3 is still a claim *after a run*. The
`whip run` command evaluates such a claim. An assertion judges a true run. A
test rehearses a hypothetical run. A mature workflow has the two constructs.

The separate `whip accept <fixture.json>` command replays recorded acceptance
fixtures. The command checks the conformance of a provider. This command is a
tool for an operator more than a surface for an author. This manual gives one
pointer to the command.

## Where next

A test checks the behavior against an expectation that you already have.
Chapter 26 starts the measurement of *quality* that you do not yet know how to
score. The chapter gives gauges, the evidence plane, and ambient scores.
