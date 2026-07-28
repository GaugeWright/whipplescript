# Tutorial: build a workflow

In this tutorial you write a workflow in an empty file. You then run the
workflow to a complete instance. The workflow seeds two bug tickets. An agent
proposes a triage plan for each ticket. The workflow then asks a person to
approve the ticket that has high severity. The workflow completes or fails as a
function of the answer.

In this tutorial you use the largest part of the language: typed facts, a seed
table, an agent, effect sequence control with `after`, a review gate for a
person that uses a tracker, guards, and workflow terminals. The fixture
provider replaces a true agent. Thus you do not need credentials.

If you did not install the CLI, [install the CLI](../install.md) first.

## 1. Declare the data

Make the file `triage.whip`. Start with the name of the workflow, the terminal
contracts of the workflow, and the types of fact that the workflow uses:

```whip
workflow TicketTriage

output result TriageDecision
failure error TriageBlocked

class Ticket {
  id string
  title string
  severity string
  status string
}

class TriagedTicket {
  id string
  title string
  severity string
  plan string
  status "triaged"
}

class TriageDecision {
  decision string
}

class TriageBlocked {
  reason string
}

class AwaitingSignoff {
  request string
}
```

Two items are important:

- The `output` declaration and the `failure` declaration give the data that
  this workflow supplies at its end. Each workflow must end. A workflow with
  the `@service` tag is the exception. The checker applies this rule. Step 4
  shows the result.
- The `status "triaged"` field is a literal type. A `TriagedTicket` fact can
  have only that status. Literal fields are the idiomatic method to model a
  small state machine.

## 2. Declare the agent, the trackers, and the seed data

Add `use std.tracker` at the top of the file. Then add this source:

```whip
agent triager {
  provider fixture
  profile "repo-reader"
  capacity 1
}

tracker approvals
tracker answers

table tickets as Ticket [
  {
    id "T-31"
    title "Login returns 500 on empty password"
    severity "high"
    status "open"
  }
  {
    id "T-32"
    title "Typo in footer copyright"
    severity "low"
    status "open"
  }
]
```

For now, the agent binds to the `fixture` provider. To use a true provider
later, change this one line. The rules do not change. The two trackers are the
machinery of the gate for the person. The workflow files its question into
`approvals`. A person files the decision into `answers`. The table seeds two
`Ticket` facts when the instance starts.

## 3. Write the triage rule

```whip
rule triage_open_ticket
  when Ticket as ticket where ticket.status == "open"
  when triager is available
=> {
  tell triager as turn """markdown
  Suggest an owner and a fix plan for this ticket:

  {{ ticket.title }} (severity: {{ ticket.severity }})
  """

  after turn succeeds as triaged {
    done ticket -> record TriagedTicket {
      id ticket.id
      title ticket.title
      severity ticket.severity
      plan triaged.summary
      status "triaged"
    }
  }

}
```

This is the primary pattern of the language:

- The `when` clauses give the conditions that the rule waits for. The
  conditions are an open ticket and free capacity on the agent.
- The `tell` statement does not call the agent. The statement records a durable
  `agent.tell` effect. A worker executes the effect later through the provider.
- The `after turn succeeds as triaged` block runs when the effect completes
  with success. This can occur some minutes later or some days later. The
  output of the turn binds to `triaged`. The output is visible only in the
  `after` block.
- The `done ticket -> record ...` statement consumes the open ticket. The
  statement records the replacement fact in the same atomic commit. Thus a
  ticket can never be open and triaged at the same time.

## 4. Let the checker find the missing end

Check the source that you have now:

```sh
whip check triage.whip
```

```text
error: workflow `TicketTriage` has no rule that reaches `complete` or `fail`
  = help: add a rule that runs `complete <output> { ... }` or `fail <failure> { ... }`,
          or tag the workflow `@service` if it intentionally runs forever
```

The checker is correct. The workflow triages the tickets, but no rule completes
the workflow. The checker also gives a warning: no arm handles the failure of
`turn`. The next step routes the failure. Now add the gate for the person and
the two ends.

## 5. Add the approval gate for a person

The language has no primitive that stops a workflow to ask a person a question.
This is deliberate. A synchronous question puts a person in an effect. In an
effect, a person becomes a timeout. The durable form is a **round trip through
a tracker**. The workflow files its question as an issue. The answer of the
person comes back as an issue. The workflow monitors for that issue.

```whip
rule request_signoff
  when TriagedTicket as ticket where ticket.severity == "high"
=> {
  then req <- file issue into approvals {
    title "Approve the triage plan for {{ ticket.id }}?"
    body "{{ ticket.plan }}"
  }

  record AwaitingSignoff {
    request req.id
  }
}

rule approve_plan
  when AwaitingSignoff as p
  when answers has ready issue as a where a.body == p.request && a.title == "approve"
=> {
  claim a as hold

  after hold succeeds {
    then closed <- finish a {
      summary "applied"
    }
    done p
    complete result {
      decision "approve"
    }
  }

  after hold fails {
    # another claimant took this answer; wait for the next
  }
}

rule reject_plan
  when AwaitingSignoff as p
  when answers has ready issue as a where a.body == p.request && a.title == "reject"
=> {
  claim a as hold

  after hold succeeds {
    then closed <- finish a {
      summary "acknowledged"
    }
    done p
    fail error {
      reason "triage plan rejected"
    }
  }

  after hold fails {
    # another claimant took this answer; wait for the next
  }
}
```

Last, route the failure of the turn. The checker gave a warning about this
failure. In the `triage_open_ticket` rule, add a typed failure terminal
adjacent to the success arm:

```whip
  after turn fails as oops {
    fail error {
      reason oops.reason
    }
  }
```

Learn this shape. The `file issue` statement records the request durably. The
`AwaitingSignoff` fact holds the identifier of the request. The two decision
rules wait for a ready issue in `answers` with a body that contains that
identifier. The `claim` statement makes the reaction safe against races. If two
instances monitor the same tracker, only one instance gets each answer. The
`after hold fails` branch of the other instance then waits. Many days can pass
between the file operation and the answer. In this time, the instance is idle
and durable.

Last, add the assertions. An assertion is an executable statement about the
complete run. The `run` command evaluates the assertions for you:

```whip
assert count(Ticket where status == "open") == 0
assert count(TriagedTicket) == 2
```

Check the source again. The check must pass and print the graph of the compiled
rules:

```sh
whip check triage.whip
```

## 6. Run the workflow

```sh
mkdir -p .whipplescript
whip --store .whipplescript/triage.sqlite \
  run triage.whip --provider fixture --until idle
```

The `run` command evaluates the two assertions and exits with code `0`. If an
assertion fails, the command prints the assertion and exits with a code that is
not `0`. To see the detail of each assertion, use the `--json` flag.

The `status` command shows that the instance is still `running`. The instance
waits for the approval. The approval request is now in the tracker:

```sh
whip issue list --tracker approvals
```

You do not need the `--store` flag here. The trackers are in the coordination
store. The scope of the coordination store is the workspace. The coordination
store is different from the store for each run. Thus each instance and each
shell in this directory sees the same backlog.

```text
WS-1 [open] tracker=approvals Approve the triage plan for T-31?
```

Only the ticket with high severity made a request. The workflow triaged ticket
T-32 with no request. The `whip issue show WS-1` command prints the plan in the
body.

## 7. Answer the question and complete the workflow

The answer of the person is also an issue. The title is `approve` or `reject`.
The body contains the identifier of the request:

```sh
whip issue new --tracker answers --title approve --body WS-1 --actor alice
```

Then drive the pending work. The claim executes on one worker pass. The finish
operation depends on the claim. Thus the finish operation executes on the
subsequent pass. Each effect uses this same division between the stepper and
the worker:

```sh
whip --store .whipplescript/triage.sqlite step <instance_id> --program triage.whip
whip --store .whipplescript/triage.sqlite worker <instance_id> --program triage.whip --provider fixture
whip --store .whipplescript/triage.sqlite step <instance_id> --program triage.whip
whip --store .whipplescript/triage.sqlite worker <instance_id> --program triage.whip --provider fixture
whip --store .whipplescript/triage.sqlite step <instance_id> --program triage.whip
whip --store .whipplescript/triage.sqlite status <instance_id>
```

```text
instance ins_… completed
```

You can now query the durable record of the full run:

```sh
whip --store .whipplescript/triage.sqlite facts <instance_id>
```

```text
TriagedTicket TriagedTicket:triaged:8cb1f2… {"id":"T-31","plan":"fixture completed","severity":"high","status":"triaged",…}
TriagedTicket TriagedTicket:triaged:bd7c77… {"id":"T-32","plan":"fixture completed","severity":"low","status":"triaged",…}
agent.turn.completed key_35005c… {"agent":"triager","provider":"fixture","status":"completed",…}
agent.turn.completed key_fa33ec… {"agent":"triager","provider":"fixture","status":"completed",…}
tracker.claim.completed key_6b295f… {"status":"completed","value":{"claimed_by":"ins_f18394…","id":"WS-2"}}
tracker.file.completed key_ac3cbd… {"status":"completed","value":{"id":"WS-1","queue":"approvals","title":"Approve the triage plan for T-31?"}}
```

Each line gives the type of the fact, the key of the fact, and then the JSON
payload. The `effects` command shows the two agent turns and the tracker verbs.
The status of each item is `completed`. The `trace --check` command makes sure
that the lifecycle agrees with the model of the runtime.

## 8. Try the failure path

Run a new instance and reject the plan. The scope of a tracker is the
workspace. Thus the second instance files its own request (`WS-3`) into the
same `approvals` tracker. The decision rules match on the body. Thus each
instance answers only its own question:

```sh
whip --store .whipplescript/triage.sqlite \
  run triage.whip --provider fixture --until idle
whip issue list --tracker approvals --status open
whip issue new --tracker answers --title reject --body WS-3 --actor alice
# …then the same step/worker drive as above…
whip --store .whipplescript/triage.sqlite status <instance_id>
```

```text
instance ins_… failed
```

The `reject_plan` rule executed `fail error { ... }`. The two instances are in
the same store with their full histories. One instance is complete. The other
instance failed.

## Where to go next

- Change `provider fixture` to a true provider after you configure one. Refer
  to [providers & packages](../providers.md).
- Add a typed model review with `coerce`. Do not trust the summary of the turn.
  Refer to
  [`examples/queue-worker-with-review.whip`](https://github.com/jamesjscully/whipplescript/blob/main/examples/queue-worker-with-review.whip).
- [Tutorial 3](governance.md) puts the data flows of this workflow in a signed
  governance envelope.
- Read the [manual](../manual.md) for authoring guidance about retries,
  branches, and composition. Read the
  [language reference](../language-reference.md) for the full list of
  constructs.
