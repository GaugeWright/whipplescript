# Trackers

The last chapter refused one job. A coordination resource limits *permission, a
budget, and a record*. No coordination resource distributes work. That job has
its own construct. A **tracker** is durable issue tracking that you declare in
the source. A tracker is independent of any vendor. A tracker is a backlog of
items. A component files an item, claims the item, works the item, and finishes
the item. Each type of participant uses the *same* backlog. This behavior is
deliberate. Rules file into the backlog. Agents work the backlog. A person
operates the backlog from the command line. That shared surface is the purpose
of a tracker. At the end of this chapter, the shared surface replaces the
absent primitive that asks a person a question.

## How to declare a tracker and file an issue

```whip
tracker backlog
```

The bare declaration uses the `builtin` provider by default. The scope of this
provider is the workspace. The issues are adjacent to your instances, in the
`.whipplescript/` directory. The identifiers are sequential: `WS-1`, `WS-2`,
and so on. The durable status of an issue is `open`, `closed`, or `canceled`.
The tracker stores no other status.

## Assignment

An issue can name who should act on it:

```sh
whip issue assign WS-1 --to alice
whip issue assign WS-1 --clear
```

An assignment and a claim are different facts, and the difference matters.
An **assignment** is durable and says who *should* act. It survives a restart,
and it is visible before anyone responds. A **claim** is the transient CAS of
chapter 13 that decides who *is* acting.

An assignment is advisory. It never restricts who may claim. The tracker holds
no model of identity or authority, so the assignee is an opaque string that the
embedding host interprets. A host that requires "only the assignee may claim"
enforces that rule in the place that knows what an identity is.

An issue with no assignee is the ordinary case. It means "whoever has access",
and any party can claim it. Do not treat the absence of an assignee as an
omission.

Work enters from the two sides of the surface. A rule files an issue with a
statement:

```whip
file issue into backlog {
  title "Fix login 500 on empty password"
  body "Users report a 500 from /login."
}
```

An operator files an issue with the CLI:

```sh
whip issue new --tracker backlog --title "Typo in footer" --body "Copyright year is stale."
```

```text
WS-2 filed into backlog
```

Each file operation carries provenance. The issue of a workflow records the
instance that filed the issue. An issue that an agent files during a turn
carries the identity of the run that caused the issue. Thus you can always
trace the growth of the backlog to its cause.

## How to empty a backlog

The worker loop is a composition of three constructs from earlier chapters.
These constructs are the readiness pattern from chapter 12
(`has ready issue`), the join for rate control from chapter 13, and a `then`
chain from the claim operation to the finish operation:

```whip
use std.tracker
use std.agent

@service
workflow Fixer

tracker backlog

agent fixer

rule work
  when backlog has ready issue as issue
  when fixer is available
=> {
  claim issue as hold

  after hold succeeds {
    then outcome <- tell fixer """markdown
    Resolve this issue:

    {{ issue.title }}

    {{ issue.body }}
    """
    finish issue {
      summary outcome.summary
    }
  }

  after hold fails {
    record ClaimLost {
      issue issue.id
    }
  }
}

class ClaimLost {
  issue string
}
```

File two issues, run the service, and then examine the backlog:

```sh
whip issue new --tracker backlog --title "Fix login 500 on empty password" \
  --body "Users report a 500 from /login."
whip issue new --tracker backlog --title "Typo in footer" --body "Copyright year is stale."
whip run fixer.whip
whip issue list --tracker backlog
```

```text
WS-1 [closed] tracker=backlog Fix login 500 on empty password
WS-2 [closed] tracker=backlog Typo in footer
```

The workflow claimed the two issues. One turn worked each issue. The workflow
then finished each issue with the summary of the turn as the resolution. These
are the parts of the rule:

- **The `when backlog has ready issue as issue` clause** matches an issue that
  a rule can *claim*. Such an issue is open, and no rule claimed it. The
  binding carries `issue.id`, `issue.title`, and `issue.body`.
- **The `claim issue as hold` statement is an atomic take.** The statement can
  fail. When a different claimant won the race, the claim effect fails
  *normally*. The `after hold fails` block is a branch, as each other failure
  branch is. The failure is not an error. Here the rule records the loss as a
  fact. To do nothing and to wait for the next ready issue is equally correct.
  This behavior is the tracker equivalent of the `contended` outcome from
  chapter 14.
- **While a rule holds a claim, the issue shows `in_progress`.** This value is
  an overlay of the claim. The value is not a stored status. The value appears
  while the instance that claimed the issue holds the issue. The value goes
  away on a `release` operation or on a `finish` operation.
- **A claimant that stops never abandons its work.** A lease releases
  automatically. A claim does the same. An instance that claimed an issue and
  then got to a terminal returns its claimed issues to the open state. The
  terminal includes a `whip cancel` command from an operator. The next worker
  then gets the issue.

The `@service` tag is important here. A workflow that empties a backlog has no
natural end. Chapter 10 gave this rule: a service has no terminal. Chapter 6
gave a second rule: in a service, a turn failure with no handler records a
durable diagnostic and the service continues to run. The failure does not stop
the loop of the group of agents.

## The commands for an operator

The CLI can do each operation that a rule can do to a tracker. The CLI also
adds inspection:

```sh
whip issue list [--tracker backlog] [--status open]
whip issue show WS-1
whip issue ready backlog          # what a worker would see
whip issue claim WS-1 / renew / release / finish [--summary "done"]
whip issue dep add WS-2 depends-on WS-1
```

The full set of commands is larger than this working set. The set also has
`set` with an optimistic `--expect-state-token` flag, `conflicts`, `note`,
`comments`, `evidence`, `link`, and `unlink`. The set also has `export`,
`import`, and `sync` to move a backlog between machines. The `whip help issue`
command lists each command.

This surface is not a back door for an administrator. This surface is the other
half of the design. The backlog is state of the workspace with a neutral
surface. Thus a person at the shell and an `@service` workflow with many agents
are peers on the same queue. This equality makes the last pattern of this
chapter possible.

## A person in the loop

There is no primitive that stops a workflow to ask a person a question. This is
deliberate. A synchronous question puts a person in an effect. In an effect, a
person becomes a timeout. The durable form is the tracker, in the two
directions.

**A person gives work to a workflow** with the method above. The person runs
the `whip issue new` command. Each service that runs and that has a
`has ready issue` rule then reacts. The question of the person is only a file
operation.

**A workflow escalates to a person** when the workflow files an issue into a
tracker that persons monitor. The retry pattern in chapter 13 ended one `fail`
statement before this pattern. In place of a failure after three attempts, file
the case into an `escalations` tracker. Put the evidence in the body. A person
then works the case from the CLI.

**A round trip** occurs when the workflow needs an *answer*. A round trip
combines the two directions. The workflow files a request. The answer of the
person comes back as a new issue. The workflow monitors for that issue:

```whip
use std.tracker

workflow Relaunch

output result Done
failure error Rejected

class Pending {
  request string
}

class Done {
  note string
}

class Rejected {
  reason string
}

tracker approvals
tracker answers

rule ask
  when started
=> {
  then req <- file issue into approvals {
    title "Approve the relaunch?"
    body "File approve or reject into the answers tracker, body = this issue id."
  }
  record Pending {
    request req.id
  }
}

rule approved
  when Pending as p
  when answers has ready issue as a where a.body == p.request && a.title == "approve"
=> {
  claim a as hold

  after hold succeeds {
    then closed <- finish a {
      summary "applied"
    }
    done p
    complete result {
      note "relaunch approved"
    }
  }

  after hold fails {
    # another claimant took this answer; wait for the next
  }
}

rule rejected
  when Pending as p
  when answers has ready issue as a where a.body == p.request && a.title == "reject"
=> {
  claim a as hold

  after hold succeeds {
    then closed <- finish a {
      summary "acknowledged"
    }
    done p
    fail error {
      reason "relaunch rejected"
    }
  }

  after hold fails {
    # another claimant took this answer; wait for the next
  }
}
```

Run the program. The instance files its question and becomes idle. The instance
is durable, as chapter 5 promised. Some hours or some days can pass. The person
then answers from the shell:

```sh
whip issue list --tracker approvals      # read the question (WS-1)
whip issue new --tracker answers --title "approve" --body "WS-1"

# drive the ORIGINAL instance (a fresh `whip run` would mint a new one,
# which files its own duplicate question):
whip step <instance> --program relaunch.whip
whip worker <instance> --program relaunch.whip --once
whip step <instance> --program relaunch.whip
whip worker <instance> --program relaunch.whip --once
whip step <instance> --program relaunch.whip
```

The instance claims the answer, closes the answer, and completes with the note
`relaunch approved`. If the person files a `reject` answer, the instance fails
with the typed rejection. The claim executes on one worker pass. The dependent
`finish` operation executes on the subsequent pass. This is the usual division
between the stepper and the worker. Note one loose end. The question of the
workflow (`WS-1`) stays open in `approvals`. Close the question from the shell
with the `whip issue finish WS-1` command. As an alternative, add the close
operation to the rule that completes the workflow.

These are the parts that make the pattern operate. The
`then req <- file issue …` statement binds the filed question. Thus the
identifier of the question goes into the `Pending` fact. The
`where a.body == p.request` join pairs each answer with its own question. Thus
many pending approvals can exist together. The claim operation before the
action consumes each answer exactly one time. The `after hold fails` branch is
deliberate. A loss of the race only means a wait for the next answer. The
sequence of the chain is the sequence of the record operations. The `then`
statement puts the terminal *after* the finish operation. Thus the workflow
never completes while the answer is still open.

One semantic makes the full chain operate, and the semantic needs a name: **a
firing that commits completes**. The trigger of the rule here is a *projected*
fact: a ready issue. The `finish` operation in the middle of the chain closes
that issue. Thus the operation retracts the projection that admitted the rule.
The continuation still runs. The continuation is the `done p` statement and the
terminal. The bindings of a firing are values that the runtime captured at
admission. The bindings are not live references. The match operation decides
when a progression *starts*. The match operation never decides if a progression
completes. The `whip progressions <instance>` command shows each firing, its
captured bindings, and the item that the firing waits for. Sometimes you want a
durable audit trail of the decision as data and not only the terminal. In that
condition, record a fact for the decision adjacent to the finish operation.
This is good style. This is a choice and not a requirement.

The asymmetry with the `tell` statement is the lesson of this pattern. A
workflow invokes an agent. A workflow *petitions* a person. The question of the
workflow is durable work in the queue of the person. The answer of the person
is durable work in the queue of the workflow. The two items continue after a
restart, show in the `whip issue list` output, and carry provenance.

## Where next

A tracker moves work between participants that share a workspace. Chapter 16
opens the workspace itself. The chapter gives channels and messages that go
out, and signals and ingress sources that come in. These are the connections
of a workflow to systems that are not whip.
