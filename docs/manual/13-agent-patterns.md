# Agent patterns

This chapter introduces no new construct. Chapters 11 and 12 gave the parts: a
turn as an effect, an outcome as a fact, and capacity as a condition that a
rule can match. Part I gave the other parts. What stays is the composition.
These are the recurrent shapes that make a workflow a *harness* around its
agents. Without these shapes, a workflow is only a caller with hope. Three
patterns cover the largest part of the practice. Limit the **time** that an
agent can use. Limit the **rate** at which the workflow admits work. Limit the
**quantity of failures** that the workflow permits before a component gives a
decision.

Each pattern is a small quantity of rules. This is the intent. No pattern is a
feature with a control. You can examine each pattern with the `whip facts`
command and the `whip effects` command while the pattern runs.

## The watchdog: one deadline on many steps

The `timeout` clause in chapter 10 limits one effect. A **watchdog** limits a
full progression against one clock. The progression can have more than one
turn, and each turn can take a different quantity of time:

```whip
use std.agent

workflow WeeklyReport

output result Done
failure error MissedDeadline

class Done {
  body string
}

class MissedDeadline {
  reason string
}

agent drafter
agent reviewer

rule produce
  when started
=> {
  timer 10m as deadline

  after deadline completes {
    fail error {
      reason "report not produced within the deadline"
    }
  }

  then draft <- tell drafter "Draft the weekly report."
  then review <- tell reviewer """markdown
  Review and tighten this draft:

  {{ draft.summary }}
  """
  cancel deadline
  complete result {
    body review.summary
  }
}
```

The shape is this. Request the deadline and declare its result **first**. Then
run the true work. The side that completes first then retires the other side.
On the success path, the chain ends with the `cancel deadline` statement. The
ledger then shows the settled race:

```text
key_b50341… agent.tell status=completed target=drafter
key_c45ca1… agent.tell status=completed target=reviewer
key_f5b5a8… timer.wait status=cancelled
```

If the deadline fires first, its `after` block fails the workflow. The terminal
then retires the turns that are still pending. This is the rule from chapter 5:
an instance that is complete runs no more operations. The rule does the
cleanup.

Two positions in that rule are important:

- **The rule arms the watchdog before the work.** A `then` line puts each
  subsequent statement into the success continuation. Thus an observer of the
  deadline *below* the chain would come into existence only after the draft
  succeeds. That period is exactly the period that the deadline must cover.
  Above the chain, the rule arms the deadline at the moment that the rule
  fires.
- **The deadline is not a `then` step.** The `cancel` statement needs the
  handle of an effect. The `then` statement hides its handle deliberately. The
  chained binding is the success payload and not the effect. Use the
  traditional `as` and `after` form for each item that the rule must address
  later. Such an item is an effect that the rule cancels, races, or observes
  explicitly for failure. Use the sugar for a step that no subsequent statement
  addresses.

The same rule applies in the opposite direction. Sometimes the *turn* is the
side that the program retires. In that condition, request the turn with
`tell … as turn`. A deadline branch can then use the `cancel turn` statement. A
cancelled turn settles as `agent.turn.cancelled`. Chapter 6 gave this rule: a
cancellation never causes an automatic failure. A deliberate stop is not an
error.

## Rate control: admit work at the rate of the agent

Chapter 12 introduced the `when … is available` clause. This is the pipeline
that needed the clause. The pipeline has a queue of facts, admission at
capacity, and detection of completion when the queue becomes empty:

```whip
use std.agent

workflow Digest

output result Done

class Topic {
  name string
}

class Summary {
  topic string
  body string
}

class Done {
  note string
}

agent summarizer

table topics as Topic [
  {
    name "tidal power"
  }
  {
    name "geothermal"
  }
  {
    name "grid storage"
  }
]

rule assign
  when Topic as topic
  when summarizer is available
=> {
  then s <- tell summarizer "Summarize {{ topic.name }} in two sentences."
  done topic -> record Summary {
    topic topic.name
    body s.summary
  }
}

rule finish
  when Summary as s where empty(Topic)
=> {
  complete result {
    note "all topics summarized"
  }
}
```

Three details make the pattern operate:

- **The admission clause joins the queue.** The `assign` rule fires only when a
  topic is present *and* a slot is free. A rule without the availability clause
  is not incorrect. Three topics then request three turns, and the `capacity`
  value puts the turns in a queue. But the state of the work that waits
  changes. The work becomes a set of committed requests for effects. The work
  is no longer a set of facts. As facts, the work that waits stays
  *matchable*. A rule that changes the priority can consume a `Topic` fact that
  the workflow has **not yet admitted**. Thus the rule stops that topic. After
  the firing of a topic commits, its progression completes. Consumption
  controls the admission. Consumption does not control work in progress. The
  `whip facts` command also shows the queue directly. Admission control keeps
  your options open. A queue removes your options.
- **Consumption is the record of completion.** The
  `done topic -> record Summary` statement moves each topic out of the queue.
  The statement records the result of the topic in the same atomic commit. Thus
  there is no moment where a topic is complete and still admissible.
- **The detection of an empty queue is only a rule.** The last consumption
  makes `empty(Topic)` true. The summary in that same commit is the fact that
  triggers the `finish` rule. No coordinator counts the completions. The state
  of the queue *is* the coordination.

Note one property of this pipeline. The pipeline uses a `then` chain. Thus a
turn that fails fails the full workflow automatically. Chapter 9 gave this
contract. For a digest of three topics, this default is correct. Sometimes the
default is not correct, because one failure must not stop the batch. In that
condition, a failure must become a fact that the workflow can reason about.
That is the third pattern.

## Retries as facts

An effect that fails stays failed. The runtime has no hidden retry policy.
Chapter 6 made an unhandled failure loud and not a loop. Sometimes an agent is
truly unreliable, and a retry with a limit is the correct response. In that
condition, the budget goes where each other item of workflow state goes: in
facts, with rules as the guards:

```whip
use std.agent

workflow Resilient

output result Done
failure error GaveUp

class Task {
  name string
}

class Attempt {
  task string
  n int
}

class Done {
  body string
}

class GaveUp {
  reason string
}

agent summarizer

table tasks as Task [
  {
    name "tidal power"
  }
]

rule start
  when Task as task
=> {
  done task -> record Attempt {
    task task.name
    n 1
  }
}

rule attempt
  when Attempt as a where a.n <= 3
=> {
  tell summarizer as turn "Summarize {{ a.task }} in two sentences."

  after turn succeeds as ok {
    complete result {
      body ok.summary
    }
  }

  after turn fails as e {
    done a -> record Attempt {
      task a.task
      n a.n + 1
    }
  }
}

rule give_up
  when Attempt as a where a.n > 3
=> {
  fail error {
    reason "three attempts failed"
  }
}
```

The loop has no loop construct. A failure **advances the trigger**. The
`done a -> record Attempt { … n a.n + 1 }` statement consumes the current
attempt and records the next attempt in one commit. The new fact has different
content. Thus the new fact is a different fact under the set semantics from
chapter 2. The new fact fires the `attempt` rule again. The two guards divide
the domain. The `a.n <= 3` guard makes an attempt. The `a.n > 3` guard gives
the decision. When the third failure records `n 4`, the guard of the `attempt`
rule excludes the fact and the `give_up` rule fires. The termination comes from
arithmetic and not from a convention.

This shape is not only idiomatic. The checker needs this shape. The checker
rejects an effectful rule that records its own trigger class *without* a
consume operation:

```text
error: effectful rule `attempt` preserves trigger fact `schema:Attempt`
  = help: consume or advance the triggering fact, or move the next effect
    behind an external completion event
```

That condition is the retry loop with no limit. The `whip check` command
refuses the loop. Advance the trigger, and the budget becomes structural.

Note where the `record` of this pattern sits. It sits inside an `after` block,
so the fact of the next attempt arrives only with the terminal of the turn, and
each pass of the loop waits on the world. That placement is what the compiler
reads. The same rule with the `record` at the top level advances its trigger
just as well, and it is a check error
(`graph.unbounded_effect_recursion`): nothing paces it, so it would enqueue a
turn for every commit. A ring of two rules or more is read the same way. See
[Diagnostics](../diagnostics.md).

Two properties come with this pattern at no cost:

- **Each attempt is a true and different effect.** The identity of an effect
  comes from its firing. A new attempt fact gives a new idempotency key. Thus
  the runtime never deduplicates a retry against the attempt that it retries. A
  replay also reconstructs the same three attempts.
- **You can examine the retry state.** During the run, the `whip facts` command
  shows exactly one `Attempt` fact that no rule consumed. The fact has the
  current `n` value. Thus a query gives the condition of the loop. You do not
  need a debug session. The rule that stops the retries is also a usual rule.
  Replace the `fail` statement with an escalation. The rule can tell a stronger
  agent. As an alternative, the rule can file an issue in a tracker for a
  person. Part III gives trackers.

## Where next

The three patterns compose. A pipeline with a rate control, a watchdog on each
step, and a retry on each failure is still only rules on facts. Part II ends
here. To this point, an agent used the conversation only. The default `no-repo`
profile permits nothing else. Part III gives a workflow and its agents items to
touch. The items are coordination, trackers, messaging, files, and version
control. Part III also gives the governance that makes such a grant of
authority safe.
