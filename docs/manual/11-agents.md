# Agents

A coercion asks a language model one question and receives one typed answer. An
**agent** is the other type of model worker. An agent takes a task, does the
task in more than one step, and reports the result. An agent can use tools.
WhippleScript exists to direct agents. The design keeps a strict division. The
workflow decides the question, the time of the question, and the subsequent
operation. The agent does the work. The component that runs the agent is
configuration and not code.

## How to declare an agent

```whip
use std.agent

agent researcher
```

This is a complete declaration. It gives a name to a worker that you can
address. Each default is safe. The harness of whip runs the turns. During
development, a deterministic replacement for the model runs the turns and needs
no credentials. One turn runs at a time. The agent has no authority outside the
conversation. It has no files and no commands. Each default is a control. This
chapter increases each control at the point where its reason occurs.

## How to ask for work: the `tell` statement

The `tell` statement is the effect that requests a turn:

```whip
use std.agent

workflow Research

output result Done

class Done {
  summary string
}

class Topic {
  name string
}

table topics as Topic [
  {
    name "tidal power"
  }
]

agent researcher

rule assign
  when Topic as topic
=> {
  tell researcher as turn """markdown
  Write two sentences about {{ topic.name }}.
  """

  after turn succeeds as completed {
    complete result {
      summary completed.summary
    }
  }
}
```

The prompt is a template, as in chapter 8. The `{{ topic.name }}` template puts
the matched fact into the task. The effect is the new part.

**The turn is a usual effect.** The `tell … as turn` statement requests the
effect. The `after turn succeeds as completed` block observes the effect. The
lifecycle, the ledger, and the semantics of `after` are the same as for each
effect from chapter 5. The failure handling is the same as in chapter 6. The
`after turn fails` block, timeouts, and cancellation each apply. The success
binding carries the result of the turn. The `completed.summary` field is the
summary that the agent reported.

Run the program:

```sh
whip run research.whip
```

```text
status completed
```

The summary is a deterministic placeholder: `fixture completed`. The
**fixture** is the replacement model of whip. This is the default during
development. The full workflow runs from end to end with no model and no
credentials. This includes the match operation, the prompts, the branches, and
the terminals. Development, tests, and this manual each use the fixture. A true
model enters through the configuration. The next section gives the detail.

## The three controls

The bare declaration gives a default to each item below. Declare an item when
its reason occurs:

```whip
agent researcher {
  provider fixture
  profile "internet-research"
  capacity 2
}
```

- `capacity` — the quantity of turns of this agent that can run at the same
  time. The default is `1`. The fan-out from chapter 4 applies to an agent. A
  rule that matches ten facts requests ten turns. The capacity prevents ten
  turns that run at the same time. Increase the capacity when you want parallel
  turns. Chapter 12 shows how the match operation can wait for free capacity.
- `provider` — the component that executes the turn. Use `fixture` during
  development. Chapter 32 gives the owned harness and the native families. For
  an external agent runtime, the primary form in the reference is
  `agent coder delegated to claude`. The `provider <kind>` clause is the
  compact spelling of the same selection. This spelling is legacy.
- `profile` — a named level of authority. The default is `no-repo`, which
  permits the conversation only. A profile such as `"repo-reader"`,
  `"internet-research"`, or `"repo-writer"` increases the items that a turn can
  touch. The items include files, search, and changes to data. The default is
  the most narrow profile. This is deliberate. An absent field can never grant
  more than a declared field. Authority enters this manual in Part II, with the
  resources that it governs.

## The data that the workflow sees of a turn

A turn is deliberately opaque while the turn runs. The workflow does not see
the model think. In a turn of a true provider, the ledger records the
intermediate use of a tool as evidence. The ledger does not record the use as a
fact that a rule can match. A rule gets the **settled outcome** only. The
outcome is a success with a summary, or a failure with the uniform failure
base. This opacity is a commitment of the design. Policy stays in the rules and
reacts to typed results. Prose stays in the turns.

One result is important now. No part of a summary is structured. When a
decision needs typed data from a model, use the `coerce` statement from chapter
8. The two constructs compose. A turn does the work that has no fixed limits. A
coercion then changes the outcome of the turn into a decision that you can
route.

## How to make the authority of a turn more narrow

The declaration of the agent sets the ceiling. One `tell` statement can lower
the ceiling. A turn can carry explicit grants. A grant gives access to a
specified resource with a specified set of operations. Write the grants between
the target and the prompt:

```whip
tell researcher as turn
  with access to project_files {
    read ["docs/**"]
  }
"Survey the docs."
```

A grant can only make the authority more narrow. A turn can never get more
authority than the profile of its agent permits. Part II gives the full
vocabulary of grants. The vocabulary includes file stores, commands, and
trackers. Part II introduces those resources. For now, know that you can make
the authority of a turn more narrow, and that the profile is not the finest
level of control.

## Where next

This chapter observed a turn from the rule that requested the turn, with an
`after` block. Chapter 12 gives a larger view. A turn settles into a fact, and
*each* rule can react to the fact. These are the readiness patterns. They let a
workflow with more than one rule and more than one agent compose.
