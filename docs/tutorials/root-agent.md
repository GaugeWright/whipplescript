# Tutorial: run a root agent

In this tutorial you put an agent at the top of the workflow. The result is a
**root loop**. Each message that you send becomes a governed agent turn. The
full conversation is durable and you can examine it. Grants that you wrote in
the source limit the conversation. This is the whip-native method to drive
work. It is different from a script of the work.

Two facts are important before you start. First, all the steps in this tutorial
use the `fixture` provider. The fixture provider is deterministic and needs no
credentials. To change the loop into a true coding agent, change one word to
`provider codex` or to `provider claude`. Second, this loop is the
command-line pattern for a seat. The GaugeDesk workbench occupies the same seat
fully. GaugeDesk supplies an interactive session root with a UI, governance
between more than one party, and its own event-sourced store for the
conversation. GaugeDesk runs WhippleScript below as the governed runtime. If
you want that experience, use GaugeDesk. This tutorial drives whip directly.

## 1. The root loop

Make the file `root.whip`:

```whip
use std.files
use std.messaging

@service
description "A root agent loop: every operator message becomes a governed turn"
workflow RootLoop

channel operator {
  provider local
}

file store project {
  root "."
  allow read ["**"]
  allow write ["notes/**", "todo.md"]
}

agent root {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule instruct
  when message from operator as msg
=> {
  tell root as turn
    with access to project {
      read ["**"]
      write ["notes/**", "todo.md"]
    }
"""markdown
{{ msg.text }}
"""

  after turn completes {
    record TurnDone { note "turn settled" }
  }
}

class TurnDone { note string }
```

Read the source as a contract. Do not read it as a script:

- `@service` — the loop never completes. The loop continues while you keep it.
- `channel operator { provider local }` — this is an inbound channel. Each
  message on the channel fires the `instruct` rule. The `whip message` command
  injects the message through the fixture path. Thus the recorded fact contains
  `"provider":"fixture"`. The rule fires in the same manner in the two
  conditions.
- The `with access to` block is the **ceiling** of the turn. The agent can read
  the project. The agent can write only in `notes/` and to `todo.md`. This
  limit applies to each instruction. The authority is in the source, and you
  review the source in the same manner as other code. The authority is not in
  the prompt.
- `after turn completes` observes each outcome. Thus a turn that fails becomes
  a recorded fact. The loop does not stop.

## 2. Start the loop

```sh
whip check root.whip
whip run root.whip
```

The instance starts and becomes idle. There is no work until you send a
message. Make a note of the `ins_…` identifier that the command prints. You can
also find the identifier later with the `whip instances` command.

## 3. Send an instruction

```sh
whip message <instance> --channel operator \
  --text "Summarize the release checklist into a note." \
  --by jack --program root.whip
```

```text
delivered message on `operator` to ins_35af2401d67a754d6cf0aa9ab5141e53 at event #3
```

The message is a durable fact in the log of the instance. Now drive the loops.
Chapter 5 of the manual tells you why the step operation and the work operation
are separate:

```sh
whip step <instance> --program root.whip      # the rule fires: one agent.tell
whip worker <instance> --program root.whip --provider fixture
whip step <instance> --program root.whip      # the completion folds back in
```

```text
step ins_35af24… committed_rules=1 facts=0 consumed=0 effects=1
worker ins_35af24… ran=1 provider=fixture …
step ins_35af24… committed_rules=1 facts=1 consumed=0 effects=0
```

The result is one message, one turn, and one settled outcome. Run the
`whip message` command again for each new instruction. Each instruction is a
new governed turn with the same ceiling.

## 4. The record is the conversation

You can query each operation of the loop. You can do this now or in the
subsequent month:

```sh
whip status <instance>     # counts, recent events
whip facts <instance>      # the message, the TurnDone marks
whip log <instance>        # the full causal event stream
whip effects <instance>    # every turn, with status and grants
```

The effect line of the turn shows the exact authority of the turn:

```text
key_03899d576bac9bab agent.tell status=completed target=root profile=repo-writer …
```

For live observation, use the `whip run … --stream ndjson` command. The command
emits the stream of session events while the events occur. A UI reads the same
stream.

## 5. Make the loop operational

There are three upgrades. Each upgrade is one line. The list gives them in
sequence of increasing commitment:

- **A true model**: change `provider fixture` to `provider codex` or to
  `provider claude`. The [providers](../providers.md) page tells you about
  credentials. The rules, the grants, and the record do not change. Only the
  component that thinks changes.
- **True work**: make the file store and the grant larger. Include the paths
  that the agent must touch. You review the grant block. Thus keep the grant
  block as small as the work permits. Chapter
  [33](../manual/33-script-capabilities.md) of the manual gives the full
  discipline for the tool surface.
- **A permanent todo list**: add `use std.tracker` and a `tracker backlog`. The
  todo tools of the agent operate on the backlog durably in each turn. You can
  monitor and edit the same backlog from the shell with the `whip issue`
  command. Refer to chapter [15](../manual/15-trackers.md) of the manual.

The loop also gives you two durability tools at no cost. The `whip checkpoint`
and `whip restore` commands rewind the full loop to any recorded moment. Refer
to chapter [21](../manual/21-checkpoints.md) of the manual. The
`whip fork <instance>` command branches a live conversation. Thus you can try
two continuations. A fork starts from the live thread of the agent. Thus a fork
operates with the native providers. A fork does not operate with the fixture
provider.

## Where next

[Tutorial 2](build-a-workflow.md) reverses the relationship. In tutorial 1, you
drive an agent. In tutorial 2, a *workflow* drives the agents. The workflow
also asks you for approval when it needs a person.
