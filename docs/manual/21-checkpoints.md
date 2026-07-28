# Checkpoints, restore & forking

The history of an instance permits append only, and the history is immutable.
Chapter 5 promised that each part of the state is in the store. Each subsequent
chapter used that promise. This chapter shows how to *move* through that
history. Give a name to a coherent moment with the `checkpoint` command. Rewind
the working context to that moment with the `restore` command. Branch the
conversation of an agent into a different result with the `fork` command. No
command makes the record false.

## The workspace is a database

The substrate comes first, because the substrate gives the reason that these
operations have a low cost and are safe. Each item that an instance owns is in
one store. The items are the event log, the facts, the effects, and the file
plane from chapter 20. The store keeps the body of each written file by its
**content**. Identical bytes are in the store one time. The store keeps each
version by its hash. The store never updates an item destructively. A consume
operation is a marker. An overwrite operation keeps the two versions. The
current state is always a *fold* of the log. There are two results:

- **A cut is only a coordinate.** A name for a consistent moment across the
  three planes costs one row. The name does not cost a copy. The three planes
  are the events, the facts, and the files.
- **A branch has a cost of O(1).** A branch is a new lineage. The lineage reads
  the same immutable record. The key of each derived effect contains its branch
  and its restore lineage. Thus a parallel timeline can never deduplicate
  against the work of a different timeline. The same machinery supports a
  version-control protocol for a workspace that a host uses. That protocol has
  the operations init, branch, merge-probe, merge, and promote. External tools
  use the protocol. The protocol has no surface in the workflow language now.
  Thus this manual teaches the operations at the level of the instance that the
  protocol supports.

## The `checkpoint` command: how to name a cut

```sh
whip checkpoint ins_955a76… --cut-id mid
```

```text
checkpoint `mid` captured at event #9 (0 file(s))
```

A checkpoint captures the position of the instance across the planes. The
position has the event sequence, the state of the facts, and the manifest of
the file plane. The checkpoint has a name. A checkpoint changes nothing. A
checkpoint is a durable bookmark. The `whip handles <instance>` command lists
the positions of an instance. The positions are the event position, the
identifiers of the effects, and the binding to the workspace. Use this command
when an external tool needs the coordinates.

## The `restore` command: how to rewind the context

```sh
whip restore ins_955a76… mid
```

```text
restored `ins_955a76…` to cut `mid` (event #14); 0 written, 0 removed;
undo with `whip restore ins_955a76… auto-before-mid`
```

A restore operation rewinds the *working context* to the cut. The facts return
to their state at the cut. The runtime writes the content of the file plane
back from the bodies that it stores by content. The instance then continues
from that point. The mechanics obey the append-only rule. A restore is also an
event. The event is a `context.restored` marker that each reader folds. Thus
the abandoned segment stays in the log, and you can examine the segment
permanently. The runtime also makes an automatic `auto-before-<cut>`
checkpoint. Thus you can undo each restore.

Look at the promise about the honesty of a replay. Take a workflow with two
steps. Make a cut after step one. Let step two run. Then restore the instance
and drive the instance again:

```text
post-restore: instance ins_955a76… running
Step Step:0c85d173… {"n":1}
re-driven: instance ins_955a76… completed  timers=4
```

The instance that rewound executed its second step again. The ledger shows
*four* timer effects and not three. The suffix that executed again derived
**new** effect keys, because the generation of the restore is part of the
identity of an effect. Thus the suffix never deduplicated against the work of
the abandoned timeline. A replay of a different result is a true replay. The
replay is not a cache hit on the history that you abandoned.

Two limits keep a restore operation honest:

- **A terminal absorbs the instance, also here.** A restore of a *complete*
  instance rewinds the fact context and the file context for inspection. The
  restore does not put the instance back into the `running` state. The
  absorbing-terminal rule from chapter 4 has no exception. Use a rewind and a
  continuation on an instance that is still in operation.
- **The runtime checks coherence.** A cut names the three planes at the same
  time. The restore operation refuses a cut that it cannot rewind coherently.
  The operation does not leave the planes in disagreement.

## The `fork` command: how to branch a conversation

The `whip fork <instance> [--agent <name>]` command targets an item that is
more specific than the instance. The target is the **live thread of the
conversation** of an agent. Chapter 11 kept a turn opaque. An agent runs under a
harness. A harness can keep a thread that continues across turns. A fork seeds
a *branch instance* from that thread. The branch instance has the same history
to the seed. The branch instance then has a different continuation. The effect
keys of the branch are different. Thus the different result can never
deduplicate against the true run. A fork is the instrument that answers this
question: what would the agent have done in a different condition?

The preconditions of a fork are loud and not silent:

```text
fork refused: `ins_955a76…` has no completed agent turn — nothing to seed (pass --agent to pick one explicitly)
fork refused: agent `helper` has no live thread on `ins_18f8ac…` — nothing to seed (pass --agent to pick one explicitly)
```

A fork needs an agent, a complete turn, and a live thread to branch. A turn
that occurs one time under the development fixture leaves no thread. When there
is nothing to seed, the fork says so and changes nothing. Use the `--agent`
flag to select an agent explicitly.

## The purpose of these commands

The usual uses are more ordinary than the term "time travel" suggests. Make a
checkpoint before a phase with a risk. Then the recovery is a `restore`
operation and not an examination of the history. Restore an instance that is
still in operation and that got an incorrect context. A bad import and a fact
with an incorrect record are examples. This is better than the abandonment of
the instance. Fork the thread of an agent to test a judgment without an effect
on the true lineage. In each condition, the record stays complete. The
`whip log` command shows the abandoned segment, the restore marker, and the
suffix that executed again. The command shows these items in sequence,
permanently. This property makes these operations sufficiently safe for usual
work.

## Where next

Chapter 22 starts the three chapters on governance. Chapter 22 gives
information-flow control. The chapter gives labels, clearances, and the deny
properties that limit the destinations of each value in a workflow.
