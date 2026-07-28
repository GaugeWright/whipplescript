# Memory: recall, learn & curate

A workflow ends. The data that the workflow learned must not end with it. The
`std.memory` package is the durable memory store. Its scope is the workspace.
It holds notes. A note continues after the instance ends. A later workflow
recalls the note. A person or a rule then prunes the note deliberately. Chapter
31 used the package surface with the `call memory.query` statement. This chapter
gives the dedicated language surface.

## A pool and its three verbs

```whip
use std.memory

memory pool project_memory {
  context limit 8
}
```

A `memory pool` declaration makes a named store with a **context limit**. The
limit is the maximum quantity of entries that a recall operation injects.
Memory with no limit degrades a prompt. Three verbs in the body of a rule
operate on a pool. Each verb is a usual durable effect:

```whip
rule remember_then_recall
  when Note as note
=> {
  learn from note into project_memory { note "remember alpha" } as saved

  after saved succeeds {
    recall project_memory for note as context
  }
}
```

- The `learn from <binding> into <pool> { note "…" } as x` statement writes an
  entry. The entry has the note and the provenance of the source binding. A
  learn operation is explicit. No agent quietly accumulates memory as a side
  effect.
- The `recall <pool> for <binding> as x` statement gets the most relevant
  entries. The context limit of the pool limits the quantity. A downstream
  statement then uses the entries. The statement can be a prompt, a coercion,
  or a turn. The form that the package owns is
  `recall from <pool> for <query> as x`. This form is the same verb behind a
  package lock.
- The `curate <pool> { reason "compact" } as x` statement prunes the pool. The
  statement removes duplicates and compacts the pool. The statement is a
  *recorded decision* with a reason. The pool does not decay silently.

The `examples/memory-roundtrip.whip` file and the `examples/memory-curate.whip`
file run the full cycle on the fixture. The `openclaw-lite.whip` file shows the
working pattern: a recall operation before the planning turn, and a learn
operation after the work settles.

## The commands for an operator

Memory is state of the workspace, as a tracker is and as coordination state is.
Memory is adjacent to the run stores. You can examine memory from the shell:

```sh
whip memory pools
whip memory entries project_memory --limit 10
```

```text
project_memory	1 entries
1	remember alpha
```

The `WHIPPLESCRIPT_MEMORY_STORE` variable overrides the path of the store. The
scope of a pool is the workspace. Thus one workflow learns an item, and a
different workflow recalls the item. This behavior is the purpose of a pool.
This behavior is also the reason that a `learn` statement needs the same
attention in a review as each other write to shared state.

## Memory under governance

The three verbs are effects. Thus each rule from Part III applies with no
change. The verbs appear in the `whip effects` output and in the chain of
evidence. A pool is a resource, and an envelope can put a label on the pool.
Recalled content that enters a prompt gets the same egress checks as each other
read. Grants in a turn make the access more narrow. The grant block of a turn
can hold `recall for issue` and `learn for issue`. These grants limit the items
that the tools of an agent can touch. This behavior is the same as the behavior
of a grant for a file.

## Where next

This chapter completes the tour of the standard packages in this manual.
Chapter 31 gives the mechanics of a package behind the `use std.memory`
statement. The [language reference](../language-reference.md) gives the full
grammar of the verbs.
