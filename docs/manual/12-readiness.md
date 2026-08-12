# Readiness patterns

To this point, each rule waited for one of two items: the `started` event, or a
fact of a given class. This chapter completes the vocabulary of the `when`
clause. The chapter also gives a second method to react to an effect. That
method changes the organization of a workflow.

## A turn settles into a fact

Run the `Research` workflow from chapter 11. Then examine the facts:

```sh
whip facts ins_…
```

```text
Topic                {"name": "tidal power"}
agent.turn.completed {"agent": "researcher", "effect_id": "key_b11b58…", …}
```

The turn did more than the resolution of an `after` block. The turn derived a
durable fact with the name `agent.turn.completed`. The fact is the same type of
fact as each other fact in the instance. Thus a rule can *match* the fact:

<!-- check: skip — excerpt; its fact class and agent belong to the surrounding program -->
```whip
rule assign
  when Topic as topic
=> {
  tell researcher as turn "Summarize {{ topic.name }}."
}

rule collect
  when researcher completed turn as t
=> {
  complete result { note "turn observed" }
}
```

The `assign` rule requests the turn. The rule says nothing about the subsequent
operation. The `collect` rule is a separate rule. It fires when a turn of
`researcher` completes. The two rules share no binding. Each rule knows nothing
about the other rule. The stream of facts is their only connection.

## `after` or `when`: two methods to continue

Thus each effect has two styles of observation. The selection between them is a
true design decision:

- **The `after` block in the rule that requests the effect** — use this style
  for a *continuation*. The reaction belongs to this progression. The reaction
  needs the bindings of the progression, such as the matched facts together
  with the result of the turn. The reaction has no meaning outside the
  progression.
- **The `when` clause in a separate rule** — use this style for a *policy*. The
  reaction applies to each turn of this type. The rule that requested the turn
  is not important. One `collect` rule handles the turns of ten rules of the
  `assign` type.

A small workflow reads best with an `after` block. The full sequence stays in
one location. When a workflow gets more agents and more stages, a rule with a
`when` clause keeps each rule small. One rule requests, one rule collects, and
one rule escalates. Each rule matches the facts that apply to it. The two
styles settle on the same derived facts. Thus a change from one style to the
other changes the structure and not the behavior.

## How to wait for capacity: the `is available` clause

The `capacity` control in chapter 11 limits the quantity of turns that run at
the same time. The `is available` readiness pattern makes that limit visible to
the match operation:

<!-- check: skip — excerpt; its fact class and agent belong to the surrounding program -->
```whip
rule assign
  when Topic as topic
  when researcher is available
=> {
  tell researcher as turn "Summarize {{ topic.name }}."
}
```

The rule joins this clause with the fact clause. The join semantics from
chapter 4 do not change. The rule now fires only when two conditions are true:
a topic is available for assignment, *and* the agent has free capacity. Without
this clause, ten matched topics request ten turns immediately, and the capacity
puts the turns in a queue. With this clause, the workflow admits work at the
rate that the agent can accept. Frequently this clause is the difference
between a controlled pipeline and a large queue.

## The general form: the `when fact` clause

Each specialized pattern is a short form of one general form. The general form
matches a derived fact by its dotted name:

<!-- check: skip — a readiness clause, not a rule body -->
```whip
when fact agent.turn.completed as t
```

This clause is exactly the `when researcher completed turn as t` clause, but
without the limit to one agent. The general form matches the turns of each
agent. Add a `where` clause on the payload to make the match more narrow. This
is the full vocabulary:

| Pattern | Short form for |
| --- | --- |
| `when started` | the event that starts the instance |
| `when Class as x [where …]` | a fact of `Class` that no rule consumed |
| `when <agent> is available` | free capacity on the agent |
| `when <agent> completed turn [as x]` | `when fact agent.turn.completed`, limited to the agent |
| `when <tracker> has ready issue as x` | an issue in a tracker that a rule can claim (Part II) |
| `when <signal.name> as x [where …]` | a declared signal, by its dotted name alone (the clock ticks in chapter 10) |
| `when fact <dotted.name> as x [where …]` | the general form |

The word `worker` in the position of a declared agent name matches the turns of
each agent. Use the `when fact` clause directly when the event that you need
has no dedicated phrase. Subsequent parts of this manual give signals,
trackers, and ingress. Each of these derives facts that the short forms in this
table do not cover.

## Where next

Chapter 13 gives agent patterns. The patterns are the watchdog, the pipeline
with a set rate, and retries as facts. Each pattern is a composition of the
constructs from Part I and Part II.
