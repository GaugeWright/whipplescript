# Progressions

Chapter 15 ended with a sentence that needs a full chapter: **a firing that
commits completes**. This chapter gives the semantics behind that sentence. It
gives the definition of a progression, the data that a progression captures,
and the events that can and cannot stop a progression. The chapter then
introduces the construct for the one type of stop that exists deliberately: the
`during` region and the `until` region.

## A binding is a value

When a rule fires, the runtime captures each matched item **as a value**. The
firing owns its bindings for the remainder of its life. The match operation
decides when a progression *starts*. The match operation never decides if a
progression completes. This program shows the two halves of that statement:

```whip
workflow Consumed

output result Done

class Job {
  id string
}

class Taken {
  id string
}

class Worked {
  id string
}

class Done {
  note string
}

table jobs as Job [
  {
    id "j-1"
  }
]

rule slow_path
  when Job as j
=> {
  timer 1s as t

  after t completes {
    record Worked {
      id j.id
    }
  }
}

rule fast_path
  when Job as j
=> {
  done j -> record Taken {
    id j.id
  }
}

rule finish
  when Worked as w
  when Taken as k
=> {
  complete result {
    note "both paths ran"
  }
}
```

The two rules match the same `Job` fact. The `fast_path` rule consumes the fact
immediately. At that moment, the `slow_path` rule is in the middle of its
timer. Run the program:

```text
status completed
```

The `Worked` fact and the `Taken` fact each exist, and the join completes. The
consume operation of the `fast_path` rule did its function: the operation
prevents the `Job` fact from admitting a *new* firing. The operation did not do
an operation that it cannot do: the operation did not stop the progression of
the `slow_path` rule, because that progression already committed. The
progression completed from its captured `j` binding, long after the trigger
went away. The same behavior applies when the trigger is a projection. The
round trip in chapter 15 finishes the ready issue that admitted the rule, and
the remainder of the chain still runs.

Three limits complete the model:

- **A guard is a predicate for admission.** The runtime evaluates a `where`
  clause one time, when it admits the firing. The clause is then spent. The
  clause never evaluates again during the progression. If you want a guard that
  continues to guard, use the syntax below. That intent has its own syntax.
- **A query stays live in each location.** The `count(…)`, `exists(…)`, and
  `empty(…)` functions read the world at the *present* time. This behavior
  applies in each expression that contains such a function. These functions are
  the explicit construct of the language that looks at the present. The capture
  of the bindings does not freeze these functions.
- **The firing also owns its code.** If a person revises the program while a
  progression is open, the open firing completes under the rule body that
  admitted the firing. The new body governs the new admissions. Nothing changes
  below a progression. Its bindings do not change, and its rules do not change.

## How to see the progressions: the `whip progressions` command

Each firing is durable state. Each firing has a surface for inspection:

```sh
whip progressions ins_81f3d6…
```

```text
fir_1d5687f5e0ed  rule=trouble  admitted=#2  state=effects-settled
  effect   key_0debf308… timer.wait (completed)
fir_b8a1a19416f9  rule=ship  admitted=#3  state=closed(terminal)
  region   lapsed (exists(Incident where sev == "sev1"))
  trigger  j = Job {"id":"j-1"}
  effect   key_0d402009… timer.wait (completed)
```

Each firing shows the bindings of its captured trigger, the effects that it
requested with their live statuses, and its state. The states are
`open(effects-pending)`, `effects-settled`, and `closed(terminal)`. This
chapter introduces two more states below. Sometimes a different rule consumed
the pinned trigger fact of an open firing. In that condition, the view states
this explicitly. The annotation is
`trigger no longer live; consumed by <rule> at #<seq>`. In the `--json` output,
the field is `stale_triggers`. This annotation answers the question of the
operator: why does this progression still run work for a fact that is absent?
When an instance is idle and the reason is not known, use this view. The view
gives the item that each progression waits for.

Sometimes a stale trigger must *change the course of the firing* and not only
be visible. The language gives two remedies. Put a live query in the guard of
the late `after` arm. Then the rule reacts at the moment of the action. As an
alternative, put the full progression in an `until` region, which the next
section gives. The region then lapses the progression deliberately. The
"Handling cross-rule retraction" section of the
[language reference](../language-reference.md) gives the two remedies.

## Explicit reactivity: the `during` region and the `until` region

Sometimes a progression *must* stop when the world changes. A deploy must not
continue into a sev-1 incident. A guard deliberately cannot do this. Thus the
intent has first-class syntax. The construct is a **region**.

```whip
workflow Deploy

output result Done
failure error Halted

class Incident {
  sev string
}

class Done {
  note string
}

class Halted {
  reason string
}

rule trouble
  when started
=> {
  timer 2s as spark

  after spark completes {
    record Incident {
      sev "sev1"
    }
  }
}

rule ship
  when started
=> {
  until exists(Incident where sev == "sev1") {
    then plan <- timer 1s
    then approved <- timer 6s
    complete result {
      note "shipped"
    }
  } on lapse as got {
    fail error {
      reason "halted mid-deploy"
    }
  }
}
```

The timers replace true work. In production, the steps are agent turns and
coercions. Usually a deploy is also under a lease from chapter 14. The
mechanics are identical.

The `until <cond> { … }` region runs its steps only while the condition is
false. The `during <cond>` region is the opposite polarity. Its steps run while
the condition is true. The condition is a pure query expression. Its grammar is
the grammar of a guard. But a region condition is different from a guard. The
runtime checks the condition again **in each pass in which the region is open**,
and the check is atomic with the commit that it produces. There is no period
between the check and the action. There is no interleaved pass that can race.
Each commit of a step either found the condition intact or did not commit.

The runtime checks the condition also in a pass in which no step can advance,
because each effect of the region is still in operation. This behavior is the
purpose of the construct: a region halts a deploy that runs at this moment.

When an evaluation finds the condition broken while the region still owes work —
an action that did not run, or an effect that did not settle — the commit
commits the **lapse** instead. A break that arrives after the last action of the
region committed lapses nothing. Each part of the lapse occurs as one atomic
unit:

- the mandatory `on lapse { … }` arm runs. A region with no declared result
  does not compile;
- a durable `progression.region.lapsed` fact records the lapse, with the text
  of the condition and the time;
- the runtime cancels the effects of the region that are in progress. The steps
  of the region that the runtime did not yet request never start.

Run the program above. The incident occurs at two seconds. At that time, the
`plan` step settled and the `approved` step is in progress:

```text
instance ins_81f3d6… failed
```

```text
progression.region.lapsed ship:started {"condition":"exists(Incident where
sev == \"sev1\")","got":{"plan":{…}},"steps":{"plan":"completed",
"approved":"cancelled_by_lapse"},"until":true,…}
```

The instance failed with the typed reason of the arm. The `approved` effect
shows the `cancelled` status in the ledger of the effects. The lapse fact is
available for each subsequent audit. The behavior occurs exactly one time. A
region lapses one time or completes one time. A region never does both, and a
region never does either two times.

## The progress view

The lapse arm has a scoping rule, and the checker applies the rule. The arm can
reference only a binding from a position *before* the region. The region itself
introduces the `plan` binding and the `approved` binding. These bindings can be
absent at the moment when the arm runs. Thus a direct reference to one of these
bindings is a compile error:

<!-- render: examples/diagnostics/lapse-arm-scope.whip code expr.binding_out_of_scope -->
```text
error[expr.binding_out_of_scope]: the `on lapse` arm of rule `ship` references `plan`, a binding the region introduces — it may not exist when the arm runs
   --> examples/diagnostics/lapse-arm-scope.whip:37:4
   |
37 | => {
   |    ^
   = help: reference only bindings from before the region, or bind the progress view (`on lapse as got`) and read `got.<binding>` — its fields are present exactly if that step settled
```

The permitted method to see the progress is the **progress view**. The
`on lapse as got` clause binds a record. The fields of the record are the step
bindings of the region. Each field is present exactly when its step **succeeded**
before the lapse. In the run above, `got.plan` exists, because the step of one
second completed. The `got.approved` field does not exist, because the runtime
cancelled that effect during its operation. A step that failed or that timed out
is equally absent from the view, as a step that never ran is.

To tell those apart, read `got.steps`. The view reserves that one field for the
**status of each step**:

<!-- check: skip — the tail of a region opened in the fence above -->
```whip
  } on lapse as got {
    case got.steps.plan == "failed" {
      record Escalation {
        note "the plan step failed before the incident"
      }
    }

    fail error {
      reason "halted mid-deploy"
    }
  }
```

A status is one of `completed`, `failed`, `timed_out`, `cancelled`,
`cancelled_by_lapse` for a step that the commit of the lapse itself stopped, and
`not_requested` for a step that the region never reached. Thus an escalation arm
distinguishes "that step failed" from "that step never ran" without a query.

The checker types the whole view. A field that is neither a step of this region
nor `steps` is a compile error, and so is a path through a status, because a
status is a string:

<!-- render: examples/diagnostics/progress-view-field.whip code type.unknown_field -->
```text
error[type.unknown_field]: rule `ship` has invalid field path `got.plna`: schema `region.ship.Progress` has no field `plna`
   --> examples/diagnostics/progress-view-field.whip:37:4
   |
37 | => {
   |    ^
   = help: did you mean `plan`? otherwise use a field declared on the bound schema or add it to the class declaration
```

The runtime pins the statuses in the same commit as the values, so a step that
settles after the lapse changes neither. Read a step's value with the machinery
for an optional value from chapter 3. Use `exists got.plan` to branch. Then use
`got.plan.status` under that guard to get the value. The runtime pins the view
**at the time of the lapse**, in the lapse fact. Thus an effect that settles
after the lapse can never change the data that the arm saw.

## The point of no return

The boundary of the region block is a statement of intent. A step *in* the
block stops when the condition breaks. A statement *after* the block reads no
condition. Usually a deploy that started to apply changes must complete the
application. Thus the apply step goes after the region. The apply step chains
on the results of the region:

<!-- check: skip — a region whose steps call the surrounding program's coercion -->
```whip
  until exists(Incident where sev == "sev1") {
    then plan <- tell deployer "Plan the deploy."
    then approved <- coerce reviewPlan(plan.summary)
  } on lapse {
    fail error { reason "halted before apply" }
  }

  then applied <- tell deployer "Apply: {{ approved.plan }}"
  complete result { note applied.summary }
```

One reminder from chapter 5 keeps this honest. The sequence of the source
orders nothing. The chain after the region runs after the region because the
chain *depends on* the `approved` binding. The chain does not run after the
region because the chain is lower in the source. A statement after a region
with no data dependency on the region is concurrent with the region, as always.

## A break that heals

The runtime checks a condition at a commit. The runtime does not monitor the
condition on a wall clock. Sometimes an incident opens and closes while a step
of a region still runs. If no evaluation observed the broken condition,
**no lapse occurs**. This behavior is the deterministic reading. The outcome is
a function of the commit log and never a function of the timing.

The window is narrow. The window is **one pass**, and not one step. The runtime
evaluates the condition in each pass in which the region is open. Thus an
incident that stands at the boundary of a pass lapses the region, also when each
effect of the region still runs and the incident closes a moment later. An
incident that opens and closes inside one pass is the case that heals. The audit
trail still shows the full lifecycle of the incident in each case.

Sometimes you want a stronger behavior: each incident, at any time, must stop
the deploy for good. In that condition, put the condition on a durable fact that
nothing consumes. Use `until exists(IncidentOpened)`, where the program records
the `IncidentOpened` fact one time and never uses a `done` statement on the fact.
The reactivity that you get is exactly the reactivity of the facts that you
select.

## A limit on time and a limit on the world

The watchdog in chapter 13 and the regions in this chapter are complements.
They are not competitors. A **watchdog** limits a progression by *time*. A
timer races against the work, because the condition of a region is a query on
facts and not a clock. A **region** limits a progression by *the state of the
world*. An incident, a stop on the budget, and a cancellation fact are
examples. A careful deploy uses the two constructs: a timer for the deadline
around the full progression, and a region around the steps that are sensitive
to a stop.

## How an operator closes a progression

A progression is a first-class item. Thus an operator can end one progression
without a stop of the instance:

```sh
whip progressions ins_b2866c…              # find the firing
whip progression cancel ins_b2866c… fir_3233a0548de7 --reason "operator says stop"
```

```text
fir_3233a0548de7 cancelled (rule=work effects_cancelled=1)
```

The runtime cancels the outstanding effects of the firing. A durable
`progression.cancelled` event closes the firing. The firing never advances
again. The identity of its trigger never admits the firing again. The firing
and the identity stay the same. The instance continues to run. The lapse arm
does **not** run. The abandonment by an operator is a decision from outside the
program. The abandonment is not a condition that the program declared. The
equivalent at one level lower is the `whip cancel` command.

## Where next

A region reacts to facts. To this point, the workspace made each fact. Chapter
17 opens the doors. The chapter gives messages that go out through a channel,
and signals that come in through ingress. Usually the incident that breaks the
condition of a region comes from ingress.
