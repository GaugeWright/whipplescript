# Gauges & evidence

A test asserts a deterministic expectation one time. But the largest part of
the quality of a workflow that a model drives is not a single assertion. Was
the priority correct? Was the tone of the reply acceptable? Did the extraction
find the due date? Each of these is a dimension of quality that you observe
across many runs. A **gauge** declares such a dimension. A gauge then changes
each run into an observation.

## How to declare a gauge

```whip
gauge priority_correct {
  judge via exec "python3 ./judge_priority.py"
  expect P(ok) at least 0.9
}
```

A gauge has one **judge** slot. The slot has four granularities of ground
truth. The list below goes from the most rigorous to the least rigorous:

- `judge via exec "<command>"` — a deterministic validator. The command reads
  JSON with the context of the run on stdin. The command writes a JSON decision
  on stdout, such as `{"ok": true, "score": 1.0}`. The same
  `WHIPPLESCRIPT_EXEC_ALLOW` gate from chapter 6 governs the command.
- `judge via labels "<source>"` — ground truth from a file of labels that a
  user owns. The key is the scenario.
- `judge via coerce <Name>(<args>)` — a judge that is a model, with an explicit
  binding for each parameter. Each argument gives the record value that
  supplies the parameter. The forms are `input.<path>` and
  `facts.<Class>.<field>`. Thus a signature that changes gives a check error.
  The system never rebinds a judge silently.
- `judge via prompt "<template>"` — the model judge with the fewest
  requirements.

The sequence is important, because of the law of Goodhart. **A person cannot
persuade an exec judge or a labels judge.** A model under pressure to optimize
finds the data that a model judge likes. The model cannot find the data that
satisfies a validator that parses the output and checks the date. Use a
deterministic granularity where ground truth exists. Use the judgment of a
model only where judgment is the purpose.

An `expect` bar makes a gauge a *constraint*. A bar has one of two shapes. A
chance bar operates on a boolean field of the decision, such as
`expect P(ok) at least 0.9`. A statistical bar operates on the distribution of
the scores, such as `expect p90 at most 800` or `expect mean at least 0.7`. A
declared bar is a hard constraint for the optimizer in chapter 28.

## Derived gauges and built-in gauges

```whip
gauge triage_cost {
  judge via exec "python3 ./cost_model.py"
  inputs priority_correct, std.latency
}
```

The `inputs` clause supplies the scores of other gauges to the judge of this
gauge. Thus a composite objective and a business objective are *usual gauges*.
This design is deliberate. There is no feature for weights that you must tune.
There is only one more judged dimension.

Three gauges for resources exist with no declaration. The runtime reads these
gauges deterministically from the ledger of the run. The gauges are
`std.spend`, `std.latency`, and `std.tokens`. Each of these three descends: a
smaller value is better. The fourth gauge is `std.cache_hit`, which ascends.
This gauge exists where the provider reports the use of its cache.

## Ambient scores: each run is evidence

You do not need to run a workflow in a special evaluation mode. The `whip run`
command scores the deterministic judges that have no cost after each settled
run. The evidence then accumulates in the workspace:

```sh
whip run triage.whip --input '{"ticket":{"id":"T-1","title":"Fix login"}}'
whip gauges
```

```text
priority_correct: mean 1.0000 · N=1 (0 regen · 1 live) · passes=1
```

The reading separates two types of observation. A **live** observation comes
from a true run in the ambient stream. A **regenerated** observation comes from
a paired re-execution in chapter 27. Provenance goes with each number. A judge
that is a model never runs ambiently. Such a judge is in a `coerce` slot or in
a `prompt` slot. Such a judge needs a provider and a decision to spend money.
Thus the free stream of evidence stays free, and the expensive type of evidence
is always deliberate.

This is the evidence *plane*. The readings are durable, the scope is the
workspace, and you can attribute each reading. Chapters 27 to 29 pin, compare,
certify, and optimize against these readings.

Remember chapter 25 when you design a gauge. A test holds the property that
must always be true. A gauge measures the property that you try to make more
true. A workflow with a bar that the workflow always passes has a test in the
clothing of a gauge. A workflow that only a model judges has a target for
optimization and not a measurement.

## Where next

Chapter 27 shows how to change an interesting run into a scenario that you can
use again. The chapter gives marks as declared cut points, the `pin` construct
that freezes a case, and the `suppose` construct that asks whether a change
would have helped *in that case*.
