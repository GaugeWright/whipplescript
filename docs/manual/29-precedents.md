# Precedents, spend & estimators

The last three chapters built a machine for evidence. This chapter shows how to
live with the machine across time. The chapter gives decisions that persist,
budgets that bind, and the statistics that find an old decision that stopped
being true.

## Precedents: a decision with provenance

The `whip answer <campaign>:<candidate> --accept --by <who>` command from
chapter 28 does more than a merge operation. An accepted answer is a
**precedent**. A precedent is a durable record. The record binds *the change*,
*the campaign evidence that the change survived*, *the person who accepted the
change*, and *the time*. A precedent is history that you can query. When a
gauge moves in the subsequent quarter, the question "which accepted change
touched this dimension?" is a lookup. The question is not an examination of the
history. You can also revoke a precedent by the same method that made it:

```sh
whip answer C-7:candidate-2 --revoke --by jack
```

A revocation is also a recorded decision. The lifecycle of a precedent permits
append only. This is the behavior of each other item in the workspace. The
position is the same as the tracker provenance in chapter 15 and the trusted
surface in chapter 24. Each acceptance with a consequence is a first-class
object that you can attribute.

## Spend: caps that truly bind

A model judge costs money. A proposer costs money. Thus the evaluation
machinery treats the spend as a governed resource. The machinery does not treat
the spend as a hope:

- **A price is configuration.** The `prices` block of the provider
  configuration maps a provider and a model to a value in USD for each Mtok.
  The usage with a price accumulates into `std.spend`, which is a built-in
  gauge from chapter 26. Usage with no price records a cost of 0. Thus usage
  with no price *cannot bind a cap*. The system states this behavior and does
  not hide it. A provider with no price makes a cap advisory. Put a price on
  each item that you meter.
- **A cap parks work. A cap never truncates work.** The
  `whip improve … --spend-cap $5` flag limits one invocation of a campaign. A
  campaign that gets to its cap **parks**. Its state, its candidates, and its
  evidence stay intact. The `whip improve --resume <campaign-id>` command
  continues the campaign later with a new allowance. A budget boundary is a
  pause. A budget boundary is never a silently smaller evaluation.

The same `std.spend` gauge composes with each other construct. A campaign can
use `guard std.spend within …`. A bar can hold the p90 latency. Thus the trade
between quality and cost is a *declared* trade, as each other trade is.

## Estimators: the numbers behind the decisions

Each probabilistic readout in Part IV comes from two small Bayesian estimators.
The readouts are the `P(better)` value in a suppose operation and the
`P(bar met)` value in a settle operation. The estimators are honest at a small
N:

- **Pass and fail evidence** uses a paired sign test. A win is a pair that
  favors the change. A loss is the opposite. A tie gives no information. Thus
  one pair with a tie reads `P(better)=50%`. One agreement is not evidence.
  The estimator is defined from the first pair. Thus an early reading is honest
  and not absent.
- **Continuous evidence** uses a Student-t posterior on the paired deltas. The
  estimator needs a minimum of two deltas, because one delta gives no scale.
  The refusal to estimate from one point is deliberate.

## The reopener: a settled decision is not permanent

The system continues to monitor a settled decision from chapter 27. Live
evidence continues to accumulate ambiently. Sometimes the posterior against a
settled decision becomes strong *and stays strong*. In that condition, the
probability that the decision is now incorrect is high, and the probability
does not decrease across consecutive informative observations. The
**contradiction reopener** then flags the decision:

```text
⚠ contradicts answered call <id>: P(worse than <bar>)=81% and tightening
  · N=… since the answer — reopen, or revoke with `whip answer`
```

The flag appears in the `whip gauges` output and in the gauge evidence view,
which is the `whip evidence <gauge>` command. The flag gives the name of the
answered decision and the path to a revocation.

The trigger is deliberately for a sustained condition only. A spike that
decreases never gives a flag. The reopener is also **advisory only**. The
reopener has no authority to revoke. The reopener tells a person that reality
changed. The adoption discipline from chapter 28 then makes the decision again.
The loop closes at its start: a person owns each decision. The machinery makes
sure that a decision never quietly continues after its evidence stops.

## Where next

Chapter 30 completes Part IV with the detail on observability. The chapter
gives the surfaces for inspection that you used to this point: `status`,
`facts`, `log`, `effects`, and `progressions`. The chapter also gives
conformance tracing, lint, and the export of telemetry.
