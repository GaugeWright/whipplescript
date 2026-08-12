# Marks: pin, suppose & settle

Chapter 26 made each run an observation. This chapter makes an interesting run
*reusable*. A *mark* declares the position of the important moments in a run. A
*pin* freezes a true run at one moment. The `suppose` command re-executes only
the part that you changed. This command is the instrument for a paired
comparison. The remainder of Part IV uses this instrument.

## Marks: a cut point as a part of the program

<!-- check: skip — rides a gauge site the surrounding program declares -->
```whip
mark "assessed" after triage
```

A `mark` declaration gives a name to the moment when the `triage` rule commits.
On each run, the runtime stamps a `mark.reached` event *in* that commit. Thus
the coordinate can never be lost between a commit and a separate append
operation. The name is stable across an edit of the program. A raw event offset
is not stable across an edit.

A mark is deliberately different from a milestone in chapter 18. A milestone is
a signal about the lifecycle to a parent that observes the child. A mark is a
position in the event log for an evaluation. Declare a mark at each position
where you want to stand when you ask this question: what if the remainder had
been different? Good positions are after the intake, after the judgment, and
before the step with a high cost.

## The pin operation: each past run becomes a scenario

A mark stamps each run. Thus the capture is **retroactive and ambient**. You
never decide in advance which run is important:

```sh
whip pin ins_8b3f28… at assessed --as login-case
```

```text
pinned `login-case` from instance ins_8b3f28… at mark `assessed` (cut seq 4)
```

The pin freezes the *prefix* of the run. The prefix is each item to the mark.
The prefix includes the true inputs and the true outcomes of the effects. The
pin gives a name to the prefix. A library of pinned scenarios is a corpus for
regression tests. The corpus contains production reality and not fixtures that
a person wrote.

Note one discipline that the pin machinery applies. The marked rule must
consume or advance its trigger. This is the idiom from chapter 13. If the rule
does not, the replayed prefix cannot hold the cut faithfully. The pin then
degrades to a replay of the input, and the command says so loudly.

## The suppose operation: paired regeneration at the cut

The `suppose` command answers the one question that isolates a change cleanly:
on this exact case, is the current program better?

```sh
whip suppose login-case --program improve-triage.whip
```

```text
suppose `login-case` (prefix-replay)
  priority_correct: 1.0000 -> 1.0000 ✓ · P(better)=50% · N=1 pair
  · replay: prefix-replay: 4 events replayed, 0 refires
```

The command *replays* the frozen prefix. A replayed effect never fires again.
Thus the replay spends nothing and drifts nowhere. This behavior is the replay
honesty from chapter 21, in use. Only the suffix executes again, under the
current program. The gauges score the regenerated suffix. The reading is
**paired**: the old score against the new score on the same case. The
`P(better)` value is a Bayesian readout on those pairs. The test is a sign
test. One pair with a tie gives no information, and thus the readout is 50%.
The value becomes more precise when more pairs accumulate across your pinned
scenarios. A regenerated reading enters the evidence plane with the `regen`
tag. Thus you can never confuse a regenerated reading with a live reading.

## The settle operation: how to certify a gauge

Accumulated evidence eventually needs a *decision*: does the workflow truly
meet the bar of this gauge? The `settle` command does the certification:

```sh
whip settle priority_correct --program improve-triage.whip
```

```text
settle priority_correct: undetermined (no informative readings at N=0 · level 0/3)
  · a full pass over 1 pinned scenario added no net evidence — pin more
    scenarios (whip pin) or revisit the bar
```

The `settle` command evaluates the gauge again across the pinned corpus. The
command uses levels that increase. The command stops early when the decision is
already known. The honesty of the command is its purpose. With one scenario
that gives no information, the command reports *undetermined*. The command then
tells you the evidence that is missing. The command never gives an empty pass.
A settled bar has a high `P(bar met)` value across the levels. Such a bar is
the strongest claim of the evidence plane. The estimators in chapter 29 then
continue to monitor the bar.

## The loop that these commands make

Mark the position of the judgment. Let the workflow run in production. Pin each
run that surprised you. Change the program. Run the `suppose` command on each
pinned case. Run the `settle` command when the corpus is sufficient. Each step
is durable and you can attribute each step. Each step also has a low cost in
the important dimension, because a replayed prefix spends nothing. Chapter 28
makes the middle of this loop automatic.

## Where next

Chapter 28 gives campaigns. A campaign declares the gauges that can improve and
the gauges that pay the cost. The chapter also gives the `whip improve`
command. This command is the optimizer. The command holds your bars while it
searches.
