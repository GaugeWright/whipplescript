# Campaigns & improve

Optimization with no declared intent gives a quality regression with numbers
that appear better. A **campaign** is objective intent that has a version and
that you can diff. The campaign states the dimensions that can increase, the
dimensions that pay the cost, and the limits. The `whip improve` command is the
optimizer. The command operates strictly in the campaign.

## How to declare the trade

<!-- check: skip — names gauges the surrounding program declares -->
```whip
campaign release_tuning {
  ascend    priority_correct
  reach     std.latency at most 800ms
  guard     triage_cost within 5 percent
  sacrifice verbosity
}
```

Four verbs divide the vector of gauges. The division is total:

- `ascend` — the focus. These are the gauges that the campaign tries to
  increase.
- `reach` — a target. After the workflow meets the target, the target holds as
  a hard limit.
- `guard` — an explicit band of indifference. Here `triage_cost` can increase
  by a maximum of 5 percent.
- `sacrifice` — a gauge that the campaign releases deliberately. The evidence
  records this decision. The record of the campaign carries the sacrifice.
  Thus the statement "we traded verbosity for accuracy" is a written decision.
  The statement is not a result of an examination of the history.

**A gauge with no name in the campaign is always guarded.** There are no modes
and no weights. A gauge that you did not name cannot degrade silently. A
declared `expect` bar from chapter 26 is a hard constraint at each point. The
campaign is a declaration in the program. A person reviews the declaration, the
declaration has a version, and you can diff the declaration. This is the same
behavior as each other line of the source.

## The `whip improve` command

```sh
whip improve release_tuning --program improve-triage.whip
```

```text
campaign C-1 on `improve-triage.whip`
  tags: unheld-out (fewer than 4 pinned scenarios)
  no candidates produced (proposer exhausted)
```

The loop has these steps. A **proposer** makes candidate edits to the program.
The paired regeneration from chapter 27 then evaluates each candidate on the
pinned corpus. The regeneration replays the prefix, executes the suffix again,
and scores the gauges. The command discards each candidate that breaks a bar or
a guard. The command discards such a candidate even when the focus improved by
a large quantity. The command then ranks the candidates that stay and reports
them as a record of the campaign. Read the record with the `whip campaigns`
command and the `whip campaign <id>` command.

Two mechanisms for honesty go with each campaign:

- **The holdout set.** With sufficient pinned scenarios, the command seals a
  fraction of the scenarios from the proposer. The command uses the sealed
  scenarios only for the final score. Thus the optimizer cannot overfit to the
  corpus that it saw. With too few scenarios, the command *tags* the campaign
  as `unheld-out`. The command does not continue silently. The example above
  shows this tag. Thus the record contains the weakness.
- **The redacted view.** A `proposer redacted` clause limits the data that the
  model of the proposer sees. The `--redacted-view` flag does the same. The
  model then sees aggregate statistics only. The model never sees the input of
  a scenario, a trace, or the reasoning of a judge. The command tags the
  evidence accordingly. A flag can make a declared clause more strict. A flag
  can never make a declared clause less strict. This behavior is the position
  from chapter 22, applied to optimization: the component under pressure sees
  the minimum data that it needs.

A bare `whip improve` command with no campaign is **repair mode**. In this
mode, the command restores a bar that the workflow violated and changes nothing
else. This mode is the conservative default after a regression.

## A person adopts a candidate

The optimizer proposes a candidate. The optimizer never ships a candidate. A
person adopts a candidate that survives, and the adoption is explicit:

```sh
whip answer C-1:candidate-2 --accept --by jack
whip adopt …
```

An accepted answer becomes a durable decision that you can attribute. Chapter
29 gives these decisions as precedents. A rejected answer is equally in the
record. The division of authority is the same as in chapter 24. The machinery
collects evidence and holds the constraints. A person owns the change.

## Where next

Chapter 29 completes the story of evaluation. The chapter gives the result of
an accepted answer, which is a precedent. The chapter gives the limits on the
spend, which are the caps and the park and resume operations. The chapter also
gives the estimators. An estimator continues to monitor a settled decision
after each person stops the examination.
