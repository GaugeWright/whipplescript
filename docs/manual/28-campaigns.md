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
  scenarios only for the promotion check. This limits one route for fitting to
  visible cases; it does not prove that a change will generalize. Repeated
  promotion checks also wear out a seal. With too few scenarios, the command
  *tags* the campaign as `unheld-out`. The command does not continue silently.
  The example above shows this tag. Thus the record contains the weakness.
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

## Improve the whole admitted harness

The native proposer can change more than prompt text in a `.whip` file. It may
change rules, agent instructions, tool use, and control flow, subject to the
program's gauges and compiler checks. To include project instructions, skills,
or documents an Agent reads through file tools, put the `.whip` file outside a
dedicated context directory and admit that directory explicitly:

```sh
whip improve release_tuning --program agent.whip --context-root ./agent-context --provider owned
```

Every regular UTF-8 file under that root becomes part of the versioned
candidate. The current limit is 64 files, 64 KiB per file, and 256 KiB in
total; symbolic links are refused. The proposer may add, replace, or delete
files. Baseline and candidate evaluations use separate materialized copies, so
an unadopted proposal does not edit the live directory. The program and all
admitted files must still match the campaign's baseline when you adopt. A
campaign evaluating an Agent should use its actual provider binding; `owned`
is the local Managed provider in this example. A fixture provider is useful for
contained tests but cannot establish how the deployed Agent will respond. A
marked scenario uses input replay on both sides of a context campaign, because
its frozen prefix might already have read the old context; the evidence says
`context-input-replay`. A global context directory is not captured by this
flag. See the [`improve` reference](../api-reference.md#improve) for the exact
limits and refusals.

Each native proposal states one testable mechanism, the declarations and
resource paths it expects to change, and the gauges it expects to improve.
The campaign card shows the actual changed declarations and files beside that
account. An `edit-account-mismatch` warns that the account omitted a change;
it does not prove that the proposal contains independent mechanisms. Before
open-case evaluation, a semantic shortcut critic looks for case-specific
dependencies in the new source or context. A finding must cite a newly added
excerpt, and its judgment is advisory. A verified clear finding may trigger
one generalizing revision; both the finding and the revision remain in the
campaign record. An unavailable critic is recorded as unassessed, not clean.
Neither the proposer nor the critic receives sealed scenario contents.

A broad native draft may receive one scope refinement before scoring. For a
resource-focused deletion, a passing narrower revision does not automatically
discard a draft that removes more declarations: the loop can evaluate both on
open cases, charge the extra evaluation to the campaign, and keep the original
only if it also clears the baseline gates and dominates the revision. The
campaign record shows that comparison. Only the selected source reaches the
sealed promotion check.

For a useful campaign, pin cases that exercise the behavior you want and its
important guards, run `whip improve`, then inspect `whip campaign <id>` and
the candidate cards before adopting. Keep different cases outside the
campaign for a later transfer check. An open-case gain, a sealed promotion,
and an `unheld-out` tag make different evidence claims. None substitutes for
checking the adopted behavior on later work.

## A person adopts a candidate

The optimizer proposes a candidate. It does not apply it. A person reviews the
card and explicitly adopts a proposed candidate:

```sh
whip campaign C-1
whip adopt C-1:K-2 --program agent.whip
```

If the system instead surfaces a **tradeoff**, a person can accept or reject
that tradeoff with `whip answer C-1:K-2 --accept|--reject --by jack`. An
accepted tradeoff then becomes adoptable and sets a revocable precedent; an
ordinary proposed candidate does not need an `answer`. Chapter 29 explains
precedents. The division of authority is the same as in chapter 24. The
machinery collects evidence and holds the constraints. A person owns the change.

## Where next

Chapter 29 completes the story of evaluation. The chapter gives the result of
an accepted answer, which is a precedent. The chapter gives the limits on the
spend, which are the caps and the park and resume operations. The chapter also
gives the estimators. An estimator continues to monitor a settled decision
after each person stops the examination.
