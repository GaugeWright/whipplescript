# Quickstart

Run a workflow and examine the result. This procedure takes approximately five
minutes. All the steps use the deterministic fixture provider. Thus you do not
need agent credentials.

The terms "fact", "rule", and "effect" can be new to you. The first chapters of
the [manual](manual.md) teach these terms fully. This page only starts a
workflow.

## 1. Install

```sh
git clone https://github.com/jamesjscully/whipplescript.git
cd whipplescript
cargo install --path crates/whipplescript-cli --locked
whip doctor
```

The [install](install.md) page gives the prebuilt binaries and the data for
each platform. To find how to use a command, run `whip help <command>`.

## 2. Check a workflow

```sh
whip check examples/multi-agent-bounded-concurrency.whip
```

The `check` command parses the source, type-checks the source, and lowers the
source. The command then prints a summary of the compiled program. The summary
gives the source tags and the descriptions, the declared trackers and agents,
and data for each rule. For each rule, the summary gives its reads, its
effects, and the dependency edges between them. The example below is shortened.
The true output prints each rule fully:

```text
== examples/multi-agent-bounded-concurrency.whip
workflow MultiAgentBoundedConcurrency
source_tags
@service workflow MultiAgentBoundedConcurrency
trackers
  tracker backlog provider=builtin
agents
  agent implementer harness=<fallback> provider=codex profile=repo-writer capacity=2 ...
  agent reviewer harness=<fallback> provider=claude profile=repo-reader capacity=1 ...
rules
  rule implement_ready_work
    reads
      pattern:backlog has ready issue as issue
      pattern:implementer is available
    effects
      active_claim kind=tracker.claim binding=active_claim key=...
      turn kind=agent.tell binding=turn key=...
      effect3 kind=tracker.finish binding=- key=...
    dependencies
      active_claim --succeeds--> turn
      turn --succeeds--> effect3
  rule review_completed_turn
    ...
```

The `check` command also applies two static liveness rules. Each workflow must
be able to get to `complete` or to `fail`. Each read of each rule must be
producible. Refer to
[liveness checks](language-reference.md#liveness-checks).

## 3. Run a workflow

The `run` command starts an instance, steps the rules, executes the effects
with the fixture provider, and evaluates the assertions. The command does these
operations in a loop until the instance becomes idle:

```sh
mkdir -p .whipplescript
whip --store .whipplescript/quickstart.sqlite \
  run examples/minimal-noop.whip \
  --provider fixture \
  --until idle \
  --json
```

Make a note of the `instance_id` in the output. These are the important parts
of the report:

```json
{
  "workflow": "MinimalNoop",
  "instance_id": "ins_...",
  "steps": [
    {"committed_rules": 1, "facts_created": 1, "effects_created": 0}
  ],
  "workers": [
    {"provider": "fixture", "ran_effects": 0}
  ]
}
```

One rule fired and recorded one fact. The workflow then ran
`complete result { ... }`. Thus the instance is complete.

## 4. Examine the run

Each command that touches an instance takes the same `--store` value that
created the instance. As an alternative, set `WHIPPLESCRIPT_STORE` one time.

```sh
whip --store .whipplescript/quickstart.sqlite status <instance_id>
whip --store .whipplescript/quickstart.sqlite facts  <instance_id>
whip --store .whipplescript/quickstart.sqlite log    <instance_id>
whip --store .whipplescript/quickstart.sqlite --json trace <instance_id> --check
```

The `status` command reports the instance as `completed`. The `facts` command
shows the recorded fact:

```text
StartupSeen StartupSeen:... {"source":"external.started","state":"observed"}
```

The `trace --check` command replays the lifecycle of the effects against the
conformance model of the runtime. The command then reports
`"conformance": {"ok": true}`.

## 5. The parts of the `run` command

The `run` command is a composition of three commands. You can also run these
three commands separately:

```sh
# start an instance (records the start event, nothing else)
whip --store .whipplescript/quickstart.sqlite \
  start examples/minimal-noop.whip

# advance deterministic rules for that instance
whip --store .whipplescript/quickstart.sqlite \
  step <instance_id> --program examples/minimal-noop.whip

# execute any ready effects through a provider
whip --store .whipplescript/quickstart.sqlite \
  worker <instance_id> --provider fixture
```

This separation becomes important when a workflow waits for a real agent or for
input from a person. The instance is durable. Thus the `step` command and the
`worker` command can run later, from a different process, or after a restart.

## Next

- The [tutorials](tutorials/index.md) give more detail. They drive a root
  agent, build a workflow from the start, add an approval gate for a person,
  and complete an instance.
- The [examples catalog](examples.md) gives the subject that each supplied
  example shows.
- The [language reference](language-reference.md) gives each construct.
