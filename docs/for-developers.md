# How WhippleScript works

This page is the honest description of the system. It states the design, the
limits that the design accepts, and the artifacts that carry each claim.

## The one idea

A workflow has two parts, and WhippleScript keeps them apart.

- **Rules decide.** A rule is deterministic policy. It reads facts and it gives
  the next step. A rule does no I/O. A rule makes no model call.
- **Effects do.** An agent turn, a typed model decision, a request for review, a
  timer, and a child workflow are durable effects. A worker executes each effect
  through a provider and records the result as an event.

Thus the decision layer is a pure function of the record. You can replay it, you
can step it, and you can check it before it runs. The parts that touch the world
are the only parts that can surprise you, and each one is on durable record
first.

## The language has no arbitrary control flow

There is no `for` loop. There is no `while` loop. There are no exceptions.

- To branch, use `case` with pattern matching.
- To fan out, let a rule fire one time for each matched fact.
- To sequence steps, use a `then` chain. The chain desugars to the same rules.

This is a deliberate limit, and it is the source of the value. A language with
arbitrary control flow cannot promise that a program stops, and it cannot bound
the paths that data takes. A language without it can promise both. The compiler
checks exhaustive branches, typed effect failures, liveness, and information
flow. The invariants of the compiler are the product.

## The construct grammar

The surface syntax is small, but the language is extensible. A package declares
a construct. The construct declares its family, its lowering class, its
interface, the capabilities that it needs, and its contract version. The
compiler lowers each construct to the same kernel of facts, rules, and effects.

Thus a package cannot add a new execution mechanism. It can only add new syntax
over the mechanism that exists. There is no hidden subroutine at run time.

The `whip check` command prints the result of the lowering. For each rule, the
output gives its reads, its effects, and the dependency edges between them:

```text
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
```

The models `models/maude/construct-grammar.maude`,
`models/maude/construct-lowering.maude`, and `models/maude/construct-graph.maude`
carry the grammar and the preservation properties of the lowering.

## The formal layer

The repository holds 93 Maude models, 12 TLA+ specifications, and 12 Lean
proofs. The `scripts/check-formal-models.sh` script runs all of them in CI.

The division of the tools is deliberate. TLA+ covers the distributed properties
and the lifecycle. Maude covers the rule system and the compiler. Lean carries
the proofs that need an inductive argument, such as non-interference.

Each promise on the [Guarantees](guarantees.md) page names the model that
carries it. A model also carries its own bite: a negative fixture shows the
property fail when you remove the mechanism. A model that cannot fail proves
nothing.

## Information flow control

Under a signed governance envelope, the checker applies universal deny
properties. Each property has exactly one permitted crossing, and the source
must mark that crossing. The checker denies:

- a value to each audience outside its set of readers; the crossing is a
  `declassified` coercion, and the output schema limits it;
- the context of a turn to each provider with no clearance for the data that the
  turn read;
- untrusted data influence over a sink with more trust; the crossing is an
  `endorsed` coercion;
- data that an attacker controls the ability to steer its own release, which is
  the NMIF property;
- a field that a `redact … keep` statement dropped, which the runtime physically
  removes;
- an agent each read above the clearance of its user;
- an output of an effect influence over a sink with a `from` label above the
  vouched clearance of its executor.

Labels attach to the true resources in the policy file, not to the code. A
consumed fact gives its consumers its computed producer reach. Thus untrusted
content cannot pass through an intermediate fact with no label and lose its
provenance.

Governance is per environment. With no envelope, a whip is ungoverned, the check
makes no claim about information flow, and development has no cost.

## The durable kernel

Each effect derives a stable idempotency key from its firing identity. The
identity has the program version, the revision epoch, the rule, the binding
path, and the trigger identity. Re-evaluation, crash recovery, and replay
deduplicate against that key. A branched timeline and a restored timeline get
distinct keys. Thus a counterfactual never deduplicates against a real run.

A rule firing commits its facts, its consumed facts, its effects, and its
terminal in one transaction. An instance never observes half a firing.

A committed firing owns its trigger bindings as immutable values. A sibling rule
that consumes the trigger later cannot strand the progression.

The same kernel runs with no change in a Cloudflare Durable Object wasm isolate.
The isolate is sans-IO. Its only async primitive is `fetch`, and each effect that
uses HTTP is a step machine that can resume after an eviction. The `whip deploy`
command deploys a workflow to a Worker and a Durable Object in one operation.

## Reading paths

| Goal | Read |
| --- | --- |
| Install the CLI | [Install](install.md) |
| Install the CLI and run a checked workflow | [Quickstart](quickstart.md) |
| Learn the language fully | [The manual](manual.md) |
| Drive an agent, build a workflow, and govern the workflow | [Tutorials](tutorials/index.md) |
| Find the exact syntax | [Language reference](language-reference.md) |
| Find what the compiler and the runtime promise | [Guarantees](guarantees.md) |
| Select an example that is known to be good | [Examples](examples.md) |
| Run instances or examine instances | [CLI reference](api-reference.md) |
| Use machine-readable output | [JSON reference](json-reference.md) |
| Use the Rust crates | [Rust API reference](rust-api.md) |
| Understand errors | [Diagnostics guide](diagnostics.md) |
| Operate workflows that run now | [Runtime & operations](runtime-operations.md) |
| Configure agents, providers, and packages | [Providers & packages](providers.md) |
| Correct a first run that fails | [Troubleshooting](troubleshooting.md) |
| Find the stability and the limitations | [Current state](current-state.md) |

Design records and implementation trackers stay internal, and you do not need
them for usual authoring. The repository publishes the machine-readable report
schemas at
[`spec/report-schemas/`](https://github.com/jamesjscully/whipplescript/tree/main/spec/report-schemas).

## The route for a coding agent

Use this route when the task is to write a workflow or to correct a workflow.

1. Read
   [`skills/whipplescript-author/SKILL.md`](https://github.com/jamesjscully/whipplescript/blob/main/skills/whipplescript-author/SKILL.md).
   The companion skill has the route map, the table that helps you select
   features, the canonical patterns, and the command loop.
2. Select the nearest checked example from [Examples](examples.md).
3. Use the [Manual](manual.md) to select the pattern.
4. Use the [Language reference](language-reference.md) only for the exact
   grammar.
5. Validate the workflow with `whip check` and with a `whip run` command that
   uses the fixture provider.
6. Examine the runtime state with the `status`, `effects`, `runs`,
   `diagnostics`, and `evidence` commands, and with `trace --check`. Do this
   before you change a prompt.

## The documents

The Markdown files stay canonical. Thus an agent can navigate them without a
build of the site. To serve the same files as a site, run these commands from
the root of the repository:

```sh
python3 -m pip install -r docs/requirements.txt
mkdocs serve
```

These scripts check the site and the documents that show complete workflows or
cataloged example commands:

```sh
scripts/check-docs-site.sh
scripts/check-docs-quickstart.sh
scripts/check-docs-examples.sh
scripts/check-docs-snippets.sh
```

The documents use this convention for code blocks:

- An `sh` block contains commands that you can run. An `sh` block with a
  placeholder such as `<instance>` is an exception.
- A `whip` block is complete source in two conditions only. The text introduces
  the block as a full file, or one of the scripts above covers the block.
- A `json` block or a `text` block shows output, or the shape of a schema or a
  diagnostic. The adjacent text can tell you to save the block as input.
- The `...` symbol and the angle-bracket placeholders identify a fragment that
  is an illustration only.

Put each complete workflow example in `examples/`, or make sure that one of the
scripts above covers the example.

## Version scope

The Markdown in this repository applies to the most recent released line of the
CLI. The published CLI version is `0.2.1`. If the exact CLI flags or the exact
JSON fields are important, read the documents from the applicable Git tag. The
`whip --help` command prints an implementation-stage label. That label is an
internal marker of progress. It is not a different compatibility version.
