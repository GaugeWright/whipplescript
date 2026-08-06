# WhippleScript

You can build an AI automation in an afternoon. It works.

Then the automation becomes real. A second person uses it. It reads data that
you must protect. It replies on a channel. It starts other agents. The
automation is now a distributed system, and it has the faults of one. It can
leak data. It can run forever. It can do the same paid action two times.

WhippleScript is a language for that automation. The compiler refuses to build
a workflow with these faults. The runtime makes each external action durable
and exactly-once.

> WhippleScript is a pre-1.0 product. The language, the CLI, and the provider
> interfaces can change between releases. Refer to
> [current state](docs/current-state.md) for the parts that are sufficiently
> stable to use today.
>
> The Markdown documents in this checkout apply to `main`. To find the exact
> behavior of a released CLI, use the documents from the applicable Git tag.

## Select your page

| Your position | Read |
| --- | --- |
| You know the automations that you want. You do not write code. | [Build your own automations](docs/for-builders.md) |
| You approve the tools that your staff use. | [For IT and data owners](docs/for-it.md) |
| You want to see the system as it is. | [How WhippleScript works](docs/for-developers.md) |

## What the compiler refuses to build

The invariants are the product. Each promise below has a formal model, and CI
runs each model with the `scripts/check-formal-models.sh` script.

- **A workflow that leaks.** Under a governance envelope, the compiler denies a
  value to each audience outside its set of readers. It denies untrusted content
  influence over a sink with more trust. It denies an attacker the ability to
  steer the release of his own data. The permitted crossings are explicit, and
  the source must mark each one.
- **A workflow with no way to stop.** A minimum of one rule must be able to get
  to `complete` or to `fail`. A tree of recursive agent tools must be acyclic and
  locally convergent. Non-termination is a privilege of the root only, and it
  needs an explicit `@service` tag. The compiler does not prove general
  termination, and it does not claim to.
- **A workflow that ignores a failure.** Each `case` statement on a closed
  domain must be exhaustive. An effect that fails with no observer does not stall
  the instance. The kernel fails the instance instead.
- **A workflow that pays two times.** Each effect derives a stable idempotency
  key from the identity of its firing. A retry, a recovery after a crash, and a
  replay each deduplicate against that key.

Refer to [Guarantees](docs/guarantees.md) for each promise with its model.

## The design

WhippleScript keeps two concerns apart:

- **Rules decide.** A rule is deterministic policy. It gives the next step for
  the current facts. A rule does no I/O and makes no model calls.
- **Effects do.** Agent turns, typed model decisions, requests for review, and
  child workflows are durable effects. Workers execute these effects through
  providers and record the results as events.

The result is a workflow that you can step, pause, resume, revise, checkpoint,
restore, and audit.

The language is small. It is a **Gleam-inspired syntax on a durable,
stream-backed rule engine**. The language has no arbitrary control flow. This
is deliberate. There is no `for` loop, no `while`, and no exceptions. To
branch, use `case` and pattern matching only. To fan out, let a rule fire one
time for each matched fact. To sequence steps, use a `then` chain. A `then`
chain desugars to the same rules.

This discipline is what makes the promises above possible. A language with
arbitrary control flow cannot show that a program stops, and it cannot bound the
paths that data takes. A language without it can do both. Thus the compiler
checks exhaustive branches, typed effect failures, liveness, and information
flow, and the runtime can replay the result.

The same durable kernel also runs on the edge. The `whip deploy` command sends
a workflow to a Cloudflare Durable Object. The `whip checkpoint` and
`whip restore` commands rewind a running instance to an earlier coherent point.
Refer to [Runtime & operations](docs/runtime-operations.md) for the cloud
runtime and the operator commands.

## A taste

This is a triage workflow. An agent proposes a plan for each open ticket. A
person then approves the tickets that have high severity.

```whip
rule triage_open_ticket
  when Ticket as ticket where ticket.status == "open"
  when triager is available
=> {
  tell triager as turn """markdown
  Suggest an owner and a fix plan for this ticket:

  {{ ticket.title }} (severity: {{ ticket.severity }})
  """

  after turn succeeds as triaged {
    done ticket -> record TriagedTicket {
      id ticket.id
      title ticket.title
      severity ticket.severity
      plan triaged.summary
      status "triaged"
    }
  }
}

rule request_signoff
  when TriagedTicket as ticket where ticket.severity == "high"
=> {
  then req <- file issue into approvals {
    title "Approve the triage plan for {{ ticket.id }}?"
    body "{{ ticket.plan }}"
  }

  record AwaitingSignoff {
    request req.id
  }
}

rule approve_plan
  when AwaitingSignoff as p
  when answers has ready issue as a where a.body == p.request && a.title == "approve"
=> {
  claim a as hold

  after hold succeeds {
    done p
    complete result {
      decision "approve"
    }
  }
}
```

Review by a person uses the tracker. It does not use a prompt that blocks the
workflow. The workflow files its question as a durable issue. A person answers
the issue from the shell with the `whip issue` command. The rule then reacts.
The rule can react many days later.

The equivalent in a general-purpose language is a queue, a retry loop with
idempotency keys, a receiver for the callback, a table for the state, and a
scheduler. You must also write the code that makes all five agree after a crash.
The rules above are the whole workflow.

The [tutorial](docs/tutorials/build-a-workflow.md) builds this workflow from
the start. The tutorial also runs the workflow from end to end and shows the
two approval paths.

## Install

GitHub Releases supplies prebuilt binaries:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/GaugeWright/whipplescript/releases/latest/download/whipplescript-installer.sh | sh
```

As an alternative, install from source:

```sh
git clone https://github.com/GaugeWright/whipplescript.git
cd whipplescript
cargo install --path crates/whipplescript-cli --locked
whip doctor
```

Refer to [install](docs/install.md) for Windows, checksums, and problem
correction.

## Run something

The fixture provider executes workflows deterministically and needs no
credentials. Thus you can make sure that the orchestration is correct before
you connect real agents:

```sh
whip --store .whipplescript/quickstart.sqlite \
  run examples/minimal-noop.whip --provider fixture --until idle --json
```

Then examine the run:

```sh
whip --store .whipplescript/quickstart.sqlite status <instance_id>
whip --store .whipplescript/quickstart.sqlite facts  <instance_id>
whip --store .whipplescript/quickstart.sqlite log    <instance_id>
```

## Documentation

| | |
| --- | --- |
| [Docs home](docs/README.md) | Reading paths for persons and for agents. |
| [Quickstart](docs/quickstart.md) | Install the CLI, run an example, and examine the result. |
| [Tutorials](docs/tutorials/index.md) | Run a root agent. Build a triage workflow. Govern the workflow with a signed envelope. |
| [Language reference](docs/language-reference.md) | Each construct in `.whip` source. |
| [Guarantees](docs/guarantees.md) | The invariants that the compiler and the runtime promise, with links to their formal models. |
| [CLI reference](docs/api-reference.md) | Commands, flags, exit behavior, and a compact index of source constructs. |
| [JSON reference](docs/json-reference.md) | Machine-readable reports, inspection output, and the shapes of status and event data. |
| [Diagnostics guide](docs/diagnostics.md) | Usual compiler errors and runtime errors, and their repairs. |
| [Rust API reference](docs/rust-api.md) | Crate APIs with internal stability, for contributors. |
| [Runtime & operations](docs/runtime-operations.md) | Stores, lifecycle, failures, revision, and recovery. |
| [Providers & packages](docs/providers.md) | The fixture provider, the native providers, credentials, and packages. |
| [Examples](docs/examples.md) | The catalog of checked examples. |
| [Troubleshooting](docs/troubleshooting.md) | Usual problems in a first session. |
| [Current state](docs/current-state.md) | The parts that operate today and the parts that are not yet stable. |

When you point a coding agent at WhippleScript, start the agent with
[`skills/whipplescript-author/SKILL.md`](skills/whipplescript-author/SKILL.md).

You can also serve the same Markdown documents as a site that you can navigate:

```sh
python3 -m pip install mkdocs
mkdocs serve
```

These scripts check the documents:

```sh
scripts/check-docs-quickstart.sh
scripts/check-docs-examples.sh
scripts/check-docs-snippets.sh
scripts/check-docs-site.sh
```

## The green bar

One command runs the complete check set that applies to every change, and CI
runs the same script:

```sh
scripts/check.sh
```

The Rust and Node versions are pinned in `rust-toolchain.toml` and
`.node-version`; the workflows derive their versions from those files.
[AGENTS.md](AGENTS.md) is the working guide for this repository.

## Contributing

WhippleScript is open source, but it is not open to contributions from all
persons. Issues and written diagnoses are welcome from all persons. The project
accepts pull requests only from invited contributors. Refer to
[CONTRIBUTING.md](CONTRIBUTING.md) for the policy, the reasons for the policy,
and the layout of the workspace.

## The name

A whippletree distributes a load from more than one source. WhippleScript does
the same.

## License

You can use this work under the [Apache License, Version 2.0](LICENSE-APACHE)
or under the [MIT license](LICENSE-MIT). Select the license that you prefer.

If you do not state something different, your contribution to this work is
dual-licensed as above, with no additional terms or conditions. This applies to
each contribution that you intentionally submit for inclusion, as the Apache-2.0
license defines the term.

The `scripts/check-release-readiness.sh` script runs the full release gate. The
gate includes validation of the report schemas and artifacts, and the checks of
the formal models. A Nix dev shell supplies the necessary tools: run
`nix develop`. In an environment without Nix, install the dependencies of the
Python scripts with
`python3 -m pip install -r requirements-dev.txt`.
The document [`spec/implementation-plan.md`](spec/implementation-plan.md)
records the remaining work.
