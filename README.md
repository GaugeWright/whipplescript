# WhippleScript

**Vibe-code the workflow. Let the compiler decide whether it is safe to run.**

Describe the automation you want and let an agent write it. WhippleScript is
the language it writes in — and the language will not compile a workflow that
leaks protected data, spends twice, or has no way to stop. You do not have to
read the generated code closely to trust it. You read the report the compiler
prints about it, and the compiler enforces the report on every line.

[Documentation](https://docs.whipplescript.com/) ·
[Quickstart](docs/quickstart.md) ·
[Guarantees](docs/guarantees.md) ·
[For IT and data owners](docs/for-it.md)

> WhippleScript is a pre-1.0 product. The language, the CLI, and the provider
> interfaces can change between releases. Refer to
> [current state](docs/current-state.md) for the parts that are sufficiently
> stable to use today. The Markdown documents in this checkout apply to `main`.
> To find the exact behavior of a released CLI, use the documents from the
> applicable Git tag.

## The afternoon automation, and the day after

You can build an AI automation in an afternoon. It works. Then the automation
becomes real. A second person uses it. It reads data that you must protect. It
replies on a channel. It starts other agents. The automation is now a
distributed system, and it has the faults of one. It can leak data. It can run
forever. It can do the same paid action two times.

That day is the reason your IT department says no to the automation an agent
wrote for you in twenty minutes. Nobody could say what the automation would do
with the data. A prompt is not a control, and a code review does not scale to
the rate at which agents now write code.

WhippleScript answers the question with a compiler. Your data owner signs one
policy file that puts labels on the true data sources. Everybody else then
writes workflows freely, at whatever speed they like, and the compiler holds
each one to the policy before it runs.

## Five minutes

Install the CLI:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/GaugeWright/whipplescript/releases/latest/download/whipplescript-installer.sh | sh
```

Run a workflow. The fixture provider executes deterministically and needs no
credentials, so the orchestration is correct before you connect a real agent:

```sh
whip --store .whipplescript/quickstart.sqlite \
  run examples/minimal-noop.whip --provider fixture --until idle --json
```

Examine the run:

```sh
whip --store .whipplescript/quickstart.sqlite status <instance_id>
whip --store .whipplescript/quickstart.sqlite facts  <instance_id>
whip --store .whipplescript/quickstart.sqlite log    <instance_id>
```

Refer to [install](docs/install.md) for Windows, checksums, prebuilt binaries,
and problem correction, and to the [quickstart](docs/quickstart.md) for the
same walk with each command explained.

## What a workflow looks like

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
The rule can react many days later, on a different machine, after a crash.

The equivalent in a general-purpose language is a queue, a retry loop with
idempotency keys, a receiver for the callback, a table for the state, and a
scheduler. You must also write the code that makes all five agree after a
crash. The rules above are the whole workflow. The
[tutorial](docs/tutorials/build-a-workflow.md) builds this one from the start
and runs both approval paths.

## Why you do not have to read it closely

Put the same job under a signed governance envelope. The envelope labels the
*true* data sources, not the variables in any program:

```text
grant file_store crm    -> file:/srv/crm.db          readable by Operator from Operator
grant file_store inbox  -> maildir:/var/mail/support readable by public   from public
grant channel public_reply -> smtp:out               readable by public   from public
```

Now the obvious workflow — read the customer record, read the inbound email,
reply, file the note — does not compile:

```text
error: denied flow in rule `triage`: `crm` may be read by Operator only —
  writing it to `public_reply` (readable by public) would expose it to parties
  outside its readers
   --> examples/infoflow/support-triage-unsafe.whip:43:4
  = help: self-serve (no grant needed): separate the contexts — read `crm` in a
    distinct turn and pass only a bounded result. escalate (needs governance):
    route the release through a `coerce … declassified` whose output is the
    egress's whole payload, under `grant declassify crm to <role>`

error: denied influence in rule `triage`: `inbox` is untrusted (integrity
  public) — it can never influence `crm`, which only Operator-vouched data may
  shape
```

The refusal arrives before the workflow runs, not during an incident, and it
names the two repairs: restructure the workflow, or ask for a grant that puts
the crossing on the record. The same job written safely
([`examples/infoflow/support-triage-safe.whip`](examples/infoflow/support-triage-safe.whip))
passes with no exception at all, and `whip check` prints the receipt:

```text
information-flow guarantee report
  violations caught in this program: 0
  flagged risks: none (every touched resource is governed)
  trusted surface (declassify + endorse grants): none
  information-flow surface (every door this workflow opens):
    - audit_log
    - crm
    - inbox
    - public_reply
  result/milestone flow signature (per field, the reads a consumer inherits):
    - result.ok: independent of every governed read
```

That report is the artifact you hand your data owner. Walk the whole loop in
[Govern a workflow](docs/tutorials/governance.md); it takes about 20 minutes.

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

Refer to [Guarantees](docs/guarantees.md) for each promise with its model, and
to [For IT and data owners](docs/for-it.md) for the same set as a
questionnaire with the evidence for each answer.

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

## What comes in the box

The list below is the surface that exists today, not a roadmap. Every external
operation in it is a durable effect: it has a stable idempotency key, a success
branch, and a typed failure branch, so each one composes with the four
guarantees above rather than sitting beside them. The
[language reference](docs/language-reference.md) and the
[CLI reference](docs/api-reference.md) carry the full detail.

### Work, agents, and coordination

| | Surface | What it gives you |
| --- | --- | --- |
| **Agents** | `agent`, `harness`, `tell … as turn` | Logical agents with a profile, a capacity limit, a capability list, and skills. The provider families are `owned` (whip runs the tool-use loop itself), `codex`, `claude`, `command`, and `fixture`. Swapping one for another is configuration, not a rewrite. |
| **MCP tool servers** | `whip mcp`, `require mcp <rung>` | A registry of external MCP servers with a derived trust rung — unattested, pinned, attested, classified. The envelope states the floor; the registry holds the evidence. |
| **Typed model calls** | `coerce fn(…) -> Type`, `decide "…" -> { … }` | A model decision that arrives as a typed value or fails — there is no free-form string to parse downstream. It runs against OpenAI, Anthropic, or any OpenAI-compatible endpoint, which includes a local Ollama, LM Studio, or vLLM. |
| **Issue tracker** | `tracker`, `file issue into`, `claim`, `release`, `finish`, `whip issue` | A durable, vendor-independent backlog. Rules file into it, agents work it, a person operates it from the shell. It is also how a workflow asks a human a question without blocking. |
| **Coordination** | `lease`, `counter`, `ledger` | Workspace-scoped mutexes and semaphores, capped budgets that reset on a boundary, and append-only partitioned logs with retention. Each is one atomic effect, and contention is a branch you handle — there is no lock and nothing blocks. |
| **Progressions** | `during … on lapse`, `until … on lapse`, `whip progressions` | A firing that commits runs to completion on the bindings that admitted it. A region bounds that with a condition, and the mandatory lapse arm says what happens when the condition breaks mid-flight. |
| **Composition** | `invoke … as child`, `emit milestone`, `include`, `pattern` / `apply`, `action` | Child instances with their own log and lifecycle, observable milestones during the run, and compile-time reuse that expands before anything runs. |
| **Time** | `timer <dur>`, `timer until <time>`, `timeout`, `cancel`, `source clock` | Durable waits measured in days, absolute deadlines, and timezone-aware recurring schedules that survive a restart. |

### Doors to the outside world

| | Surface | What it gives you |
| --- | --- | --- |
| **Messaging channels** | `channel`, `send via`, `when message from`, `whip mailbox` | Outbound messages with a durable receipt and inbound messages as a typed `Message` fact. Providers today are `local`, `desktop`, `stdio`, and `fixture`; live Slack and email delivery is still deferred. |
| **Ingress** | `signal`, `source file`, `source http`, `emit signal to`, `whip ingress serve` | One admission point for everything external. A source turns a schedule, a file, a watched path, or a GET-only fetch into a typed signal fact. The HTTP path is allowlisted and SSRF-checked: no loopback, no private address. |
| **Files** | `file store`, `read text`, `write text`, `import`, `export` | A declared directory with a root scope and read/write globs — never an open handle to the file system. Structured rows import and export as typed facts, all-or-nothing. |
| **Shell and scripts** | `exec "…"`, `exec <name> with <rec> -> Type`, Bashkit | A dev-profile escape hatch behind an operator allowlist, a hosted form with a SHA-256-pinned manifest and typed stdout, and an in-isolate virtual shell with no reach to the OS or the network. |
| **Memory** | `memory pool`, `learn from … into`, `recall … for`, `whip memory` | Workspace-scoped memory that outlives the instance. A write is an explicit statement; no agent quietly accumulates memory as a side effect. |

### Secrets and governance

| | Surface | What it gives you |
| --- | --- | --- |
| **Credentials** | `credential { kind }`, the `secret<kind>` type | The material never enters whip's address space. A separate custodian process substitutes it at egress and signs with it. No operation in the language yields it, no model can produce it, and a `sign` with a `bearer` credential is a compile error. |
| **Custodian operations** | authenticated `request`, `mint`, `wrap` / `unwrap` | An outbound authenticated call whose secret slots leave as sentinels, an exchange for a scoped child token bounded by its parent's ceiling, and sealed envelopes whose plaintext exists only inside one `after` block. |
| **Sealing rung** | `require credential hardware` | The envelope demands a floor — process shim, OS keyring, TPM or PKCS#11, or a remote vault — and the custodian's own evidence decides whether it is met. |
| **Escalation** | `obtain credential … into <tracker>` | A workflow that discovers it lacks authority files a tracker item and records a `credential.requested` fact, then keeps going. Nothing blocks on a human. |
| **Information flow** | signed envelope, `redact … keep`, `declassified` / `endorsed` under a grant | Reader sets and integrity levels on the real data sources, enforced per field, with a printed guarantee report. `redact` removes the fields at run time, not just from the type. |
| **Egress scope** | `grant request <cred> for <METHOD> <url>…`, `with access to` | Where a credential may reach, matched component-wise against a parsed URL. A turn narrows beneath that ceiling and can never widen it. |

### Running, operating, and seeing

| | Surface | What it gives you |
| --- | --- | --- |
| **Runtimes** | `whip run`, `whip worker`, `whip deploy`, `whip executor` | The same kernel on a local SQLite store and in a Cloudflare Durable Object, where the kernel is sans-IO, timers are DO alarms, and an evicted isolate resumes mid-effect. One deploy command, no rewrite. |
| **Lifecycle** | `pause`, `resume`, `cancel`, `retry`, `recover`, `revise` | Operator control over a live instance, including revising the program of an instance that has not terminated. |
| **Restorable context** | `checkpoint`, `restore`, `fork`, `handles` | The files, the agent transcript, and the position in the event log rewind together as one coherent cut, and the record of what happened stays true. |
| **Observability** | `status`, `log`, `facts`, `effects`, `runs`, `artifacts`, `evidence`, `diagnostics`, `trace --check` | The full instrument panel, plus a conformance replay that checks a real run against the formal model. Everything has a `--json` form. |
| **Telemetry** | `whip otel-export`, `whip telemetry` | OTLP/HTTP spans for provider runs, with a durable cursor so a second pass emits each span exactly once. |
| **Testing** | `assert`, `whip test`, `whip accept`, the fixture provider | Deterministic runs with no credentials, plus `--fail`, `--timeout`, and `--cancel` flags that force a terminal branch so you can test the paths that only happen at 3 a.m. |
| **Improve** | `gauge`, `campaign`, `whip improve`, `pin` / `suppose` / `settle`, `whip answer` | Declared dimensions of quality scored across runs, an optimizer that works strictly inside a versioned statement of intent, holdout sets, spend caps that park rather than truncate, and durable precedents. |
| **Authoring tools** | `whip check`, `fmt`, `lint`, `lsp`, `package`, `doctor` | An idempotent formatter, a linter with zero false positives, an LSP over stdio with cross-file definitions, and a package surface that cannot add hidden control flow. |
| **Versioned workspace** | `whip branch`, `whip stream` — *experimental* | A whip-native VCS: cuts, diff, merge with conflict resolution, bisect, attribution, undo, and transport of a selection onto another line, with streams grouping branches for review. It operates; expect it to change. |

## Where you start

| Your position | Read |
| --- | --- |
| You know the automations that you want. You do not write code. | [Build your own automations](docs/for-builders.md) |
| You approve the tools that your staff use. | [For IT and data owners](docs/for-it.md) |
| You want to see the system as it is. | [How WhippleScript works](docs/for-developers.md) |

When you point a coding agent at WhippleScript, start the agent with
`skills/whipplescript-author/SKILL.md`.

## Documentation

The full set is at [docs.whipplescript.com](https://docs.whipplescript.com/),
and the same Markdown is in this checkout.

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

To serve the same documents locally:

```sh
python3 -m pip install mkdocs
mkdocs serve
```

## The green bar

One command runs the complete check set that applies to every change, and CI
runs the same script:

```sh
scripts/check.sh
```

The Rust and Node versions are pinned in `rust-toolchain.toml` and
`.node-version`; the workflows derive their versions from those files.
[AGENTS.md](AGENTS.md) is the working guide for this repository. These scripts
check the documents themselves:

```sh
scripts/check-docs-quickstart.sh
scripts/check-docs-examples.sh
scripts/check-docs-snippets.sh
scripts/check-docs-site.sh
```

The `scripts/check-release-readiness.sh` script runs the full release gate. The
gate includes validation of the report schemas and artifacts, and the checks of
the formal models. A Nix dev shell supplies the necessary tools: run
`nix develop`. In an environment without Nix, install the dependencies of the
Python scripts with `python3 -m pip install -r requirements-dev.txt`. The
document `spec/implementation-plan.md` records
the remaining work.

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
