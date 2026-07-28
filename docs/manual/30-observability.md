# Observability & tracing

Chapter 1 taught the basic loop: `check`, `run`, `status`, `facts`, and `log`.
Each subsequent chapter added a view. Chapter 5 added `effects` and `runs`.
Chapter 6 added diagnostics. Chapter 15 added `issue`. Chapter 16 added
`progressions`. Chapter 26 added `gauges`. This last chapter of Part IV
assembles the full instrument panel. The chapter also adds the deep tools:
conformance tracing, lint, and the export of telemetry.

## The panel, by question

| Question | View |
| --- | --- |
| What is the state of this instance? | `whip status <id>` — the status, the version, the counts, and the recent events |
| What can the rules see now? | `whip facts <id>` — the facts that no rule consumed, and the live projections |
| What occurred, and in what sequence? | `whip log <id>` — the append-only stream of events with the causation identifiers |
| What external work exists? | `whip effects <id>` and `whip runs <id>` — the requests and the attempts |
| What does each firing wait for? | `whip progressions <id>` — the pinned bindings, the residue, and the state of a region |
| What failed quietly? | `whip diagnostics <id>` — the durable diagnostics, by code |
| Is the environment correct? | `whip doctor` — the store, the schema, and the probes of the providers |
| What instances does this store hold? | `whip instances` |
| What did a run supply or prove? | `whip evidence instance <id>` — the evidence records and the links. Use `whip artifacts <run-id>` for the artifacts of a run |
| What waits for a person? | `whip issue list` — the tracker questions for a person that no person finished |

The principle behind the panel comes from chapter 5. A workflow is not a
program that runs. A workflow is a durable record that a program advances.
Thus observability is a *query of the record*. Observability never attaches to
a process. Each view operates identically on a live instance, on an instance
that completed, and on an instance that completed one month before.

## Conformance tracing: the `whip trace --check` command

The record itself has a shape that you can check. Each effect moves through a
declared lifecycle. Each event carries its causation. The full stream must
conform to the model of the lifecycle:

```sh
whip trace ins_8b3f28… --check
```

```text
trace ins_8b3f28…
events=4 facts=2 effects=0 runs=0 evidence=1 links=6
conformance=ok abstract_events=0
```

The `trace` command folds the stream of the instance against the lifecycle
model of the runtime. The model is the conformance checker of the kernel. The
file `models/tla/ControlPlaneLifecycle.tla` pins its invariants. The command
then reports each violation. The value `conformance=ok` is a statement that a
machine checked. The statement says that the history of this run obeys the
semantics that the Guarantees page promises. Use this tool when a deep problem
occurs. An effect that settled two times and a commit in the incorrect sequence
are examples. The tool gives a precise report.

## Lint: the analyses that do not block

The `whip lint <file>` command runs the set of analyses with zero false
positives. These diagnostics are useful, but they must not fail a build. The
diagnostics find rules that appear unreachable, shapes that appear incorrect,
and the configured actions of the project. The message `no lint findings` is
the result with no problem. The division with the `whip check` command is the
strictness. An error from the `check` command blocks the build. A finding from
the `lint` command gives advice. The two commands give spans that your editor
can go to. The same engine supports the LSP.

## Telemetry: export to OTLP

For a large group of instances, the record exports to standard tools:

```sh
whip otel-export ins_8b3f28…
```

The exporter is a sidecar with a cursor. The exporter reads the end of the
durable log. The exporter emits traces as OTLP/HTTP JSON. The name of each span
comes from a *construct in the source*. The attributes are structural only. The
exporter remembers its position. Thus a second run of the command exports only
the new data. The message `nothing new to export` is the result when no new
data exists. The `--dry-run` flag prints the payload and sends nothing. Point
the exporter at an OpenTelemetry Collector with the
`OTEL_EXPORTER_OTLP_ENDPOINT` variable. The collector owns the TLS
configuration and the distribution to the backends. Each span reflects a
construct. Thus the trace in a dashboard is the program that you wrote. The
trace shows rules, effects, and turns. The trace does not show noise from the
implementation. The `whip telemetry` family of commands manages the cursors for
the export.

## How to read an instance that stopped

This manual taught a procedure for debug operations. This is the procedure in
sequence:

1. `status` — is the instance running and idle, blocked, or failed? The line
   with the counts gives the view to open next.
2. `progressions` — each firing and the item that it owes. A region that lapsed
   and a pending effect are visible here, with the condition or the status.
3. `effects` — each `blocked_by_*` value gives its gate. The gates are a
   capability, a capacity, a dependency, and a profile.
4. `diagnostics` — unhandled failures in service mode, problems in the lowering
   operation, and refusals by a policy. Each item has a stable code.
5. `log` — the ground truth with links for causation. Use this view when a
   summary view does not agree with your expectation.
6. `trace --check` — use this view when you believe that the *engine* has the
   problem and not the program.

Each item in this list reads the same store that your workflow writes. You
instrument no agent. You add no log statement. There is no sampling. The record
is the observability.

## Where next

Part V extends WhippleScript. Chapter 31 gives the authoring of a package.
Chapter 32 gives the configuration of providers and harnesses. Chapter 33 gives
script capabilities and the bash tool. Chapter 34 gives the runtimes below each
of these constructs.
