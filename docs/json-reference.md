# JSON Reference

This page is the public contract surface of the CLI that a machine can read. A
set of fields can become larger in the same version of a schema. Thus a consumer
must ignore an unknown field. The necessary fields on this page are safe to
depend on. They are safe for the current set of documents and for the released
`0.2.1` CLI, unless the version of a schema changes.

For the use of a command, refer to the [CLI reference](api-reference.md).

## Stability Model

| Surface | Schema/version | Stability |
| --- | --- | --- |
| `check --json` | `whipplescript.check_report.v0` | A public report in draft. The necessary fields are stable. More fields can appear. |
| `compile --json` | `whipplescript.compile_report.v0` | A public report in draft. The necessary fields are stable. More fields can appear. |
| `run --json` | `whipplescript.dev_report.v0` | A public report in draft. The report is for the acceptance tests and for the tools on your machine. |
| `run --stream ndjson` | `whipplescript.dev_stream.v0` | An envelope of an event in draft. The set of the names of the events can become larger. |
| `accept --json` | `whipplescript.acceptance_report.v0` | A report for a test only. The expectations about the isolation of the store are part of the contract. |
| `trace --json --check` | `whipplescript.local_trace.v0` | A report of a trace and of the conformance, in draft. |
| `test --json` | `whipplescript.test_report.v0` | A public report in draft. The `whip test --json` command emits the report. The report has one entry for each selected scenario, and a summary. |
| `verify-report` | `whipplescript.verified_artifacts.v0` | A bundle of verification. The `whip verify-report` command emits the bundle over a check report, a compile report, or an artifacts report. |
| `verify-report --emit lowered-ir` | `whipplescript.lowered_ir_report.v0` | The artifact of the lowered IR. The `whip verify-report --emit lowered-ir` command emits the artifact. |
| `verify-report --emit construct-graph` | `whipplescript.construct_graph.v0` | The artifact of the graph of the constructs, alone. The check report below also contains this artifact. |
| Package manifest | `whipplescript.package_manifest.v0` | The first-class manifest of a package, a library, and a provider. |
| Platform construct catalog | `whipplescript.platform_construct_catalog.v0` | The vocabulary of the constructs and the lowering operations of a package. The compiler owns the vocabulary. The `whip package catalog` command emits the vocabulary. |
| Package check | `whipplescript.package_check.v0` | The result of the `whip package check --json` command. |
| Package contract | `whipplescript.package_contract.v0` | The normalized artifact of the package and the registry. The artifact carries a digest. The check report, the compile report, and the report of the verified artifacts use the artifact. |
| Package lock | `whipplescript.package_lock.v0` | Pins each accepted manifest of a package by its exact SHA-256 value. |
| Package set | `whipplescript.package_set.v0` | A declarative set of packages in a `whip.packages.json` file. The `whip package sync` command resolves the set. |
| Package sync | `whipplescript.package_sync.v0` | The result of the `whip package sync [--json]` command. |
| Artifact manifest | `whipplescript.artifact_manifest.v1` | The contract for the metadata of an artifact of a provider. The document for the model of the providers gives this schema. The schema is not in `spec/report-schemas/`. |
| Inspection commands | JSON with the shape of the command | Sufficiently stable for an operator. The surface has no schema identifier now. |
| Coordination inspection | JSON with the shape of the command | Sufficiently stable for an operator. The surface has no schema identifier now. |

The JSON schemas for the envelopes of the reports with a version are in
`spec/report-schemas/`.
Validate the schemas with the `scripts/check-report-schemas.sh` script.

## Required Fields

### Check Report

An entry of a `whip --json check <workflow.whip>` command that succeeds needs
these fields:

```json
{
  "schema": "whipplescript.check_report.v0",
  "path": "examples/minimal-noop.whip",
  "status": "ok",
  "workflow": "MinimalNoop",
  "source_hash": "...",
  "ir_hash": "...",
  "snapshot": "...",
  "source_metadata": {
    "tags": [],
    "descriptions": [],
    "targets": {}
  },
  "contract_registry": {
    "schema": "whipplescript.contract_registry.v0",
    "libraries": [],
    "declaration_forms": [],
    "effect_contracts": [],
    "diagnostics": []
  },
  "package_contract": {
    "schema": "whipplescript.package_contract.v0",
    "package_contract_digest": "...",
    "package_lock_digest": "...",
    "contract_registry": {}
  },
  "construct_graph": {
    "schema": "whipplescript.construct_graph.v0",
    "package_contract_digest": "...",
    "nodes": [],
    "edges": [],
    "derived_facts": [],
    "diagnostics": []
  }
}
```

An entry with an error needs the `schema` field, the `path` field, the
`status: "error"` field, and an `error` object. The kinds of error are `io`,
`diagnostics`, `package_lock`, and `construct_graph`. A diagnostic has a message
and a span of the source, when the span is available.

The `package_contract` field is the normalized artifact of the package and the
registry. The field carries the summaries of the locked manifests, the catalog
of the constructs of the platform, the registry of the contracts, and a
`package_contract_digest` value over that body.

The `construct_graph` field is the normalized artifact of the static
composition of the program that the command checked. The field gives the same
`package_contract_digest` value. Thus the verification of a report can reject a
graph that a command checked against a package contract that is no longer
current.

In the current executable part, a call to a capability of a locked package
emits nodes for the operations of the effects, nodes for the effect contracts of
the package, and edges for the resolved capabilities. A `timer.wait` node gives
a `schedule_template` output. A node for a core rule template also gives the
`fact_record` templates that the rule owns, when the body of the rule can record
a fact. An empty graph is valid for a program that does not yet use a construct
that a package supports. An accepted graph has the `derived_facts` field. The
`construct_graph_validator` component owns that field for the structural
predicates of the graph that the current validator checks.

### Compile Report

The `whip --json compile <workflow.whip>` command needs these fields:

```json
{
  "schema": "whipplescript.compile_report.v0",
  "path": "examples/minimal-noop.whip",
  "workflow": "MinimalNoop",
  "source_hash": "...",
  "ir_hash": "...",
  "snapshot": "...",
  "source_metadata": {
    "tags": [],
    "descriptions": [],
    "targets": {}
  },
  "contract_registry": {
    "schema": "whipplescript.contract_registry.v0",
    "libraries": [],
    "declaration_forms": [],
    "effect_contracts": [],
    "diagnostics": []
  },
  "package_contract": {
    "schema": "whipplescript.package_contract.v0",
    "package_contract_digest": "...",
    "package_lock_digest": "...",
    "contract_registry": {}
  }
}
```

The `contract_registry` field is the normalized view of the compiler of the
contracts of the libraries and the effects that the program uses. The report
gives a standard built-in surface as a `std.*` library with the version `v0`. An
import of a package that a package lock resolves appears with the pinned version
of the package. An import in the source with no lock appears with the version
`unlocked`, until the lock supplies the contract of the package.

The `declaration_forms` field gives the forms of the source that a library owns
and that a locked package registers. A `metadata_only` form is metadata for the
tools.

The accepted executable target today is `capability_call`. This target lowers a
fixed form that the core owns to the named `target_capability`. For example, the
memory package can authorize the form
`recall from <pool> for <query> as <binding>` as a call to the memory recall
capability.

The `effect_contracts` field gives the forms of the source, the necessary
capabilities, the families of provider, the output schema, and the boundary for
the validation at run time, for each kind of effect. For a call to a capability
of a locked package, the worker applies the `runtime_boundary` value before it
derives a success fact.

A declaration form of a package uses a class of lowering that the platform owns.
A new target for a lowering operation needs an extension class of the platform
before the target can appear in a manifest. An effect of a package that is not
`capability.call` also needs such an extension class.

### Package Lock

The `whip package lock --output whip.lock <manifest.json>...` command writes
this file:

```json
{
  "schema": "whipplescript.package_lock.v0",
  "packages": [
    {
      "package_id": "package-notes",
      "name": "notes",
      "version": "0.1.0",
      "source": {"type": "path", "path": "examples/packages/notes.json"},
      "manifest_sha256": "..."
    }
  ]
}
```

The `check`, `compile`, `start`, `run`, and `worker` commands reject an entry in
a lock when the name of the manifest, the version, the identifier of the
package, or the SHA-256 value no longer matches. A lock must not contain a
duplicate identifier of a package or a duplicate name of a package. An import in
the source resolves through the name of the package. Thus each name of a locked
package is unique. An entry in a lock can never claim the reserved `std.*`
namespace. A std package such as `std.memory` is embedded in the platform. A
package lock cannot supply a std package.

### Trace Report

The `whip --json trace <instance> --check` command needs these fields:

```json
{
  "schema": "whipplescript.local_trace.v0",
  "instance_id": "inst_...",
  "events": [],
  "facts": [],
  "effects": [],
  "runs": [],
  "evidence": [],
  "evidence_links": [],
  "abstract_trace": [],
  "conformance": {"ok": true}
}
```

## Inspection Shapes

### Event

```json
{
  "event_id": "evt_...",
  "instance_id": "inst_...",
  "sequence": 1,
  "event_type": "rule.committed",
  "payload": {},
  "occurred_at": "...",
  "source": "kernel",
  "causation_id": null,
  "correlation_id": null
}
```

The necessary fields are `event_id`, `instance_id`, `sequence`, `event_type`,
`payload`, `occurred_at`, and `source`.

### Fact

```json
{
  "fact_id": "fact_...",
  "program_version_id": "ver_...",
  "revision_epoch": 0,
  "name": "WorkItem",
  "key": "item-1",
  "value": {},
  "provenance_class": "rule",
  "source_span": null
}
```

The necessary fields are `fact_id`, `name`, `value`, and `provenance_class`. A
fact that comes from a `table` declaration has `provenance_class: "table"` and a
`source_span` field for its row.

### Effect

```json
{
  "effect_id": "effect-1",
  "kind": "agent.tell",
  "target": "worker",
  "status": "queued",
  "profile": "repo-writer",
  "policy_block_reason": null,
  "input": {}
}
```

The necessary fields are `effect_id`, `kind`, `status`, and `input`.

### Run

```json
{
  "run_id": "run-...",
  "effect_id": "effect-1",
  "provider": "fixture",
  "worker_id": "whip-worker",
  "status": "completed",
  "started_at": "...",
  "completed_at": "..."
}
```

The necessary fields are `run_id`, `effect_id`, `provider`, `worker_id`,
`status`, and `started_at`.

### Diagnostic

A runtime diagnostic that the `diagnostics --json` command returns needs these
fields:

```json
{
  "diagnostic_id": "diag_...",
  "instance_id": "inst_...",
  "severity": "error",
  "code": "provider.failure",
  "message": "provider run failed",
  "source_span": null,
  "event_id": "evt_...",
  "effect_id": "effect-...",
  "run_id": "run-..."
}
```

The optional fields link to the records of the program, the version, the
assertion, the evidence, the artifact, the causation, and the correlation, when
those records are available.

## Coordination Inspection

The `leases --json` command returns this data:

```json
[
  {
    "resource": "deploy_slot",
    "key": "prod",
    "holder": "inst_...",
    "acquired_at": "...",
    "expires_at": "..."
  }
]
```

The `ledger --json` command returns this data:

```json
[
  {
    "ledger": "decisions",
    "partition": "incident",
    "seq": 1,
    "entry": {},
    "appended_by": "inst_...",
    "appended_at": "..."
  }
]
```

The `counters --json` command returns this data:

```json
[
  {
    "counter": "budget",
    "key": "customer-1",
    "consumed": 42,
    "period": "2026-06-11"
  }
]
```

These commands read the store that the `WHIPPLESCRIPT_COORDINATION_STORE`
variable gives. If you do not set the variable, the commands read
`.whipplescript/coordination.sqlite`.

## Tracker Issue Shapes

The `whip --json issue show <id>` command and the `list` command return the rows
of the issues. Each row has the basic fields and the phase-B surface from
ADR-0002:

| Field | Meaning |
| --- | --- |
| `id`, `queue`, `title`, `body`, `labels`, `status` | The identity and the content of the issue. |
| `filed_by`, `claimed_by`, `created_at`, `updated_at` | The provenance and the stamps of the lifecycle. An issue that an agent files carries the identity of the run. |
| `heads` | The identifiers of the heads of the Merkle DAG of the events of the issue. These identifiers are the frontier of its causal history. |
| `state_token` | An opaque token for optimistic concurrency. Give the token back with `whip issue set … --expect-state-token`. Thus the command fails cleanly when a concurrent edit occurs. |
| `conflicted` / `field_conflicts` | Whether concurrent edits diverged, and the detail of the conflict for each field. Use the `whip issue conflicts` command to examine and to resolve a conflict. |
| `relations` | The typed links to other issues. The commands are `dep add`, `link`, and `unlink`. |
| `metadata` | An open map for extensions. |

## Status Values

This is the status of an instance:

```text
running
paused
completed
failed
cancelled
```

This is the status of an effect:

```text
queued
blocked_by_dependency
blocked_by_capacity
blocked_by_capability
blocked_by_profile
running
completed
failed
timed_out
cancelled
```

This is the status of a run:

```text
running
completed
failed
timed_out
cancelled
lease_expired
```

This is the status of a lease:

```text
active
released
expired
```

## Event Types

These are the usual types of event:

| Event | Meaning |
| --- | --- |
| `external.started` | The event of the start input of an instance. |
| `rule.committed` | A rule committed its facts, effects, dependencies, and terminal action atomically. |
| `effect.run_started` | A run of a provider started for an effect. |
| `effect.terminal` | An effect completed, failed, timed out, or received a cancel operation. |
| `effect.blocked` | An effect blocked before the start of the provider. |
| `effect.cancellation_requested` | An effect that runs received a durable request for a cancel operation. |
| `effect.retried` | An effect returned to the queue for a retry. |
| `lease.expired` | An active lease of a run expired. |
| `lease.renewed` | A component renewed an active lease of a run. |
| `instance.transitioned` | A pause, resume, or cancel transition occurred. |
| `workflow.completed` | A workflow supplied its declared output and became complete. |
| `workflow.failed` | A workflow supplied its declared failure and became failed. |
| `workflow.revision_activated` | The active version of the program of an instance changed. |
| `workflow.revision_rejected` | A revision that was not a dry run failed the checks for compatibility. |
| `fact.derived` | A projection at run time derived a durable fact from an event or an effect. |
| `assertion.passed` | The evaluation of an explicit assertion returned true. |
| `assertion.failed` | The evaluation of an explicit assertion returned false and supplied a diagnostic. |
| `assertion.errored` | The evaluation of an explicit assertion could not supply a boolean result and supplied a diagnostic. |
| `agent.turn.completed` | The projection of the completion of an agent turn. |
| `agent.turn.failed` | The projection of the failure of an agent turn. |
| `agent.turn.timed_out` | The projection of the timeout of an agent turn. |
| `agent.turn.cancelled` | The projection of the cancel operation on an agent turn. |
| `agent.turn.started` | The observation of the start of a turn of a native provider. |
| `agent.turn.streamed` | The observation of a stream of a native provider. |
| `agent.turn.tool_requested` | The observation of a tool or an approval of a native provider. |
| `agent.turn.artifact_captured` | The observation of an artifact or a diff of a native provider. |
| `artifact.capture.failed` | The capture of an artifact of a provider failed. The failure occurred before or during the terminal completion. |
| `progression.cancelled` | An operator closed one open firing precisely. |
| `progression.region.lapsed` | The condition of a `during` region or an `until` region fired. The lapse arm committed. The payload holds `rule`, `condition`, `until`, the pinned progress view `got` (the steps that succeeded), and `steps`: one status for each step of the region, from `completed`, `failed`, `timed_out`, `cancelled`, `cancelled_by_lapse` (the commit of the lapse cancelled a step in operation), and `not_requested`. The lapse arm reads the same statuses as `<view>.steps.<step>`. |
| `context.restored` | A restore operation on a checkpoint rewound the instance to a recorded cut. |
| `signal.emit.completed` | The typed injection of a signal in a workflow completed. |

## Provider And Artifact Shapes

The configuration of a provider binding, the result of the validation of a
provider, the observation of a native lifecycle, the terminal metadata of a
provider, a manifest of an artifact, and a failure to capture an artifact are
JSON contracts. These contracts are for an operator and for the author of a
provider. The [Providers & packages](providers.md) page records these contracts
with the model of the providers. The details of the schemas are in
`spec/reporting.md`, `spec/observability.md`, and `spec/report-schemas/`.
